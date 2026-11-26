package server

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/volbackup"
)

// Pull request 15 of ADR 0055, second part: the control plane's backups
// (ADR 0051) on both servers. Go's server reaches the stand-in bucket in
// process (cpObjects), the program over HTTP as S3 (cpBucket, through
// armada-node's test hook ARMADA_NODE_TEST_BUCKET_ADDR); both stage one
// file the scenario sets (cpStage).

// The bucket's URL names a private address the program's test hook sends
// to the stand-in.
const (
	parityCPBucketURL = "http://AK:SECRETKEY123@10.0.0.50:9000/backups/armada"
	parityCPBucketKey = "0123456789abcdef0123456789abcdef-key"
)

type cpObject struct {
	data []byte
	mod  time.Time
}

// cpBucket is bucket "backups" as an S3 endpoint answers path-style
// requests, its objects stamped with the scenario's clock.
type cpBucket struct {
	mu    sync.Mutex
	objs  map[string]cpObject
	clock *parityClock
	srv   *httptest.Server
}

func newCPBucket(t *testing.T, clock *parityClock) *cpBucket {
	t.Helper()
	b := &cpBucket{objs: map[string]cpObject{}, clock: clock}
	b.srv = httptest.NewServer(b)
	t.Cleanup(b.srv.Close)
	return b
}

func (b *cpBucket) addr() string { return strings.TrimPrefix(b.srv.URL, "http://") }

func (b *cpBucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	b.mu.Lock()
	defer b.mu.Unlock()
	fail := func(code int, s3code string) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>`+s3code+`</Code><Message>no</Message></Error>`)
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if bucket != "backups" {
		fail(http.StatusNotFound, "NoSuchBucket")
		return
	}
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && key == "" && q.Has("location"):
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`)
	case r.Method == http.MethodPut && key != "":
		b.objs[key] = cpObject{data: body, mod: b.clock.now()}
	case r.Method == http.MethodGet && key == "":
		type content struct {
			Key          string
			Size         int64
			LastModified string
		}
		res := struct {
			XMLName               xml.Name `xml:"ListBucketResult"`
			Name                  string
			Prefix                string
			KeyCount              int
			IsTruncated           bool
			NextContinuationToken string `xml:",omitempty"`
			Contents              []content
		}{Name: "backups", Prefix: q.Get("prefix")}
		var keys []string
		for k := range b.objs {
			if strings.HasPrefix(k, res.Prefix) && k > q.Get("continuation-token") {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		if len(keys) > 3 {
			keys = keys[:3]
			res.IsTruncated, res.NextContinuationToken = true, keys[len(keys)-1]
		}
		for _, k := range keys {
			res.Contents = append(res.Contents, content{Key: k, Size: int64(len(b.objs[k].data)), LastModified: b.objs[k].mod.UTC().Format("2006-01-02T15:04:05.000Z")})
		}
		res.KeyCount = len(res.Contents)
		w.Header().Set("Content-Type", "application/xml")
		_ = xml.NewEncoder(w).Encode(res)
	case r.Method == http.MethodGet:
		o, ok := b.objs[key]
		if !ok {
			fail(http.StatusNotFound, "NoSuchKey")
			return
		}
		_, _ = w.Write(o.data)
	case r.Method == http.MethodDelete:
		delete(b.objs, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		fail(http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

// summary names what the bucket holds by kind: the repository's config,
// its backups, and its chunks, all under the control plane's root.
func (b *cpBucket) summary() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]any{}
	count := func(k string) { n, _ := out[k].(int); out[k] = n + 1 }
	for k := range b.objs {
		rest, ok := strings.CutPrefix(k, "armada/_control-plane/")
		switch {
		case !ok:
			count("elsewhere")
		case rest == "config":
			count("config")
		case strings.HasPrefix(rest, "snapshots/"):
			count("snapshots")
		case strings.HasPrefix(rest, "chunks/"):
			count("chunks")
		default:
			count("other")
		}
	}
	return out
}

// cpObjects is the same bucket as Go's volbackup reaches it.
type cpObjects struct{ b *cpBucket }

func (o cpObjects) Put(_ context.Context, key string, data []byte) error {
	o.b.mu.Lock()
	defer o.b.mu.Unlock()
	o.b.objs[key] = cpObject{data: slices.Clone(data), mod: o.b.clock.now()}
	return nil
}

func (o cpObjects) Get(_ context.Context, key string, maxSize int64) ([]byte, error) {
	o.b.mu.Lock()
	defer o.b.mu.Unlock()
	obj, ok := o.b.objs[key]
	if !ok {
		return nil, volbackup.ErrNotExist
	}
	if int64(len(obj.data)) > maxSize {
		return nil, fmt.Errorf("bucket: object larger than %d bytes", maxSize)
	}
	return slices.Clone(obj.data), nil
}

func (o cpObjects) List(_ context.Context, prefix string, fn func(volbackup.Object) error) error {
	o.b.mu.Lock()
	var out []volbackup.Object
	for k, obj := range o.b.objs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, volbackup.Object{Key: k, Size: int64(len(obj.data)), Modified: obj.mod.UTC().Truncate(time.Millisecond)})
		}
	}
	o.b.mu.Unlock()
	slices.SortFunc(out, func(a, b volbackup.Object) int { return strings.Compare(a.Key, b.Key) })
	for _, x := range out {
		if err := fn(x); err != nil {
			return err
		}
	}
	return nil
}

func (o cpObjects) Delete(_ context.Context, key string) error {
	o.b.mu.Lock()
	defer o.b.mu.Unlock()
	delete(o.b.objs, key)
	return nil
}

// cpStager is Go's stand-in for what armadad stages for a backup: one
// file, etcd.snapshot, holding content, or fail as the error.
type cpStager struct {
	mu            sync.Mutex
	content, fail string
}

func (c *cpStager) set(content, fail string) {
	c.mu.Lock()
	c.content, c.fail = content, fail
	c.mu.Unlock()
}

func (c *cpStager) backup(_ context.Context, fn func(dir string) error) error {
	c.mu.Lock()
	content, fail := c.content, c.fail
	c.mu.Unlock()
	if fail != "" {
		return errors.New(fail)
	}
	dir, err := os.MkdirTemp("", "armada-parity-cp-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.WriteFile(filepath.Join(dir, "etcd.snapshot"), []byte(content), 0o600); err != nil {
		return err
	}
	return fn(dir)
}

// cpPass runs a pass of the control plane backup loop and records
// ClusterStatus's backups and the bucket.
func (sc *scenario) cpPass(label string) {
	sc.t.Helper()
	sc.sut.cpBackups(sc.t)
	resp, err := sc.admin.ClusterStatus(sc.ctx, &armadav1.ClusterStatusRequest{})
	if err != nil {
		sc.note(label, err)
		return
	}
	sc.answer(label, resp.GetControlPlaneBackup(), nil)
	sum := sc.cpBucket.summary()
	if sc.rec != nil {
		// The replay's own stand-in bucket, which the program reaches.
		step := sc.rec.add(map[string]any{"op": "cpBucket"})
		sc.rec.expect(step, "expect", sum)
	}
	sc.note(label+": bucket", sum)
}

// cpMetrics records the control plane backup lines of the metrics
// endpoint, scraped as a cluster-admin.
func (sc *scenario) cpMetrics(label string) {
	sc.t.Helper()
	cert, key, err := sc.fx.ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindAdmin, Name: "ryan"}, Client: true})
	if err != nil {
		sc.t.Fatal(err)
	}
	sc.advance(time.Millisecond)
	_, body, err := sc.scrape(cert, key, http.MethodGet, "/metrics")
	if err != nil {
		sc.note(label, map[string]any{"error": true})
		return
	}
	var lines []string
	for _, l := range strings.Split(body, "\n") {
		if strings.Contains(l, "control_plane_backup") {
			lines = append(lines, l)
		}
	}
	sc.note(label, lines)
}

func (sc *scenario) setBackups(label string, req *armadav1.SetClusterConfigRequest) {
	sc.t.Helper()
	if req.Config == nil {
		req.Config = &armadav1.ClusterConfig{}
	}
	cc, err := sc.admin.SetClusterConfig(sc.ctx, req)
	if err != nil {
		sc.note(label, err)
		return
	}
	sc.note(label, map[string]any{"every": cc.GetBackupEverySeconds(), "schedule": cc.GetBackupSchedule(), "zone": cc.GetBackupTimeZone(),
		"bucket": cc.GetBackupBucket(), "keep": cc.GetBackupKeep().String()})
}

// TestControlPlaneBackupSettings, TestControlPlaneBackupsRunPruneAndRetry,
// and TestControlPlaneBackupWrongKey on both servers: the settings'
// checks, nothing in the clear or in the audit log, backups when due into
// the repository at <prefix>_control-plane/, pruning to the keep policy,
// a failure recorded with its condition, event, and counter, retried after
// five minutes and cleared by a success, a new bucket starting afresh, a
// key that does not match the bucket's backups, and backups turned off.
func TestParityControlPlaneBackups(t *testing.T) {
	runParity(t, parityConfig{masterKey: true, cpBackups: true, metrics: true}, func(sc *scenario) {
		sc.sut.cpStage("state v1", "")
		plan := &armadav1.ClusterConfig{BackupEverySeconds: 3600, BackupKeep: &armadav1.BackupKeep{Last: 2}}
		full := func(mut func(*armadav1.SetClusterConfigRequest)) *armadav1.SetClusterConfigRequest {
			r := &armadav1.SetClusterConfigRequest{Config: plan, SetBackupPlan: true, SetBackupKeep: true,
				SetBackupUrl: true, BackupUrl: []byte(parityCPBucketURL), SetBackupKey: true, BackupKey: []byte(parityCPBucketKey)}
			mut(r)
			return r
		}
		for _, tc := range []struct {
			name string
			mut  func(*armadav1.SetClusterConfigRequest)
		}{
			{"not a URL", func(r *armadav1.SetClusterConfigRequest) { r.BackupUrl = []byte("s3://AK:SECRETKEY123@h/b") }},
			{"http to a public IP", func(r *armadav1.SetClusterConfigRequest) {
				r.BackupUrl = []byte("http://AK:SECRETKEY123@203.0.113.9/b")
			}},
			{"loopback bucket", func(r *armadav1.SetClusterConfigRequest) { r.BackupUrl = []byte("https://AK:SECRETKEY123@127.0.0.1/b") }},
			{"no keys in the URL", func(r *armadav1.SetClusterConfigRequest) { r.BackupUrl = []byte("https://s3.example.com/b") }},
			{"empty URL", func(r *armadav1.SetClusterConfigRequest) { r.BackupUrl = nil }},
			{"short key", func(r *armadav1.SetClusterConfigRequest) { r.BackupKey = []byte("short-SECRETKEY123") }},
			{"missing key", func(r *armadav1.SetClusterConfigRequest) { r.SetBackupKey, r.BackupKey = false, nil }},
			{"missing URL", func(r *armadav1.SetClusterConfigRequest) { r.SetBackupUrl, r.BackupUrl = false, nil }},
			{"no plan", func(r *armadav1.SetClusterConfigRequest) { r.SetBackupPlan = false }},
			{"keeps nothing", func(r *armadav1.SetClusterConfigRequest) { r.SetBackupKeep = false }},
			{"every 1m", func(r *armadav1.SetClusterConfigRequest) {
				r.Config = &armadav1.ClusterConfig{BackupEverySeconds: 60, BackupKeep: plan.BackupKeep}
			}},
			{"negative", func(r *armadav1.SetClusterConfigRequest) {
				r.Config = &armadav1.ClusterConfig{BackupEverySeconds: -5, BackupKeep: plan.BackupKeep}
			}},
			{"bad schedule", func(r *armadav1.SetClusterConfigRequest) {
				r.Config = &armadav1.ClusterConfig{BackupSchedule: "every day", BackupKeep: plan.BackupKeep}
			}},
			{"bad time zone", func(r *armadav1.SetClusterConfigRequest) {
				r.Config = &armadav1.ClusterConfig{BackupSchedule: "0 3 * * *", BackupTimeZone: "Mars/Olympus", BackupKeep: plan.BackupKeep}
			}},
			{"off with more", func(r *armadav1.SetClusterConfigRequest) { r.SetBackupOff = true }},
		} {
			sc.setBackups("refused: "+tc.name, full(tc.mut))
		}
		sc.cpPass("off")

		sc.setBackups("on", full(func(*armadav1.SetClusterConfigRequest) {}))
		sc.cpPass("first backup")
		sc.cpMetrics("metrics after the first")
		sc.advance(30 * time.Minute)
		sc.cpPass("not due within the hour")
		for i := range 3 {
			sc.advance(time.Hour)
			sc.sut.cpStage("state v1"+strings.Repeat("a", i+1), "")
			sc.cpPass(fmt.Sprintf("hourly %d", i+1))
		}
		// A failure: recorded, its condition, retried after five minutes.
		sc.sut.cpStage("", "the state is not reachable")
		sc.advance(time.Hour)
		sc.cpPass("failed")
		sc.cpMetrics("metrics after the failure")
		sc.advance(time.Minute)
		sc.cpPass("not retried within the minute")
		sc.advance(5 * time.Minute)
		sc.cpPass("retried after five minutes")
		sc.sut.cpStage("state v2", "")
		sc.advance(5 * time.Minute)
		sc.cpPass("a success clears the failure")
		sc.keyspace("keyspace after backups")

		// A plan alone keeps the bucket and the key.
		sc.setBackups("a schedule", &armadav1.SetClusterConfigRequest{Config: &armadav1.ClusterConfig{BackupSchedule: "0 3 * * *", BackupTimeZone: "Asia/Jakarta"}, SetBackupPlan: true})
		// Another key for the same bucket: refused by the repository.
		sc.setBackups("another key", &armadav1.SetClusterConfigRequest{SetBackupKey: true, BackupKey: []byte(strings.Repeat("k", 40))})
		sc.cpPass("wrong key")
		// A new bucket starts afresh: due at once.
		sc.setBackups("new bucket", &armadav1.SetClusterConfigRequest{SetBackupUrl: true, BackupUrl: []byte(parityCPBucketURL + "/other")})
		sc.cpPass("new bucket")

		sc.setBackups("off", &armadav1.SetClusterConfigRequest{SetBackupOff: true})
		cc, err := sc.admin.GetClusterConfig(sc.ctx, &armadav1.GetClusterConfigRequest{})
		sc.note("config after off", map[string]any{"bucket": cc.GetBackupBucket(), "keep": cc.GetBackupKeep() != nil, "error": err != nil})
		sc.setBackups("a plan alone after off", &armadav1.SetClusterConfigRequest{Config: plan, SetBackupPlan: true, SetBackupKeep: true})
		sc.cpPass("off again")
		sc.keyspace("keyspace")
	})
}

// No master key: nothing to seal the URL and key with.
func TestParityControlPlaneBackupsWithoutKey(t *testing.T) {
	runParity(t, parityConfig{cpBackups: true}, func(sc *scenario) {
		sc.setBackups("refused", &armadav1.SetClusterConfigRequest{Config: &armadav1.ClusterConfig{BackupEverySeconds: 3600, BackupKeep: &armadav1.BackupKeep{Last: 2}},
			SetBackupPlan: true, SetBackupKeep: true, SetBackupUrl: true, BackupUrl: []byte(parityCPBucketURL), SetBackupKey: true, BackupKey: []byte(parityCPBucketKey)})
		sc.keyspace("keyspace")
	})
}
