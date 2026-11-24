package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/volbackup"
)

// The parity tests compare armada-node volume snapshot|prune|snapshots|
// restore-snapshot|target (ADR 0054 step 5) with Go's volbackup against a
// bucket in the test (fakeBucket: TLS with a test CA, or plain HTTP, and
// every request's AWS signature checked); Go reaches the same objects
// through volbackup.Objects:
//
//	make node-test-hooks && ARMADA_NODE_BIN=$PWD/node/target/test-hooks/x86_64-unknown-linux-musl/release/armada-node \
//	  go test -run 'TestArmadaNodeSnapshot|TestNativeSnapshot' ./internal/agent/

const (
	fakeAccess = "AKIDTEST"
	fakeSecret = "secret/with+chars"
)

var snapKey = []byte("0123456789abcdef0123456789abcdef")

type fakeObject struct {
	data []byte
	mod  time.Time
}

// fakeBucket is bucket bk1 as an S3 endpoint answers the requests
// armada-node makes, path-style, listing pageSize keys at a time.
type fakeBucket struct {
	mu       sync.Mutex
	objs     map[string]fakeObject
	now      time.Time
	deny     bool
	pageSize int
	bad      []string // requests whose signature did not check
	requests int
	srv      *httptest.Server
	ca       string
}

func newFakeBucket(t *testing.T, tlsOn bool) *fakeBucket {
	t.Helper()
	f := &fakeBucket{objs: map[string]fakeObject{}, now: time.Now(), pageSize: 3}
	if tlsOn {
		cert, ca := bucketPKI(t)
		f.srv = httptest.NewUnstartedServer(f)
		f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		f.srv.StartTLS()
		f.ca = ca
	} else {
		f.srv = httptest.NewServer(f)
	}
	t.Cleanup(f.srv.Close)
	t.Cleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.bad) > 0 {
			t.Errorf("requests with bad signatures: %v", f.bad)
		}
	})
	return f
}

// bucketPKI is a server certificate for example.com signed by a test CA,
// and the CA's file for armada-node's --extra-ca.
func bucketPKI(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mustDo(t, err)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test bucket CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	mustDo(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	mustDo(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mustDo(t, err)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"example.com"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	mustDo(t, err)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	mustDo(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600))
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}, caFile
}

func (f *fakeBucket) addr() string {
	return strings.TrimPrefix(strings.TrimPrefix(f.srv.URL, "https://"), "http://")
}

func (f *fakeBucket) setNow(t time.Time) {
	f.mu.Lock()
	f.now = t
	f.mu.Unlock()
}

// clone copies the objects into a new bucket.
func (f *fakeBucket) clone(t *testing.T) *fakeBucket {
	g := newFakeBucket(t, f.ca != "")
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, o := range f.objs {
		g.objs[k] = fakeObject{data: slices.Clone(o.data), mod: o.mod}
	}
	g.now = f.now
	return g
}

func (f *fakeBucket) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(maps.Keys(f.objs))
}

// checkSignature recomputes the request's AWS Signature Version 4.
func checkSignature(r *http.Request, body []byte) error {
	auth := r.Header.Get("Authorization")
	rest, ok := strings.CutPrefix(auth, "AWS4-HMAC-SHA256 ")
	if !ok {
		return errors.New("no AWS4 authorization")
	}
	parts := map[string]string{}
	for p := range strings.SplitSeq(rest, ", ") {
		k, v, _ := strings.Cut(p, "=")
		parts[k] = v
	}
	cred := strings.Split(parts["Credential"], "/")
	if len(cred) != 5 || cred[0] != fakeAccess || cred[3] != "s3" || cred[4] != "aws4_request" {
		return fmt.Errorf("credential %q", parts["Credential"])
	}
	payload := r.Header.Get("X-Amz-Content-Sha256")
	if sum := sha256.Sum256(body); payload != hex.EncodeToString(sum[:]) {
		return errors.New("payload hash")
	}
	if m := r.Header.Get("Content-Md5"); m != "" {
		sum := md5.Sum(body)
		if m != base64.StdEncoding.EncodeToString(sum[:]) {
			return errors.New("content MD5")
		}
	} else if r.Method == http.MethodPut {
		return errors.New("a write without Content-MD5")
	}
	path, query, _ := strings.Cut(r.RequestURI, "?")
	var q []string
	if query != "" {
		q = strings.Split(query, "&")
	}
	sort.Strings(q)
	signed := strings.Split(parts["SignedHeaders"], ";")
	var hdrs strings.Builder
	for _, h := range signed {
		v := r.Header.Get(h)
		if h == "host" {
			v = r.Host
		}
		fmt.Fprintf(&hdrs, "%s:%s\n", h, strings.TrimSpace(v))
	}
	canonical := strings.Join([]string{r.Method, path, strings.Join(q, "&"), hdrs.String(), parts["SignedHeaders"], payload}, "\n")
	date := r.Header.Get("X-Amz-Date")
	scope := strings.Join(cred[1:], "/")
	sum := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	mac := func(k []byte, s string) []byte { h := hmac.New(sha256.New, k); h.Write([]byte(s)); return h.Sum(nil) }
	k := mac([]byte("AWS4"+fakeSecret), cred[1])
	for _, p := range cred[2:] {
		k = mac(k, p)
	}
	if hex.EncodeToString(mac(k, toSign)) != parts["Signature"] {
		return errors.New("signature")
	}
	if !slices.Contains(signed, "host") || !slices.Contains(signed, "x-amz-date") || !slices.Contains(signed, "x-amz-content-sha256") {
		return errors.New("headers left unsigned")
	}
	return nil
}

func (f *fakeBucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if err := checkSignature(r, body); err != nil {
		f.bad = append(f.bad, r.Method+" "+r.URL.Path+": "+err.Error())
	}
	fail := func(code int, s3code string) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>`+s3code+`</Code><Message>no</Message></Error>`)
	}
	if f.deny {
		fail(http.StatusForbidden, "AccessDenied")
		return
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if bucket != "bk1" {
		fail(http.StatusNotFound, "NoSuchBucket")
		return
	}
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && key == "" && q.Has("location"):
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`)
	case r.Method == http.MethodPut && key != "":
		f.objs[key] = fakeObject{data: body, mod: f.now}
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
		}{Name: "bk1", Prefix: q.Get("prefix")}
		var keys []string
		for k := range f.objs {
			if strings.HasPrefix(k, res.Prefix) && k > q.Get("continuation-token") {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		if len(keys) > f.pageSize {
			keys = keys[:f.pageSize]
			res.IsTruncated, res.NextContinuationToken = true, keys[len(keys)-1]
		}
		for _, k := range keys {
			res.Contents = append(res.Contents, content{Key: k, Size: int64(len(f.objs[k].data)), LastModified: f.objs[k].mod.UTC().Format("2006-01-02T15:04:05.000Z")})
		}
		res.KeyCount = len(res.Contents)
		w.Header().Set("Content-Type", "application/xml")
		_ = xml.NewEncoder(w).Encode(res)
	case r.Method == http.MethodGet:
		o, ok := f.objs[key]
		if !ok {
			fail(http.StatusNotFound, "NoSuchKey")
			return
		}
		_, _ = w.Write(o.data)
	case r.Method == http.MethodDelete:
		delete(f.objs, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		fail(http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

// fakeObjects is the same bucket as Go's volbackup reaches it.
type fakeObjects struct{ f *fakeBucket }

func (o fakeObjects) Put(_ context.Context, key string, data []byte) error {
	o.f.mu.Lock()
	defer o.f.mu.Unlock()
	o.f.objs[key] = fakeObject{data: slices.Clone(data), mod: o.f.now}
	return nil
}

func (o fakeObjects) Get(_ context.Context, key string, maxSize int64) ([]byte, error) {
	o.f.mu.Lock()
	defer o.f.mu.Unlock()
	obj, ok := o.f.objs[key]
	if !ok {
		return nil, volbackup.ErrNotExist
	}
	if int64(len(obj.data)) > maxSize {
		return nil, fmt.Errorf("bucket: object larger than %d bytes", maxSize)
	}
	return slices.Clone(obj.data), nil
}

func (o fakeObjects) List(_ context.Context, prefix string, fn func(volbackup.Object) error) error {
	o.f.mu.Lock()
	var out []volbackup.Object
	for k, obj := range o.f.objs {
		if strings.HasPrefix(k, prefix) {
			// Listings name times to the millisecond.
			out = append(out, volbackup.Object{Key: k, Size: int64(len(obj.data)), Modified: obj.mod.UTC().Truncate(time.Millisecond)})
		}
	}
	o.f.mu.Unlock()
	slices.SortFunc(out, func(a, b volbackup.Object) int { return strings.Compare(a.Key, b.Key) })
	for _, obj := range out {
		if err := fn(obj); err != nil {
			return err
		}
	}
	return nil
}

func (o fakeObjects) Delete(_ context.Context, key string) error {
	o.f.mu.Lock()
	defer o.f.mu.Unlock()
	delete(o.f.objs, key)
	return nil
}

// snapAgents are an agent that backs up through armada-node and one that
// uses Go's code, both reaching f.
func snapAgents(t *testing.T, bin string, f *fakeBucket) (rust, golang *Agent) {
	t.Helper()
	rust, _ = volumeAgent(t)
	rust.cfg.VolumeProgram = func() string { return bin }
	rust.volNative.extraCA = f.ca
	rust.volNative.env = []string{"ARMADA_NODE_TEST_BUCKET_ADDR=" + f.addr()}
	golang, _ = volumeAgent(t)
	golang.cfg.Buckets = func(volbackup.Target) (volbackup.Objects, error) { return fakeObjects{f}, nil }
	return rust, golang
}

func snapURL(f *fakeBucket) string {
	if f.ca != "" {
		return "https://" + fakeAccess + ":" + strings.ReplaceAll(fakeSecret, "/", "%2F") + "@example.com/bk1/pre"
	}
	return "http://" + fakeAccess + ":" + strings.ReplaceAll(fakeSecret, "/", "%2F") + "@10.0.0.9:9000/bk1?region=eu-test-1"
}

func snapReq(f *fakeBucket, op armadav1.VolumeRequest_Op, snapshot string) *armadav1.VolumeRequest {
	return &armadav1.VolumeRequest{Op: op, App: "web.sp", Volume: "data", Snapshot: snapshot,
		Backup: &armadav1.BackupTarget{Url: snapURL(f), Key: snapKey, Keep: &armadav1.BackupKeep{Last: 100}}}
}

// bigFile is content that cuts into several chunks.
func bigFile(t *testing.T, dir string, n int) {
	t.Helper()
	b := make([]byte, n)
	_, _ = rand.Read(b)
	// Runs of one byte too: the gear hash sees long equal stretches.
	copy(b[n/3:], bytes.Repeat([]byte{7}, n/6))
	mustDo(t, os.WriteFile(filepath.Join(dir, "big-chunks"), b, 0o640))
}

// TestArmadaNodeSnapshotRoundTrip backs a volume up with each, then has
// each restore both snapshots: the four volumes are the same, and the
// second backup found every chunk the first wrote (the same boundaries and
// names for the same content and key).
func TestArmadaNodeSnapshotRoundTrip(t *testing.T) {
	bin := hooksBin(t)
	for _, tlsOn := range []bool{true, false} {
		t.Run(fmt.Sprintf("tls=%v", tlsOn), func(t *testing.T) {
			f := newFakeBucket(t, tlsOn)
			rust, golang := snapAgents(t, bin, f)
			vol := parityTree(t)
			bigFile(t, vol, 23<<20+11)
			ctx := context.Background()
			now := time.Date(2026, 11, 24, 10, 0, 0, 123456789, time.UTC)

			rs, rst, err := rust.backupSnapshot(ctx, snapReq(f, armadav1.VolumeRequest_OP_SNAPSHOT, ""), vol, now)
			if err != nil {
				t.Fatalf("armada-node backup: %v", err)
			}
			gs, gst, err := golang.backupSnapshot(ctx, snapReq(f, armadav1.VolumeRequest_OP_SNAPSHOT, ""), vol, now.Add(time.Second))
			if err != nil {
				t.Fatalf("Go backup: %v", err)
			}
			if gst.NewBytes != 0 || rst.NewBytes < 23<<20 {
				t.Errorf("new bytes: armada-node %d, Go after it %d (want 0: the same chunks)", rst.NewBytes, gst.NewBytes)
			}
			if !rs.Time.Equal(now) || rs.Files != gs.Files || rs.Bytes != gs.Bytes || rs.Node != "n1" {
				t.Errorf("snapshots: armada-node %+v, Go %+v", rs, gs)
			}
			if _, st, err := rust.backupSnapshot(ctx, snapReq(f, armadav1.VolumeRequest_OP_SNAPSHOT, ""), vol, now.Add(2*time.Second)); err != nil || st.NewBytes != 0 {
				t.Errorf("armada-node backup after Go's: %d new bytes, %v", st.NewBytes, err)
			}

			rl, err := rust.listSnapshots(ctx, snapReq(f, armadav1.VolumeRequest_OP_SNAPSHOTS, ""))
			mustDo(t, err)
			gl, err := golang.listSnapshots(ctx, snapReq(f, armadav1.VolumeRequest_OP_SNAPSHOTS, ""))
			mustDo(t, err)
			if fmt.Sprint(rl) != fmt.Sprint(gl) || len(rl) != 3 || rl[0].ID != rs.ID {
				t.Errorf("listings:\n rust %v\n go   %v", rl, gl)
			}

			trees := map[string]string{}
			for _, who := range []struct {
				name string
				a    *Agent
			}{{"rust", rust}, {"go", golang}} {
				for _, id := range []string{rs.ID, gs.ID} {
					dst := filepath.Join(t.TempDir(), "app", "data")
					snap, err := who.a.restoreSnapshot(ctx, snapReq(f, armadav1.VolumeRequest_OP_RESTORE_SNAPSHOT, id), dst)
					if err != nil {
						t.Fatalf("%s restores %s: %v", who.name, id, err)
					}
					if snap.ID != id || snap.Files != rs.Files || snap.Bytes != rs.Bytes {
						t.Errorf("%s restored %+v", who.name, snap)
					}
					trees[who.name+" restores "+id] = treeOf(t, dst)
				}
			}
			var first string
			for name, tree := range trees {
				if first == "" {
					first = tree
					if !strings.Contains(tree, fmt.Sprintf("%q", "bad\ufffd\ufffd")) || !strings.Contains(tree, `"big-chunks"`) {
						t.Errorf("restored tree:\n%s", tree)
					}
					continue
				}
				if tree != first {
					t.Errorf("%s differs:\n%s\nfrom\n%s", name, tree, first)
				}
			}
			// latest is the newest, for both.
			dst := filepath.Join(t.TempDir(), "app", "data")
			snap, err := rust.restoreSnapshot(ctx, snapReq(f, armadav1.VolumeRequest_OP_RESTORE_SNAPSHOT, "latest"), dst)
			if err != nil || snap.ID != rl[2].ID {
				t.Errorf("latest: %+v %v", snap, err)
			}
			if rust.volNative.StoodIn("snapshot")+rust.volNative.StoodIn("restore-snapshot") != 0 || rust.volNative.Ran("restore-snapshot") != 3 {
				t.Errorf("Go stood in for armada-node")
			}
		})
	}
}

// TestArmadaNodeSnapshotPruneMatchesGo prunes the same repository with
// each, in a zone with summer time, and compares what is left.
func TestArmadaNodeSnapshotPruneMatchesGo(t *testing.T) {
	bin := hooksBin(t)
	if _, err := time.LoadLocation("America/New_York"); err != nil {
		t.Skip("no time zone data")
	}
	f := newFakeBucket(t, true)
	rust, golang := snapAgents(t, bin, f)
	vol := filepath.Join(t.TempDir(), "v")
	mustDo(t, os.MkdirAll(vol, 0o700))
	ctx := context.Background()
	start := time.Date(2026, 3, 1, 0, 30, 0, 0, time.UTC)
	var last time.Time
	for i := range 40 {
		at := start.Add(time.Duration(i) * 9 * time.Hour)
		mustDo(t, os.WriteFile(filepath.Join(vol, "f"), fmt.Appendf(nil, "content %d", i%7), 0o600))
		f.setNow(at)
		a := rust
		if i%2 == 1 {
			a = golang
		}
		if _, _, err := a.backupSnapshot(ctx, snapReq(f, armadav1.VolumeRequest_OP_SNAPSHOT, ""), vol, at); err != nil {
			t.Fatal(err)
		}
		last = at
	}
	req := func(f *fakeBucket) *armadav1.VolumeRequest {
		r := snapReq(f, armadav1.VolumeRequest_OP_SNAPSHOT, "")
		r.Backup.Keep = &armadav1.BackupKeep{Last: 2, Hourly: 3, Daily: 5, Weekly: 2, Monthly: 2}
		r.Backup.TimeZone = "America/New_York"
		return r
	}
	base := f
	for _, after := range []time.Duration{10 * time.Minute, 2 * time.Hour} {
		f, g := base.clone(t), base.clone(t)
		rust, _ := snapAgents(t, bin, f)
		_, golang := snapAgents(t, bin, g)
		now := last.Add(after)
		ru, rerr := rust.pruneSnapshots(ctx, req(f), now)
		gu, gerr := golang.pruneSnapshots(ctx, req(g), now)
		if rerr != nil || gerr != nil {
			t.Fatalf("prune: armada-node %v, Go %v", rerr, gerr)
		}
		if ru != gu {
			t.Errorf("after %v: usage armada-node %+v, Go %+v", after, ru, gu)
		}
		if rk, gk := f.keys(), g.keys(); !slices.Equal(rk, gk) {
			t.Errorf("after %v: objects left differ:\n rust %v\n go   %v", after, rk, gk)
		}
		if ru.DeletedSnapshots == 0 || ru.Snapshots == 0 {
			t.Errorf("after %v: nothing pruned: %+v", after, ru)
		}
	}
}

// TestArmadaNodeSnapshotRefusesAsGo has both meet the same broken
// repositories and requests.
func TestArmadaNodeSnapshotRefusesAsGo(t *testing.T) {
	bin := hooksBin(t)
	ctx := context.Background()
	vol := filepath.Join(t.TempDir(), "v")
	mustDo(t, os.MkdirAll(vol, 0o700))
	mustDo(t, os.WriteFile(filepath.Join(vol, "f"), bytes.Repeat([]byte("x"), 1<<20), 0o600))
	type outcome struct{ backup, list, restore string }
	run := func(a *Agent, f *fakeBucket, mod func(*armadav1.VolumeRequest), id string) outcome {
		// The restore and the listing first: a backup repairs a
		// repository.
		var o outcome
		r := snapReq(f, armadav1.VolumeRequest_OP_RESTORE_SNAPSHOT, id)
		mod(r)
		dst := filepath.Join(t.TempDir(), "app", "data")
		if _, err := a.restoreSnapshot(ctx, r, dst); err != nil {
			o.restore = restoreSuffix.ReplaceAllString(strings.ReplaceAll(err.Error(), dst, "DST"), "")
		}
		r = snapReq(f, armadav1.VolumeRequest_OP_SNAPSHOTS, "")
		mod(r)
		if _, err := a.listSnapshots(ctx, r); err != nil {
			o.list = err.Error()
		}
		r = snapReq(f, armadav1.VolumeRequest_OP_SNAPSHOT, "")
		mod(r)
		if _, _, err := a.backupSnapshot(ctx, r, vol, time.Now()); err != nil {
			o.backup = err.Error()
		}
		return o
	}
	// A repository with one backup, damaged by each case.
	base := newFakeBucket(t, true)
	r0, _ := snapAgents(t, bin, base)
	snap, _, err := r0.backupSnapshot(ctx, snapReq(base, armadav1.VolumeRequest_OP_SNAPSHOT, ""), vol, time.Now())
	mustDo(t, err)
	chunkKey := ""
	for _, k := range base.keys() {
		if strings.Contains(k, "/chunks/") {
			chunkKey = k
		}
	}
	same := func(*armadav1.VolumeRequest) {}
	cases := []struct {
		name   string
		damage func(f *fakeBucket)
		mod    func(*armadav1.VolumeRequest)
		id     string
	}{
		{"wrong key", nil, func(r *armadav1.VolumeRequest) { r.Backup.Key = bytes.Repeat([]byte("k"), 40) }, snap.ID},
		{"short key", nil, func(r *armadav1.VolumeRequest) { r.Backup.Key = []byte("short") }, snap.ID},
		{"invalid ID", nil, same, "../x"},
		{"missing backup", nil, same, "20200101T000000.000Z-00000000"},
		{"damaged chunk", func(f *fakeBucket) { o := f.objs[chunkKey]; o.data[len(o.data)-1] ^= 1; f.objs[chunkKey] = o }, same, snap.ID},
		{"missing chunk", func(f *fakeBucket) { delete(f.objs, chunkKey) }, same, snap.ID},
		{"chunk moved", func(f *fakeBucket) {
			o := f.objs[chunkKey]
			f.objs[chunkKey] = fakeObject{data: f.objs["pre/web.sp/data/snapshots/"+snap.ID].data, mod: o.mod}
		}, same, snap.ID},
		{"damaged manifest", func(f *fakeBucket) { f.objs["pre/web.sp/data/snapshots/"+snap.ID] = fakeObject{data: []byte("nope")} }, same, "latest"},
		{"config damaged", func(f *fakeBucket) { f.objs["pre/web.sp/data/config"] = fakeObject{data: []byte("{")} }, same, snap.ID},
		{"config version", func(f *fakeBucket) {
			f.objs["pre/web.sp/data/config"] = fakeObject{data: []byte(`{"version":2,"id":"00112233445566778899aabbccddeeff","check":"x"}`)}
		}, same, snap.ID},
		{"config ID", func(f *fakeBucket) {
			f.objs["pre/web.sp/data/config"] = fakeObject{data: []byte(`{"version":1,"id":"0011","check":"x"}`)}
		}, same, snap.ID},
		{"no backups", func(f *fakeBucket) {
			for k := range f.objs {
				if strings.Contains(k, "/snapshots/") {
					delete(f.objs, k)
				}
			}
		}, same, "latest"},
		{"bad URL", nil, func(r *armadav1.VolumeRequest) { r.Backup.Url = "http://k:s@s3.example.com/bk1" }, snap.ID},
	}
	for _, c := range cases {
		fr, fg := base.clone(t), base.clone(t)
		if c.damage != nil {
			c.damage(fr)
			c.damage(fg)
		}
		rust, _ := snapAgents(t, bin, fr)
		_, golang := snapAgents(t, bin, fg)
		ro := run(rust, fr, c.mod, c.id)
		gout := run(golang, fg, c.mod, c.id)
		if ro != gout {
			t.Errorf("%s:\n rust %+v\n go   %+v", c.name, ro, gout)
		}
		t.Logf("%s: %+v", c.name, ro)
		if ro == (outcome{}) {
			t.Errorf("%s: nothing refused", c.name)
		}
		if rust.volNative.StoodIn("snapshot")+rust.volNative.StoodIn("snapshots")+rust.volNative.StoodIn("restore-snapshot") != 0 {
			t.Errorf("%s: Go stood in", c.name)
		}
	}

	// A bucket that refuses: armada-node says what it answered, never the
	// URL or the keys.
	f := newFakeBucket(t, true)
	f.deny = true
	rust, _ := snapAgents(t, bin, f)
	_, err = rust.listSnapshots(ctx, snapReq(f, armadav1.VolumeRequest_OP_SNAPSHOTS, ""))
	if err == nil || err.Error() != "bucket: read: AccessDenied (HTTP 403)" {
		t.Errorf("denied: %v", err)
	}
}

// TestArmadaNodeSnapshotTargetMatchesGo compares ParseTarget's checks.
func TestArmadaNodeSnapshotTargetMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	for _, u := range []string{
		"https://AK:SE%2Fc@s3.example.com:9000/bk1/a/b?region=eu-1",
		" https://k:s@s3.example.com/bk1/ ",
		"http://k:s@10.0.0.9:9000/bk1",
		"http://k:s@[fd00::5]/bk1",
		"http://k:s@s3.example.com/bk1",
		"http://k:s@203.0.113.7/bk1",
		"https://k:s@127.0.0.1/bk1",
		"https://k:s@[::1]/bk1",
		"https://k:s@169.254.169.254/bk1",
		"https://k:s@[fe80::1%25eth0]/bk1",
		"https://k:s@0.0.0.0/bk1",
		"https://k:s@224.0.0.1/bk1",
		"https://k:s@[::ffff:127.0.0.1]/bk1",
		"ftp://k:s@h/bk1",
		"https://h/bk1",
		"https://k@h/bk1",
		"https://:s@h/bk1",
		"https://k:s@h/",
		"https://k:s@h",
		"https://k:s@h/Bk1",
		"https://k:s@h/b..k",
		"https://k:s@h/ab",
		"https://k:s@h/bk1//x",
		"https://k:s@h/bk1/./x",
		"https://k:s@h/bk1/a%20b",
		"https://k:s@h/bk1/" + strings.Repeat("p", 300),
		"https://k:s@h/bk1?x=1",
		"https://k:s@h/bk1?" + strings.Repeat("é", 20) + "=1",
		"https://k:s@h/bk1?region=EU",
		"https://k:s@h/bk1?region=",
		"https://k:s@h/bk1?a;b=1",
		"https://k:s@h/bk1#frag",
		"https://k:s@h/bk1#",
		"https:opaque",
		"https://k:s@h:x/bk1",
		"https://k:s@h:99999/bk1",
		"https://k:s@h%zz/bk1",
		"https://" + strings.Repeat("a", 2100),
		"",
		"not a url\x01",
	} {
		cmd := exec.Command(bin, "volume", "target")
		line, _ := json.Marshal(map[string]string{"url": u})
		cmd.Stdin = bytes.NewReader(append(line, '\n'))
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%q: %v", u, err)
		}
		var ans struct {
			Error    *string
			Endpoint string
			Secure   bool
			Bucket   string
			Prefix   string
			Region   string
		}
		mustDo(t, json.Unmarshal(out, &ans))
		tg, gerr := volbackup.ParseTarget(u)
		switch {
		case gerr != nil && (ans.Error == nil || *ans.Error != gerr.Error()):
			t.Errorf("%q: armada-node %s, Go %v", u, out, gerr)
		case gerr == nil && ans.Error != nil:
			t.Errorf("%q: armada-node refused (%s), Go accepted", u, *ans.Error)
		case gerr == nil && (ans.Endpoint != tg.Endpoint || ans.Secure != tg.Secure || ans.Bucket != tg.Bucket || ans.Prefix != tg.Prefix || ans.Region != tg.Region):
			t.Errorf("%q: armada-node %s, Go %+v", u, out, tg.String())
		}
		if strings.Contains(string(out), ":s@") || strings.Contains(string(out), "SE%2Fc") {
			t.Errorf("%q: the answer repeats the credentials: %s", u, out)
		}
	}
}

// TestNativeSnapshotFallsBackToGo checks when Go does a call itself.
func TestNativeSnapshotFallsBackToGo(t *testing.T) {
	t.Parallel()
	stand := func(t *testing.T, script string) string {
		p := filepath.Join(t.TempDir(), "armada-node")
		mustDo(t, os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o700))
		return p
	}
	ctx := context.Background()
	vol := t.TempDir()
	mustDo(t, os.WriteFile(filepath.Join(vol, "f"), []byte("hello"), 0o600))
	mem := volbackup.NewMemory()
	agentWith := func(bin string) *Agent {
		a, _ := volumeAgent(t)
		a.cfg.VolumeProgram = func() string { return bin }
		a.cfg.Buckets = func(volbackup.Target) (volbackup.Objects, error) { return mem, nil }
		return a
	}
	req := func(op armadav1.VolumeRequest_Op, id string) *armadav1.VolumeRequest {
		return &armadav1.VolumeRequest{Op: op, App: "web", Volume: "data", Snapshot: id,
			Backup: &armadav1.BackupTarget{Url: "https://k:s@s3.example.com/bk1", Key: snapKey, Keep: &armadav1.BackupKeep{Last: 5}}}
	}

	// Failing before anything was written: Go does every call.
	for name, bin := range map[string]string{
		"missing": filepath.Join(t.TempDir(), "none"),
		"fails":   stand(t, "exit 3"),
		"garbage": stand(t, "echo nonsense"),
	} {
		a := agentWith(bin)
		snap, _, err := a.backupSnapshot(ctx, req(armadav1.VolumeRequest_OP_SNAPSHOT, ""), vol, time.Now())
		if err != nil {
			t.Fatalf("%s: backup: %v", name, err)
		}
		if _, err := a.pruneSnapshots(ctx, req(armadav1.VolumeRequest_OP_SNAPSHOT, ""), time.Now()); err != nil {
			t.Errorf("%s: prune: %v", name, err)
		}
		if l, err := a.listSnapshots(ctx, req(armadav1.VolumeRequest_OP_SNAPSHOTS, "")); err != nil || len(l) == 0 {
			t.Errorf("%s: list: %v %v", name, l, err)
		}
		dst := filepath.Join(t.TempDir(), "app", "data")
		if _, err := a.restoreSnapshot(ctx, req(armadav1.VolumeRequest_OP_RESTORE_SNAPSHOT, snap.ID), dst); err != nil {
			t.Errorf("%s: restore: %v", name, err)
		}
		if b, err := os.ReadFile(filepath.Join(dst, "f")); err != nil || string(b) != "hello" {
			t.Errorf("%s: restored %q %v", name, b, err)
		}
		for _, op := range []string{"snapshot", "prune", "snapshots", "restore-snapshot"} {
			if a.volNative.StoodIn(op) != 1 {
				t.Errorf("%s: %s stood in %d times", name, op, a.volNative.StoodIn(op))
			}
		}
	}
	snaps, err := volbackup.Open(ctx, mem, "web/data/", snapKey)
	mustDo(t, err)
	list, err := snaps.Snapshots(ctx)
	mustDo(t, err)
	id := list[0].ID

	// Ready, then no answer before touching anything: Go restores the
	// snapshot armada-node named, the app still paused.
	a := agentWith(stand(t, `read req; echo "ready `+id+`"; read go; exit 3`))
	dst := filepath.Join(t.TempDir(), "app", "data")
	if s, err := a.restoreSnapshot(ctx, req(armadav1.VolumeRequest_OP_RESTORE_SNAPSHOT, "latest"), dst); err != nil || s.ID != id {
		t.Errorf("restore after ready: %+v %v", s, err)
	}

	// Once it touched the bucket or the volume, the failure is the call's.
	a = agentWith(stand(t, `read req; echo touched; echo "ready `+id+`"; read go; exit 3`))
	_, _, err = a.backupSnapshot(ctx, req(armadav1.VolumeRequest_OP_SNAPSHOT, ""), vol, time.Now())
	if err == nil || !strings.Contains(err.Error(), "armada-node: no answer") {
		t.Errorf("backup after touching: %v", err)
	}
	dst = filepath.Join(t.TempDir(), "app", "data")
	if _, err := a.restoreSnapshot(ctx, req(armadav1.VolumeRequest_OP_RESTORE_SNAPSHOT, id), dst); err == nil || !strings.Contains(err.Error(), "armada-node: no answer") {
		t.Errorf("restore after touching: %v", err)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Error("Go restored after armada-node touched the volume")
	}
	if a.volNative.StoodIn("snapshot")+a.volNative.StoodIn("restore-snapshot") != 0 {
		t.Error("Go stood in after armada-node touched something")
	}

	// An answered error is the call's, as armada-node words it.
	a = agentWith(stand(t, `read req; echo '{"error":"backup URL: invalid bucket name"}'`))
	if _, err := a.listSnapshots(ctx, req(armadav1.VolumeRequest_OP_SNAPSHOTS, "")); err == nil || err.Error() != "backup URL: invalid bucket name" {
		t.Errorf("answered error: %v", err)
	}
	// The request reaches armada-node on stdin only.
	argv := filepath.Join(t.TempDir(), "argv")
	a = agentWith(stand(t, `echo "$@" > `+argv+`; read req; echo '{"snapshots":[]}'`))
	_, _ = a.listSnapshots(ctx, req(armadav1.VolumeRequest_OP_SNAPSHOTS, ""))
	if b, _ := os.ReadFile(argv); strings.TrimSpace(string(b)) != "volume snapshots" {
		t.Errorf("arguments %q", b)
	}
}
