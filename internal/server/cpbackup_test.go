package server

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/volbackup"
)

const (
	cpBucketURL = "https://AK:SECRETKEY123@s3.example.com/backups/armada"
	cpBucketKey = "0123456789abcdef0123456789abcdef-key"
)

// cpBackupServer is a server on a clock whose control plane backups go to
// bucket: each backup holds one file with content's current value.
type cpBackupServer struct {
	*clockServer
	bucket  *volbackup.Memory
	content []byte
	// fail, when set, fails the next backups.
	fail error
	runs int
}

func newCPBackupServer(t *testing.T) *cpBackupServer {
	t.Helper()
	c := &cpBackupServer{clockServer: newClockServer(t), bucket: volbackup.NewMemory(), content: []byte("state v1")}
	keys, err := secrets.NewKeyring(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c.srv.keys = keys
	c.srv.cpBuckets = func(volbackup.Target) (volbackup.Objects, error) { return c.bucket, nil }
	c.srv.cpBackup = func(_ context.Context, fn func(dir string) error) error {
		c.runs++
		if c.fail != nil {
			return c.fail
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "etcd.snapshot"), c.content, 0o600); err != nil {
			return err
		}
		return fn(dir)
	}
	return c
}

func (c *cpBackupServer) set(req *armadav1.SetClusterConfigRequest) error {
	if req.Config == nil {
		req.Config = &armadav1.ClusterConfig{}
	}
	_, err := c.srv.SetClusterConfig(c.ctx, req)
	return err
}

func (c *cpBackupServer) pass() {
	c.t.Helper()
	if err := c.srv.controlPlaneBackupPass(c.ctx); err != nil {
		c.t.Fatal(err)
	}
}

func (c *cpBackupServer) status() *armadav1.ControlPlaneBackupStatus {
	c.t.Helper()
	b, err := c.srv.controlPlaneBackupStatus(c.ctx)
	if err != nil {
		c.t.Fatal(err)
	}
	return b
}

// turnOn sets backups every hour, keeping two.
func (c *cpBackupServer) turnOn() {
	c.t.Helper()
	err := c.set(&armadav1.SetClusterConfigRequest{
		Config:        &armadav1.ClusterConfig{BackupEverySeconds: 3600, BackupKeep: &armadav1.BackupKeep{Last: 2}},
		SetBackupPlan: true, SetBackupKeep: true,
		SetBackupUrl: true, BackupUrl: []byte(cpBucketURL + "\n"), SetBackupKey: true, BackupKey: []byte(cpBucketKey),
	})
	if err != nil {
		c.t.Fatal(err)
	}
}

func TestControlPlaneBackupSettings(t *testing.T) {
	t.Parallel()
	c := newCPBackupServer(t)
	plan := &armadav1.ClusterConfig{BackupEverySeconds: 3600, BackupKeep: &armadav1.BackupKeep{Last: 2}}
	full := func(mut func(*armadav1.SetClusterConfigRequest)) *armadav1.SetClusterConfigRequest {
		r := &armadav1.SetClusterConfigRequest{Config: plan, SetBackupPlan: true, SetBackupKeep: true,
			SetBackupUrl: true, BackupUrl: []byte(cpBucketURL), SetBackupKey: true, BackupKey: []byte(cpBucketKey)}
		mut(r)
		return r
	}
	refuse := map[string]*armadav1.SetClusterConfigRequest{
		"not a URL": full(func(r *armadav1.SetClusterConfigRequest) { r.BackupUrl = []byte("s3://AK:SECRETKEY123@h/b") }),
		"http to a public IP": full(func(r *armadav1.SetClusterConfigRequest) {
			r.BackupUrl = []byte("http://AK:SECRETKEY123@203.0.113.9/b")
		}),
		"loopback bucket":    full(func(r *armadav1.SetClusterConfigRequest) { r.BackupUrl = []byte("https://AK:SECRETKEY123@127.0.0.1/b") }),
		"no keys in the URL": full(func(r *armadav1.SetClusterConfigRequest) { r.BackupUrl = []byte("https://s3.example.com/b") }),
		"empty URL":          full(func(r *armadav1.SetClusterConfigRequest) { r.BackupUrl = nil }),
		"short key":          full(func(r *armadav1.SetClusterConfigRequest) { r.BackupKey = []byte("short-SECRETKEY123") }),
		"missing key":        full(func(r *armadav1.SetClusterConfigRequest) { r.SetBackupKey, r.BackupKey = false, nil }),
		"missing URL":        full(func(r *armadav1.SetClusterConfigRequest) { r.SetBackupUrl, r.BackupUrl = false, nil }),
		"no plan":            full(func(r *armadav1.SetClusterConfigRequest) { r.SetBackupPlan = false }),
		"keeps nothing":      full(func(r *armadav1.SetClusterConfigRequest) { r.SetBackupKeep = false }),
		"every 1m": full(func(r *armadav1.SetClusterConfigRequest) {
			r.Config = &armadav1.ClusterConfig{BackupEverySeconds: 60, BackupKeep: plan.BackupKeep}
		}),
		"bad schedule": full(func(r *armadav1.SetClusterConfigRequest) {
			r.Config = &armadav1.ClusterConfig{BackupSchedule: "every day", BackupKeep: plan.BackupKeep}
		}),
		"bad time zone": full(func(r *armadav1.SetClusterConfigRequest) {
			r.Config = &armadav1.ClusterConfig{BackupSchedule: "0 3 * * *", BackupTimeZone: "Mars/Olympus", BackupKeep: plan.BackupKeep}
		}),
		"off with more": full(func(r *armadav1.SetClusterConfigRequest) { r.SetBackupOff = true }),
	}
	for name, req := range refuse {
		err := c.set(req)
		if code := status.Code(err); code != codes.InvalidArgument && code != codes.FailedPrecondition {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "SECRETKEY123") {
			t.Errorf("%s: the secret is in the error: %v", name, err)
		}
	}
	if b := c.status(); b != nil {
		t.Fatalf("a refused request turned backups on: %v", b)
	}

	c.turnOn()
	cc, err := c.srv.GetClusterConfig(c.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cc.BackupBucket != "s3.example.com/backups/armada/" || cc.BackupEverySeconds != 3600 || cc.BackupKeep.GetLast() != 2 {
		t.Errorf("config %v", cc)
	}
	// Stored sealed, and in no audit entry.
	raw, err := c.st.GetMeta(c.ctx, metaCPBackup)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "SECRETKEY123") || strings.Contains(raw, cpBucketKey) {
		t.Error("the URL or key is stored in the clear")
	}
	audit, err := c.st.ListAudit(c.ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range audit {
		if strings.Contains(a.Detail, "SECRETKEY123") || strings.Contains(a.Detail, cpBucketKey) || strings.Contains(a.Detail, "s3.example.com") {
			t.Errorf("the bucket URL or key in the audit log: %+v", a)
		}
		found = found || a.Action == "cluster.backup"
	}
	if !found {
		t.Error("no audit entry")
	}

	// A change of the plan alone keeps the bucket and key.
	if err := c.set(&armadav1.SetClusterConfigRequest{Config: &armadav1.ClusterConfig{BackupSchedule: "0 3 * * *", BackupTimeZone: "Asia/Jakarta"}, SetBackupPlan: true}); err != nil {
		t.Fatal(err)
	}
	if cc, _ := c.srv.GetClusterConfig(c.ctx, nil); cc.BackupSchedule != "0 3 * * *" || cc.BackupEverySeconds != 0 || cc.BackupBucket == "" {
		t.Errorf("after the schedule: %v", cc)
	}

	if err := c.set(&armadav1.SetClusterConfigRequest{SetBackupOff: true}); err != nil {
		t.Fatal(err)
	}
	if b := c.status(); b != nil {
		t.Errorf("still on: %v", b)
	}
	if cc, _ := c.srv.GetClusterConfig(c.ctx, nil); cc.BackupBucket != "" || cc.BackupKeep != nil {
		t.Errorf("config after off: %v", cc)
	}
	// Off forgets the URL and key: a plan alone is refused now.
	if err := c.set(&armadav1.SetClusterConfigRequest{Config: plan, SetBackupPlan: true, SetBackupKeep: true}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("plan without a bucket: %v", err)
	}

	// No master key, nothing to seal with.
	c.srv.keys = nil
	if err := c.set(full(func(*armadav1.SetClusterConfigRequest) {})); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("no master key: %v", err)
	}
}

func TestControlPlaneBackupsRunPruneAndRetry(t *testing.T) {
	t.Parallel()
	c := newCPBackupServer(t)
	c.pass()
	if c.runs != 0 {
		t.Fatal("backed up while off")
	}
	c.turnOn()

	// The first backup is due at once.
	c.pass()
	b := c.status()
	if c.runs != 1 || b.LastAt == nil || b.Snapshots != 1 || b.LastServer != c.srv.name || b.LastSizeBytes != int64(len("state v1")) || b.Error != "" {
		t.Fatalf("after the first: runs %d, %v", c.runs, b)
	}
	for _, k := range c.bucket.Keys() {
		if !strings.HasPrefix(k, "armada/_control-plane/") {
			t.Errorf("object outside the control plane's repository: %s", k)
		}
	}
	if got := b.NextAt.AsTime(); !got.Equal(c.clock.Add(time.Hour)) {
		t.Errorf("next at %s, want an hour later", got)
	}

	// Not due again within the hour.
	c.clock = c.clock.Add(30 * time.Minute)
	c.pass()
	if c.runs != 1 {
		t.Fatalf("backed up early: %d", c.runs)
	}

	// Due after it; keep 2 prunes the oldest.
	for i := range 3 {
		c.clock = c.clock.Add(time.Hour)
		c.content = append(c.content, byte('a'+i))
		c.pass()
	}
	if b := c.status(); c.runs != 4 || b.Snapshots != 2 {
		t.Fatalf("runs %d, kept %d", c.runs, b.Snapshots)
	}

	// A failure is recorded as a condition and retried after min(5m, every).
	c.fail = errors.New("the state is not reachable")
	c.clock = c.clock.Add(time.Hour)
	c.pass()
	b = c.status()
	if b.Error == "" || !strings.Contains(b.Error, "not reachable") || b.FailedAt == nil || b.Snapshots != 2 {
		t.Fatalf("failure not recorded: %v", b)
	}
	if n := counterValue(c.srv.cpFailures); n != 1 {
		t.Errorf("failures counted %v", n)
	}
	events, err := c.st.ListEvents(c.ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	failed := 0
	for _, e := range events {
		if e.Reason == "ControlPlaneBackupFailed" {
			failed++
			if e.Kind != eventCluster || !strings.Contains(e.Message, "not reachable") || strings.Contains(e.Message, "SECRETKEY123") {
				t.Errorf("event %+v", e)
			}
		}
	}
	if failed != 1 {
		t.Errorf("%d failure events, want 1", failed)
	}
	c.clock = c.clock.Add(time.Minute)
	c.pass()
	if c.runs != 5 {
		t.Fatalf("retried within the minute: %d", c.runs)
	}
	c.clock = c.clock.Add(5 * time.Minute)
	c.pass()
	if c.runs != 6 {
		t.Fatalf("not retried after 5 minutes: %d", c.runs)
	}
	if _, active := c.srv.events.active[cpBackupCondition]; !active {
		t.Error("the failure condition is not active")
	}

	// A success clears the failure and the condition.
	c.fail = nil
	c.clock = c.clock.Add(5 * time.Minute)
	c.pass()
	if b := c.status(); b.Error != "" || b.FailedAt != nil || b.Snapshots != 2 {
		t.Errorf("after the success: %v", b)
	}
	if _, active := c.srv.events.active[cpBackupCondition]; active {
		t.Error("the failure condition did not clear")
	}

	// A new bucket starts afresh: due at once.
	err = c.set(&armadav1.SetClusterConfigRequest{Config: &armadav1.ClusterConfig{}, SetBackupUrl: true, BackupUrl: []byte(cpBucketURL + "/other")})
	if err != nil {
		t.Fatal(err)
	}
	if b := c.status(); b.LastAt != nil {
		t.Errorf("the new bucket shows the old one's backups: %v", b)
	}
	runs := c.runs
	c.pass()
	if c.runs != runs+1 {
		t.Error("the new bucket was not backed up at once")
	}
}

// A backup cut short because the leader steps down records nothing.
func TestControlPlaneBackupStepsDown(t *testing.T) {
	t.Parallel()
	c := newCPBackupServer(t)
	c.turnOn()
	ctx, cancel := context.WithCancel(c.ctx)
	c.srv.cpBackup = func(ctx context.Context, _ func(string) error) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}
	if err := c.srv.controlPlaneBackupPass(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("pass = %v", err)
	}
	if b := c.status(); b.Error != "" || b.LastAt != nil {
		t.Errorf("a cut backup was recorded: %v", b)
	}
	if n := counterValue(c.srv.cpFailures); n != 0 {
		t.Errorf("failures counted %v", n)
	}
	// The loop ends with its term.
	done := make(chan struct{})
	go func() {
		c.srv.controlPlaneBackupLoop(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop outlived its term")
	}
}

// The serving leader backs up once `cluster set` turns backups on, and
// cluster status shows it.
func TestControlPlaneBackupThroughTheAPI(t *testing.T) {
	t.Parallel()
	bucket := volbackup.NewMemory()
	keys := withKeys(t)
	c := newCluster(t, func(cfg *Config) {
		keys(cfg)
		cfg.BackupInterval = time.Hour // only the wake after cluster set runs it
		cfg.ControlPlaneBuckets = func(volbackup.Target) (volbackup.Objects, error) { return bucket, nil }
		cfg.ControlPlaneBackup = func(_ context.Context, fn func(string) error) error {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "etcd.snapshot"), []byte("state"), 0o600); err != nil {
				return err
			}
			return fn(dir)
		}
	})
	if resp, err := c.admin.ClusterStatus(c.ctx, &armadav1.ClusterStatusRequest{}); err != nil || resp.ControlPlaneBackup != nil {
		t.Fatalf("status before: %v %v", resp, err)
	}
	_, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{
		Config:        &armadav1.ClusterConfig{BackupEverySeconds: 3600, BackupKeep: &armadav1.BackupKeep{Daily: 7}},
		SetBackupPlan: true, SetBackupKeep: true,
		SetBackupUrl: true, BackupUrl: []byte(cpBucketURL), SetBackupKey: true, BackupKey: []byte(cpBucketKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	c.eventually("backed up", func() bool {
		resp, err := c.admin.ClusterStatus(c.ctx, &armadav1.ClusterStatusRequest{})
		b := resp.GetControlPlaneBackup()
		return err == nil && b.GetLastAt() != nil && b.GetSnapshots() == 1 && b.GetBucket() == "s3.example.com/backups/armada/"
	})
}

func counterValue(c prometheus.Counter) float64 {
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		return -1
	}
	return m.GetCounter().GetValue()
}

// A wrong key for the bucket's repository is a failure that says so.
func TestControlPlaneBackupWrongKey(t *testing.T) {
	t.Parallel()
	c := newCPBackupServer(t)
	c.turnOn()
	c.pass()
	if err := c.set(&armadav1.SetClusterConfigRequest{Config: &armadav1.ClusterConfig{}, SetBackupKey: true, BackupKey: []byte(strings.Repeat("z", 40))}); err != nil {
		t.Fatal(err)
	}
	c.pass()
	if b := c.status(); !strings.Contains(b.Error, "backup key does not match") {
		t.Errorf("wrong key: %v", b)
	}
}
