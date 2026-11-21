package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/clientconfig"
)

// settingsAdmin answers GetClusterConfig with cur and records each
// SetClusterConfig.
type settingsAdmin struct {
	armadav1.AdminServiceClient
	cur  *armadav1.ClusterConfig
	sets []*armadav1.SetClusterConfigRequest
}

func (f *settingsAdmin) GetClusterConfig(context.Context, *armadav1.GetClusterConfigRequest, ...grpc.CallOption) (*armadav1.ClusterConfig, error) {
	return f.cur, nil
}

func (f *settingsAdmin) SetClusterConfig(_ context.Context, req *armadav1.SetClusterConfigRequest, _ ...grpc.CallOption) (*armadav1.ClusterConfig, error) {
	f.sets = append(f.sets, proto.CloneOf(req))
	return f.cur, nil
}

func withSettingsFake(t *testing.T, f *settingsAdmin) string {
	t.Helper()
	orig := dialAdmin
	dialAdmin = func(*globals) (armadav1.AdminServiceClient, io.Closer, error) { return f, nopCloser{}, nil }
	t.Cleanup(func() { dialAdmin = orig })
	path := filepath.Join(t.TempDir(), "config")
	cc := &clientconfig.Config{Servers: []string{"10.0.0.1:7443"}, CA: "ca", Cert: "cert", Key: "key"}
	if err := cc.SaveFile(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestClusterSetBackup(t *testing.T) {
	f := &settingsAdmin{cur: &armadav1.ClusterConfig{BackupEverySeconds: 3600, BackupTimeZone: "Asia/Jakarta"}}
	cfg := withSettingsFake(t, f)
	cli := func(args ...string) (int, string, string) {
		return run(t, append(append([]string{"cluster", "update"}, args...), "--config", cfg)...)
	}
	dir := t.TempDir()
	secret := func(name, v string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v+"\n"), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	url := secret("url", "https://AK:SK@s3.example.com/bucket/armada", 0o600)
	key := secret("key", strings.Repeat("k", 32), 0o600)

	code, _, stderr := cli("--backup-url", url, "--backup-key", key, "--backup-every", "1h", "--backup-keep", "last=24,daily=7")
	if code != 0 {
		t.Fatalf("set: %s", stderr)
	}
	r := f.sets[len(f.sets)-1]
	if !r.SetBackupUrl || !r.SetBackupKey || !r.SetBackupPlan || !r.SetBackupKeep || r.SetBackupOff ||
		string(r.BackupUrl) != "https://AK:SK@s3.example.com/bucket/armada" || string(r.BackupKey) != strings.Repeat("k", 32) ||
		r.Config.BackupEverySeconds != 3600 || r.Config.BackupSchedule != "" || r.Config.BackupTimeZone != "Asia/Jakarta" ||
		r.Config.BackupKeep.GetLast() != 24 || r.Config.BackupKeep.GetDaily() != 7 {
		t.Errorf("sent %v", r)
	}

	// A schedule replaces the interval; the time zone not given stays.
	if code, _, stderr := cli("--backup-schedule", "0 3 * * *"); code != 0 {
		t.Fatalf("schedule: %s", stderr)
	}
	if r := f.sets[len(f.sets)-1]; !r.SetBackupPlan || r.SetBackupUrl || r.Config.BackupSchedule != "0 3 * * *" || r.Config.BackupEverySeconds != 0 || r.Config.BackupTimeZone != "Asia/Jakarta" {
		t.Errorf("schedule sent %v", r)
	}
	if code, _, _ := cli("--backup-keep", "7"); code != 0 || f.sets[len(f.sets)-1].Config.BackupKeep.GetLast() != 7 || f.sets[len(f.sets)-1].SetBackupPlan {
		t.Errorf("keep 7: %v", f.sets[len(f.sets)-1])
	}
	if code, _, _ := cli("--backup", "none"); code != 0 || !f.sets[len(f.sets)-1].SetBackupOff {
		t.Errorf("off: %v", f.sets[len(f.sets)-1])
	}

	sent := len(f.sets)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--backup", "off"}, "only none"},
		{[]string{"--backup-every", "1h", "--backup-schedule", "0 3 * * *"}, "not both"},
		{[]string{"--backup-keep", "yearly=3"}, "unknown"},
		{[]string{"--backup-keep", "many"}, "want a number"},
		{[]string{"--backup-url", "-", "--backup-key", "-"}, "only one"},
		// A file others can read is refused: it holds the bucket's keys.
		{[]string{"--backup-url", secret("open", "https://AK:SK@h/b", 0o644)}, "--backup-url"},
	} {
		code, _, stderr := cli(tc.args...)
		if code == 0 || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: %d %q", tc.args, code, stderr)
		}
		if strings.Contains(stderr, "SK@") {
			t.Errorf("%v: the URL is in the error: %q", tc.args, stderr)
		}
	}
	if len(f.sets) != sent {
		t.Errorf("a refused command sent %d requests", len(f.sets)-sent)
	}
}

func TestPrintBackups(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	cc := &armadav1.ClusterConfig{BackupBucket: "s3.example.com/bucket/armada/", BackupEverySeconds: 3600, BackupKeep: &armadav1.BackupKeep{Last: 24, Daily: 7}}
	if err := printClusterConfig(&b, cc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "backups:           to s3.example.com/bucket/armada/, every 1h, keeping 24 latest, 7 daily") {
		t.Errorf("config:\n%s", b.String())
	}
	b.Reset()
	now := time.Now()
	err := printClusterStatus(&b, &armadav1.ClusterStatusResponse{ControlPlaneBackup: &armadav1.ControlPlaneBackupStatus{
		Bucket: "s3.example.com/bucket/", LastAt: timestamppb.New(now.Add(-time.Hour)), LastServer: "s1", LastSizeBytes: 2 << 20,
		Snapshots: 3, StoredBytes: 5 << 20, FailedAt: timestamppb.New(now), Error: "bucket said no\x1b[2J", NextAt: timestamppb.New(now.Add(5 * time.Minute)),
	}})
	if err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"backups: to s3.example.com/bucket/, last ", " on s1 (2Mi, 3 kept, 5Mi stored), next ", "backup failed at ", "bucket said no"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing:\n%s", want, out)
		}
	}
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("control character printed:\n%q", out)
	}
}
