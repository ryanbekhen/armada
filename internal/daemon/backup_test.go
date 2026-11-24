package daemon

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/backup"
	"github.com/ryanbekhen/armada/internal/runtime/containerd"
	"github.com/ryanbekhen/armada/internal/volbackup"
)

// The backup package keeps its own copy of the data dir layout.
func TestBackupCoversDataDirLayout(t *testing.T) {
	t.Parallel()
	all := append(slices.Clone(backup.Required), backup.Optional...)
	for _, f := range []string{fileMasterKey, fileCACert, fileCAKey, fileServerCert, fileServerKey, fileNodeCert, fileNodeKey, fileAgent} {
		if !slices.Contains(all, f) {
			t.Errorf("backup does not cover %s", f)
		}
	}
	if backup.DirEtcd != dirEtcd {
		t.Errorf("etcd dir %q != %q", backup.DirEtcd, dirEtcd)
	}
	if backup.FileNetworkKey != fileNetworkKey || slices.Contains(all, fileNetworkKey) {
		t.Errorf("network key %q != %q, or copied", backup.FileNetworkKey, fileNetworkKey)
	}
	if backup.DirNode != containerd.NodeDir || slices.Contains(all, backup.DirNode) {
		t.Errorf("armada-node's directory %q, or copied", backup.DirNode)
	}
	if backup.FileMeshCache != fileMeshCache || slices.Contains(all, fileMeshCache) {
		t.Errorf("mesh peer list %q != %q, or copied", backup.FileMeshCache, fileMeshCache)
	}
}

func TestBackupRestoreCommands(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	if code, _, stderr := run(t, "init", "--data-dir", dataDir, "--config", filepath.Join(dir, "home", "config"), "--private-ip", "10.0.0.2"); code != 0 {
		t.Fatalf("init: %s", stderr)
	}
	archive := filepath.Join(dir, "backup.tar.gz")

	if code, _, stderr := run(t, "backup", "--data-dir", dataDir); code == 0 || !strings.Contains(stderr, "-o") {
		t.Errorf("backup without -o: %d %s", code, stderr)
	}
	code, _, stderr := run(t, "backup", "--data-dir", dataDir, "-o", archive)
	if code != 0 {
		t.Fatalf("backup: %s", stderr)
	}
	if !strings.Contains(stderr, "store it encrypted") {
		t.Errorf("no encryption reminder: %s", stderr)
	}
	if fi, _ := os.Stat(archive); fi.Mode().Perm() != 0o600 {
		t.Errorf("archive mode %o", fi.Mode().Perm())
	}
	if code, _, _ := run(t, "backup", "--data-dir", dataDir, "-o", archive); code == 0 {
		t.Error("backup overwrote an existing archive")
	}

	// Restoring over the live data dir is refused.
	if code, _, stderr := run(t, "restore", archive, "--data-dir", dataDir); code == 0 || !strings.Contains(stderr, "nothing was changed") {
		t.Errorf("restore over live data: %d %s", code, stderr)
	}

	hostHasIP = func(netip.Addr) bool { return false }
	t.Cleanup(func() { hostHasIP = func(netip.Addr) bool { return true } })
	restored := filepath.Join(dir, "restored")
	code, stdout, stderr := run(t, "restore", archive, "--data-dir", restored)
	if code != 0 {
		t.Fatalf("restore: %s", stderr)
	}
	if !strings.Contains(stdout, "10.0.0.2:7443") || !strings.Contains(stdout, "WARNING: 10.0.0.2 is not assigned") {
		t.Errorf("restore output:\n%s", stdout)
	}
	for _, f := range []string{dirEtcd, fileMasterKey, fileCAKey, fileServerKey, fileNodeKey, fileAgent} {
		if _, err := os.Stat(filepath.Join(restored, f)); err != nil {
			t.Errorf("%s not restored: %v", f, err)
		}
	}
}

// armadad backup list and armadad restore --backup-url read the backups the
// leader keeps in a bucket (ADR 0051).
func TestBackupFromBucketCommands(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	if code, _, stderr := run(t, "init", "--data-dir", dataDir, "--config", filepath.Join(dir, "home", "config"), "--private-ip", "10.0.0.2"); code != 0 {
		t.Fatalf("init: %s", stderr)
	}
	bucket := volbackup.NewMemory()
	openBucket = func(volbackup.Target) (volbackup.Objects, error) { return bucket, nil }
	t.Cleanup(func() { openBucket = volbackup.S3 })
	secret := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	urlFile := secret("url", "https://AK:SECRETKEY123@s3.example.com/backups/armada")
	keyFile := secret("key", strings.Repeat("k", 32))

	// No backups yet.
	if code, stdout, stderr := run(t, "backup", "list", "--backup-url", urlFile, "--backup-key", keyFile); code != 0 || !strings.Contains(stdout, "No backups yet") {
		t.Fatalf("list empty: %d %s %s", code, stdout, stderr)
	}

	// Back up as the leader does.
	ctx := context.Background()
	c, release, err := stateClient(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	tgt, _ := volbackup.ParseTarget("https://AK:SECRETKEY123@s3.example.com/backups/armada")
	repo, err := volbackup.Open(ctx, bucket, volbackup.ControlPlaneRoot(tgt), []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for range 2 {
		if _, err := backup.Stage(ctx, dataDir, c, func(d string, _ backup.Manifest) error {
			snap, _, err := repo.Backup(ctx, d, "n1", time.Now())
			ids = append(ids, snap.ID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	_ = release()

	code, stdout, stderr := run(t, "backup", "list", "--backup-url", urlFile, "--backup-key", keyFile)
	if code != 0 || !strings.Contains(stdout, ids[0]) || !strings.Contains(stdout, ids[1]) || !strings.Contains(stdout, "n1") {
		t.Fatalf("list: %d %s %s", code, stdout, stderr)
	}
	if code, _, stderr := run(t, "backup", "list", "--backup-url", urlFile, "--backup-key", secret("wrong", strings.Repeat("w", 32))); code == 0 || !strings.Contains(stderr, "does not match") {
		t.Errorf("wrong key: %d %s", code, stderr)
	}
	for _, args := range [][]string{
		{"restore", "x.tar.gz", "--backup-url", urlFile, "--backup-key", keyFile},
		{"restore", "x.tar.gz", "--snapshot", ids[0]},
		{"restore", "--backup-url", urlFile},
		{"restore", "--backup-url", "-", "--backup-key", "-"},
		{"restore"},
	} {
		if code, _, stderr := run(t, append(args, "--data-dir", filepath.Join(dir, "never"))...); code == 0 || strings.Contains(stderr, "SECRETKEY123") {
			t.Errorf("%v: %d %s", args, code, stderr)
		}
	}

	restored := filepath.Join(dir, "restored")
	code, stdout, stderr = run(t, "restore", "--backup-url", urlFile, "--backup-key", keyFile, "--snapshot", ids[0], "--data-dir", restored)
	if code != 0 {
		t.Fatalf("restore: %s", stderr)
	}
	if !strings.Contains(stdout, "Restored backup "+ids[0]) || !strings.Contains(stdout, "10.0.0.2:7443") {
		t.Errorf("restore output:\n%s", stdout)
	}
	for _, f := range []string{dirEtcd, fileMasterKey, fileCAKey, fileServerKey, fileNodeKey, fileAgent} {
		if _, err := os.Stat(filepath.Join(restored, f)); err != nil {
			t.Errorf("%s not restored: %v", f, err)
		}
	}
	// latest is the default.
	code, stdout, stderr = run(t, "restore", "--backup-url", urlFile, "--backup-key", keyFile, "--data-dir", filepath.Join(dir, "latest"))
	if code != 0 || !strings.Contains(stdout, "Restored backup "+ids[1]) {
		t.Errorf("restore latest: %d %s %s", code, stdout, stderr)
	}
}
