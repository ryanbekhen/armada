package daemon

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/backup"
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
