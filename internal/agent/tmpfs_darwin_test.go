package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSecretsRAMDisk mounts a real RAM disk; it runs only with
// ARMADA_TEST_RAMDISK=1 (CI's macOS job), since it attaches a disk image.
func TestSecretsRAMDisk(t *testing.T) {
	if os.Getenv("ARMADA_TEST_RAMDISK") != "1" {
		t.Skip("set ARMADA_TEST_RAMDISK=1 to mount a RAM disk")
	}
	parent, err := os.MkdirTemp("", "armada-ram")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	dir := filepath.Join(parent, "secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckTmpfs(dir); err == nil {
		t.Fatal("a plain directory passed as a RAM disk")
	}
	if err := PrepareSecretsDisk(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var st unix.Statfs_t
		dev := ""
		if unix.Statfs(dir, &st) == nil {
			dev = unix.ByteSliceToString(st.Mntfromname[:])
		}
		_ = exec.Command("/usr/sbin/diskutil", "unmount", "force", dir).Run()
		if diskRe.MatchString(dev) {
			_ = exec.Command("/usr/sbin/diskutil", "eject", dev).Run()
		}
	})
	if err := CheckTmpfs(dir); err != nil {
		t.Fatalf("mounted RAM disk refused: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "s"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Mounted already: nothing new is attached.
	if err := PrepareSecretsDisk(dir); err != nil {
		t.Errorf("second prepare: %v", err)
	}
	// The RAM disk ignores ownership, so an open parent is refused.
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckTmpfs(dir); err == nil {
		t.Error("RAM disk below an open directory accepted")
	}
}
