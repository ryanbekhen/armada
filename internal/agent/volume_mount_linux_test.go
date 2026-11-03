package agent

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrepareVolumesDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to mount")
	}
	dir := filepath.Join(t.TempDir(), "volumes")
	if err := PrepareVolumesDir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dir, unix.MNT_DETACH) })
	if ok, err := nosuidNodev(dir); err != nil || !ok {
		t.Fatalf("not nosuid,nodev: %v", err)
	}
	// A second start finds the mount and leaves it as it is.
	if err := PrepareVolumesDir(dir); err != nil {
		t.Fatal(err)
	}
	// Directories below it, which runtimes bind, have the flags too.
	sub := filepath.Join(dir, "app", "data")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if ok, err := nosuidNodev(sub); err != nil || !ok {
		t.Fatalf("volume not nosuid,nodev: %v", err)
	}
}
