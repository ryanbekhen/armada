package supervisor

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Layers and root filesystems are made with 022 whatever the agent's umask,
// and the rest of the process keeps its own.
func TestWithImageUmask(t *testing.T) {
	old := unix.Umask(0o077)
	t.Cleanup(func() { unix.Umask(old) })
	dir := t.TempDir()
	if err := withImageUmask(func() error { return os.Mkdir(filepath.Join(dir, "layer"), 0o755) }); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{"layer": 0o755, "agent": 0o700} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s: mode %v, want %v", name, got, want)
		}
	}
	if got := unix.Umask(0o077); got != 0o077 {
		t.Errorf("the process umask became %o", got)
	}
}
