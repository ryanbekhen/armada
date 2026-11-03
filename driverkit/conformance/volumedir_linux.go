package conformance

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// volumeDir returns a new directory on a nosuid,nodev filesystem, as the
// agent gives drivers (it mounts its volume directory that way): the
// temporary directory if its filesystem is, else one under /dev/shm. The
// suite then checks that the driver's mount keeps both flags.
func volumeDir(t *testing.T) (dir string, checkFlags bool) {
	t.Helper()
	for _, parent := range []string{os.TempDir(), "/dev/shm"} {
		var st unix.Statfs_t
		if unix.Statfs(parent, &st) != nil || st.Flags&unix.ST_NOSUID == 0 || st.Flags&unix.ST_NODEV == 0 {
			continue
		}
		dir, err := os.MkdirTemp(parent, "armada-conformance-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		return dir, true
	}
	t.Fatal("no nosuid,nodev filesystem for the volume test: set TMPDIR to a directory on one")
	return "", false
}
