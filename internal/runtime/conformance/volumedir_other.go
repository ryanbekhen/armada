//go:build !linux

package conformance

import "testing"

// volumeDir returns a new directory for the volume test. Off Linux the
// suite does not run on a node, so the mount flags are not checked.
func volumeDir(t *testing.T) (dir string, checkFlags bool) {
	t.Helper()
	return t.TempDir(), false
}
