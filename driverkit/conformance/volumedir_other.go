//go:build !linux

package conformance

import "testing"

// volumeDir returns a new directory for the volume test. Off Linux (macOS
// nodes) containers run in virtual machines whose mount table cannot show
// the host directory's flags, so they are not checked.
func volumeDir(t *testing.T) (dir string, checkFlags bool) {
	t.Helper()
	return t.TempDir(), false
}
