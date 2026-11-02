package cli

import (
	"os"
	"testing"
)

// TestMain runs the tests as on Linux, also on a macOS development
// machine, and never mounts a RAM disk there; macOS behaviour is tested
// through the functions that take the system as an argument.
func TestMain(m *testing.M) {
	goos = "linux"
	prepareSecretsDisk = func(string) error { return nil }
	os.Exit(m.Run())
}
