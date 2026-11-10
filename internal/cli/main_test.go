package cli

import (
	"os"
	"testing"

	"github.com/ryanbekhen/armada/internal/release"
)

// TestMain keeps tests off the network: no look for the latest release.
func TestMain(m *testing.M) {
	_ = os.Setenv(release.DisableEnv, "1")
	os.Exit(m.Run())
}
