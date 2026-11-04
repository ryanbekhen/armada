package cli

import (
	"strings"
	"testing"
)

func TestLinuxOnly(t *testing.T) {
	t.Parallel()
	for _, system := range []string{"darwin", "windows", "freebsd"} {
		if err := linuxOnlyOn(system, "armada agent"); err == nil || !strings.Contains(err.Error(), "Linux only") {
			t.Errorf("agent on %s: %v", system, err)
		}
	}
	if err := linuxOnlyOn("linux", "armada agent"); err != nil {
		t.Errorf("agent on Linux: %v", err)
	}
}
