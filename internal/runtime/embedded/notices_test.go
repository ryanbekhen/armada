package embedded

import (
	"os"
	"strings"
	"testing"
)

// THIRD_PARTY_NOTICES.md names every embedded program at the version the
// lock pins, so an upgrade cannot leave the notices behind.
func TestNoticesMatchLock(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../../THIRD_PARTY_NOTICES.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range Lock {
		row := "| " + a.Name + " | " + a.Version + " |"
		if !strings.Contains(string(b), row) {
			t.Errorf("THIRD_PARTY_NOTICES.md has no row %q; update it with lock.go", row)
		}
	}
}
