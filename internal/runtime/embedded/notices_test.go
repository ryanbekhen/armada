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

// armada-log is built from the standard library alone (logger/Cargo.toml):
// a crate added to it would need a license review and a line in the
// notices first.
func TestLoggerStandardLibraryOnly(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../../logger/Cargo.lock")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "[[package]]"); n != 1 {
		t.Errorf("logger/Cargo.lock lists %d packages; armada-log uses the Rust standard library only", n)
	}
	b, err = os.ReadFile("../../../shim/Cargo.lock")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "[[package]]"); n != 1 {
		t.Errorf("shim/Cargo.lock lists %d packages; armada-shim uses the Rust standard library only", n)
	}
	b, err = os.ReadFile("../../../dns/Cargo.lock")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "[[package]]"); n != 1 {
		t.Errorf("dns/Cargo.lock lists %d packages; armada-dns uses the Rust standard library only", n)
	}
	notices, err := os.ReadFile("../../../THIRD_PARTY_NOTICES.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"armada-log", "armada-shim", "armada-dns", "musl", "Rust standard library"} {
		if !strings.Contains(string(notices), want) {
			t.Errorf("THIRD_PARTY_NOTICES.md does not mention %q", want)
		}
	}
}
