package conntrack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const gib = 1 << 30

func table(t *testing.T, memory int64, count, limit string) (*Table, string) {
	t.Helper()
	dir := t.TempDir()
	for name, v := range map[string]string{fileCount: count, fileMax: limit} {
		if v == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return At(dir, memory), filepath.Join(dir, fileMax)
}

func TestTarget(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ memory, want int64 }{
		{-1, 0},
		{0, 0},
		{512 << 20, 131072},
		{1 * gib, Minimum},
		{64 * gib, Minimum},
	} {
		if got := Target(c.memory); got != c.want {
			t.Errorf("Target(%d) = %d, want %d", c.memory, got, c.want)
		}
	}
}

func TestRaise(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name     string
		memory   int64
		limit    string
		previous int64
		after    string
	}{
		{"below", 4 * gib, "65536\n", 65536, "262144"},
		{"small machine", 512 << 20, "16384\n", 16384, "131072"},
		{"small machine at its share", 512 << 20, "131072\n", 0, "131072"},
		{"at the target", 4 * gib, "262144\n", 0, "262144"},
		{"an operator's higher limit stands", 4 * gib, "2000000\n", 0, "2000000"},
		{"memory unknown leaves it alone", 0, "65536\n", 0, "65536"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			tb, path := table(t, c.memory, "1\n", c.limit)
			previous, err := tb.Raise()
			if err != nil {
				t.Fatal(err)
			}
			if previous != c.previous {
				t.Errorf("previous = %d, want %d", previous, c.previous)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSpace(string(b)); got != c.after {
				t.Errorf("limit = %s, want %s", got, c.after)
			}
		})
	}
}

func TestRaiseWithoutTheModule(t *testing.T) {
	t.Parallel()
	tb, path := table(t, 4*gib, "", "")
	if previous, err := tb.Raise(); err != nil || previous != 0 {
		t.Fatalf("Raise = %d, %v", previous, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("a limit file appeared: %v", err)
	}
	if _, _, ok := tb.Read(); ok {
		t.Error("Read reports a table that is not there")
	}
}

func TestRaiseRefusesGarbage(t *testing.T) {
	t.Parallel()
	tb, path := table(t, 4*gib, "1\n", "not a number\n")
	if _, err := tb.Raise(); err == nil {
		t.Fatal("Raise accepted an unreadable limit")
	}
	if b, _ := os.ReadFile(path); string(b) != "not a number\n" {
		t.Errorf("limit rewritten to %q", b)
	}
}

func TestRead(t *testing.T) {
	t.Parallel()
	tb, _ := table(t, 4*gib, "42\n", "65536\n")
	if e, l, ok := tb.Read(); !ok || e != 42 || l != 65536 {
		t.Errorf("Read = %d, %d, %v", e, l, ok)
	}
	for _, limit := range []string{"0\n", "-1\n", "x\n"} {
		tb, _ := table(t, 4*gib, "42\n", limit)
		if _, _, ok := tb.Read(); ok {
			t.Errorf("Read accepted limit %q", limit)
		}
	}
}
