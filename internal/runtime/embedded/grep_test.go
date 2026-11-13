package embedded

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// Grep filters on the node, and Tail counts matching lines.
func TestReadLogsGrep(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	start := time.Date(2026, 11, 13, 1, 0, 0, 0, time.UTC)
	writeLines(t, dir, "c1", 1<<20, start, "ERROR one", "ok", "error two", "ok", "ok")
	s, err := ReadLogs(context.Background(), dir, "c1", runtime.LogOptions{Tail: 1, Grep: "error"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var got []string
	for {
		f, err := s.Next()
		if err != nil {
			break
		}
		got = append(got, string(f.Data))
		if !f.Time.Equal(start.Add(2 * time.Second)) {
			t.Errorf("time %v", f.Time)
		}
	}
	if strings.Join(got, "") != "error two\n" {
		t.Errorf("got %q", got)
	}
}
