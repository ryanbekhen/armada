package embedded

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tail(t *testing.T, dir, target string, maxBytes int64, now time.Time, commit bool) string {
	t.Helper()
	lt, err := TailLogs(context.Background(), dir, target, maxBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, r := range lt.Records {
		b.WriteString(r.App + "/" + r.Replica + ":" + string(r.Data))
	}
	if commit {
		if err := lt.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	return b.String()
}

func TestTailLogs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	start := time.Date(2026, 11, 13, 1, 0, 0, 0, time.UTC)
	// old existed before the destination: its output so far is not sent.
	if err := WriteLogMeta(dir, "old1", LogMeta{App: "web", Replica: "old", Created: start.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	writeLines(t, dir, "old1", 1<<20, start, "before")
	if got := tail(t, dir, "loki-a", 1<<20, start, true); got != "" {
		t.Errorf("first tail sent old output: %q", got)
	}
	writeLines(t, dir, "old1", 1<<20, start.Add(time.Minute), "after")
	if err := WriteLogMeta(dir, "new1", LogMeta{App: "api", Replica: "new", Created: start.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	writeLines(t, dir, "new1", 1<<20, start.Add(time.Second), "n1", "n2")
	// No meta: system containers are never sent.
	writeLines(t, dir, "sys1", 1<<20, start, "system")
	got := tail(t, dir, "loki-a", 1<<20, start.Add(time.Minute), false)
	if got != "api/new:n1\napi/new:n2\nweb/old:after\n" {
		t.Errorf("tail: %q", got)
	}
	// Not committed: the same again.
	if again := tail(t, dir, "loki-a", 1<<20, start.Add(time.Minute), true); again != got {
		t.Errorf("uncommitted tail lost output: %q", again)
	}
	if got := tail(t, dir, "loki-a", 1<<20, start.Add(time.Minute), true); got != "" {
		t.Errorf("committed output sent again: %q", got)
	}

	// Rotation (small files) and removal into history lose nothing.
	var many []string
	for i := range 30 {
		many = append(many, fmt.Sprintf("line %02d", i))
	}
	writeLines(t, dir, "new1", 120, start.Add(2*time.Minute), many...)
	if err := RemoveLogs(dir, "new1"); err != nil {
		t.Fatal(err)
	}
	got = tail(t, dir, "loki-a", 1<<20, start.Add(3*time.Minute), true)
	for _, l := range many {
		if strings.Count(got, "api/new:"+l+"\n") != 1 {
			t.Errorf("rotated output %q sent %d times:\n%s", l, strings.Count(got, l+"\n"), got)
		}
	}

	// A budget splits a container's output over tails, in order.
	writeLines(t, dir, "old1", 1<<20, start.Add(4*time.Minute), many...)
	var all string
	for range 40 {
		all += tail(t, dir, "loki-a", 100, start.Add(5*time.Minute), true)
	}
	if want := "web/old:" + strings.Join(many, "\nweb/old:") + "\n"; all != want {
		t.Errorf("budgeted tails:\n%s", all)
	}

	// Another destination starts at the end.
	writeLines(t, dir, "old1", 1<<20, start.Add(6*time.Minute), "for a")
	if got := tail(t, dir, "otlp-b", 1<<20, start.Add(7*time.Minute), true); got != "" {
		t.Errorf("new destination got old output: %q", got)
	}
}

func TestTailLogsPruned(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	start := time.Date(2026, 11, 13, 1, 0, 0, 0, time.UTC)
	if err := WriteLogMeta(dir, "a1", LogMeta{App: "web", Replica: "a", Created: start}); err != nil {
		t.Fatal(err)
	}
	writeLines(t, dir, "a1", 1<<20, start.Add(time.Second), "one")
	if got := tail(t, dir, "x", 1<<20, start, true); got != "web/a:one\n" {
		t.Fatalf("tail %q", got)
	}
	// The file the cursor points into is gone (moved and pruned while the
	// endpoint was down); later output goes on by time.
	if err := os.Rename(filepath.Join(dir, "a1.log"), filepath.Join(dir, "a1.log.1")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "a1.log.1")); err != nil {
		t.Fatal(err)
	}
	writeLines(t, dir, "a1", 1<<20, start, "older than sent")
	writeLines(t, dir, "a1", 1<<20, start.Add(time.Minute), "two")
	if got := tail(t, dir, "x", 1<<20, start, true); got != "web/a:two\n" {
		t.Errorf("after prune: %q", got)
	}
}
