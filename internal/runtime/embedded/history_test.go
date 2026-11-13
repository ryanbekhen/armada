package embedded

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// writeLines writes n lines through a container's log file, one second
// apart from start, rotating at maxSize.
func writeLines(t *testing.T, dir, id string, maxSize int64, start time.Time, lines ...string) {
	t.Helper()
	l, err := openLogFile(filepath.Join(dir, id+".log"), maxSize)
	if err != nil {
		t.Fatal(err)
	}
	l.dir, l.id = dir, id
	now := start
	l.now = func() time.Time { return now }
	for _, s := range lines {
		if err := l.write("stdout", []byte(s+"\n")); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func lines(recs []runtime.LogRecord) string {
	var b strings.Builder
	for _, r := range recs {
		b.WriteString(r.Replica + ":" + string(r.Data))
	}
	return b.String()
}

func TestLogHistory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	start := time.Date(2026, 11, 13, 1, 0, 0, 0, time.UTC)
	if err := WriteLogMeta(dir, "web-a1", LogMeta{App: "web", Replica: "web-a"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteLogMeta(dir, "web-b1", LogMeta{App: "web", Replica: "web-b"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteLogMeta(dir, "api-a1", LogMeta{App: "api", Replica: "api-a"}); err != nil {
		t.Fatal(err)
	}
	// Small files: every few lines rotate, the oldest goes to history.
	var many []string
	for i := range 40 {
		many = append(many, fmt.Sprintf("line %02d", i))
	}
	writeLines(t, dir, "web-a1", 120, start, many...)
	writeLines(t, dir, "web-b1", 1<<20, start.Add(500*time.Millisecond), "b ERROR one", "b ok")
	writeLines(t, dir, "api-a1", 1<<20, start, "api line")
	// No meta: rotated-out files are dropped as before.
	writeLines(t, dir, "sys1", 120, start, many...)
	// web-b's container is removed: its files move to history.
	if err := RemoveLogs(dir, "web-b1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "web-b1.log")); !os.IsNotExist(err) {
		t.Errorf("live file of a removed container: %v", err)
	}

	search := func(q runtime.LogQuery) string {
		t.Helper()
		if q.Limit == 0 {
			q.Limit = 1000
		}
		if q.MaxBytes == 0 {
			q.MaxBytes = 1 << 30
		}
		recs, _, err := SearchLogs(context.Background(), dir, q)
		if err != nil {
			t.Fatal(err)
		}
		return lines(recs)
	}
	all := search(runtime.LogQuery{App: "web"})
	for _, want := range []string{"web-a:line 00\n", "web-a:line 39\n", "web-b:b ERROR one\n"} {
		if !strings.Contains(all, want) {
			t.Errorf("history lost %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, "api") || strings.Count(all, "\n") != 42 {
		t.Errorf("web search:\n%s", all)
	}
	// Merged by time: b's first line (at 0.5s) comes after a's line 00.
	if !strings.HasPrefix(all, "web-a:line 00\nweb-b:b ERROR one\nweb-a:line 01\n") {
		t.Errorf("not in time order:\n%s", all[:80])
	}
	if got := search(runtime.LogQuery{App: "web", Grep: "error"}); got != "web-b:b ERROR one\n" {
		t.Errorf("grep: %q", got)
	}
	if got := search(runtime.LogQuery{App: "web", Replica: "web-a", Since: start.Add(38 * time.Second)}); got != "web-a:line 38\nweb-a:line 39\n" {
		t.Errorf("since: %q", got)
	}
	if got := search(runtime.LogQuery{App: "web", Replica: "web-a", Until: start.Add(1 * time.Second)}); got != "web-a:line 00\nweb-a:line 01\n" {
		t.Errorf("until: %q", got)
	}
	if got := search(runtime.LogQuery{App: "web", Replica: "web-a", Limit: 2}); got != "web-a:line 38\nweb-a:line 39\n" {
		t.Errorf("limit keeps the newest: %q", got)
	}
	if _, notice, _ := SearchLogs(context.Background(), dir, runtime.LogQuery{App: "web", Limit: 10, MaxBytes: 100}); !strings.Contains(notice, "narrow it") {
		t.Errorf("budget notice %q", notice)
	}
	// Patterns are plain text.
	if got := search(runtime.LogQuery{App: "web", Grep: "line .."}); got != "" {
		t.Errorf("grep as a pattern: %q", got)
	}
}

func TestPruneLogs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Now()
	if err := WriteLogMeta(dir, "web-a1", LogMeta{App: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteLogMeta(dir, "web-b1", LogMeta{App: "web"}); err != nil {
		t.Fatal(err)
	}
	h := historyDir(dir)
	file := func(id string, seq int, size int, age time.Duration) string {
		p := filepath.Join(h, fmt.Sprintf("%s.%d.log", id, seq))
		if err := os.WriteFile(p, make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
		return p
	}
	old := file("web-a1", 1, 10, 8*24*time.Hour)
	b1 := file("web-b1", 2, 100, time.Hour)
	b2 := file("web-b1", 3, 100, time.Minute)
	live := filepath.Join(dir, "web-a1.log")
	if err := os.WriteFile(live, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PruneLogs(dir, 7*24*time.Hour, 150, now); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{old: false, b1: false, b2: true} {
		if _, err := os.Stat(p); (err == nil) != want {
			t.Errorf("%s kept = %v, want %v", filepath.Base(p), err == nil, want)
		}
	}
	// web-a1 still runs: its meta stays. web-b1 has history left.
	for _, id := range []string{"web-a1", "web-b1"} {
		if !hasMeta(dir, id) {
			t.Errorf("meta of %s removed", id)
		}
	}
	if err := os.Remove(live); err != nil {
		t.Fatal(err)
	}
	if err := PruneLogs(dir, time.Second, 150, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if hasMeta(dir, "web-a1") || hasMeta(dir, "web-b1") {
		t.Error("meta of removed containers with no history kept")
	}
}

func TestDefaultHistoryBytes(t *testing.T) {
	t.Parallel()
	if n := DefaultHistoryBytes(t.TempDir()); n < minDefaultHistory || n > maxDefaultHistory {
		t.Errorf("default %d", n)
	}
}
