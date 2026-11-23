package embedded

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// armada-log search (logger/src/search.rs) must find what SearchLogs finds
// reading the files itself. CI sets ARMADA_LOG_BIN (see
// TestArmadaLogMatchesGo).
func TestArmadaLogSearchMatchesGo(t *testing.T) {
	bin := os.Getenv("ARMADA_LOG_BIN")
	if bin == "" {
		t.Skip("ARMADA_LOG_BIN is not set (make logger)")
	}
	searchFellBack = func(err error) { t.Errorf("armada-log search was not used: %v", err) }
	t.Cleanup(func() { searchFellBack = func(error) {} })

	dir := t.TempDir()
	start := time.Date(2026, 11, 23, 1, 0, 0, 123456789, time.UTC)
	for id, m := range map[string]LogMeta{
		"web-a1": {App: "web", Replica: "web-a", Container: "app"},
		"web-a2": {App: "web", Replica: "web-a", Container: "proxy"},
		"web-b1": {App: "web", Replica: "web-b"},
		"api-a1": {App: "api", Replica: "api-a"},
	} {
		if err := WriteLogMeta(dir, id, m); err != nil {
			t.Fatal(err)
		}
	}
	odd := []string{
		`GET /x <b>bold</b> & "quoted" \back\slash`,
		"tab\there and a bell \x07 and NUL \x00",
		"unicode é€😀 ERROR Ünïcode",
		"invalid \xff\xfe utf-8 error",
		"line sep \u2028 para \u2029",
		"Timeout after 30s",
		"TIMEOUT shouting",
		strings.Repeat("long ", 4000) + "needle-at-the-end",
	}
	var many []string
	for i := range 300 {
		many = append(many, fmt.Sprintf("%03d %s", i, odd[i%len(odd)]))
	}
	writeLines(t, dir, "web-a1", 4096, start, many...)
	writeLines(t, dir, "web-a2", 1<<20, start.Add(250*time.Millisecond), many[:50]...)
	writeLines(t, dir, "web-b1", 2048, start.Add(500*time.Millisecond), many[100:200]...)
	writeLines(t, dir, "api-a1", 1<<20, start, "api ERROR")
	if err := RemoveLogs(dir, "web-b1"); err != nil {
		t.Fatal(err)
	}
	// A live file with a line Go cannot decode and a last line still being
	// written.
	f, err := os.OpenFile(filepath.Join(dir, "web-a1.log"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("not json at all error\n{\"log\":\"bad time error\",\"stream\":\"stdout\",\"time\":\"yesterday\"}\n{\"log\":\"partial error")
	_ = f.Close()

	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	for _, q := range []runtime.LogQuery{
		{App: "web"},
		{App: "web", Grep: "error"},
		{App: "web", Grep: "ERROR"},
		{App: "web", Grep: "timeout"},
		{App: "web", Grep: "<b>"},
		{App: "web", Grep: `"quoted"`},
		{App: "web", Grep: `\back`},
		{App: "web", Grep: "\t"},
		{App: "web", Grep: "needle-at-the-end"},
		{App: "web", Grep: "nothing matches this"},
		{App: "web", Replica: "web-a", Since: at(100), Until: at(150)},
		{App: "web", Container: "proxy"},
		{App: "web", Replica: "web-b", Since: at(150)},
		{App: "web", Limit: 7},
		{App: "web", Limit: 1, Grep: "e"},
		{App: "web", MaxBytes: 20000},
		{App: "web", Since: at(1000)},
		{App: "api"},
		{App: "ghost"},
	} {
		if q.Limit == 0 {
			q.Limit = 1000
		}
		if q.MaxBytes == 0 {
			q.MaxBytes = 1 << 30
		}
		goRecs, goNotice, goErr := SearchLogs(context.Background(), dir, q)
		rRecs, rNotice, rErr := SearchLogsWith(context.Background(), bin, dir, q)
		if goErr != nil || rErr != nil {
			t.Fatalf("%+v: %v, %v", q, goErr, rErr)
		}
		if goNotice != rNotice {
			t.Errorf("%+v: notice %q, armada-log %q", q, goNotice, rNotice)
		}
		if !reflect.DeepEqual(goRecs, rRecs) {
			t.Errorf("%+v: %d records, armada-log %d:\n%s\n---\n%s", q, len(goRecs), len(rRecs), lines(goRecs), lines(rRecs))
		}
	}
	// A deadline that has passed stops it before the first file.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	searchFellBack = func(error) {}
	if _, notice, _ := SearchLogsWith(ctx, bin, dir, runtime.LogQuery{App: "web", Limit: 10, MaxBytes: 1 << 30}); notice != noticeTimeout() {
		t.Errorf("past deadline: %q", notice)
	}
}

// An armada-log without search (an older pack) leaves the search to Go.
func TestSearchFallsBack(t *testing.T) {
	dir := t.TempDir()
	if err := WriteLogMeta(dir, "web-a1", LogMeta{App: "web", Replica: "web-a"}); err != nil {
		t.Fatal(err)
	}
	writeLines(t, dir, "web-a1", 1<<20, time.Now().Add(-time.Minute), "hello")
	old := filepath.Join(t.TempDir(), "armada-log")
	if err := os.WriteFile(old, []byte("#!/bin/sh\necho 'armada-log: unknown argument' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var fell error
	searchFellBack = func(err error) { fell = err }
	t.Cleanup(func() { searchFellBack = func(error) {} })
	recs, _, err := SearchLogsWith(context.Background(), old, dir, runtime.LogQuery{App: "web", Limit: 10, MaxBytes: 1 << 30})
	if err != nil || lines(recs) != "web-a:hello\n" || fell == nil {
		t.Errorf("fallback: %q %v (fell back: %v)", lines(recs), err, fell)
	}
}
