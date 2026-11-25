//go:build linux

package containerd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// TestRustSupervisorLogs keeps what the embedded runtime's log readers do
// for the driver (logs.json): searches of the log history read here (the
// reference armada-log search follows), tails for an export with their
// cursors in export.json (inodes named by their file), and prunes, over
// a log directory the file describes. The Rust agent's supervisor runtime
// (agent/src/supervisor/history.rs) replays it.

type rsLogFile struct {
	Path string `json:"path"`
	Data string `json:"data"`
	Mod  int64  `json:"mod"` // Unix seconds
}

type rsLogRecord struct {
	Time      string `json:"time"`
	Stderr    bool   `json:"stderr"`
	Data      string `json:"data"`
	Replica   string `json:"replica"`
	Container string `json:"container"`
	App       string `json:"app,omitempty"`
	Revision  string `json:"revision,omitempty"`
}

type rsSearch struct {
	App       string        `json:"app"`
	Replica   string        `json:"replica"`
	Container string        `json:"container"`
	Since     string        `json:"since"`
	Until     string        `json:"until"`
	Grep      string        `json:"grep"`
	Limit     int           `json:"limit"`
	MaxBytes  int64         `json:"maxBytes"`
	Records   []rsLogRecord `json:"records"`
	Notice    string        `json:"notice"`
}

type rsTail struct {
	// Appended before the tail: files written or extended.
	Append   []rsLogFile   `json:"append"`
	Now      string        `json:"now"`
	Target   string        `json:"target"`
	MaxBytes int64         `json:"maxBytes"`
	Records  []rsLogRecord `json:"records"`
	State    string        `json:"state"` // export.json after the commit, inodes as file names
}

type rsPrune struct {
	Now       string   `json:"now"`
	Retention int64    `json:"retention"` // seconds
	MaxBytes  int64    `json:"maxBytes"`
	Left      []string `json:"left"`
}

type rsLogs struct {
	Files    []rsLogFile `json:"files"`
	Searches []rsSearch  `json:"searches"`
	Tails    []rsTail    `json:"tails"`
	Prunes   []rsPrune   `json:"prunes"`
}

func rsLogLine(stream, log string, t time.Time) string {
	b, _ := json.Marshal(map[string]any{"log": log, "stream": stream, "time": t.UTC()})
	return string(b) + "\n"
}

func rsWriteLogFiles(t *testing.T, dir string, files []rsLogFile, appendTo bool) {
	t.Helper()
	for _, f := range files {
		p := filepath.Join(dir, f.Path)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		flag := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		if appendTo {
			flag = os.O_WRONLY | os.O_CREATE | os.O_APPEND
		}
		w, err := os.OpenFile(p, flag, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.WriteString(f.Data); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		mt := time.Unix(f.Mod, 0)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
}

func rsRecords(recs []runtime.LogRecord) []rsLogRecord {
	out := []rsLogRecord{}
	for _, r := range recs {
		out = append(out, rsLogRecord{
			Time: rsTime(r.Time), Stderr: r.Stream == runtime.Stderr, Data: string(r.Data),
			Replica: r.Replica, Container: r.Container, App: r.App, Revision: r.Revision,
		})
	}
	return out
}

// rsInodes names each file of dir by its inode.
func rsInodes(t *testing.T, dir string) map[uint64]string {
	t.Helper()
	out := map[uint64]string{}
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || !fi.Mode().IsRegular() {
			return nil
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			rel, _ := filepath.Rel(dir, p)
			out[st.Ino] = rel
		}
		return nil
	})
	return out
}

// rsState is export.json with every inode replaced by its file's name.
func rsState(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "history", "export.json"))
	if err != nil {
		return ""
	}
	var st map[string]any
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	names := rsInodes(t, dir)
	s := string(b)
	files, _ := st["files"].(map[string]any)
	for _, c := range files {
		if m, ok := c.(map[string]any); ok {
			if ino, ok := m["ino"].(float64); ok {
				s = strings.ReplaceAll(s, fmt.Sprintf(`"ino":%d`, uint64(ino)), fmt.Sprintf(`"ino":%q`, names[uint64(ino)]))
			}
		}
	}
	return s
}

func rsLeft(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func TestRustSupervisorLogs(t *testing.T) {
	base := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }
	meta := func(app, replica, revision, container string, created time.Time) string {
		b, _ := json.Marshal(embedded.LogMeta{App: app, Replica: replica, Revision: revision, Container: container, Created: created})
		return string(b)
	}
	mod := base.Add(time.Hour).Unix()
	out := rsLogs{Files: []rsLogFile{
		{Path: "history/web-r1-aaaa.meta", Data: meta("web", "web-r1", "web-1", "", at(-3600)), Mod: mod},
		{Path: "web-r1-aaaa.log.1", Data: rsLogLine("stdout", "one\n", at(1)) + rsLogLine("stderr", "ERR two\n", at(2)), Mod: mod},
		{Path: "web-r1-aaaa.log", Data: rsLogLine("stdout", "three\n", at(3)) + "not json\n" + rsLogLine("stdout", "four\n", at(4)) + `{"log":"cut`, Mod: mod},
		{Path: "history/web-r1-bbbb.meta", Data: meta("web", "web-r1", "web-1", "proxy", at(-3600)), Mod: mod},
		{Path: "web-r1-bbbb.log", Data: rsLogLine("stdout", "proxy up\n", at(5)), Mod: mod},
		{Path: "history/web-r2-0000.meta", Data: meta("web", "web-r2", "web-0", "app", at(-7200)), Mod: mod},
		{Path: "history/web-r2-0000.1767340000000000001.log", Data: rsLogLine("stdout", "old err\n", at(-100)) + rsLogLine("stderr", "older\n", at(-90)), Mod: base.Add(-40 * 24 * time.Hour).Unix()},
		{Path: "history/web-r2-0000.1767340000000000002.log", Data: rsLogLine("stdout", "newer\n", at(-50)), Mod: base.Add(-time.Hour).Unix()},
		{Path: "history/api-r1-cccc.meta", Data: meta("api.dev", "api-r1", "api-3", "", at(-60)), Mod: mod},
		{Path: "api-r1-cccc.log", Data: rsLogLine("stdout", "api\n", at(6)), Mod: mod},
		{Path: "history/gone-1111.meta", Data: meta("web", "web-r9", "web-1", "", at(-60)), Mod: mod},
		{Path: "history/junk.txt", Data: "x", Mod: mod},
		{Path: "history/x.notanumber.log", Data: "x", Mod: mod},
	}}
	dir := t.TempDir()
	rsWriteLogFiles(t, dir, out.Files, false)
	ctx := context.Background()

	searches := []rsSearch{
		{App: "web", Limit: 100, MaxBytes: 1 << 30},
		{App: "web", Limit: 2, MaxBytes: 1 << 30},
		{App: "web", Grep: "err", Limit: 100, MaxBytes: 1 << 30},
		{App: "web", Container: "proxy", Limit: 100, MaxBytes: 1 << 30},
		{App: "web", Replica: "web-r2", Limit: 100, MaxBytes: 1 << 30},
		{App: "web", Since: rsTime(at(2)), Until: rsTime(at(3)), Limit: 100, MaxBytes: 1 << 30},
		{App: "web", Since: rsTime(base.Add(2 * time.Hour)), Limit: 100, MaxBytes: 1 << 30},
		{App: "web", Limit: 100, MaxBytes: 200},
		{App: "api.dev", Limit: 100, MaxBytes: 1 << 30},
		{App: "web", Limit: 0, MaxBytes: 1 << 30},
	}
	parse := func(s string) time.Time {
		if s == "" {
			return time.Time{}
		}
		v, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, s := range searches {
		recs, notice, err := embedded.SearchLogs(ctx, dir, runtime.LogQuery{
			App: s.App, Replica: s.Replica, Container: s.Container, Since: parse(s.Since), Until: parse(s.Until),
			Grep: s.Grep, Limit: s.Limit, MaxBytes: s.MaxBytes,
		})
		if err != nil {
			t.Fatal(err)
		}
		s.Records, s.Notice = rsRecords(recs), notice
		out.Searches = append(out.Searches, s)
	}

	tails := []rsTail{
		// A new target: what exists starts at its end.
		{Now: rsTime(at(100)), Target: "loki|https://logs.test", MaxBytes: 8 << 20},
		// New output, a container made since, and one rotated.
		{Append: []rsLogFile{
			{Path: "web-r1-aaaa.log", Data: `"}` + "\n" + rsLogLine("stdout", "five\n", at(101)), Mod: mod},
			{Path: "history/web-r3-dddd.meta", Data: meta("web", "web-r3", "web-1", "", at(150)), Mod: mod},
			{Path: "web-r3-dddd.log", Data: rsLogLine("stderr", "hello\n", at(151)) + rsLogLine("stdout", "world\n", at(152)), Mod: mod},
		}, Now: rsTime(at(200)), Target: "loki|https://logs.test", MaxBytes: 8 << 20},
		// Nothing new: the cursors stay.
		{Now: rsTime(at(300)), Target: "loki|https://logs.test", MaxBytes: 8 << 20},
		// A budget smaller than the new output.
		{Append: []rsLogFile{
			{Path: "web-r3-dddd.log", Data: strings.Repeat(rsLogLine("stdout", strings.Repeat("x", 100)+"\n", at(301)), 1000), Mod: mod},
		}, Now: rsTime(at(400)), Target: "loki|https://logs.test", MaxBytes: 1},
		// Another target starts over.
		{Now: rsTime(at(500)), Target: "otlp|https://other.test", MaxBytes: 8 << 20},
	}
	for _, tl := range tails {
		rsWriteLogFiles(t, dir, tl.Append, true)
		tail, err := embedded.TailLogs(ctx, dir, tl.Target, tl.MaxBytes, parse(tl.Now))
		if err != nil {
			t.Fatal(err)
		}
		if err := tail.Commit(); err != nil {
			t.Fatal(err)
		}
		tl.Records, tl.State = rsRecords(tail.Records), rsState(t, dir)
		out.Tails = append(out.Tails, tl)
	}

	prunes := []rsPrune{
		{Now: rsTime(base.Add(2 * time.Hour)), Retention: 30 * 24 * 3600, MaxBytes: 1 << 30},
		{Now: rsTime(base.Add(2 * time.Hour)), Retention: 30 * 24 * 3600, MaxBytes: 10},
	}
	for _, p := range prunes {
		if err := embedded.PruneLogs(dir, time.Duration(p.Retention)*time.Second, p.MaxBytes, parse(p.Now)); err != nil {
			t.Fatal(err)
		}
		p.Left = rsLeft(t, dir)
		out.Prunes = append(out.Prunes, p)
	}
	rsCompare(t, "logs.json", out)
}
