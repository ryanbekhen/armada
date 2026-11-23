package embedded

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/logexport"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// exportSplit stands in for spec.SplitAppID: "name.space", or a name in
// default; IDs with "!" are refused.
func exportSplit(id string) (string, string, bool) {
	if strings.Contains(id, "!") {
		return "", "", false
	}
	if name, space, ok := strings.Cut(id, "."); ok {
		return space, name, true
	}
	return "default", id, true
}

// goRequests renders a Go tail the way the agent's exportOnce does.
func goRequests(t *testing.T, tail runtime.LogTail, enc runtime.LogEncoding) ([][]byte, int64) {
	t.Helper()
	var recs []logexport.Record
	var size int64
	for _, r := range tail.Records {
		space, name, ok := enc.Split(r.App)
		if !ok {
			continue
		}
		container := r.Container
		if container == "" {
			container = "app"
		}
		recs = append(recs, logexport.Record{Time: r.Time, Stderr: r.Stream == runtime.Stderr, Line: string(r.Data),
			App: name, Space: space, Revision: r.Revision, Replica: r.Replica, Container: container, Node: enc.Node})
		size += int64(len(r.Data))
	}
	var out [][]byte
	for _, b := range logexport.Batches(recs, enc.BatchRecords, enc.BatchBytes) {
		body, err := logexport.Encode(enc.Format, b)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, body)
	}
	return out, size
}

var observed = regexp.MustCompile(`"observedTimeUnixNano":"-?[0-9]+"`)

func appendRaw(t *testing.T, dir, id string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, id+".log"), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, l := range lines {
		if _, err := f.WriteString(l); err != nil {
			t.Fatal(err)
		}
	}
}

// armada-log export (logger/src/export.rs) must send what the agent sends
// from TailLogs' records, request for request, and leave the same cursors.
// CI sets ARMADA_LOG_BIN (see TestArmadaLogMatchesGo).
func TestArmadaLogExportMatchesGo(t *testing.T) {
	bin := os.Getenv("ARMADA_LOG_BIN")
	if bin == "" {
		t.Skip("ARMADA_LOG_BIN is not set (make logger)")
	}
	exportFellBack = func(err error) { t.Errorf("armada-log export was not used: %v", err) }
	t.Cleanup(func() { exportFellBack = func(error) {} })

	for _, format := range []string{logexport.Loki, logexport.OTLP} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			start := time.Date(2026, 11, 23, 1, 0, 0, 123456789, time.UTC)
			now := start.Add(-time.Hour) // every container is newer than the destination
			for id, m := range map[string]LogMeta{
				"web-a1": {App: "web.prod", Replica: "web.prod-r1-a", Revision: "web.prod--r1", Container: "app", Created: start},
				"web-a2": {App: "web.prod", Replica: "web.prod-r1-a", Revision: "web.prod--r1", Container: "proxy", Created: start},
				"web-b1": {App: "web.prod", Replica: "web.prod-r1-b", Created: start},
				"api-a1": {App: "api", Replica: "api-r2-a", Revision: "api--r2", Created: start},
				"bad-a1": {App: "bad!", Replica: "bad-r1-a", Created: start},
			} {
				if err := WriteLogMeta(dir, id, m); err != nil {
					t.Fatal(err)
				}
			}
			odd := []string{
				`GET /x <b>bold</b> & "quoted" \back\slash`,
				"tab\there and a bell \x07 and NUL \x00",
				"unicode é€😀 Ünïcode",
				"invalid \xff\xfe utf-8 \xe2\x80",
				"line sep \u2028 para \u2029",
				"",
				strings.Repeat("long ", 3000),
			}
			var many []string
			for i := range 400 {
				many = append(many, fmt.Sprintf("%03d %s", i, odd[i%len(odd)]))
			}
			writeLines(t, dir, "web-a1", 8192, start, many...)
			writeLines(t, dir, "web-a2", 1<<20, start.Add(250*time.Millisecond), many[:50]...)
			writeLines(t, dir, "web-b1", 4096, start.Add(500*time.Millisecond), many[100:200]...)
			writeLines(t, dir, "bad-a1", 1<<20, start, "never sent")
			if err := RemoveLogs(dir, "web-b1"); err != nil {
				t.Fatal(err)
			}
			// Lines only another writer would leave: no time, a null log, an
			// offset, escapes the writers do not use, raw invalid UTF-8,
			// stderr in another case, lines Go refuses, and a last line still
			// being written.
			appendRaw(t, dir, "api-a1",
				`{"log":"no time\n","stream":"stdout"}`+"\n",
				`{"log":null,"stream":"stderr","time":"2026-11-23T08:00:00.5+07:00"}`+"\n",
				`{"log":"esc \u00e9 \ud83d\ude00 \ud800 lone \/ \b\f\n","stream":"stderr","time":"2026-11-23T01:00:01Z"}`+"\n",
				"{\"log\":\"raw \xff\xc3 bytes\\n\",\"Stream\":\"stderr\",\"time\":\"2026-11-23T01:00:02Z\"}\n",
				"not json at all\n",
				`{"log":"bad time","time":"yesterday"}`+"\n",
				`{"log":"partial","stream":"stdout","time":"2026-11-23T01:00:03Z"}`)

			round := func(maxBytes int64, enc runtime.LogEncoding) bool {
				t.Helper()
				g, err := TailLogs(context.Background(), dir, "dest", maxBytes, now)
				if err != nil {
					t.Fatal(err)
				}
				want, wantSize := goRequests(t, g, enc)
				r, err := TailLogsWith(context.Background(), bin, dir, "dest", maxBytes, now, &enc)
				if err != nil {
					t.Fatal(err)
				}
				if r.Records != nil {
					t.Fatal("armada-log export returned records")
				}
				if len(r.Bodies) != len(want) || r.Size != wantSize {
					t.Fatalf("armada-log sent %d requests of %d bytes, Go %d of %d", len(r.Bodies), r.Size, len(want), wantSize)
				}
				for i := range want {
					w := observed.ReplaceAll(want[i], []byte(`"observedTimeUnixNano":"N"`))
					got := observed.ReplaceAll(r.Bodies[i], []byte(`"observedTimeUnixNano":"N"`))
					if string(got) != string(w) {
						t.Fatalf("request %d differs:\n armada-log %.600s\n Go         %.600s", i, got, w)
					}
				}
				if err := g.Commit(); err != nil {
					t.Fatal(err)
				}
				goState := loadExportState(dir)
				if err := r.Commit(); err != nil {
					t.Fatal(err)
				}
				if st := loadExportState(dir); !sameState(goState, st) {
					t.Fatalf("cursors differ:\n armada-log %+v\n Go         %+v", st.Files, goState.Files)
				}
				return len(want) > 0
			}
			enc := runtime.LogEncoding{Format: format, Node: "node-1", BatchRecords: 37, BatchBytes: 16 << 10, Split: exportSplit}
			// A small budget: several rounds, cut within files.
			rounds := 0
			for round(40<<10, enc) {
				if rounds++; rounds > 200 {
					t.Fatal("the output never ended")
				}
			}
			if rounds < 3 {
				t.Fatalf("only %d rounds", rounds)
			}

			// A file gone before it was sent (pruned) goes on by time: the
			// replacement's entries up to the last one sent are skipped.
			writeLines(t, dir, "web-a2", 1<<20, start.Add(time.Hour), "more 1", "more 2")
			if err := os.Remove(filepath.Join(dir, "web-a2.log")); err != nil {
				t.Fatal(err)
			}
			writeLines(t, dir, "web-a2", 1<<20, start.Add(30*time.Minute), "old", "older")
			writeLines(t, dir, "web-a2", 1<<20, start.Add(2*time.Hour), "new 1", "new 2")
			appendRaw(t, dir, "api-a1", "\n", `{"log":"after\n","stream":"stdout","time":"2026-11-23T05:00:00Z"}`+"\n")
			if !round(8<<20, runtime.LogEncoding{Format: format, Node: "node-1", BatchRecords: 2000, BatchBytes: 1 << 20, Split: exportSplit}) {
				t.Fatal("nothing new was sent")
			}
			if round(8<<20, enc) {
				t.Fatal("output sent twice")
			}
		})
	}
}

// A runtime pack whose armada-log cannot export leaves the reading to Go.
func TestExportFallsBack(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 11, 23, 1, 0, 0, 0, time.UTC)
	if err := WriteLogMeta(dir, "web-a1", LogMeta{App: "web", Replica: "web-r1-a", Created: start}); err != nil {
		t.Fatal(err)
	}
	writeLines(t, dir, "web-a1", 1<<20, start, "hello")
	var fell error
	exportFellBack = func(err error) { fell = err }
	t.Cleanup(func() { exportFellBack = func(error) {} })
	bin := filepath.Join(t.TempDir(), "armada-log")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'armada-log: unknown argument' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	enc := runtime.LogEncoding{Format: logexport.Loki, BatchRecords: 10, BatchBytes: 1 << 20, Split: exportSplit}
	tail, err := TailLogsWith(context.Background(), bin, dir, "dest", 1<<20, start.Add(-time.Hour), &enc)
	if err != nil {
		t.Fatal(err)
	}
	if fell == nil || tail.Bodies != nil || len(tail.Records) != 1 || string(tail.Records[0].Data) != "hello\n" {
		t.Fatalf("fell back with %v: %d bodies, records %+v", fell, len(tail.Bodies), tail.Records)
	}
	var exitErr interface{ ExitCode() int }
	if !errors.As(fell, &exitErr) {
		t.Errorf("fallback error %v", fell)
	}
}
