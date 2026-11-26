package embedded

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Recording the logger cases for the Rust replay (ADR 0055, item 20).
// With -record-fixtures, TestRecordLoggerCases runs every case of
// compareLoggers through WriteLogs alone and writes
// daemon/tests/testdata/logwriter.json.gz: each case's output and limits,
// the history meta file WriteLogMeta wrote when the case has one, and the
// files WriteLogs left as logFiles reads them (times checked and blanked).
// daemon/tests/logwriter.rs runs `armadad runtime-log` and, with
// ARMADA_LOG_BIN, armada-log on each case and compares as compareLoggers
// does, so TestRuntimeLogMatchesGo and TestArmadaLogMatchesGo keep
// checking once Go is gone.

var recordFixtures = flag.Bool("record-fixtures", false,
	"write daemon/tests/testdata/logwriter.json.gz (each logger case and what WriteLogs stored) for the Rust replay")

const loggerFixtures = "../../../daemon/tests/testdata/logwriter.json.gz"

func TestRecordLoggerCases(t *testing.T) {
	if !*recordFixtures {
		t.Skip("-record-fixtures writes the logger cases for the Rust replay")
	}
	type file struct {
		Name string `json:"name"`
		Body string `json:"body"`
	}
	type recorded struct {
		Name string `json:"name"`
		ID   string `json:"id"`
		// The output as written (base64: it holds bytes that are not
		// UTF-8).
		Stdout   []byte  `json:"stdout"`
		Stderr   []byte  `json:"stderr"`
		MaxSize  int64   `json:"maxSize"`
		MaxFiles int     `json:"maxFiles"`
		Rate     float64 `json:"rate"`
		Burst    float64 `json:"burst"`
		// Meta is the history meta file the case starts with, by its
		// path below the logs directory.
		Meta  map[string]string `json:"meta,omitempty"`
		Files []file            `json:"files"`
	}
	var out []recorded
	for _, c := range loggerCases() {
		dir := t.TempDir()
		r := recorded{Name: c.name, ID: loggerCaseID, Stdout: []byte(c.stdout), Stderr: []byte(c.stderr),
			MaxSize: c.lim.maxSize, MaxFiles: c.lim.maxFiles, Rate: c.lim.rate, Burst: c.lim.burst}
		if c.meta {
			if err := WriteLogMeta(dir, loggerCaseID, LogMeta{App: "web", Replica: "web-r1"}); err != nil {
				t.Fatal(err)
			}
			metas, _ := filepath.Glob(filepath.Join(dir, historyDirName, "*"+metaSuffix))
			r.Meta = map[string]string{}
			for _, m := range metas {
				b, err := os.ReadFile(m)
				if err != nil {
					t.Fatal(err)
				}
				rel, _ := filepath.Rel(dir, m)
				r.Meta[rel] = string(b)
			}
		}
		start := time.Now()
		if err := writeLogs(dir, loggerCaseID, strings.NewReader(c.stdout), strings.NewReader(c.stderr), c.lim); err != nil {
			t.Fatal(err)
		}
		for _, f := range logFiles(t, dir, start) {
			r.Files = append(r.Files, file{f.name, f.body})
		}
		out = append(out, r)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	_, _ = zw.Write(b)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(loggerFixtures, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("recorded %d cases into %s (%d bytes)", len(out), loggerFixtures, buf.Len())
}
