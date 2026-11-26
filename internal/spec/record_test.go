package spec

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// The parity tests of nativespec_test.go recorded once from Go (ADR 0055,
// item 20): with -record-fixtures every TestArmadaSpec* test runs its
// cases against this package alone and writes each request it would send
// armada-spec-check, with Go's answer in the program's form, as
// spec/tests/testdata/<test>.jsonl.gz (one JSON line per case, gzipped).
// The crate's test spec/tests/parity.rs sends the same requests to
// armada-spec-check and compares as these tests do, with no Go:
//
//	TZ=UTC ARMADA_SPEC_MUTATIONS=8000 go test ./internal/spec -run TestArmadaSpec -record-fixtures
//
// The fixtures hold the exact inputs (the repository's specs as they were,
// and the mutations of the seeded generators), so a later change to the
// corpus does not change what the replay checks.
var recordFixtures = flag.Bool("record-fixtures", false, "write spec/tests/testdata from Go's answers instead of asking armada-spec-check")

type specRecorder struct {
	t  *testing.T
	f  *os.File
	gz *gzip.Writer
	w  *bufio.Writer
}

func newSpecRecorder(t *testing.T) *specRecorder {
	t.Helper()
	dir := filepath.Join("..", "..", "spec", "tests", "testdata")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, t.Name()+".jsonl.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gz, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	r := &specRecorder{t: t, f: f, gz: gz, w: bufio.NewWriterSize(gz, 1<<20)}
	t.Cleanup(func() {
		if err := r.w.Flush(); err != nil {
			t.Error(err)
		}
		if err := r.gz.Close(); err != nil {
			t.Error(err)
		}
		if err := r.f.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

// write records one request and Go's answer to it.
func (r *specRecorder) write(req, want any) {
	r.t.Helper()
	b, err := json.Marshal(map[string]any{"req": req, "want": want})
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.w.Write(append(b, '\n')); err != nil {
		r.t.Fatal(err)
	}
}
