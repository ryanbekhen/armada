package store

import (
	"bufio"
	"encoding/json"
	"flag"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"go.etcd.io/etcd/client/v3/concurrency"
)

// The parity tests of nativestore_test.go recorded once from Go (ADR 0055,
// item 20): with -record-fixtures the TestArmadaStore* tests that compare
// one store with the other run against Go's store alone and write every
// step as store/tests/testdata/<test>.jsonl: the calls with their
// arguments as armada-store-parity reads them, Go's answer (value, or
// error kind and text), and the keys each call wrote or deleted; the
// clock's moves; the keyspaces written by hand before; the reencode and
// lease checks. store/tests/replay.rs (make store-replay) replays them
// against armada-store-parity on the pinned etcd with no Go. The tests
// that run Go and Rust at once (one keyspace written by both, fencing
// across them, one election) record nothing; replay.rs checks the Rust
// side of each alone.
//
//	go test ./internal/store -run 'TestArmadaStore|TestRecordStoreTexts' -record-fixtures
var recordFixtures = flag.Bool("record-fixtures", false, "write store/tests/testdata from Go's answers instead of comparing with armada-store-parity")

const storeFixtures = "../../store/tests/testdata"

type storeRecorder struct {
	t      *testing.T
	prefix string
	f      *os.File
	w      *bufio.Writer
	keys   map[string]string
}

func newStoreRecorder(t *testing.T, prefix string) *storeRecorder {
	t.Helper()
	if err := os.MkdirAll(storeFixtures, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(storeFixtures, t.Name()+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	r := &storeRecorder{t: t, prefix: prefix, f: f, w: bufio.NewWriter(f), keys: dump(t, prefix)}
	t.Cleanup(func() {
		if err := r.w.Flush(); err != nil {
			t.Error(err)
		}
		if err := r.f.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

// step writes one line. An open carries Go's keyspace right after its
// store opened, which the replay's must equal.
func (r *storeRecorder) step(v map[string]any) {
	r.t.Helper()
	if v["op"] == "open" {
		r.keys = dump(r.t, r.prefix)
		v["keys"] = r.keys
	}
	b, err := json.Marshal(v)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.w.Write(append(b, '\n')); err != nil {
		r.t.Fatal(err)
	}
}

// call records a call, Go's answer, and what it changed in the keyspace.
func (r *storeRecorder) call(method string, args map[string]any, v any, err error) {
	r.t.Helper()
	want := map[string]any{}
	if err != nil {
		want["kind"], want["error"] = errKind(err), err.Error()
	} else {
		b, merr := json.Marshal(v)
		if merr != nil {
			r.t.Fatal(merr)
		}
		want["value"] = json.RawMessage(b)
	}
	now := dump(r.t, r.prefix)
	set := map[string]string{}
	for k, v := range now {
		if old, ok := r.keys[k]; !ok || old != v {
			set[k] = v
		}
	}
	var del []string
	for _, k := range slices.Sorted(maps.Keys(r.keys)) {
		if _, ok := now[k]; !ok {
			del = append(del, k)
		}
	}
	r.keys = now
	r.step(map[string]any{"op": "call", "method": method, "args": args, "want": want, "set": set, "del": del})
}

// TestRecordStoreTexts records the texts of Go's errors that the Rust-only
// checks of replay.rs expect.
func TestRecordStoreTexts(t *testing.T) {
	if !*recordFixtures {
		t.Skip("-record-fixtures is not set")
	}
	b, err := json.MarshalIndent(map[string]string{
		"notLeader": ErrNotLeader.Error(),
		"locked":    concurrency.ErrLocked.Error(),
	}, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(storeFixtures, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storeFixtures, "texts.json"), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
