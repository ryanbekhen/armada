package nodeprog

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// script writes a stand-in for armada-node.
func script(t *testing.T, body string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "armada-node")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin
}

// ownError is a caller's own type for armada-node's failures.
type ownError struct{ err error }

func (e ownError) Error() string { return "own: " + e.err.Error() }

func TestRun(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ok := script(t, `cat >/dev/null; echo '{"n": 7}'`)
	var out struct{ N int }
	if err := New(ok).Call(ctx, map[string]int{"x": 1}, &out); err != nil || out.N != 7 {
		t.Errorf("call: %v %v", out, err)
	}
	answered := script(t, `echo '{"error": "the queue does not exist"}'`)
	if err := New(answered).Call(ctx, nil, nil); err == nil || err.Error() != "the queue does not exist" || errors.As(err, new(Error)) {
		t.Errorf("an answered error: %v", err)
	}
	failed := script(t, `echo 'no such thing' >&2; exit 3`)
	_, err := Run(ctx, failed, RunOptions{}, nil)
	if !errors.As(err, new(Error)) || !strings.Contains(err.Error(), "no such thing") {
		t.Errorf("a failed program: %v", err)
	}
	// A caller's own type for failures.
	_, err = Run(ctx, failed, RunOptions{Fail: func(err error) error { return ownError{err} }}, nil)
	if !errors.As(err, new(ownError)) {
		t.Errorf("own failure type: %v", err)
	}
	if err := Answer([]byte("not json"), nil, func(err error) error { return ownError{err} }); !errors.As(err, new(ownError)) {
		t.Errorf("own failure type of an answer: %v", err)
	}
	// Running out of Limit: a failure, or the plain context error.
	slow := script(t, `exec sleep 5`)
	if _, err := Run(ctx, slow, RunOptions{Limit: 50 * time.Millisecond, LimitFails: true}, nil); !errors.As(err, new(Error)) {
		t.Errorf("limit that fails: %v", err)
	}
	if _, err := Run(ctx, slow, RunOptions{Limit: 50 * time.Millisecond}, nil); !errors.Is(err, context.DeadlineExceeded) || errors.As(err, new(Error)) {
		t.Errorf("limit: %v", err)
	}
	// A cancelled caller gets its own error at once.
	cctx, cancel := context.WithCancel(ctx)
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	if _, err := Run(cctx, slow, RunOptions{}, nil); !errors.Is(err, context.Canceled) || time.Since(start) > 3*time.Second {
		t.Errorf("cancelled: %v after %v", err, time.Since(start))
	}
}

// Each distinct failure is logged once, Go standing in each time; a call
// that works again says so.
func TestTally(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	var tl Tally
	fail := Error{errors.New("exit status 3")}
	for range 3 {
		if !tl.Fallback("nfs source", fail) {
			t.Fatal("a failure was not left to Go")
		}
	}
	if tl.Fallback("nfs source", errors.New("an answer")) {
		t.Error("an answered error was left to Go")
	}
	if n := strings.Count(logs.String(), "armada-node failed; Go did it instead"); n != 1 {
		t.Errorf("logged %d times:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "armada-node works again") {
		t.Errorf("no recovery:\n%s", logs.String())
	}
	tl.StandIn("nfs source")
	tl.Count("exec")
	if tl.StoodIn("nfs source") != 4 || tl.Ran("exec") != 1 {
		t.Errorf("stood in %d, ran %d", tl.StoodIn("nfs source"), tl.Ran("exec"))
	}
	var p *Program
	if p.StoodIn("x") != 0 {
		t.Error("a nil program stood in")
	}
}
