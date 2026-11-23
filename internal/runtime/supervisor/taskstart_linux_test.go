package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A container whose shim is not up yet when asked for its task (a member
// of a pod getting its task: Shims.For holds the group's lock while it
// starts the shim) gets the task from the shim that started meanwhile,
// not "does not answer", through Go and through armada-node alike. The
// slower calls through armada-node made the window wide enough for the
// conformance suite's init containers to meet it.
func TestTaskWhileShimStarts(t *testing.T) {
	natives := []*Native{nil}
	if os.Getenv("ARMADA_NODE_BIN") != "" {
		natives = append(natives, openNative(t))
	}
	for _, n := range natives {
		ctx := context.Background()
		dir := t.TempDir()
		mustWrite(t, filepath.Join(dir, "m1", bundleRecord), `{"id":"m1","image":"x","group":"g","created":"2026-11-23T08:00:00Z"}`)
		s := &Store{Bundles: Bundles{Dir: dir}, Native: n, Shims: &Shims{Dir: filepath.Join(t.TempDir(), "shim"), Native: n}}
		c, err := s.LoadContainer(ctx, "m1")
		if err != nil {
			t.Fatal(err)
		}
		// The group's lock, as Shims.For holds it while it starts a shim.
		unlock, err := s.Shims.lock(ctx, "g")
		if err != nil {
			t.Fatal(err)
		}
		type result struct {
			pid uint32
			err error
		}
		done := make(chan result, 1)
		go func() {
			tk, err := c.Task(ctx, nil)
			if err != nil {
				done <- result{err: err}
				return
			}
			done <- result{pid: tk.Pid()}
		}()
		// Task found no shim and waits in Abandon for the lock.
		for waiting := false; !waiting; {
			s.Shims.mu.Lock()
			waiting = s.Shims.groups["g"] != nil && s.Shims.groups["g"].n == 2
			s.Shims.mu.Unlock()
			time.Sleep(time.Millisecond)
		}
		if err := os.MkdirAll(s.Shims.Dir, 0o700); err != nil {
			t.Fatal(err)
		}
		fakeShim(t, s.Shims.Get("g").Socket, func(req string) string {
			if req == "state m1" {
				return "ok running 42"
			}
			return "ok"
		})
		unlock()
		if r := <-done; r.err != nil || r.pid != 42 {
			t.Errorf("armada-node %v: task pid %d, %v", n != nil, r.pid, r.err)
		}
	}
}
