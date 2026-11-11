package agent

import (
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// A queue rule's command runs in one ready replica of its app, the lowest by
// ID; what it prints is kept for the usage report, and anything that is not
// a whole number is left out (ADR 0034).
func TestQueueLengths(t *testing.T) {
	t.Parallel()
	a, d := probeAgent(t, newChecker())
	var out atomic.Value
	out.Store("42\n")
	var ran atomic.Value
	d.ExecAppFunc = func(_ context.Context, id string, opts runtime.ExecOptions) (int, error) {
		ran.Store(id)
		_, _ = io.WriteString(opts.Stdout, out.Load().(string))
		return 0, nil
	}
	var specs []*armadav1.ReplicaSpec
	for _, id := range []string{"worker-2", "worker-1"} {
		s := replica(id, "worker", 0)
		s.Queues = []*armadav1.QueueProbe{{Type: "queue", Command: []string{"queue-length", "--token=secret-argument"}}}
		specs = append(specs, s)
	}
	a.setDesired(specs, nil)
	// Both replicas run and pass their checks; the reading comes from the
	// lowest ID.
	read := func() []*armadav1.QueueLength {
		if _, err := a.Reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
		a.measureQueues(context.Background())
		return a.queues.fresh(time.Now(), time.Minute)
	}
	deadline := time.Now().Add(5 * time.Second)
	got := read()
	for (len(got) != 1 || got[0].GetId() != "worker-1") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		got = read()
	}
	if len(got) != 1 || got[0].GetId() != "worker-1" || got[0].GetLength() != 42 {
		t.Fatalf("queues = %v", got)
	}
	cs, _ := d.List(context.Background(), nil)
	for _, c := range cs {
		if c.Labels[runtime.LabelReplica] == "worker-1" && ran.Load() != c.ID {
			t.Errorf("ran in %v, want worker-1's container %s", ran.Load(), c.ID)
		}
	}
	// Output that is not a whole number keeps the last good reading, which
	// ages out of reports.
	for _, bad := range []string{"lots", "-3", strings.Repeat("9", 80), "2000000000000"} {
		out.Store(bad)
		a.measureQueues(context.Background())
		if got := a.queues.fresh(time.Now(), time.Minute); len(got) != 1 || got[0].GetLength() != 42 {
			t.Errorf("after %q: %v", bad, got)
		}
	}
	if got := a.queues.fresh(time.Now().Add(time.Hour), time.Minute); len(got) != 0 {
		t.Errorf("stale readings reported: %v", got)
	}
	// An app that loses its queue rule loses its reading.
	plain := replica("worker-1", "worker", 0)
	a.setDesired([]*armadav1.ReplicaSpec{plain}, nil)
	if _, err := a.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	a.measureQueues(context.Background())
	if got := a.queues.fresh(time.Now(), time.Minute); len(got) != 0 {
		t.Errorf("readings without a rule: %v", got)
	}
}

func TestReadQueueErrors(t *testing.T) {
	t.Parallel()
	a, d := probeAgent(t, newChecker())
	a.setDesired([]*armadav1.ReplicaSpec{replica("worker-1", "worker", 0)}, nil)
	if _, err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	cs, _ := d.List(context.Background(), nil)
	for name, tt := range map[string]struct {
		fn   func(context.Context, string, runtime.ExecOptions) (int, error)
		want string
	}{
		"exit code": {func(context.Context, string, runtime.ExecOptions) (int, error) { return 2, nil }, "exited with code 2"},
		"too much": {func(_ context.Context, _ string, o runtime.ExecOptions) (int, error) {
			_, _ = io.WriteString(o.Stdout, strings.Repeat("1", 100))
			return 0, nil
		}, "more than a number"},
		"not a number": {func(_ context.Context, _ string, o runtime.ExecOptions) (int, error) {
			_, _ = io.WriteString(o.Stdout, "12 items")
			return 0, nil
		}, "whole number"},
	} {
		d.ExecAppFunc = tt.fn
		if _, err := a.readQueue(context.Background(), cs[0].ID, &armadav1.QueueProbe{Type: "queue", Command: []string{"queue-length", "--token=secret-argument"}}); err == nil ||
			!strings.Contains(err.Error(), tt.want) || strings.Contains(err.Error(), "secret-argument") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
