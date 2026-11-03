package agent

import (
	"context"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime"
)

func TestSampleUsage(t *testing.T) {
	t.Parallel()
	a, d := newAgent(t)
	ctx := context.Background()
	app := func(id, replica, state string) runtime.Container {
		return runtime.Container{ID: id, State: state, Labels: map[string]string{runtime.LabelManaged: "true", runtime.LabelReplica: replica}}
	}
	d.Add(app("c1", "web-1", runtime.StateRunning))
	d.Add(app("c2", "web-2", runtime.StateExited))
	sys := app("px", "proxy", runtime.StateRunning)
	sys.Labels[runtime.LabelSystem] = "proxy"
	d.Add(sys)
	d.SetUsage("web-1", runtime.Stats{CPU: time.Second, MemoryBytes: 40 << 20})
	d.SetUsage("proxy", runtime.Stats{CPU: time.Hour, MemoryBytes: 1 << 30})

	// CPU is a rate: the first sample of a container reports nothing.
	r, prev := a.sampleUsage(ctx, d, map[string]usageSample{})
	if len(r.GetReplicas()) != 0 || len(prev) != 1 {
		t.Fatalf("first sample: report %v, kept %v", r, prev)
	}

	time.Sleep(100 * time.Millisecond)
	d.SetUsage("web-1", runtime.Stats{CPU: time.Second + 50*time.Millisecond, MemoryBytes: 42 << 20})
	r, prev = a.sampleUsage(ctx, d, prev)
	if len(r.GetReplicas()) != 1 {
		t.Fatalf("second sample: %v", r)
	}
	// 50ms of CPU in a little over 100ms of wall time.
	if u := r.GetReplicas()[0]; u.GetId() != "web-1" || u.GetMemoryBytes() != 42<<20 || u.GetCpuMillis() < 100 || u.GetCpuMillis() > 500 {
		t.Errorf("second sample: %v", u)
	}

	// A replacement container starts over, as does a counter that went
	// backwards.
	if err := d.Remove(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	d.Add(app("c3", "web-1", runtime.StateRunning))
	if r, _ = a.sampleUsage(ctx, d, prev); len(r.GetReplicas()) != 0 {
		t.Errorf("new container: %v", r)
	}
	if r, _ = a.sampleUsage(ctx, d, map[string]usageSample{"web-1": {container: "c3", cpu: time.Hour, at: time.Now().Add(-time.Second)}}); len(r.GetReplicas()) != 0 {
		t.Errorf("counter went backwards: %v", r)
	}
}

func TestUsageLoopWithoutStats(t *testing.T) {
	t.Parallel()
	a, d := newAgent(t)
	d.NoStats = true
	a.cfg.UsageInterval = time.Millisecond
	done := make(chan struct{})
	go func() {
		a.usageLoop(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("usage loop runs although the runtime cannot sample containers")
	}
}
