package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/conntrack"
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
	d.SetUsage("web-1", runtime.Stats{CPU: time.Second + 50*time.Millisecond, MemoryBytes: 42 << 20, EgressBytes: 1500})
	r, prev = a.sampleUsage(ctx, d, prev)
	if len(r.GetReplicas()) != 1 {
		t.Fatalf("second sample: %v", r)
	}
	// 50ms of CPU in a little over 100ms of wall time.
	if u := r.GetReplicas()[0]; u.GetId() != "web-1" || u.GetMemoryBytes() != 42<<20 || u.GetCpuMillis() < 100 || u.GetCpuMillis() > 500 || u.GetEgressBytes() != 1500 {
		t.Errorf("second sample: %v", u)
	}
	// Egress is reported as what was sent since the previous sample.
	time.Sleep(10 * time.Millisecond)
	d.SetUsage("web-1", runtime.Stats{CPU: time.Second + 60*time.Millisecond, MemoryBytes: 42 << 20, EgressBytes: 1600})
	if r, prev = a.sampleUsage(ctx, d, prev); len(r.GetReplicas()) != 1 || r.GetReplicas()[0].GetEgressBytes() != 100 {
		t.Errorf("third sample: %v", r)
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

func TestSampleConntrack(t *testing.T) {
	t.Parallel()
	a, _ := newAgent(t)
	dir := t.TempDir()
	for name, v := range map[string]string{"nf_conntrack_count": "7\n", "nf_conntrack_max": "65536\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a.cfg.Conntrack = conntrack.At(dir, 4<<30)
	report, warned := &armadav1.UsageReport{}, false
	a.sampleConntrack(report, &warned)
	if report.GetConntrackEntries() != 7 || report.GetConntrackMax() != conntrack.Minimum {
		t.Errorf("report %d of %d", report.GetConntrackEntries(), report.GetConntrackMax())
	}

	// A limit that cannot be read warns once and reports nothing.
	if err := os.WriteFile(filepath.Join(dir, "nf_conntrack_max"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report = &armadav1.UsageReport{}
	a.sampleConntrack(report, &warned)
	if !warned || report.GetConntrackMax() != 0 {
		t.Errorf("warned %v, limit %d", warned, report.GetConntrackMax())
	}
}
