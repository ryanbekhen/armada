package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/conntrack"
	"github.com/ryanbekhen/armada/internal/proxy"
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
	d.NoStats, d.NoExec = true, true
	a.cfg.UsageInterval = time.Millisecond
	done := make(chan struct{})
	go func() {
		a.usageLoop(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("usage loop runs although the runtime can neither sample containers nor read queues in them")
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

// A container whose interface stays gone is recreated; one sample is not enough.
func TestLostNetworkRestarts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, d := newAgent(t)
	a.setDesired([]*armadav1.ReplicaSpec{{Id: "web-1", App: "web", Image: "nginx:1"}}, nil)
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	before, _ := d.List(ctx, nil)
	if len(before) != 1 {
		t.Fatalf("containers %v", before)
	}
	d.SetUsage("web-1", runtime.Stats{NetworkLost: true})
	_, prev := a.sampleUsage(ctx, d, map[string]usageSample{})
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if after, _ := d.List(ctx, nil); len(after) != 1 || after[0].ID != before[0].ID {
		t.Fatalf("recreated after one sample: %v", after)
	}
	a.sampleUsage(ctx, d, prev)
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if after, _ := d.List(ctx, nil); len(after) != 1 || after[0].ID == before[0].ID {
		t.Errorf("not recreated: %v", after)
	}
}

// A container stopped by the memory limit says so, and a process killed in a
// container that lives on is reported once.
func TestOutOfMemory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, d := newAgent(t)
	a.setDesired([]*armadav1.ReplicaSpec{{Id: "web-1", App: "web", Image: "nginx:1"}}, nil)
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	cs, _ := d.List(ctx, nil)
	if len(cs) != 1 {
		t.Fatalf("containers %v", cs)
	}
	_, prev := a.sampleUsage(ctx, d, map[string]usageSample{})
	d.SetUsage("web-1", runtime.Stats{OOMKills: 2})
	report, prev := a.sampleUsage(ctx, d, prev)
	if len(report.GetReplicas()) != 1 || report.GetReplicas()[0].GetOomKills() != 2 {
		t.Errorf("report = %v", report.GetReplicas())
	}
	report, _ = a.sampleUsage(ctx, d, prev)
	if len(report.GetReplicas()) != 1 || report.GetReplicas()[0].GetOomKills() != 0 {
		t.Errorf("reported again: %v", report.GetReplicas())
	}

	d.SetState(cs[0].ID, runtime.StateExited, 137)
	msg, _ := a.crashed(ctx, &armadav1.ReplicaSpec{Id: "web-1"}, cs[0])
	if !strings.Contains(msg, "out of memory") || !strings.Contains(msg, "137") {
		t.Errorf("message = %q", msg)
	}
	// Exit code 137 alone is any SIGKILL, not proof of running out of memory.
	d.SetUsage("web-1", runtime.Stats{})
	msg, _ = a.crashed(ctx, &armadav1.ReplicaSpec{Id: "web-1"}, cs[0])
	if strings.Contains(msg, "out of memory") || !strings.Contains(msg, "137") {
		t.Errorf("message = %q", msg)
	}
}

type loadMap map[string]proxy.ServerLoad

func (l loadMap) Load(context.Context) (map[string]proxy.ServerLoad, error) { return l, nil }

// The proxy routes to every replica in the cluster: only busy ones are
// sent, and too many busy ones leave the load unmeasured.
func TestSampleLoadSendsBusyReplicas(t *testing.T) {
	t.Parallel()
	a, _ := newAgent(t)
	ctx := context.Background()
	lr := loadMap{"idle": {Total: 5}, "busy": {InFlight: 2, Total: 9}, "served": {Total: 7}}
	prev := map[string]int64{"idle": 5, "busy": 9, "served": 3}
	r := &armadav1.UsageReport{}
	a.sampleLoad(ctx, lr, r, prev)
	got := map[string]*armadav1.ReplicaLoad{}
	for _, l := range r.Load {
		got[l.Id] = l
	}
	if !r.LoadMeasured || len(got) != 2 || got["busy"].InFlight != 2 || got["served"].Requests != 4 {
		t.Errorf("load %v measured=%v", r.Load, r.LoadMeasured)
	}

	many := loadMap{}
	for i := range proxy.MaxLoadEntries + 1 {
		many[fmt.Sprintf("r%d", i)] = proxy.ServerLoad{InFlight: 1}
	}
	r = &armadav1.UsageReport{}
	a.sampleLoad(ctx, many, r, nil)
	if r.LoadMeasured || len(r.Load) != 0 {
		t.Errorf("too many busy replicas: measured=%v entries=%d", r.LoadMeasured, len(r.Load))
	}
}
