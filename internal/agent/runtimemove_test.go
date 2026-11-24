package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
)

// The leader's MoveRuntime (ADR 0054) runs the node's move only with no
// replica assigned (finished job attempts aside) and after the first
// assignment; a refusal or a failure is reported with the node's runtime
// until a later request moves it, and a move that succeeded is never run
// again.
func TestMoveRuntime(t *testing.T) {
	t.Parallel()
	var (
		mu    sync.Mutex
		calls []string
		fail  error
	)
	d := fake.New()
	d.SetRuntimeAgent(runtime.AgentStatus{Agent: runtime.AgentContainerd})
	var plans []*armadav1.RuntimeMovePlan
	a := New(Config{NodeID: "n1", Driver: d, CPUMillis: 1000, MemoryBytes: 1 << 30,
		MoveRuntime: func(_ context.Context, to string) error {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, to)
			return fail
		},
		OnRuntimeMove: func(p *armadav1.RuntimeMovePlan) { plans = append(plans, p) },
	})
	ctx := context.Background()
	ask := func() { a.moveRuntime(ctx, &armadav1.MoveRuntime{To: "supervisor"}) }
	moveErr := func() string { return a.withMoveError(runtimeStatus(d.RuntimeAgent())).GetMoveError() }

	ask()
	if len(calls) != 0 || !strings.Contains(moveErr(), "no assignment") {
		t.Fatalf("before an assignment: calls %v, error %q", calls, moveErr())
	}
	a.setDesired([]*armadav1.ReplicaSpec{
		{Id: "web-r1-a"},
		{Id: "job-j1-b", Job: &armadav1.JobAttempt{Done: true}},
	}, nil)
	ask()
	if len(calls) != 0 || !strings.Contains(moveErr(), "web-r1-a") || strings.Contains(moveErr(), "job-j1-b") {
		t.Fatalf("with a replica: calls %v, error %q", calls, moveErr())
	}

	a.setDesired([]*armadav1.ReplicaSpec{{Id: "job-j1-b", Job: &armadav1.JobAttempt{Done: true}}}, nil)
	fail = errors.New("containerd is gone")
	ask()
	if len(calls) != 1 || moveErr() != "containerd is gone" {
		t.Fatalf("failed move: calls %v, error %q", calls, moveErr())
	}
	fail = nil
	ask()
	if len(calls) != 2 || calls[1] != "supervisor" || moveErr() != "" {
		t.Fatalf("move: calls %v, error %q", calls, moveErr())
	}
	ask()
	if len(calls) != 2 {
		t.Errorf("moved again: %v", calls)
	}

	// A supervisor node's status carries no move error.
	a.moveErr.Store("x")
	if got := a.withMoveError(&armadav1.RuntimeStatus{Agent: runtime.AgentSupervisorRust}); got.GetMoveError() != "" {
		t.Errorf("supervisor status %v", got)
	}

	// The leader's plan reaches OnRuntimeMove when it changes.
	a.setRuntimeMovePlan(&armadav1.RuntimeMovePlan{State: "queued"})
	a.setRuntimeMovePlan(&armadav1.RuntimeMovePlan{State: "queued"})
	a.setRuntimeMovePlan(nil)
	if len(plans) != 2 || plans[0].GetState() != "queued" || plans[1] != nil {
		t.Errorf("plans %v", plans)
	}
}

// PrepareRuntimeMove runs before MoveRuntime, while the node's containers
// still run and outside reconcileMu, and only when the node may move.
func TestMoveRuntimePreparesFirst(t *testing.T) {
	t.Parallel()
	var steps []string
	d := fake.New()
	ctx := context.Background()
	if _, err := d.Run(ctx, runtime.ContainerSpec{Name: "armada-haproxy", Image: "haproxy"}); err != nil {
		t.Fatal(err)
	}
	var a *Agent
	a = New(Config{NodeID: "n1", Driver: d, CPUMillis: 1000, MemoryBytes: 1 << 30,
		PrepareRuntimeMove: func(ctx context.Context, to string) {
			if !a.reconcileMu.TryLock() {
				t.Error("prepared under reconcileMu")
			} else {
				a.reconcileMu.Unlock()
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Error("prepared without a deadline")
			}
			cs, _ := d.List(ctx, nil)
			steps = append(steps, fmt.Sprintf("prepare %s with %d containers", to, len(cs)))
		},
		MoveRuntime: func(ctx context.Context, to string) error {
			cs, _ := d.List(ctx, nil)
			for _, c := range cs {
				_ = d.Remove(ctx, c.ID)
			}
			steps = append(steps, "move "+to)
			return nil
		},
	})
	ask := func() { a.moveRuntime(ctx, &armadav1.MoveRuntime{To: "supervisor"}) }
	a.setDesired([]*armadav1.ReplicaSpec{{Id: "web-r1-a"}}, nil)
	ask()
	if len(steps) != 0 {
		t.Fatalf("prepared a node that cannot move: %v", steps)
	}
	a.setDesired(nil, nil)
	ask()
	if want := []string{"prepare supervisor with 1 containers", "move supervisor"}; !slices.Equal(steps, want) {
		t.Errorf("steps %q, want %q", steps, want)
	}
}

// An agent without MoveRuntime ignores the request and does not offer it.
func TestMoveRuntimeUnsupported(t *testing.T) {
	t.Parallel()
	a := New(Config{NodeID: "n1", Driver: fake.New(), CPUMillis: 1000, MemoryBytes: 1 << 30})
	a.setDesired(nil, nil)
	a.moveRuntime(context.Background(), &armadav1.MoveRuntime{To: "supervisor"})
	if e, _ := a.moveErr.Load().(string); e != "" || a.moving.Load() {
		t.Errorf("error %q, moving %v", e, a.moving.Load())
	}
}
