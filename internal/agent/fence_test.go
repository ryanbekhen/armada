package agent

import (
	"context"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/store"
)

func TestFencedReplicaStopsWhileCutOff(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, d := newAgent(t)
	s := replica("web-r1-a", "nginx:1", 80)
	s.FenceAfterSeconds = 60
	a.setDesired([]*armadav1.ReplicaSpec{s}, nil)
	if r, err := a.Reconcile(ctx); err != nil || r.Replicas[0].State != store.ReplicaRunning {
		t.Fatalf("start: %v %v", r, err)
	}
	cs, _ := d.List(ctx, nil)
	if cs[0].Labels[runtime.LabelFenceAfter] != "60" {
		t.Fatalf("labels = %v", cs[0].Labels)
	}
	hash := cs[0].Labels[runtime.LabelSpecHash]
	plain := replica("web-r1-a", "nginx:1", 80)
	if specHash(plain) != hash {
		t.Error("the fence time changes the spec hash")
	}

	// Cut off for longer than the fence time: stopped, and kept stopped.
	a.mu.Lock()
	a.contactLost = time.Now().Add(-2 * time.Minute)
	a.mu.Unlock()
	for range 2 {
		r, err := a.Reconcile(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st := r.Replicas[0]; st.State != store.ReplicaExited || st.Message != fencedMessage {
			t.Fatalf("while cut off: %v", st)
		}
		if cs, _ := d.List(ctx, nil); len(cs) != 1 || cs[0].State == runtime.StateRunning {
			t.Fatalf("containers while cut off: %v", cs)
		}
	}

	// Back in touch: it runs again at once.
	a.setContact(true)
	r, err := a.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st := r.Replicas[0]; st.State != store.ReplicaRunning {
		t.Fatalf("after contact: %v", st)
	}

	// Replicas without a fence time keep running whatever happens.
	a.setDesired([]*armadav1.ReplicaSpec{plain}, nil)
	a.setContact(false)
	a.mu.Lock()
	a.contactLost = time.Now().Add(-time.Hour)
	a.mu.Unlock()
	if r, _ := a.Reconcile(ctx); r.Replicas[0].State != store.ReplicaRunning {
		t.Errorf("unfenced replica: %v", r.Replicas[0])
	}
}

func TestFenceBeforeTheFirstAssignment(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, d := newAgent(t)
	s := replica("web-r1-a", "nginx:1", 80)
	s.FenceAfterSeconds = 60
	a.setDesired([]*armadav1.ReplicaSpec{s}, nil)
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	// The agent restarts while the control plane is out of reach.
	b := New(Config{NodeID: "n1", PrivateIP: "10.0.0.2", Driver: d, CPUMillis: 1, MemoryBytes: 1})
	b.fenceUnassigned(ctx)
	if cs, _ := d.List(ctx, nil); cs[0].State != runtime.StateRunning {
		t.Fatal("stopped before the fence time")
	}
	b.began = time.Now().Add(-2 * time.Minute)
	b.fenceUnassigned(ctx)
	if cs, _ := d.List(ctx, nil); cs[0].State == runtime.StateRunning {
		t.Fatal("still running after the fence time")
	}
}
