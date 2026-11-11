package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

func TestHeldReplicaPullsWithoutStarting(t *testing.T) {
	t.Parallel()
	a, d := newAgent(t)
	d.Digests = map[string]string{"nginx:2": "nginx@sha256:two"}
	release := make(chan struct{})
	d.SetPullHook(func(ctx context.Context, image string) error {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	})
	held := replica("web-r2-a", "nginx:2", 80)
	held.Hold = true
	a.setDesired([]*armadav1.ReplicaSpec{held}, nil)

	report, err := a.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Replicas) != 1 || report.Replicas[0].State != store.ReplicaPulling {
		t.Fatalf("report while pulling = %v", report)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		report, err = a.Reconcile(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if report.Replicas[0].State == store.ReplicaPulled {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never pulled: %v", report)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r := report.Replicas[0]; r.ImageDigest != "nginx@sha256:two" || r.ContainerId != "" {
		t.Errorf("pulled report = %v", r)
	}
	if cs, _ := d.List(context.Background(), nil); len(cs) != 0 {
		t.Fatalf("a held replica started %d containers", len(cs))
	}

	// Lifting the hold starts it.
	held = replica("web-r2-a", "nginx:2", 80)
	a.setDesired([]*armadav1.ReplicaSpec{held}, nil)
	report, err = a.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Replicas) != 1 || report.Replicas[0].State != store.ReplicaRunning {
		t.Fatalf("report after the hold = %v", report)
	}
	a.mu.Lock()
	left := len(a.holds)
	a.mu.Unlock()
	if left != 0 {
		t.Errorf("%d pulls kept after the hold", left)
	}
}

func TestHeldReplicaReportsAFailedPull(t *testing.T) {
	t.Parallel()
	a, d := newAgent(t)
	d.SetPullHook(func(context.Context, string) error { return errors.New("manifest unknown") })
	held := replica("web-r2-a", "nginx:nope", 80)
	held.Hold = true
	a.setDesired([]*armadav1.ReplicaSpec{held}, nil)
	deadline := time.Now().Add(5 * time.Second)
	for {
		report, err := a.Reconcile(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if r := report.Replicas[0]; r.State == store.ReplicaFailed {
			if r.Message != "manifest unknown" {
				t.Errorf("message = %q", r.Message)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the failed pull was never reported")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cs, _ := d.List(context.Background(), nil); len(cs) != 0 {
		t.Fatalf("%d containers", len(cs))
	}
}
