package store

import (
	"context"
	"errors"
	"testing"
)

const scaled = "name: web\nimage: nginx\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 2\n  max: 6\n  rules:\n    - type: cpu\n      utilization: 60\n"

func TestAutoscaleReplicas(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	r1 := deployJob(t, s, scaled)
	if err := s.CompleteRollout(ctx, "web", r1.Name); err != nil {
		t.Fatal(err)
	}
	replicas := func() int {
		a, err := s.GetApp(ctx, "web")
		if err != nil {
			t.Fatal(err)
		}
		return a.Replicas
	}
	if a, _ := s.GetApp(ctx, "web"); !a.ScaledAt.IsZero() {
		t.Errorf("ScaledAt before any decision: %v", a.ScaledAt)
	}
	if err := s.AutoscaleReplicas(ctx, "web", 2, 5, "armada:autoscaler"); err != nil || replicas() != 5 {
		t.Fatalf("autoscale: %v, %d", err, replicas())
	}
	if a, _ := s.GetApp(ctx, "web"); a.ScaledAt.IsZero() {
		t.Error("ScaledAt not set by the autoscaler")
	}
	// A decision made on stale state, or outside the bounds, is dropped.
	for _, c := range [][2]int{{2, 3}, {5, 7}, {5, 1}} {
		if err := s.AutoscaleReplicas(ctx, "web", c[0], c[1], "armada:autoscaler"); !errors.Is(err, ErrConflict) {
			t.Errorf("AutoscaleReplicas(%d->%d) = %v", c[0], c[1], err)
		}
	}
	// Manual scaling is refused.
	if err := s.SetReplicas(ctx, "web", 3, "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("SetReplicas = %v", err)
	}
	// A redeploy keeps the count within the new bounds.
	deployJob(t, s, "name: web\nimage: nginx:2\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 2\n  max: 4\n  rules:\n    - type: cpu\n      utilization: 60\n")
	if replicas() != 4 {
		t.Errorf("after redeploy with max 4: %d", replicas())
	}
	// No autoscaling during a rollout.
	if err := s.AutoscaleReplicas(ctx, "web", 4, 3, "armada:autoscaler"); !errors.Is(err, ErrConflict) {
		t.Errorf("during rollout: %v", err)
	}
	// Without rules, a deploy sets scale.min again.
	deployJob(t, s, "name: web\nimage: nginx:3\nscale:\n  min: 1\n")
	if replicas() != 1 {
		t.Errorf("after dropping the rules: %d", replicas())
	}
}
