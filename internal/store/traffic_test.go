package store

import (
	"context"
	"errors"
	"testing"

	"github.com/ryanbekhen/armada/internal/spec"
)

func multiSpec(image, traffic string) string {
	return "name: web\nimage: nginx:" + image + "\ningress:\n  type: internal\n  port: 80\nrevisions:\n  mode: multiple\n  traffic:\n" + traffic
}

func TestTraffic(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	r1 := deployJob(t, s, "name: web\nimage: nginx:1\ningress:\n  type: internal\n  port: 80\n")
	if err := s.CompleteRollout(ctx, "web", r1.Name); err != nil {
		t.Fatal(err)
	}
	app := func() App {
		a, err := s.GetApp(ctx, "web")
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	// Multiple mode: the new revision is current at once, with traffic.
	r2 := deployJob(t, s, multiSpec("2", "    - revision: web--r1\n      weight: 90\n    - revision: latest\n      weight: 10\n      label: canary\n"))
	a := app()
	if a.ActiveRevision != r2.Name || a.TargetRevision != r2.Name || a.Rolling() || len(a.Traffic) != 2 ||
		a.Traffic[1] != (spec.TrafficTarget{Revision: "web--r2", Weight: 10, Label: "canary"}) {
		t.Fatalf("after multiple deploy: %+v", a)
	}
	if r2.Spec.Revisions.Traffic != nil {
		t.Error("the revision stores traffic")
	}

	// Changing only the weights makes no new revision.
	rev, created, err := s.Deploy(ctx, mustParse(t, multiSpec("2", "    - revision: web--r1\n      weight: 50\n    - revision: latest\n      weight: 50\n      label: canary\n")), "admin:test")
	if err != nil || created || rev.Name != r2.Name || app().Traffic[0].Weight != 50 {
		t.Fatalf("weights only: %v %v %v %+v", rev.Name, created, err, app().Traffic)
	}

	// armada app traffic keeps labels; a revision left out stops serving.
	got, err := s.SetTraffic(ctx, "web", []spec.TrafficTarget{{Revision: "web--r2", Weight: 100}}, "admin:test")
	if err != nil || len(got) != 1 || got[0].Label != "canary" {
		t.Fatalf("SetTraffic: %+v %v", got, err)
	}
	for _, bad := range [][]spec.TrafficTarget{
		{{Revision: "web--r2", Weight: 90}},                                    // not 100
		{{Revision: "web--r9", Weight: 100}},                                   // no such revision
		{{Revision: "web--r1", Weight: 0}, {Revision: "web--r2", Weight: 100}}, // weight 0 without a label
		{{Revision: "latest", Weight: 100}},
	} {
		if _, err := s.SetTraffic(ctx, "web", bad, "admin:test"); !errors.Is(err, ErrPrecondition) {
			t.Errorf("SetTraffic(%+v) = %v", bad, err)
		}
	}
	// Weight 0 is fine for a revision that keeps its label.
	if _, err := s.SetTraffic(ctx, "web", []spec.TrafficTarget{{Revision: "web--r1", Weight: 100}, {Revision: "web--r2", Weight: 0}}, "admin:test"); err != nil {
		t.Errorf("labelled weight 0: %v", err)
	}
	if _, err := s.Rollback(ctx, "web", "web--r1", "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("rollback in multiple mode: %v", err)
	}

	// A revision that does not exist is refused.
	if _, _, err := s.Deploy(ctx, mustParse(t, multiSpec("3", "    - revision: web--r7\n      weight: 100\n")), "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("unknown revision: %v", err)
	}

	// Revisions in traffic are never pruned.
	_, _ = s.SetTraffic(ctx, "web", []spec.TrafficTarget{{Revision: "web--r1", Weight: 100}}, "admin:test")
	for i := range RevisionsToKeep + 2 {
		deployJob(t, s, multiSpec(string(rune('a'+i)), "    - revision: web--r1\n      weight: 100\n"))
	}
	if _, err := s.GetRevision(ctx, "web--r1"); err != nil {
		t.Errorf("web--r1 pruned while serving: %v", err)
	}

	// Back to single mode: a rollout, with the old traffic kept until it
	// completes.
	single := deployJob(t, s, "name: web\nimage: nginx:9\ningress:\n  type: internal\n  port: 80\n")
	if a := app(); !a.Rolling() || len(a.Traffic) == 0 {
		t.Fatalf("to single: %+v", a)
	}
	if err := s.CompleteRollout(ctx, "web", single.Name); err != nil {
		t.Fatal(err)
	}
	if a := app(); len(a.Traffic) != 0 {
		t.Errorf("traffic after leaving multiple mode: %+v", a.Traffic)
	}
}

func mustParse(t *testing.T, y string) *spec.App {
	t.Helper()
	sp, err := spec.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return sp
}
