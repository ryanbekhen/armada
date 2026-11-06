package server

import (
	"context"
	"testing"

	"github.com/ryanbekhen/armada/internal/store"
)

// A view stays only while the pass's replicas are unchanged: an app scheduled
// after another's change must see that change.
func TestReplicaViewFollowsChanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	revs := &revisionCache{res: map[string]resources{"": {}}}
	rc := &reconcileRun{}
	all := []store.Replica{
		{ID: "a-1", App: "a", NodeID: "n1", Done: true},
		{ID: "a-2", App: "a", NodeID: "n1"},
		{ID: "b-1", App: "b", NodeID: "n2"},
	}
	v := rc.view(ctx, all, revs)
	if rc.view(ctx, all, revs) != v {
		t.Error("worked out again with nothing changed")
	}
	if got := v.use["n1"]; got.total != 2 || got.holding != 1 {
		t.Errorf("use of n1 = %+v, want 2 replicas, 1 holding an address", got)
	}
	if len(v.byApp["a"]) != 2 || v.byApp["a"][0].ID != "a-1" {
		t.Errorf("replicas of a = %+v, want them in order", v.byApp["a"])
	}

	all = without(all, "a-2")
	if v = rc.view(ctx, all, revs); len(v.byApp["a"]) != 1 || v.use["n1"].holding != 0 {
		t.Errorf("after without: %+v", v)
	}
	moved := all[1]
	moved.MovingSince = moved.MovingSince.AddDate(2000, 0, 0)
	all = replace(all, moved)
	if v = rc.view(ctx, all, revs); !v.moving {
		t.Error("after replace: the moving replica is not seen")
	}
	all = append(all, store.Replica{ID: "c-1", App: "c", NodeID: "n3"})
	if v = rc.view(ctx, all, revs); v.use["n3"].total != 1 {
		t.Errorf("after append: %+v", v.use)
	}
	if v = rc.view(ctx, nil, revs); len(v.byApp) != 0 {
		t.Errorf("no replicas: %+v", v)
	}
}
