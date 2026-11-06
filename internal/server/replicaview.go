package server

import (
	"context"

	"github.com/ryanbekhen/armada/internal/store"
)

// placed is what the replicas on one node add up to.
type placed struct {
	total    int // every replica, finished job attempts too
	holding  int // those holding a container address
	reserved resources
}

// placedUse is the use of each node, by node ID.
type placedUse map[string]placed

func usageOf(replicas []store.Replica, reserved func(store.Replica) resources) placedUse {
	use := placedUse{}
	for _, r := range replicas {
		u := use[r.NodeID]
		u.total++
		if !r.Done {
			u.holding++
		}
		res := reserved(r)
		u.reserved.cpu += res.cpu
		u.reserved.mem += res.mem
		use[r.NodeID] = u
	}
	return use
}

// byApp groups replicas by app, keeping their order.
func byApp(replicas []store.Replica) map[string][]store.Replica {
	out := map[string][]store.Replica{}
	for _, r := range replicas {
		out[r.App] = append(out[r.App], r)
	}
	return out
}

// replicaView is what each app of a pass needs to know about all the replicas
// of the cluster, worked out once so a pass's cost does not grow with apps
// times replicas.
type replicaView struct {
	first  *store.Replica
	n      int
	byApp  map[string][]store.Replica
	use    placedUse
	moving bool // a replica is being moved and is not draining yet
}

// view returns the view of all, the pass's current replicas. It is kept while
// all stays the same slice: replace and without make a new one, and append
// changes its length. A pass only works out a new one after a change.
func (rc *reconcileRun) view(ctx context.Context, all []store.Replica, revs *revisionCache) *replicaView {
	if v := rc.current; v != nil && v.n == len(all) && (v.n == 0 || v.first == &all[0]) {
		return v
	}
	v := &replicaView{n: len(all), byApp: byApp(all), use: usageOf(all, revs.reserved(ctx))}
	if len(all) > 0 {
		v.first = &all[0]
	}
	for _, r := range all {
		if r.Moving() && !r.Draining() {
			v.moving = true
			break
		}
	}
	rc.current = v
	return v
}
