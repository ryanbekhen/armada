package server

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// Rollout parameters. maxSurge = 1 and maxUnavailable = 0: at most one
// replica above the desired count, and never fewer serving replicas than
// desired while the old revision can still serve.
const (
	maxSurge                = 1
	defaultDrainTimeout     = 10 * time.Second
	defaultWarmup           = 3 * time.Second
	defaultProgressDeadline = 3 * time.Minute
)

// rebalanceBackoff is how long an app is left alone after a move whose
// replacement never served.
const rebalanceBackoff = 10 * time.Minute

// failedMoveAfter is how long a replica keeps failing to start on its node
// before it is tried on another one.
const failedMoveAfter = time.Minute

// DefaultNodeLostTimeout is how long a node may be disconnected before its
// replicas are rescheduled elsewhere.
const DefaultNodeLostTimeout = 5 * time.Minute

// Reconcile brings scheduled replicas in line with each app's desired state
// and pushes per-node assignments to connected agents.
func (s *Server) Reconcile(ctx context.Context) error {
	apps, err := s.store.ListApps(ctx)
	if err != nil {
		return err
	}
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return err
	}
	replicas, err := s.store.ListReplicas(ctx, store.ReplicaFilter{})
	if err != nil {
		return err
	}
	s.usage.setOwners(replicas, s.now())
	revs := revisionCache{store: s.store, keys: s.keys, m: map[string]store.Revision{}}
	revs.preload(ctx, apps, replicas)
	// Scheduling sees only the capacity left after what Armada keeps.
	nodes, err = s.allocatable(ctx, nodes)
	if err != nil {
		return err
	}

	rc := reconcileRun{now: s.now(), revs: &revs}
	rc.lost = s.lostNodes(ctx, &rc, nodes)
	var jobs []store.App
	removed := map[string]bool{}
	for i, app := range apps {
		if app.Spec.IsJob() {
			jobs = append(jobs, app)
			continue
		}
		if app.Removing {
			if replicas, removed[app.Name], err = s.reconcileRemoval(ctx, &rc, app, replicas); err != nil {
				return fmt.Errorf("app %s: %w", app.Name, err)
			}
			continue
		}
		replicas, err = s.reconcileApp(ctx, &rc, &apps[i], nodes, replicas, &revs)
		if err != nil {
			return fmt.Errorf("app %s: %w", app.Name, err)
		}
	}
	if replicas, err = s.reconcileJobs(ctx, &rc, jobs, nodes, replicas, &revs); err != nil {
		return err
	}
	if rc.wake > 0 {
		s.wakeAfter(rc.wake)
	}
	apps = slices.DeleteFunc(apps, func(a store.App) bool { return removed[a.Name] })
	pxp, err := s.proxyConfig(ctx, apps, replicas)
	if err != nil {
		return err
	}
	eps, err := s.endpoints(ctx)
	if err != nil {
		return err
	}
	network, err := s.buildNetwork(ctx, nodes, replicas)
	if err != nil {
		return err
	}
	return s.pushAssignments(ctx, replicas, &revs, pxp, eps, network)
}

// proxyConfig builds the pass's proxy configuration. When it cannot, the
// nodes keep the last one that could while their replicas still start,
// move, and stop: a bad route must not freeze every node.
func (s *Server) proxyConfig(ctx context.Context, apps []store.App, replicas []store.Replica) (*armadav1.ProxyConfig, error) {
	px, err := s.buildProxy(ctx, apps, replicas)
	s.condition(ctx, "proxy-invalid", err != nil, store.Event{Kind: eventNode, Object: "*", Reason: "ProxyNotUpdated",
		Message: fmt.Sprintf("the proxy configuration was not updated: %v", err)})
	if err == nil {
		s.lastProxy = px.ToProto()
		return s.lastProxy, nil
	}
	s.log.Error("proxy configuration not updated", "err", err)
	if s.lastProxy == nil {
		return nil, err
	}
	return s.lastProxy, nil
}

// reconcileRun is the state of one Reconcile pass.
type reconcileRun struct {
	now time.Time
	// wake is the earliest time something becomes due (a drain ends, a
	// replica finishes warming up), relative to now.
	wake time.Duration
	// lost holds the nodes whose replicas are being rescheduled.
	lost map[string]bool
	revs *revisionCache
	// current is the latest view of the pass's replicas.
	current *replicaView
}

// lostNodes returns the nodes that have been disconnected for longer than
// the lost timeout. If more nodes are lost than ready, the control plane is
// more likely cut off from the cluster than the nodes dead, so nothing is
// rescheduled: emptying healthy nodes would cause the outage it guards
// against.
func (s *Server) lostNodes(ctx context.Context, rc *reconcileRun, nodes []store.Node) map[string]bool {
	lost := map[string]bool{}
	ready := 0
	for _, n := range nodes {
		switch {
		case n.State == store.NodeReady:
			ready++
		case nodeLost(n, rc.now, s.nodeLostTimeout):
			lost[n.ID] = true
		case !n.LastSeen.IsZero():
			rc.wakeAt(n.LastSeen.Add(s.nodeLostTimeout))
		}
	}
	cutOff := len(lost) > ready
	s.condition(ctx, "cut-off", cutOff, store.Event{Kind: eventNode, Object: "*", Reason: "MostUnreachable",
		Message: fmt.Sprintf("%d nodes lost and %d ready: not moving their replicas (is the control plane cut off?)", len(lost), ready)})
	if cutOff {
		s.log.Warn("most nodes are unreachable; not rescheduling their replicas (is the control plane cut off?)", "lost", len(lost), "ready", ready)
		return map[string]bool{}
	}
	for _, n := range nodes {
		s.condition(ctx, "lost:"+n.ID, lost[n.ID], store.Event{Kind: eventNode, Object: n.ID, Node: n.ID, Reason: "Lost",
			Message: fmt.Sprintf("no contact for %s; moving its replicas", s.nodeLostTimeout)})
	}
	return lost
}

// nodeStateLost is shown for nodes whose replicas are being rescheduled.
const nodeStateLost = "lost"

// nodeLost reports whether n has been disconnected for at least timeout.
// A node that never connected is not lost: it has no replicas yet.
func nodeLost(n store.Node, now time.Time, timeout time.Duration) bool {
	return n.State != store.NodeReady && !n.LastSeen.IsZero() && now.Sub(n.LastSeen) >= timeout
}

func (rc *reconcileRun) wakeAt(t time.Time) {
	d := t.Sub(rc.now)
	if d <= 0 {
		d = time.Millisecond
	}
	if rc.wake == 0 || d < rc.wake {
		rc.wake = d
	}
}

// wakeAfter schedules a reconcile after d unless one is already due sooner.
func (s *Server) wakeAfter(d time.Duration) {
	s.wakeMu.Lock()
	defer s.wakeMu.Unlock()
	at := time.Now().Add(d)
	if s.wakeTimer != nil && !s.wakeAt.IsZero() && s.wakeAt.Before(at) && s.wakeAt.After(time.Now()) {
		return
	}
	if s.wakeTimer != nil {
		s.wakeTimer.Stop()
	}
	s.wakeAt = at
	s.wakeTimer = time.AfterFunc(d, s.Trigger)
}

// serving reports whether r takes traffic and has done so long enough for
// every proxy to have picked it up and health-checked it.
// A replica of an app that publishes a port also needs an address to serve.
func (s *Server) serving(rc *reconcileRun, r store.Replica, publishes bool) bool {
	if r.State != store.ReplicaRunning || !r.Ready || r.Draining() || (publishes && r.Address == "") {
		return false
	}
	if due := r.ReadySince.Add(s.warmup); due.After(rc.now) {
		rc.wakeAt(due)
		return false
	}
	return true
}

// working reports whether r runs and is ready (and, for an app that
// publishes a port, has an address), warmed up or not.
func working(r store.Replica, publishes bool) bool {
	return r.State == store.ReplicaRunning && r.Ready && !r.Draining() && (!publishes || r.Address != "")
}

// inProxy reports whether r should receive traffic.
func inProxy(app store.App, r store.Replica) bool {
	return r.App == app.Name && (r.Revision == app.ActiveRevision || r.Revision == app.TargetRevision || trafficWeight(app, r.Revision) > 0) &&
		r.State == store.ReplicaRunning && r.Ready && !r.Draining() && r.Address != ""
}

// trafficWeight is rev's weight in app's traffic, or -1 if it has none
// (ADR 0022).
func trafficWeight(app store.App, rev string) int {
	for _, t := range app.Traffic {
		if t.Revision == rev {
			return t.Weight
		}
	}
	return -1
}

// trafficShares splits total replicas between traffic targets by weight:
// at least one each, so a revision reached only through its label runs
// too.
func trafficShares(total int, traffic []spec.TrafficTarget) []int {
	out := make([]int, len(traffic))
	for i, t := range traffic {
		out[i] = max(1, (total*t.Weight+50)/100)
	}
	return out
}

// publishesPort reports whether replicas of sp publish a port.
func publishesPort(sp *spec.App) bool {
	return sp.Ingress != nil && sp.Ingress.Type != spec.IngressNone
}

func (s *Server) reconcileApp(ctx context.Context, rc *reconcileRun, app *store.App, nodes []store.Node, all []store.Replica, revs *revisionCache) ([]store.Replica, error) {
	target, err := revs.get(ctx, app.TargetRevision)
	if err != nil {
		return nil, err
	}
	if target.Spec.HasVolumes() {
		return s.reconcileVolumeApp(ctx, rc, app, target, nodes, all, revs)
	}
	if len(app.Traffic) == 0 || app.Rolling() {
		return s.reconcileRevision(ctx, rc, app, nodes, all, revs, nil)
	}
	// Traffic splitting (ADR 0022): each revision in the traffic is
	// reconciled like an app of its own with its share of the replicas,
	// leaving the replicas of the others alone.
	shares := trafficShares(app.Replicas, app.Traffic)
	for i, t := range app.Traffic {
		others := map[string]bool{}
		for _, o := range app.Traffic {
			others[o.Revision] = o.Revision != t.Revision
		}
		sub := *app
		sub.ActiveRevision, sub.TargetRevision, sub.Replicas, sub.Traffic = t.Revision, t.Revision, shares[i], nil
		if all, err = s.reconcileRevision(ctx, rc, &sub, nodes, all, revs, others); err != nil {
			return nil, err
		}
	}
	return all, nil
}

// reconcileRevision converges app's replicas toward its target revision,
// leaving those of the revisions in others alone.
func (s *Server) reconcileRevision(ctx context.Context, rc *reconcileRun, app *store.App, nodes []store.Node, all []store.Replica, revs *revisionCache, others map[string]bool) ([]store.Replica, error) {
	publishes := map[string]bool{}
	publishesRev := func(r store.Replica) bool {
		p, ok := publishes[r.Revision]
		if !ok {
			rev, err := revs.get(ctx, r.Revision)
			p = err != nil || publishesPort(rev.Spec) // unknown: require an address
			publishes[r.Revision] = p
		}
		return p
	}
	serving := func(r store.Replica) bool { return s.serving(rc, r, publishesRev(r)) }
	// working: r runs and is ready, warmed up or not; for apps that
	// publish a port, it is also in the proxies.
	working := func(r store.Replica) bool { return working(r, publishesRev(r)) }
	var err error
	var current, old []store.Replica
	for _, r := range rc.view(ctx, all, revs).byApp[app.Name] {
		if others[r.Revision] {
			continue
		}
		switch {
		case r.Draining():
			if all, err = s.finishDrain(ctx, rc, all, r); err != nil {
				return nil, err
			}
		case r.Revision == app.TargetRevision:
			current = append(current, r)
		case app.Rolling() && (r.Revision == app.ActiveRevision || trafficWeight(*app, r.Revision) >= 0):
			// Leaving multiple revision mode: every revision in the
			// traffic serves until the new one does.
			old = append(old, r)
		default:
			// Leftovers of an aborted or superseded rollout.
			if all, err = s.retire(ctx, rc, all, r); err != nil {
				return nil, err
			}
		}
	}

	// Replicas on cordoned nodes, and on nodes the app's placement no
	// longer allows (ADR 0014), are replaced elsewhere, then retired.
	target, err := revs.get(ctx, app.TargetRevision)
	if err != nil {
		return nil, err
	}
	fit := eligible(nodes, target)
	cordoned := map[string]bool{}
	for _, n := range nodes {
		if n.Cordoned || (n.State == store.NodeReady && !placementAllows(n, target)) {
			cordoned[n.ID] = true
		}
	}
	// Replicas on lost nodes are replaced right away (they count toward
	// neither the desired count nor the surge) and retired once the
	// replacements serve; until then they stay, in case the node is only
	// cut off from the control plane and still serves. Replicas being moved
	// to spread the app are handled like those on cordoned nodes.
	var moving, lost []store.Replica
	current = slices.DeleteFunc(current, func(r store.Replica) bool {
		switch {
		case rc.lost[r.NodeID]:
			lost = append(lost, r)
			return true
		case cordoned[r.NodeID] || r.Moving():
			moving = append(moving, r)
			return true
		}
		return false
	})
	if current, moving, all, err = s.abortStuckMoves(ctx, rc, app, all, current, moving, cordoned, serving, revs); err != nil {
		return nil, err
	}

	if app.Rolling() {
		target, err := revs.get(ctx, app.TargetRevision)
		if err != nil {
			return nil, err
		}
		aborted, err := s.checkRollout(ctx, rc, app, target, current, serving)
		if err != nil || aborted {
			if err == nil {
				// Aborted: everything of the target goes, the old replicas
				// stay and become current again.
				for _, r := range current {
					if all, err = s.retire(ctx, rc, all, r); err != nil {
						return nil, err
					}
				}
			}
			return all, err
		}
	}

	if !app.Rolling() {
		if current, all, err = s.moveFailed(ctx, rc, app, target, fit, all, current, revs); err != nil {
			return nil, err
		}
	}

	// Scale down: drop unhealthy replicas first, then from the most loaded node.
	for len(current) > app.Replicas {
		victim := pickVictim(current, spreadGroups(fit, target.Spec.Placement.SpreadKey()))
		if all, err = s.retire(ctx, rc, all, victim); err != nil {
			return nil, err
		}
		current = without(current, victim.ID)
	}

	// Scale up, with one replica of surge while old replicas still run.
	unplaced := false
	if len(current) < app.Replicas {
		for len(current) < app.Replicas && len(current)+len(old)+len(moving) < app.Replicas+maxSurge {
			node, ok := pickNode(fit, all, current, target.Spec.Placement.SpreadKey(), reservation(target), revs.reserved(ctx))
			if !ok {
				s.log.Warn("no node can fit replica", "app", app.Name, "want", app.Replicas, "have", len(current))
				unplaced = true
				break
			}
			r, err := s.placeReplica(ctx, app, target, node.ID)
			if err != nil {
				return nil, err
			}
			current = append(current, r)
			all = append(all, r)
		}
	}
	unplacedKey := "unplaced:" + app.Name
	if others != nil {
		unplacedKey += "/" + target.Name
	}
	s.condition(ctx, unplacedKey, unplaced, store.Event{Kind: eventApp, Object: app.Name, App: app.Name, Reason: "Unschedulable",
		Message: fmt.Sprintf("no node can fit another replica (%d of %d placed); see armada status", len(current), app.Replicas)})
	if all, err = s.evacuate(ctx, rc, app, all, current, old, append(lost, moving...), serving, working); err != nil {
		return nil, err
	}
	if !app.Rolling() {
		if len(lost) == 0 && len(moving) == 0 {
			return s.rebalance(ctx, rc, app, fit, all, current, serving, revs)
		}
		return all, nil
	}

	// Retire old replicas while enough others serve. Unhealthy ones go
	// first because they serve nothing anyway.
	newServing := 0
	for _, r := range current {
		if serving(r) {
			newServing++
		}
	}
	oldServing := 0
	for _, r := range old {
		if serving(r) {
			oldServing++
		}
	}
	slices.SortStableFunc(old, func(a, b store.Replica) int {
		if sa, sb := serving(a), serving(b); sa != sb {
			if sa {
				return 1
			}
			return -1
		}
		return cmp.Compare(a.ID, b.ID)
	})
	for _, r := range old {
		lose := 0
		if serving(r) {
			lose = 1
		}
		if oldServing-lose+newServing < app.Replicas {
			break
		}
		if all, err = s.retire(ctx, rc, all, r); err != nil {
			return nil, err
		}
		old = without(old, r.ID)
		oldServing -= lose
	}

	if len(old) == 0 && newServing >= app.Replicas && len(current) == app.Replicas {
		if err := s.store.CompleteRollout(ctx, app.Name, app.TargetRevision); err != nil {
			return nil, err
		}
		s.log.Info("rollout complete", "app", app.Name, "revision", app.TargetRevision)
		s.record(ctx, store.Event{Kind: eventRollout, Object: app.TargetRevision, App: app.Name, Reason: "Completed", Message: app.TargetRevision + " serves"})
		app.ActiveRevision = app.TargetRevision
		app.RolloutState = store.RolloutNone
		app.Spec = mustRevision(ctx, revs, app.TargetRevision, app.Spec)
		s.forgetProgress(app.Name)
	}
	return all, nil
}

// rebalance starts moving one replica of a stable app whose replicas are
// spread unevenly, for example after a node came back or joined: the node
// holding the most of them has at least two more than the node a new
// replica would go to. Only one replica moves in the whole cluster at a
// time; the move itself goes through the cordon path (a replacement is
// scheduled, the moving replica is retired once it serves).
func (s *Server) rebalance(ctx context.Context, rc *reconcileRun, app *store.App, nodes []store.Node, all, current []store.Replica, serving func(store.Replica) bool, revs *revisionCache) ([]store.Replica, error) {
	if len(current) != app.Replicas || len(rc.lost) > 0 {
		return all, nil
	}
	for _, r := range current {
		if !serving(r) {
			return all, nil
		}
	}
	view := rc.view(ctx, all, revs)
	if view.moving {
		return all, nil
	}
	s.rebalanceMu.Lock()
	after := s.rebalanceAfter[app.Name]
	s.rebalanceMu.Unlock()
	if rc.now.Before(after) {
		return all, nil
	}
	target, err := revs.get(ctx, app.TargetRevision)
	if err != nil {
		return nil, err
	}
	victim, to, ok := rebalanceVictim(nodes, view.use, current, target.Spec.Placement.SpreadKey(), reservation(target))
	if !ok {
		return all, nil
	}
	if err := s.store.SetReplicaMoving(ctx, victim.ID, true); err != nil {
		return nil, err
	}
	s.log.Info("moving replica to spread app", "replica", victim.ID, "from", victim.NodeID, "to", to)
	s.record(ctx, store.Event{Kind: eventReplica, Object: victim.ID, App: victim.App, Node: victim.NodeID, Reason: "Rebalancing", Message: "moving from " + victim.NodeID + " to " + to})
	victim.MovingSince = rc.now
	rc.wakeAt(rc.now)
	return replace(all, victim), nil
}

// rebalanceVictim picks a replica to move and the node to move it to. With
// spreadBy, values come first: a replica moves from the value with the
// most current replicas when it has at least two more than the value of
// the node pickNode would choose; otherwise each value is balanced over its
// own nodes, so the two never undo each other's moves. Without spreadBy,
// see nodeVictim.
func rebalanceVictim(nodes []store.Node, use placedUse, current []store.Replica, spreadBy string, want resources) (store.Replica, string, bool) {
	if spreadBy == "" {
		return nodeVictim(nodes, use, current, want)
	}
	groupOf := spreadGroups(nodes, spreadBy)
	perGroup := map[string]int{}
	var placed []store.Replica
	for _, r := range current {
		if g, ok := groupOf[r.NodeID]; ok {
			perGroup[g]++
			placed = append(placed, r)
		}
	}
	if to, ok := pickNodeBy(nodes, use, current, spreadBy, want); ok && len(placed) > 0 {
		from := groupOf[slices.MaxFunc(placed, func(a, b store.Replica) int {
			ga, gb := groupOf[a.NodeID], groupOf[b.NodeID]
			if c := cmp.Compare(perGroup[ga], perGroup[gb]); c != 0 {
				return c
			}
			return cmp.Compare(gb, ga)
		}).NodeID]
		if perGroup[from]-perGroup[groupOf[to.ID]] >= 2 {
			var in []store.Replica
			for _, r := range placed {
				if groupOf[r.NodeID] == from {
					in = append(in, r)
				}
			}
			return mostLoaded(in), to.ID, true
		}
	}
	groups := map[string][]store.Node{}
	for _, n := range nodes {
		if g, ok := groupOf[n.ID]; ok {
			groups[g] = append(groups[g], n)
		}
	}
	for _, g := range slices.Sorted(maps.Keys(groups)) {
		var in []store.Replica
		for _, r := range placed {
			if groupOf[r.NodeID] == g {
				in = append(in, r)
			}
		}
		if v, to, ok := nodeVictim(groups[g], use, in, want); ok {
			return v, to, true
		}
	}
	return store.Replica{}, "", false
}

// nodeVictim picks a replica to move: one on the node with the most
// current replicas, if that node has at least two more than the node
// pickNode would choose for a new one. It also returns that node.
func nodeVictim(nodes []store.Node, use placedUse, current []store.Replica, want resources) (store.Replica, string, bool) {
	if len(current) == 0 {
		return store.Replica{}, "", false
	}
	to, ok := pickNodeBy(nodes, use, current, "", want)
	if !ok {
		return store.Replica{}, "", false
	}
	perNode := map[string]int{}
	for _, r := range current {
		perNode[r.NodeID]++
	}
	victim := mostLoaded(current)
	if perNode[victim.NodeID]-perNode[to.ID] < 2 {
		return store.Replica{}, "", false
	}
	return victim, to.ID, true
}

// mostLoaded returns the replica of rs on the node with the most of them
// (the highest ID among those, for a stable choice). rs is not empty.
func mostLoaded(rs []store.Replica) store.Replica {
	perNode := map[string]int{}
	for _, r := range rs {
		perNode[r.NodeID]++
	}
	return slices.MaxFunc(rs, func(a, b store.Replica) int {
		if c := cmp.Compare(perNode[a.NodeID], perNode[b.NodeID]); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
}

// spreadGroups maps the nodes that have label key to its value; nil when
// key is empty.
func spreadGroups(nodes []store.Node, key string) map[string]string {
	if key == "" {
		return nil
	}
	out := map[string]string{}
	for _, n := range nodes {
		if v, ok := n.AllLabels()[key]; ok {
			out[n.ID] = v
		}
	}
	return out
}

// abortStuckMoves gives up moves whose replacement has not served within
// the progress deadline: the moving replica stays where it is, the
// replacements that do not serve are retired, and the app is left alone
// for rebalanceBackoff. Moves off cordoned nodes are not affected.
func (s *Server) abortStuckMoves(ctx context.Context, rc *reconcileRun, app *store.App, all, current, moving []store.Replica, cordoned map[string]bool, serving func(store.Replica) bool, revs *revisionCache) ([]store.Replica, []store.Replica, []store.Replica, error) {
	var stuck []store.Replica
	for _, r := range moving {
		if !r.Moving() || cordoned[r.NodeID] {
			continue
		}
		rev, err := revs.get(ctx, r.Revision)
		if err != nil {
			return nil, nil, nil, err
		}
		deadline := r.MovingSince.Add(s.progressDeadline + probeBudget(rev.Spec))
		if rc.now.Before(deadline) {
			rc.wakeAt(deadline)
			continue
		}
		stuck = append(stuck, r)
	}
	if len(stuck) == 0 {
		return current, moving, all, nil
	}
	var err error
	for _, r := range stuck {
		if err := s.store.SetReplicaMoving(ctx, r.ID, false); err != nil {
			return nil, nil, nil, err
		}
		s.log.Warn("replacement of moving replica never served; keeping it", "replica", r.ID, "node", r.NodeID)
		r.MovingSince = time.Time{}
		all = replace(all, r)
		moving = without(moving, r.ID)
		current = append(current, r)
	}
	s.rebalanceMu.Lock()
	s.rebalanceAfter[app.Name] = rc.now.Add(rebalanceBackoff)
	s.rebalanceMu.Unlock()
	// Back to the desired count by retiring what does not serve; that is
	// the replacement, as an app is only rebalanced while all serve.
	for _, r := range slices.Clone(current) {
		if len(current) <= app.Replicas {
			break
		}
		if serving(r) {
			continue
		}
		if all, err = s.retire(ctx, rc, all, r); err != nil {
			return nil, nil, nil, err
		}
		current = without(current, r.ID)
	}
	return current, moving, all, nil
}

// evacuate retires replicas on cordoned or lost nodes while enough other
// replicas serve, unhealthy ones first.
func (s *Server) evacuate(ctx context.Context, rc *reconcileRun, app *store.App, all, current, old, moving []store.Replica, serving, working func(store.Replica) bool) ([]store.Replica, error) {
	if len(moving) == 0 {
		return all, nil
	}
	count := func(rs []store.Replica) int {
		n := 0
		for _, r := range rs {
			if serving(r) {
				n++
			}
		}
		return n
	}
	others := count(current) + count(old)
	left := count(moving)
	slices.SortStableFunc(moving, func(a, b store.Replica) int {
		if sa, sb := serving(a), serving(b); sa != sb {
			if sa {
				return 1
			}
			return -1
		}
		return cmp.Compare(a.ID, b.ID)
	})
	var err error
	for _, r := range moving {
		lose := 0
		if serving(r) {
			lose = 1
		}
		// A replica that does no work (one that failed to start, say)
		// goes at once: nothing depends on it, and keeping it would hold
		// the surge its replacement needs. One that works stays until
		// enough others serve, whether or not its app takes traffic.
		if working(r) && others+left-lose < app.Replicas {
			continue
		}
		reason := "cordoned"
		switch {
		case rc.lost[r.NodeID]:
			reason = "lost"
		case r.Moving():
			reason = "moving"
		}
		s.log.Info("evacuating replica", "replica", r.ID, "node", r.NodeID, "node_state", reason)
		s.record(ctx, store.Event{Kind: eventReplica, Object: r.ID, App: r.App, Node: r.NodeID, Reason: "Evacuating", Message: "node " + r.NodeID + " is " + reason})
		if all, err = s.retire(ctx, rc, all, r); err != nil {
			return nil, err
		}
		left -= lose
	}
	return all, nil
}

// checkRollout records progress of a rollout and aborts it once no new
// replica has become serving within the progress deadline. It reports
// whether the rollout was aborted.
func (s *Server) checkRollout(ctx context.Context, rc *reconcileRun, app *store.App, target store.Revision, current []store.Replica, isServing func(store.Replica) bool) (bool, error) {
	serving := 0
	for _, r := range current {
		if isServing(r) {
			serving++
		}
	}
	s.progressMu.Lock()
	prev, seen := s.progress[app.Name]
	if !seen || prev.revision != target.Name || serving > prev.serving {
		s.progress[app.Name] = rolloutProgress{revision: target.Name, serving: serving}
	}
	s.progressMu.Unlock()
	if seen && prev.revision == target.Name && serving > prev.serving {
		if err := s.store.MarkRolloutProgress(ctx, app.Name); err != nil {
			return false, err
		}
		app.RolloutProgressAt = rc.now
	}

	deadline := s.progressDeadline + probeBudget(target.Spec)
	due := app.RolloutProgressAt.Add(deadline)
	if rc.now.Before(due) {
		rc.wakeAt(due)
		return false, nil
	}
	msg := fmt.Sprintf("no progress within %s", deadline)
	for _, r := range current {
		if r.Message != "" && !isServing(r) {
			msg += fmt.Sprintf("; %s: %s", r.ID, r.Message)
			break
		}
	}
	if err := s.store.FailRollout(ctx, app.Name, target.Name, msg); err != nil {
		return false, err
	}
	s.log.Warn("rollout failed, keeping the active revision", "app", app.Name, "revision", target.Name, "active", app.ActiveRevision, "reason", msg)
	s.record(ctx, store.Event{Kind: eventRollout, Object: target.Name, App: app.Name, Reason: "Failed", Message: msg + "; " + app.ActiveRevision + " keeps serving"})
	app.TargetRevision = app.ActiveRevision
	app.RolloutState = store.RolloutFailed
	app.RolloutMessage = msg
	s.forgetProgress(app.Name)
	return true, nil
}

// probeBudget is how long a healthy replica may need to pass its startup
// and readiness probes, added to the progress deadline.
func probeBudget(sp *spec.App) time.Duration {
	if sp.Probes == nil {
		return 0
	}
	var d time.Duration
	for _, p := range []*spec.Probe{sp.Probes.Startup, sp.Probes.Readiness} {
		if p != nil {
			d += p.InitialDelay.D() + time.Duration(p.FailureThreshold)*p.Period.D()
		}
	}
	return d
}

type rolloutProgress struct {
	revision string
	serving  int
}

func (s *Server) forgetProgress(app string) {
	s.progressMu.Lock()
	delete(s.progress, app)
	s.progressMu.Unlock()
}

func mustRevision(ctx context.Context, revs *revisionCache, name string, fallback *spec.App) *spec.App {
	r, err := revs.get(ctx, name)
	if err != nil {
		return fallback
	}
	return r.Spec
}

// retire takes r out of service. A replica that may be receiving traffic is
// drained first: it leaves every proxy now and is stopped after the drain
// timeout, so in-flight requests can finish. Others are removed at once.
func (s *Server) retire(ctx context.Context, rc *reconcileRun, all []store.Replica, r store.Replica) ([]store.Replica, error) {
	if !r.Ready || r.Address == "" || r.State != store.ReplicaRunning {
		return without(all, r.ID), s.deleteReplica(ctx, r)
	}
	if err := s.store.DrainReplica(ctx, r.ID); err != nil {
		return nil, err
	}
	s.log.Info("draining replica", "replica", r.ID, "node", r.NodeID)
	r.DrainingSince = rc.now
	rc.wakeAt(rc.now.Add(s.drainFor(ctx, rc, r)))
	return replace(all, r), nil
}

// finishDrain removes a draining replica once its drain timeout has passed.
func (s *Server) finishDrain(ctx context.Context, rc *reconcileRun, all []store.Replica, r store.Replica) ([]store.Replica, error) {
	due := r.DrainingSince.Add(s.drainFor(ctx, rc, r))
	if rc.now.Before(due) {
		rc.wakeAt(due)
		return all, nil
	}
	return without(all, r.ID), s.deleteReplica(ctx, r)
}

// drainFor returns how long r drains: its revision's setting, else the default.
func (s *Server) drainFor(ctx context.Context, rc *reconcileRun, r store.Replica) time.Duration {
	if rc.revs != nil {
		if rev, err := rc.revs.get(ctx, r.Revision); err == nil && rev.Spec.Drain != 0 {
			return rev.Spec.Drain.D()
		}
	}
	return s.drainTimeout
}

func (s *Server) deleteReplica(ctx context.Context, r store.Replica) error {
	s.log.Info("removing replica", "replica", r.ID, "node", r.NodeID)
	if err := s.store.DeleteReplica(ctx, r.ID); err != nil {
		return err
	}
	s.record(ctx, store.Event{Kind: eventReplica, Object: r.ID, App: r.App, Node: r.NodeID, Reason: "Removed"})
	return nil
}

func replace(rs []store.Replica, r store.Replica) []store.Replica {
	out := slices.Clone(rs)
	for i := range out {
		if out[i].ID == r.ID {
			out[i] = r
		}
	}
	return out
}

func without(rs []store.Replica, id string) []store.Replica {
	return slices.DeleteFunc(slices.Clone(rs), func(r store.Replica) bool { return r.ID == id })
}

// pickVictim chooses the replica to remove when scaling down: one that is
// not running first, then one on nodes whose spreadBy value (groupOf, nil
// without spreadBy) has the most, then one on the node with the most.
func pickVictim(rs []store.Replica, groupOf map[string]string) store.Replica {
	perNode, perGroup := map[string]int{}, map[string]int{}
	for _, r := range rs {
		perNode[r.NodeID]++
		if g, ok := groupOf[r.NodeID]; ok {
			perGroup[g]++
		}
	}
	inGroup := func(r store.Replica) int {
		if g, ok := groupOf[r.NodeID]; ok {
			return perGroup[g]
		}
		return 0
	}
	return slices.MinFunc(rs, func(a, b store.Replica) int {
		ha, hb := a.State == store.ReplicaRunning, b.State == store.ReplicaRunning
		if ha != hb {
			if ha {
				return 1
			}
			return -1
		}
		if c := cmp.Compare(inGroup(b), inGroup(a)); c != 0 {
			return c
		}
		if c := cmp.Compare(perNode[b.NodeID], perNode[a.NodeID]); c != 0 {
			return c
		}
		return cmp.Compare(b.ID, a.ID)
	})
}

// eligible returns the nodes that may take new replicas of rev: ready, not
// cordoned, and allowed by its placement and image platforms.
func eligible(nodes []store.Node, rev store.Revision) []store.Node {
	var out []store.Node
	for _, n := range nodes {
		if n.State == store.NodeReady && !n.Cordoned && placementAllows(n, rev) {
			out = append(out, n)
		}
	}
	return out
}

// placementAllows reports whether replicas of rev may run on n: n matches the placement and, if restricted, is selected by it, and
// the image has a variant for n's platform once its platforms are known
// (ADR 0014). A node that does not report its platform is not ruled out.
func placementAllows(n store.Node, rev store.Revision) bool {
	sp := rev.Spec
	if sp.HasVolumes() && !n.Volumes {
		return false
	}
	if !sp.Placement.Matches(n.AllLabels()) {
		return false
	}
	if n.Restricted && !sp.Placement.Selects(n.Labels) {
		return false
	}
	return len(rev.Platforms) == 0 || n.OS == "" || n.Arch == "" || slices.Contains(rev.Platforms, n.OS+"/"+n.Arch)
}

// placeReplica records a new replica of target on node.
func (s *Server) placeReplica(ctx context.Context, app *store.App, target store.Revision, node string) (store.Replica, error) {
	r := store.Replica{
		ID:       fmt.Sprintf("%s-r%d-%s", app.Name, target.Seq, randomID(5)),
		App:      app.Name,
		Revision: target.Name,
		NodeID:   node,
		State:    store.ReplicaPending,
	}
	if err := s.store.CreateReplica(ctx, r); err != nil {
		return store.Replica{}, err
	}
	s.log.Info("scheduled replica", "replica", r.ID, "revision", r.Revision, "node", node)
	s.record(ctx, store.Event{Kind: eventReplica, Object: r.ID, App: app.Name, Node: node, Reason: "Scheduled", Message: "revision " + r.Revision + " on " + node})
	return r, nil
}

// moveFailed replaces, on another node, a replica that has kept failing to
// start for failedMoveAfter: what stops it may be its node's (no address left,
// a broken container network), and another node may have room. The replacement
// exists before the failed one goes, and the first of an app moves at a time.
// With no other node that fits, it stays and keeps retrying.
func (s *Server) moveFailed(ctx context.Context, rc *reconcileRun, app *store.App, target store.Revision, fit []store.Node, all, current []store.Replica, revs *revisionCache) ([]store.Replica, []store.Replica, error) {
	s.rebalanceMu.Lock()
	defer s.rebalanceMu.Unlock()
	moved := false
	for _, r := range slices.Clone(current) {
		if r.State != store.ReplicaFailed {
			delete(s.failedSince, r.ID)
			continue
		}
		since, ok := s.failedSince[r.ID]
		if !ok {
			since = rc.now
			s.failedSince[r.ID] = since
		}
		if due := since.Add(failedMoveAfter); rc.now.Before(due) {
			rc.wakeAt(due)
			continue
		}
		if moved {
			rc.wakeAt(rc.now.Add(time.Second))
			continue
		}
		others := slices.DeleteFunc(slices.Clone(fit), func(n store.Node) bool { return n.ID == r.NodeID })
		to, ok := pickNode(others, all, current, target.Spec.Placement.SpreadKey(), reservation(target), revs.reserved(ctx))
		if !ok {
			continue
		}
		fresh, err := s.placeReplica(ctx, app, target, to.ID)
		if err != nil {
			return nil, nil, err
		}
		s.log.Warn("replica keeps failing to start; trying another node", "replica", r.ID, "node", r.NodeID, "to", to.ID)
		if err := s.deleteReplica(ctx, r); err != nil {
			return nil, nil, err
		}
		delete(s.failedSince, r.ID)
		current = append(without(current, r.ID), fresh)
		all = append(without(all, r.ID), fresh)
		moved = true
	}
	return current, all, nil
}

// pickNode chooses a ready node for a new replica: with spreadBy, the
// fewest of the spread replicas on nodes with the same value of that label
// first; then the fewest of the spread replicas on the node (the app's
// replicas that stay: not draining, moving, lost, or of a revision being
// replaced, which would skew the spread once they are gone), then fewest
// replicas overall, then most free memory, then most
// free CPU. Nodes that report capacity and cannot fit want (the CPU and
// memory the replica reserves, nothing overcommitted) are skipped; capacity
// 0 means unknown. So are nodes whose container subnet is full. nodes carry the capacity left for replicas
// (allocatable). Capacity is self-reported, so beyond fitting it only
// breaks ties: a node advertising inflated capacity does not attract every
// replica.
func pickNode(nodes []store.Node, replicas, spread []store.Replica, spreadBy string, want resources, reserved func(store.Replica) resources) (store.Node, bool) {
	return pickNodeBy(nodes, usageOf(replicas, reserved), spread, spreadBy, want)
}

// pickNodeBy is pickNode with the use of each node already worked out.
func pickNodeBy(nodes []store.Node, use placedUse, spread []store.Replica, spreadBy string, want resources) (store.Node, bool) {
	groupOf := spreadGroups(nodes, spreadBy)
	sameApp, sameGroup := map[string]int{}, map[string]int{}
	for _, r := range spread {
		sameApp[r.NodeID]++
		if g, ok := groupOf[r.NodeID]; ok {
			sameGroup[g]++
		}
	}
	type cand struct {
		node      store.Node
		sameGroup int
		sameApp   int
		total     int
		free      resources
	}
	var cands []cand
	for _, n := range nodes {
		u := use[n.ID]
		if n.State != store.NodeReady || n.Cordoned || (n.Subnet != "" && u.holding >= maxSubnetReplicas) {
			continue
		}
		c := cand{node: n, sameApp: sameApp[n.ID], total: u.total, free: resources{cpu: n.CPUMillis - u.reserved.cpu, mem: n.MemoryBytes - u.reserved.mem}}
		if g, ok := groupOf[n.ID]; ok {
			c.sameGroup = sameGroup[g]
		}
		if (n.MemoryBytes > 0 && c.free.mem < want.mem) || (n.CPUMillis > 0 && c.free.cpu < want.cpu) {
			continue
		}
		cands = append(cands, c)
	}
	if len(cands) == 0 {
		return store.Node{}, false
	}
	best := slices.MinFunc(cands, func(a, b cand) int {
		if c := cmp.Compare(a.sameGroup, b.sameGroup); c != 0 {
			return c
		}
		if c := cmp.Compare(a.sameApp, b.sameApp); c != 0 {
			return c
		}
		if c := cmp.Compare(a.total, b.total); c != 0 {
			return c
		}
		if c := cmp.Compare(b.free.mem, a.free.mem); c != 0 {
			return c
		}
		if c := cmp.Compare(b.free.cpu, a.free.cpu); c != 0 {
			return c
		}
		return cmp.Compare(a.node.ID, b.node.ID)
	})
	return best.node, true
}

func (s *Server) pushAssignments(ctx context.Context, replicas []store.Replica, revs *revisionCache, px *armadav1.ProxyConfig, servers []string, network *armadav1.NetworkConfig) error {
	byNode := map[string][]store.Replica{}
	for _, r := range replicas {
		byNode[r.NodeID] = append(byNode[r.NodeID], r)
	}

	s.mu.Lock()
	sessions := make([]*session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()

	for _, sess := range sessions {
		a := &armadav1.Assignment{Proxy: px, Servers: servers, Network: network}
		for _, r := range byNode[sess.nodeID] {
			rev, err := revs.get(ctx, r.Revision)
			if err != nil {
				return err
			}
			vals, err := revs.secrets(ctx, rev)
			if err != nil {
				// Withhold the whole assignment: a partial one would make
				// the agent stop replicas that are serving.
				return err
			}
			rs, err := replicaSpec(r, rev, vals)
			if err != nil {
				return err
			}
			a.Replicas = append(a.Replicas, rs)
		}
		slices.SortFunc(a.Replicas, func(x, y *armadav1.ReplicaSpec) int { return cmp.Compare(x.Id, y.Id) })
		sess.offerAssignment(a)
	}
	return nil
}

// replicaSpec builds what an agent needs to run one replica. vals holds the
// plaintext of the secret versions rev pins.
func replicaSpec(r store.Replica, rev store.Revision, vals map[string]secrets.Value) (*armadav1.ReplicaSpec, error) {
	sp := rev.Spec
	secret := func(name string) (secrets.Value, string, error) {
		v, ok := vals[name]
		if !ok {
			return secrets.Value{}, "", fmt.Errorf("revision %s: secret %s is not resolved", rev.Name, name)
		}
		return v, name + "@v" + strconv.Itoa(rev.Secrets[name]), nil
	}
	env := make([]*armadav1.EnvVar, 0, len(sp.Env)+4)
	for _, e := range sp.Env {
		if e.SecretRef == "" {
			env = append(env, &armadav1.EnvVar{Name: e.Name, Value: e.Value})
			continue
		}
		v, ref, err := secret(e.SecretRef)
		if err != nil {
			return nil, err
		}
		env = append(env, &armadav1.EnvVar{Name: e.Name, Value: string(v.Bytes()), Ref: ref})
	}
	env = append(env,
		&armadav1.EnvVar{Name: "ARMADA_APP", Value: r.App},
		&armadav1.EnvVar{Name: "ARMADA_REVISION", Value: r.Revision},
		&armadav1.EnvVar{Name: "ARMADA_REPLICA", Value: r.ID},
	)
	if r.Run != 0 {
		env = append(env, &armadav1.EnvVar{Name: "ARMADA_JOB_RUN", Value: strconv.FormatInt(r.Run, 10)})
	}
	var port int32
	if sp.Ingress != nil && sp.Ingress.Type != spec.IngressNone {
		port = int32(sp.Ingress.Port) //nolint:gosec // validated to 1..65535
		env = append(env, &armadav1.EnvVar{Name: "PORT", Value: strconv.Itoa(sp.Ingress.Port)})
	}
	rs := &armadav1.ReplicaSpec{
		Id:               r.ID,
		App:              r.App,
		Revision:         r.Revision,
		Image:            rev.Image(),
		Command:          sp.Command,
		Args:             sp.Args,
		Env:              env,
		Port:             port,
		MemoryBytes:      sp.MemoryBytes(),
		NanoCpus:         sp.NanoCPUs(),
		CpuReserveMillis: sp.CPUMillis(),
		PidsLimit:        spec.DefaultPids,
	}
	if r.Run != 0 {
		rs.Job = &armadav1.JobAttempt{Job: r.App, Run: r.Run, Done: r.Done}
	}
	if sp.Probes != nil {
		rs.Startup = probeProto(sp.Probes.Startup)
		rs.Readiness = probeProto(sp.Probes.Readiness)
		rs.Liveness = probeProto(sp.Probes.Liveness)
	}
	for _, v := range sp.Volumes {
		rs.Volumes = append(rs.Volumes, &armadav1.VolumeSpec{Name: v.Name, Path: v.Path, Owner: v.Owner})
	}
	for _, f := range sp.SecretFiles {
		v, ref, err := secret(f.SecretRef)
		if err != nil {
			return nil, err
		}
		rs.SecretFiles = append(rs.SecretFiles, &armadav1.SecretFile{Path: f.Path, Data: v.Bytes(), Ref: ref})
	}
	if reg := sp.Registry; reg != nil {
		v, ref, err := secret(reg.PasswordSecretRef)
		if err != nil {
			return nil, err
		}
		rs.Registry = &armadav1.RegistryAuth{Server: reg.Server, Username: reg.Username, Password: string(v.Bytes()), Ref: ref}
	}
	return rs, nil
}

func probeProto(p *spec.Probe) *armadav1.Probe {
	if p == nil {
		return nil
	}
	return &armadav1.Probe{
		Path:             p.Path,
		Command:          p.Command,
		Port:             int32(p.Port), //nolint:gosec // validated to 1..65535
		InitialDelayMs:   p.InitialDelay.D().Milliseconds(),
		PeriodMs:         p.Period.D().Milliseconds(),
		TimeoutMs:        p.Timeout.D().Milliseconds(),
		FailureThreshold: int32(p.FailureThreshold), //nolint:gosec // validated to 1..100
	}
}

type revisionCache struct {
	store store.Store
	keys  *secrets.Keyring
	m     map[string]store.Revision
	vals  map[string]map[string]secrets.Value
	// res holds what a replica of each revision reserves: scheduling asks for
	// every replica of the cluster, once per app.
	res map[string]resources
}

// secrets decrypts the secret versions rev pins.
func (c *revisionCache) secrets(ctx context.Context, rev store.Revision) (map[string]secrets.Value, error) {
	if len(rev.Secrets) == 0 {
		return nil, nil
	}
	if v, ok := c.vals[rev.Name]; ok {
		return v, nil
	}
	if c.keys == nil {
		return nil, fmt.Errorf("revision %s uses secrets, but no master key is loaded", rev.Name)
	}
	vals := make(map[string]secrets.Value, len(rev.Secrets))
	for name, version := range rev.Secrets {
		sealed, err := c.store.GetSecret(ctx, rev.App, name, version)
		if err != nil {
			return nil, err
		}
		v, err := c.keys.Open(sealed, rev.App, name, version)
		if err != nil {
			return nil, err
		}
		vals[name] = v
	}
	if c.vals == nil {
		c.vals = map[string]map[string]secrets.Value{}
	}
	c.vals[rev.Name] = vals
	return vals, nil
}

// preload reads the revisions a pass over apps and replicas needs at once. A
// failure costs nothing but speed: get reads what is missing.
func (c *revisionCache) preload(ctx context.Context, apps []store.App, replicas []store.Replica) {
	seen := make(map[string]bool, len(apps)+len(replicas))
	names := make([]string, 0, len(apps)+len(replicas))
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for _, a := range apps {
		add(a.ActiveRevision)
		add(a.TargetRevision)
	}
	for _, r := range replicas {
		add(r.Revision)
	}
	revs, err := c.store.GetRevisions(ctx, names)
	if err != nil {
		return
	}
	maps.Copy(c.m, revs)
}

func (c *revisionCache) get(ctx context.Context, name string) (store.Revision, error) {
	if r, ok := c.m[name]; ok {
		return r, nil
	}
	r, err := c.store.GetRevision(ctx, name)
	if err != nil {
		return r, err
	}
	c.m[name] = r
	return r, nil
}

// reserved returns what each replica reserves on its node.
func (c *revisionCache) reserved(ctx context.Context) func(store.Replica) resources {
	return func(r store.Replica) resources {
		if r.Done {
			return resources{} // a finished job attempt, kept for its logs
		}
		if res, ok := c.res[r.Revision]; ok {
			return res
		}
		rev, err := c.get(ctx, r.Revision)
		if err != nil {
			return resources{}
		}
		res := reservation(rev)
		if c.res == nil {
			c.res = map[string]resources{}
		}
		c.res[r.Revision] = res
		return res
	}
}

// reservation is what one replica of rev reserves on its node.
func reservation(rev store.Revision) resources {
	return resources{cpu: rev.Spec.CPUMillis(), mem: rev.Spec.MemoryBytes()}
}

// assignmentsEqual reports whether two assignments are identical.
func assignmentsEqual(a, b *armadav1.Assignment) bool {
	return a != nil && b != nil && proto.Equal(a, b)
}
