package server

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/store"
)

// The leader moves nodes that still run containers on containerd to the
// supervisor runtime, one node at a time (ADR 0054, "The runtime's move",
// step 4): it drains the node like a cordon, asks its agent to move once
// no replica is left, waits for the node to report the supervisor, and
// lets it take replicas again.

// metaRuntimeMove holds the move's setting and state (runtimeMoveRec).
const metaRuntimeMove = "runtime-move"

// The move's steps.
const (
	// moveDraining: the node takes no new replicas, and its replicas start
	// on other nodes and leave it, as on a cordoned node.
	moveDraining = "draining"
	// moveMigrating: the node's agent is asked to move.
	moveMigrating = "migrating"
)

// The plans a containerd node is told (RuntimeMovePlan.state).
const (
	movePlanQueued  = "queued"
	movePlanMoving  = "moving"
	movePlanWaiting = "waiting"
	movePlanOff     = "off"
)

const (
	// runtimeDrainLimit bounds the draining step: replicas that keep
	// failing to start elsewhere, or job attempts that run on, give the
	// move up rather than hold the node out of service.
	runtimeDrainLimit = 15 * time.Minute
	// runtimeMigrateLimit bounds the migrating step: removing the node's
	// containers and starting its service again.
	runtimeMigrateLimit = 10 * time.Minute
	// runtimeMoveAsk is how often the leader asks the node again while it
	// has not moved (an agent that saw a replica left, or a new session).
	runtimeMoveAsk = 30 * time.Second
	// runtimeMoveBackoff is how long a node whose move was given up waits
	// before it is tried again.
	runtimeMoveBackoff = time.Hour
	// runtimeMoveRecheck is how often the leader looks at a move again
	// without other news.
	runtimeMoveRecheck = 10 * time.Second
	// maxRuntimeMoveWaiting bounds the waiting nodes the status names.
	maxRuntimeMoveWaiting = 20
)

// runtimeMoveRec is the move's record in etcd, so a new leader carries on
// with the node and step its predecessor was at.
type runtimeMoveRec struct {
	// Off turns the automatic move off (cluster update --runtime-move).
	Off  bool         `json:"off,omitempty"`
	Move *runtimeMove `json:"move,omitempty"`
	// GivenUp holds the nodes whose last move was given up: when and why.
	GivenUp map[string]givenUpMove `json:"givenUp,omitempty"`
}

type runtimeMove struct {
	Node string `json:"node"`
	Step string `json:"step"`
	// Since and StepSince are Unix milliseconds.
	Since     int64 `json:"since"`
	StepSince int64 `json:"stepSince"`
}

type givenUpMove struct {
	At     int64  `json:"at"`
	Reason string `json:"reason"`
}

// moveLimits are how long each step may take and how long a node whose
// move was given up waits (Config.RuntimeDrainLimit and the others).
type moveLimits struct {
	drain, migrate, backoff time.Duration
}

// moveAsk is when the leader last asked a node to move, and on which
// session; memory only, so a new leader asks again.
type moveAsk struct {
	sess *session
	at   time.Time
}

func (s *Server) loadRuntimeMove(ctx context.Context) (runtimeMoveRec, error) {
	var rec runtimeMoveRec
	raw, err := s.store.GetMeta(ctx, metaRuntimeMove)
	if errors.Is(err, store.ErrNotFound) || (err == nil && raw == "") {
		return rec, nil
	}
	if err != nil {
		return rec, err
	}
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return rec, fmt.Errorf("runtime move: %w", err)
	}
	return rec, nil
}

func (s *Server) saveRuntimeMove(ctx context.Context, rec runtimeMoveRec) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.store.SetMeta(ctx, metaRuntimeMove, string(b))
}

// setRuntimeMove turns the automatic move on or off (cluster update
// --runtime-move). Turned off during the draining step, the move ends and
// the node takes replicas again; a node already asked to move finishes.
func (s *Server) setRuntimeMove(ctx context.Context, on bool) error {
	s.moveMu.Lock()
	defer s.moveMu.Unlock()
	rec, err := s.loadRuntimeMove(ctx)
	if err != nil {
		return storeErr(err)
	}
	rec.Off = !on
	if err := s.saveRuntimeMove(ctx, rec); err != nil {
		return storeErr(err)
	}
	detail := "off"
	if on {
		detail = "on"
	}
	if err := s.store.RecordAudit(ctx, actor(ctx), "cluster.runtime_move", "cluster", detail); err != nil {
		return storeErr(err)
	}
	s.log.Info("automatic move of containerd nodes changed", "move", detail, "by", actor(ctx))
	return nil
}

// cordonMoving marks the node being moved cordoned in nodes, the pass's
// copy: no new replicas go there and its replicas move away, as with a
// cordon, while the node's own record, and an admin's cordon in it, stay
// as they are.
func cordonMoving(rec runtimeMoveRec, nodes []store.Node) {
	if rec.Move == nil {
		return
	}
	for i := range nodes {
		if nodes[i].ID == rec.Move.Node {
			nodes[i].Cordoned = true
		}
	}
}

// moveView is what one pass works out about the containerd nodes.
type moveView struct {
	status *armadav1.RuntimeMoveStatus
	plans  map[string]*armadav1.RuntimeMovePlan
}

// advanceRuntimeMove takes the move one step further when its step is done,
// gives it up when a step takes too long, or starts the next one; it
// returns the plan of each containerd node for its assignment. nodes are
// the pass's (allocatable, the moving node cordoned), replicas its latest.
func (s *Server) advanceRuntimeMove(ctx context.Context, rc *reconcileRun, nodes []store.Node, replicas []store.Replica, revs *revisionCache) (plans map[string]*armadav1.RuntimeMovePlan, ask string, err error) {
	s.moveMu.Lock()
	defer s.moveMu.Unlock()
	rec, err := s.loadRuntimeMove(ctx)
	if err != nil {
		return nil, "", err
	}
	now := rc.now
	changed := false
	byID := map[string]store.Node{}
	runtimeOf := map[string]string{}
	var onContainerd []store.Node
	for _, n := range nodes {
		byID[n.ID] = n
		agent := s.usage.runtimeOf(n.ID, now).GetAgent()
		runtimeOf[n.ID] = agent
		if agent == runtime.AgentContainerd {
			onContainerd = append(onContainerd, n)
		}
	}
	// A node that moved, by the leader or by hand, or is gone, keeps no
	// given-up move.
	for id := range rec.GivenUp {
		if _, ok := byID[id]; !ok || moved(runtimeOf[id]) {
			delete(rec.GivenUp, id)
			changed = true
		}
	}

	ended := false
	if rec.Move != nil {
		if s.stepRuntimeMove(ctx, &rec, byID, runtimeOf, replicas, revs, now) {
			changed = true
		}
		// The pass's nodes still have the moved node cordoned: the next
		// move starts in the next pass.
		ended = rec.Move == nil
	}

	view := s.planRuntimeMove(ctx, rc, &rec, nodes, onContainerd, replicas, revs, now)
	if ended && view.start != "" {
		view.plans[view.start] = &armadav1.RuntimeMovePlan{State: movePlanQueued, Reason: "one node moves at a time"}
		view.start = ""
		s.wakeAfter(100 * time.Millisecond)
	}
	if view.start != "" {
		n := view.start
		left := remaining(replicas, n)
		delete(rec.GivenUp, n)
		rec.Move = &runtimeMove{Node: n, Step: moveDraining, Since: now.UnixMilli(), StepSince: now.UnixMilli()}
		changed = true
		s.log.Info("moving a node from containerd to the supervisor runtime", "node", n, "replicas", len(left))
		s.record(ctx, store.Event{Kind: eventNode, Object: n, Node: n, Reason: "RuntimeMoveStarted",
			Message: fmt.Sprintf("moving %s from containerd to the supervisor runtime, one node at a time", n)})
		if len(left) > 0 {
			s.record(ctx, store.Event{Kind: eventNode, Object: n, Node: n, Reason: "RuntimeMoveDraining",
				Message: fmt.Sprintf("%d replicas of %s start on other nodes first", len(left), n)})
		}
		view.plans[n] = &armadav1.RuntimeMovePlan{State: movePlanMoving}
		s.wakeAfter(100 * time.Millisecond)
	}
	if changed {
		if err := s.saveRuntimeMove(ctx, rec); err != nil {
			return nil, "", err
		}
	}
	// The node is asked only once the record says so, so a new leader
	// carries on, and after its assignment without the replicas went out
	// (Reconcile).
	if m := rec.Move; m != nil && m.Step == moveMigrating && byID[m.Node].State == store.NodeReady {
		ask = m.Node
	}
	for _, n := range nodes {
		g, ok := rec.GivenUp[n.ID]
		s.condition(ctx, "runtime-move:"+n.ID, ok, store.Event{Kind: eventNode, Object: n.ID, Node: n.ID, Reason: "RuntimeMoveGivenUp",
			Message: fmt.Sprintf("gave up moving %s to the supervisor runtime: %s; it stays on containerd and is tried again after %s", n.ID, g.Reason, s.moveLimits.backoff)})
	}
	if rec.Move != nil || len(onContainerd) > 0 {
		s.wakeAfter(runtimeMoveRecheck)
	}
	st := view.status
	if m := rec.Move; m != nil {
		st.Node, st.Step, st.SinceUnix, st.StepSinceUnix = m.Node, m.Step, m.Since/1000, m.StepSince/1000
		st.Error = s.usage.runtimeOf(m.Node, now).GetMoveError()
	}
	if rec.Move == nil && len(onContainerd) == 0 {
		st = nil
	}
	s.moveSeen.Store(st)
	return view.plans, ask, nil
}

// moved reports whether a node's runtime is the supervisor's.
func moved(agent string) bool {
	return agent == runtime.AgentSupervisorGo || agent == runtime.AgentSupervisorRust
}

// remaining returns the replicas that keep node from moving, sorted: every
// one placed there but finished job attempts.
func remaining(replicas []store.Replica, node string) []store.Replica {
	var out []store.Replica
	for _, r := range replicas {
		if r.NodeID == node && !r.Done {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b store.Replica) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// stepRuntimeMove looks at the move under way: done once the node reports
// the supervisor, migrating once no replica is left, given up when a step
// takes too long or the node is gone. It reports whether rec changed.
func (s *Server) stepRuntimeMove(ctx context.Context, rec *runtimeMoveRec, byID map[string]store.Node, runtimeOf map[string]string, replicas []store.Replica, revs *revisionCache, now time.Time) bool {
	m := rec.Move
	_, ok := byID[m.Node]
	switch {
	case !ok:
		s.record(ctx, store.Event{Kind: eventNode, Object: m.Node, Node: m.Node, Reason: "RuntimeMoveGivenUp",
			Message: fmt.Sprintf("gave up moving %s to the supervisor runtime: the node was removed", m.Node)})
		rec.Move = nil
		return true
	case moved(runtimeOf[m.Node]):
		took := now.Sub(time.UnixMilli(m.Since)).Round(time.Second)
		s.log.Info("node moved to the supervisor runtime", "node", m.Node, "took", took)
		s.record(ctx, store.Event{Kind: eventNode, Object: m.Node, Node: m.Node, Reason: "RuntimeMoveDone",
			Message: fmt.Sprintf("%s runs containers on the supervisor runtime (%s, took %s); it takes replicas again", m.Node, runtimeOf[m.Node], took)})
		delete(rec.GivenUp, m.Node)
		rec.Move = nil
		s.moveAsked = moveAsk{}
		return true
	}
	stepFor := now.Sub(time.UnixMilli(m.StepSince))
	switch m.Step {
	case moveDraining:
		if rec.Off {
			s.log.Info("the automatic runtime move was turned off; the node takes replicas again", "node", m.Node)
			s.record(ctx, store.Event{Kind: eventNode, Object: m.Node, Node: m.Node, Reason: "RuntimeMoveGivenUp",
				Message: fmt.Sprintf("stopped moving %s to the supervisor runtime: the automatic move was turned off; it takes replicas again", m.Node)})
			rec.Move = nil
			return true
		}
		left := remaining(replicas, m.Node)
		if apps := volumeApps(ctx, left, revs); len(apps) > 0 {
			s.giveUpMove(rec, now, "it holds volumes of "+strings.Join(apps, ", ")+", whose app runs only there: move it by hand")
			return true
		}
		if len(left) == 0 {
			m.Step, m.StepSince = moveMigrating, now.UnixMilli()
			s.log.Info("node drained; asking it to move to the supervisor runtime", "node", m.Node)
			s.record(ctx, store.Event{Kind: eventNode, Object: m.Node, Node: m.Node, Reason: "RuntimeMoveMigrating",
				Message: fmt.Sprintf("no replica left on %s; it removes its containers (its proxy too) and restarts its service on the supervisor runtime", m.Node)})
			return true
		}
		if stepFor >= s.moveLimits.drain {
			apps := []string{}
			for _, r := range left {
				if !slices.Contains(apps, r.App) {
					apps = append(apps, r.App)
				}
			}
			s.giveUpMove(rec, now, fmt.Sprintf("%d replicas did not leave it within %s (%s)", len(left), s.moveLimits.drain, strings.Join(firstN(apps, 5), ", ")))
			return true
		}
	case moveMigrating:
		if stepFor >= s.moveLimits.migrate {
			why := s.usage.runtimeOf(m.Node, now).GetMoveError()
			if why == "" {
				why = fmt.Sprintf("it did not report the supervisor runtime within %s of being asked (see its service's log)", s.moveLimits.migrate)
			}
			s.giveUpMove(rec, now, why)
			return true
		}
	default:
		s.giveUpMove(rec, now, fmt.Sprintf("unknown step %q", m.Step))
		return true
	}
	return false
}

// giveUpMove ends the move under way: the node takes replicas again, stays
// on containerd, and is tried again after runtimeMoveBackoff. The condition
// RuntimeMoveGivenUp says so until it moves.
func (s *Server) giveUpMove(rec *runtimeMoveRec, now time.Time, why string) {
	node := rec.Move.Node
	why = cleanMessage(why) // bounded like an event's message
	s.log.Warn("gave up moving a node to the supervisor runtime", "node", node, "step", rec.Move.Step, "reason", why)
	if rec.GivenUp == nil {
		rec.GivenUp = map[string]givenUpMove{}
	}
	rec.GivenUp[node] = givenUpMove{At: now.UnixMilli(), Reason: why}
	rec.Move = nil
	s.moveAsked = moveAsk{}
}

// askToMove sends the node's agent MoveRuntime, again every runtimeMoveAsk
// and on every new session, until it moves.
func (s *Server) askToMove(node string, now time.Time) {
	s.moveMu.Lock()
	defer s.moveMu.Unlock()
	sess := s.session(node)
	if sess == nil || !sess.runtimeMove {
		return
	}
	if s.moveAsked.sess == sess && now.Sub(s.moveAsked.at) < runtimeMoveAsk {
		return
	}
	select {
	case sess.send <- &armadav1.ServerMessage{Msg: &armadav1.ServerMessage_MoveRuntime{MoveRuntime: &armadav1.MoveRuntime{To: "supervisor"}}}:
		s.moveAsked = moveAsk{sess: sess, at: now}
	default:
		// The session's queue is full; the next pass asks again.
	}
}

// moveViewOut is planRuntimeMove's answer: the status, every containerd
// node's plan, and the node to start moving now, if any.
type moveViewOut struct {
	moveView
	start string
}

// planRuntimeMove works out which containerd node moves next and why the
// others wait. A node waits for its operator when it is the cluster's only
// node that takes replicas, holds local volumes (their app runs only there,
// and moving it would stop the app), or its agent cannot move itself. It
// waits for the move to come round when the cluster is busy (a network
// switch, a node away or lost), when the other nodes have no room for its
// replicas, or after a move of it was given up. Of the nodes that can
// move, workers go first, then servers, the leader's own machine last.
func (s *Server) planRuntimeMove(ctx context.Context, rc *reconcileRun, rec *runtimeMoveRec, nodes, onContainerd []store.Node, replicas []store.Replica, revs *revisionCache, now time.Time) moveViewOut {
	out := moveViewOut{moveView: moveView{status: &armadav1.RuntimeMoveStatus{Off: rec.Off}, plans: map[string]*armadav1.RuntimeMovePlan{}}}
	if rec.Move != nil {
		out.plans[rec.Move.Node] = &armadav1.RuntimeMovePlan{State: movePlanMoving}
	}
	held := ""
	switch {
	case rec.Off:
		held = "the automatic move is turned off (armada cluster update --runtime-move=true turns it on)"
	case rec.Move != nil:
	case len(rc.lost) > 0 || rc.away:
		held = "a node is not connected"
	default:
		if n, err := s.store.GetNetwork(ctx); err == nil && n.Switch != nil {
			held = "the cluster network is switching its mode"
		}
	}
	if rec.Move == nil && len(onContainerd) > 0 {
		out.status.Held = held
	}
	order := s.moveOrder(ctx, onContainerd)
	var waiting []*armadav1.RuntimeMoveWait
	for _, n := range order {
		if rec.Move != nil && n.ID == rec.Move.Node {
			continue
		}
		reason, operator := s.moveWait(ctx, rec, n, nodes, replicas, revs, now)
		switch {
		case rec.Off:
			out.plans[n.ID] = &armadav1.RuntimeMovePlan{State: movePlanOff}
			if reason != "" {
				out.plans[n.ID].Reason, out.plans[n.ID].Operator = reason, operator
			}
		case reason != "":
			out.plans[n.ID] = &armadav1.RuntimeMovePlan{State: movePlanWaiting, Reason: reason, Operator: operator}
		case held == "" && rec.Move == nil && out.start == "":
			out.start = n.ID
			continue
		default:
			out.plans[n.ID] = &armadav1.RuntimeMovePlan{State: movePlanQueued, Reason: cmp.Or(held, "one node moves at a time")}
		}
		if reason != "" {
			waiting = append(waiting, &armadav1.RuntimeMoveWait{Node: n.ID, Reason: reason, Operator: operator})
		}
	}
	slices.SortFunc(waiting, func(a, b *armadav1.RuntimeMoveWait) int { return strings.Compare(a.Node, b.Node) })
	out.status.WaitingTotal = int32(len(waiting)) //nolint:gosec // bounded by the nodes of the cluster
	out.status.Waiting = firstN(waiting, maxRuntimeMoveWaiting)
	return out
}

// moveOrder sorts the containerd nodes the way they move: machines that
// run no control plane first, then servers, the leader's own last (moving
// it restarts its control plane, and another server takes over); by name
// within each.
func (s *Server) moveOrder(ctx context.Context, nodes []store.Node) []store.Node {
	rank := map[string]int{}
	if servers, err := s.store.ListServers(ctx); err == nil {
		for _, sv := range servers {
			r := 1
			if sv.Name == s.name {
				r = 2
			}
			rank[sv.PrivateIP] = r
		}
	}
	out := slices.Clone(nodes)
	slices.SortFunc(out, func(a, b store.Node) int {
		if c := cmp.Compare(rank[a.PrivateIP], rank[b.PrivateIP]); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// moveWait says why node is not moved now, "" when it can be, and whether
// it waits for its operator.
func (s *Server) moveWait(ctx context.Context, rec *runtimeMoveRec, node store.Node, nodes []store.Node, replicas []store.Replica, revs *revisionCache, now time.Time) (string, bool) {
	sess := s.session(node.ID)
	if sess == nil {
		return "not connected", false
	}
	if !sess.runtimeMove {
		return "its agent cannot move itself: upgrade it (sudo armadad upgrade), or move it by hand", true
	}
	left := remaining(replicas, node.ID)
	if apps := volumeApps(ctx, left, revs); len(apps) > 0 {
		return fmt.Sprintf("holds volumes of %s, whose app runs only there and would stop: move it by hand (armadad runtime migrate)", strings.Join(apps, ", ")), true
	}
	if rec.Move != nil {
		// Room and the other nodes change with the move under way: this
		// node is looked at again once it ends.
		return "", false
	}
	others := 0
	for _, n := range nodes {
		if n.ID != node.ID && n.State == store.NodeReady && !n.Cordoned && !nodeLost(n, now, s.nodeLostTimeout) {
			others++
		}
	}
	if others == 0 {
		return "no other node takes its replicas (a cluster of one node waits for its operator): move it by hand (armadad runtime migrate)", true
	}
	if g, ok := rec.GivenUp[node.ID]; ok {
		if again := time.UnixMilli(g.At).Add(s.moveLimits.backoff); now.Before(again) {
			return fmt.Sprintf("the last move was given up (%s); tried again at %s", g.Reason, again.UTC().Format(time.RFC3339)), false
		}
	}
	if node.State != store.NodeReady {
		return "not ready", false
	}
	if app, ok := roomFor(ctx, node.ID, nodes, replicas, left, revs); !ok {
		return fmt.Sprintf("the other nodes have no room for a replica of %s", app), false
	}
	return "", false
}

// roomFor reports whether the other nodes can take every replica on node
// that would be replaced (left, job attempts aside: they run to their end
// first), placing them one by one as the scheduler would; app names the
// first that does not fit.
func roomFor(ctx context.Context, node string, nodes []store.Node, all, left []store.Replica, revs *revisionCache) (string, bool) {
	others := slices.DeleteFunc(slices.Clone(nodes), func(n store.Node) bool { return n.ID == node })
	rest := slices.DeleteFunc(slices.Clone(all), func(r store.Replica) bool { return r.NodeID == node })
	use := usageOf(rest, revs.reserved(ctx))
	for _, r := range left {
		if r.Run != 0 {
			continue
		}
		rev, err := revs.get(ctx, r.Revision)
		if err != nil {
			return r.App, false
		}
		want := reservation(rev)
		to, ok := pickNodeBy(eligible(others, rev), use, nil, "", want)
		if !ok {
			return r.App, false
		}
		u := use[to.ID]
		u.total++
		u.holding++
		u.reserved.cpu += want.cpu
		u.reserved.mem += want.mem
		use[to.ID] = u
	}
	return "", true
}

// volumeApps names the apps (at most 5) of replicas whose revision has
// local volumes (ADR 0023): such an app runs only on its volume's node, so
// draining that node never moves it.
func volumeApps(ctx context.Context, replicas []store.Replica, revs *revisionCache) []string {
	var apps []string
	for _, r := range replicas {
		rev, err := revs.get(ctx, r.Revision)
		if err == nil && rev.Spec.HasLocalVolumes() && !slices.Contains(apps, r.App) {
			apps = append(apps, r.App)
		}
	}
	return firstN(apps, 5)
}

// firstN returns at most n of list.
func firstN[T any](list []T, n int) []T {
	if len(list) > n {
		return list[:n]
	}
	return list
}

// runtimeMoveStatus is the last pass's view of the move, for
// ClusterStatus; nil before the first pass, and while no node runs on
// containerd and none moves.
func (s *Server) runtimeMoveStatus() *armadav1.RuntimeMoveStatus {
	st := s.moveSeen.Load()
	if st == nil {
		return nil
	}
	return proto.CloneOf(st)
}
