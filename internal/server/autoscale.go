package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

const (
	// defaultAutoscaleInterval is how often the leader evaluates
	// autoscaled apps (ADR 0022).
	defaultAutoscaleInterval = 15 * time.Second
	// scaleDownWindow is how long the highest recommendation holds before
	// an app scales down, so it does not flap.
	scaleDownWindow = 5 * time.Minute
	// scaleTolerance ignores changes smaller than 10% of the target.
	scaleTolerance = 0.1
	autoscaleActor = "armada:autoscaler"
)

// autoscaler is what the leader remembers between evaluations, in memory
// only: a new leader starts over and waits a full window before scaling
// anything down.
type autoscaler struct {
	mu   sync.Mutex
	apps map[string]*appScaling
}

type appScaling struct {
	since  time.Time // first evaluation in this term
	recs   []recommendation
	status *armadav1.Autoscale
	// lastActive is when the app last had a request or was woken.
	lastActive time.Time
}

type recommendation struct {
	at time.Time
	n  int
}

func newAutoscaler() *autoscaler { return &autoscaler{apps: map[string]*appScaling{}} }

// get returns app's state, creating it at now. as.mu must be held.
func (as *autoscaler) get(app string, now time.Time) *appScaling {
	st := as.apps[app]
	if st == nil {
		st = &appScaling{since: now}
		as.apps[app] = st
	}
	return st
}

// touch records activity of app at now.
func (as *autoscaler) touch(app string, now time.Time) {
	as.mu.Lock()
	defer as.mu.Unlock()
	st := as.get(app, now)
	if now.After(st.lastActive) {
		st.lastActive = now
	}
}

// status returns the last evaluation of app, or nil.
func (as *autoscaler) status(app string) *armadav1.Autoscale {
	as.mu.Lock()
	defer as.mu.Unlock()
	if st, ok := as.apps[app]; ok && st.status != nil {
		return proto.CloneOf(st.status)
	}
	return nil
}

func (s *Server) autoscaleLoop(ctx context.Context) {
	t := time.NewTicker(s.autoscaleInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := s.autoscale(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("autoscale failed", "err", err)
		}
	}
}

// autoscale evaluates every autoscaled app once and applies its decision.
func (s *Server) autoscale(ctx context.Context) error {
	apps, err := s.store.ListApps(ctx)
	if err != nil {
		return err
	}
	reps, err := s.store.ListReplicas(ctx, store.ReplicaFilter{})
	if err != nil {
		return err
	}
	now := s.now()
	revs := &revisionCache{store: s.store, m: map[string]store.Revision{}}
	in := scaleInputs{now: now, usage: s.usage}
	in.load, in.loadMeasured = s.usage.load(now)

	seen := map[string]bool{}
	for _, a := range apps {
		if !a.Spec.Autoscaled() {
			continue
		}
		seen[a.Name] = true
		var mine []store.Replica
		var ids []string
		for _, r := range reps {
			if r.App == a.Name {
				mine = append(mine, r)
				ids = append(ids, r.ID)
			}
		}
		active := s.usage.lastActive(ids)
		rev, err := revs.get(ctx, a.ActiveRevision)
		if err != nil {
			continue
		}
		s.scaler.mu.Lock()
		st := s.scaler.get(a.Name, now)
		if active.After(st.lastActive) {
			st.lastActive = active
		}
		n, why, status := decide(a, reservation(rev), mine, in, st)
		st.status = status
		s.scaler.mu.Unlock()
		if n == a.Replicas {
			continue
		}
		s.applyScale(ctx, a, n, why)
	}
	s.scaler.mu.Lock()
	for name := range s.scaler.apps {
		if !seen[name] {
			delete(s.scaler.apps, name)
		}
	}
	s.scaler.mu.Unlock()
	return nil
}

// wakeApp starts an app scaled to zero for which a request waits at
// nodeID's proxy (ADR 0023). Wakes are untrusted: they are rate limited per
// node, and only raise an app that scales to zero from 0 to 1.
func (s *Server) wakeApp(ctx context.Context, nodeID, app string) {
	now := s.now()
	if !spec.ValidAppID(app) || !s.wakeLimit.allow(nodeID, now) {
		return
	}
	a, err := s.store.GetApp(ctx, app)
	if err != nil || !a.Spec.ScalesToZero() {
		return
	}
	s.scaler.touch(app, now)
	if a.Replicas != 0 {
		return
	}
	err = s.store.AutoscaleReplicas(ctx, app, 0, 1, autoscaleActor)
	if errors.Is(err, store.ErrConflict) {
		return
	}
	if err != nil {
		s.log.Error("wake", "app", app, "err", err)
		return
	}
	s.log.Info("woke app", "app", app, "node", nodeID)
	s.record(ctx, store.Event{Kind: eventApp, Object: app, App: app, Node: nodeID, Reason: "Woken",
		Message: "a request at " + nodeID + " started it from zero"})
	s.Trigger()
}

func (s *Server) applyScale(ctx context.Context, a store.App, n int, why string) {
	err := s.store.AutoscaleReplicas(ctx, a.Name, a.Replicas, n, autoscaleActor)
	if errors.Is(err, store.ErrConflict) {
		return // changed meanwhile; the next evaluation sees the new state
	}
	if err != nil {
		s.log.Error("autoscale", "app", a.Name, "err", err)
		return
	}
	reason, verb := "ScaledUp", "up"
	switch {
	case n == 0:
		reason, verb = "ScaledToZero", "down"
	case n < a.Replicas:
		reason, verb = "ScaledDown", "down"
	}
	s.log.Info("autoscaled", "app", a.Name, "from", a.Replicas, "to", n, "why", why)
	s.record(ctx, store.Event{Kind: eventApp, Object: a.Name, App: a.Name, Reason: reason,
		Message: fmt.Sprintf("scaled %s from %d to %d: %s", verb, a.Replicas, n, why)})
	s.Trigger()
}

// scaleInputs are the samples one evaluation reads.
type scaleInputs struct {
	now          time.Time
	usage        *usageStore
	load         map[string]int64
	loadMeasured bool
}

// decide returns the replica count app a should have, why, and its status.
// It returns a.Replicas to hold. st holds the recent recommendations and is
// updated.
func decide(a store.App, res resources, reps []store.Replica, in scaleInputs, st *appScaling) (int, string, *armadav1.Autoscale) {
	lo, hi := a.Spec.ScaleBounds()
	status := &armadav1.Autoscale{Min: int32(lo), Max: int32(hi)} //nolint:gosec // bounded by spec.MaxReplicas
	hold := func(msg string) (int, string, *armadav1.Autoscale) {
		status.Message = msg
		return a.Replicas, "", status
	}
	if a.Rolling() {
		return hold("holding while a rollout is in progress")
	}
	if a.Replicas == 0 {
		return hold("scaled to zero; the next request wakes it")
	}
	if a.Spec.ScalesToZero() && in.loadMeasured {
		idle := a.Spec.IdleAfter()
		quiet := in.now.Sub(st.since)
		if !st.lastActive.IsZero() {
			quiet = min(quiet, in.now.Sub(st.lastActive))
		}
		if quiet >= idle {
			status.Message = "scaling to zero: no requests for " + idle.String()
			return 0, "no requests for " + idle.String(), status
		}
	}
	// With split traffic, the replicas of every revision with a weight
	// share the load (ADR 0024).
	var ready []store.Replica
	for _, r := range reps {
		serves := r.Revision == a.ActiveRevision
		if len(a.Traffic) > 0 {
			serves = trafficWeight(a, r.Revision) > 0
		}
		if serves && r.State == store.ReplicaRunning && r.Ready && !r.Draining() && !r.Done {
			ready = append(ready, r)
		}
	}
	if len(ready) == 0 {
		return hold("holding: no ready replicas")
	}

	rec := -1
	var reasons []string
	for _, rule := range a.Spec.Scale.Rules {
		target := float64(rule.Concurrent)
		if rule.Type != spec.ScaleHTTP {
			target = float64(rule.Utilization)
		}
		cur, ok := ruleValue(rule.Type, res, ready, in)
		rs := &armadav1.AutoscaleRule{Type: rule.Type, Target: int64(target), Measured: ok, Current: int64(math.Round(cur))}
		status.Rules = append(status.Rules, rs)
		if !ok {
			continue
		}
		n := a.Replicas
		if ratio := cur / target; math.Abs(ratio-1) > scaleTolerance {
			n = int(math.Ceil(float64(len(ready)) * ratio))
		}
		rec = max(rec, n)
		unit := " per replica"
		if rule.Type != spec.ScaleHTTP {
			unit = "%"
		}
		reasons = append(reasons, fmt.Sprintf("%s %d of %d%s", rule.Type, rs.Current, rs.Target, unit))
	}
	if rec < 0 {
		return hold("holding: not enough samples yet")
	}
	// At most double the ready replicas per step (replicas that cannot be
	// placed do not compound), never below the current count on that
	// account, and within the bounds.
	// Rules never go below one replica: only idleness scales to zero.
	rec = min(max(min(rec, max(2*len(ready), a.Replicas)), lo, 1), hi)
	st.recs = append(st.recs, recommendation{at: in.now, n: rec})
	keep := st.recs[:0]
	for _, r := range st.recs {
		if in.now.Sub(r.at) <= scaleDownWindow {
			keep = append(keep, r)
		}
	}
	st.recs = keep
	why := strings.Join(reasons, ", ")
	switch {
	case a.Replicas < max(lo, 1) || a.Replicas > hi:
		n := min(max(a.Replicas, lo, 1), hi)
		status.Message = fmt.Sprintf("moving to %d (bounds %d..%d)", n, lo, hi)
		return n, "within scale.min and scale.max", status
	case rec > a.Replicas:
		status.Message = "scaling up to " + fmt.Sprint(rec) + ": " + why
		return rec, why, status
	}
	highest := rec
	for _, r := range st.recs {
		highest = max(highest, r.n)
	}
	if highest >= a.Replicas {
		status.Message = "steady: " + why
		if rec < a.Replicas {
			status.Message = fmt.Sprintf("would scale down to %d once the load stays lower for %s: %s", rec, scaleDownWindow, why)
		}
		return a.Replicas, "", status
	}
	if in.now.Sub(st.since) < scaleDownWindow {
		status.Message = fmt.Sprintf("would scale down to %d; watching load for %s first", highest, scaleDownWindow)
		return a.Replicas, "", status
	}
	status.Message = "scaling down to " + fmt.Sprint(highest) + ": " + why
	return highest, why + fmt.Sprintf(" (highest in the last %s)", scaleDownWindow), status
}

// ruleValue returns the current average per ready replica for one rule:
// requests in progress for http, percent of the reservation for cpu and
// memory. ok is false without enough samples: no proxy was read, or fewer
// than half the ready replicas were sampled on their own node.
func ruleValue(typ string, res resources, ready []store.Replica, in scaleInputs) (float64, bool) {
	if typ == spec.ScaleHTTP {
		if !in.loadMeasured {
			return 0, false
		}
		var sum int64
		for _, r := range ready {
			sum += in.load[r.ID]
		}
		return float64(sum) / float64(len(ready)), true
	}
	var sum float64
	measured := 0
	for _, r := range ready {
		n, ok := in.usage.node(r.NodeID, in.now)
		if !ok {
			continue
		}
		u, ok := n.replicas[r.ID]
		if !ok {
			continue
		}
		switch {
		case typ == spec.ScaleCPU && res.cpu > 0:
			sum += float64(u.cpu) * 100 / float64(res.cpu)
		case typ == spec.ScaleMemory && res.mem > 0:
			sum += float64(u.mem) * 100 / float64(res.mem)
		default:
			continue
		}
		measured++
	}
	if measured == 0 || measured*2 < len(ready) {
		return 0, false
	}
	return sum / float64(measured), true
}
