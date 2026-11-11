package server

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

// Failover (ADR 0041): when the node holding an app's volumes is lost, and
// every volume of the app says failover: restore, the leader restores each
// volume's latest backup on another node and binds the volumes there; the
// app then starts on that node. The lost node's agent stops the app first
// (fenceAfter), so two copies are never written at once.

// failoverActor is who the audit log names for automatic rebinding.
const failoverActor = "armada:failover"

// failoverRuns tracks failovers in progress and when a failed one may be
// tried again. Memory only: a new leader starts over.
type failoverRuns struct {
	mu sync.Mutex
	m  map[string]failoverState
}

type failoverState struct {
	running bool
	retryAt time.Time
}

func newFailoverRuns() *failoverRuns { return &failoverRuns{m: map[string]failoverState{}} }

func (f *failoverRuns) start(app string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.m[app]
	if st.running || now.Before(st.retryAt) {
		return false
	}
	f.m[app] = failoverState{running: true}
	return true
}

func (f *failoverRuns) fail(app string, retryAt time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[app] = failoverState{retryAt: retryAt}
}

func (f *failoverRuns) done(app string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, app)
}

// fenceAfter is how long an agent cut off from the control plane keeps a
// replica whose volumes fail over: half the node-lost timeout, so it stops
// well before the leader restores the volumes elsewhere.
func (s *Server) fenceAfter() int64 {
	return max(1, int64(s.nodeLostTimeout/2/time.Second))
}

// failOver starts restoring app's volumes on another node, unless one is
// running or a failed one waits for its retry.
func (s *Server) failOver(ctx context.Context, rc *reconcileRun, app, from string, target store.Revision, nodes []store.Node, all []store.Replica, revs *revisionCache) {
	if !s.failovers.start(app, rc.now) {
		return
	}
	var fit []store.Node
	for _, n := range eligible(nodes, target) {
		if n.ID == from || rc.lost[n.ID] {
			continue
		}
		if sess := s.session(n.ID); sess == nil || !sess.backups {
			continue
		}
		fit = append(fit, n)
	}
	failed := func(msg string) {
		s.failovers.fail(app, s.now().Add(backupRetry))
		s.condition(ctx, "failover-failed:"+app, true, store.Event{Kind: eventApp, Object: app, App: app, Node: from, Reason: "VolumeFailoverFailed",
			Message: msg + "; trying again in " + backupRetry.String()})
		s.log.Warn("volume failover failed", "app", app, "from", from, "err", msg)
	}
	node, ok := pickNode(fit, all, nil, "", reservation(target), revs.reserved(ctx))
	if !ok {
		failed("no other connected node that backs volumes up can take the app")
		return
	}
	s.log.Info("failing over volumes", "app", app, "from", from, "to", node.ID)
	go func() {
		ctx, cancel := context.WithTimeout(ctx, backupTimeout)
		defer cancel()
		var restored []string
		for _, v := range target.Spec.Volumes {
			bt, err := s.backupTarget(ctx, v.Backup, target)
			if err != nil {
				failed(fmt.Sprintf("volume %s: %v", v.Name, err))
				return
			}
			m, err := s.repoOp(ctx, node.ID, &armadav1.VolumeRequest{Op: armadav1.VolumeRequest_OP_RESTORE_SNAPSHOT, App: app, Volume: v.Name, Backup: bt, Snapshot: "latest"})
			if err != nil {
				failed(fmt.Sprintf("restoring volume %s on %s: %s", v.Name, node.ID, status.Convert(err).Message()))
				return
			}
			restored = append(restored, v.Name+" from "+m.GetSnapshot().GetSnapshot().GetId())
		}
		// Never bind while the old node is back: its replica may run.
		if s.session(from) != nil {
			s.failovers.done(app)
			s.log.Info("volume failover abandoned: the node is back", "app", app, "node", from)
			return
		}
		for _, v := range target.Spec.Volumes {
			if err := s.store.BindVolume(ctx, app, v.Name, node.ID, failoverActor); err != nil {
				failed(fmt.Sprintf("binding volume %s to %s: %v", v.Name, node.ID, err))
				return
			}
		}
		s.failovers.done(app)
		s.condition(ctx, "failover-failed:"+app, false, store.Event{Kind: eventApp, Object: app, App: app, Reason: "VolumeFailoverFailed"})
		s.record(ctx, store.Event{Kind: eventApp, Object: app, App: app, Node: node.ID, Reason: "VolumeFailedOver",
			Message: fmt.Sprintf("node %s was lost; restored %s on %s", from, strings.Join(restored, ", "), node.ID)})
		s.Trigger()
	}()
}
