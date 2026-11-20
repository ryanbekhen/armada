package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

const (
	// maxSwitchUnreached bounds the peers a node's switch status names.
	maxSwitchUnreached = 32
	// maxSwitchWaiting bounds the nodes a switch's progress lists.
	maxSwitchWaiting = 50
	// switchRecheck is how often the leader looks at a switch again
	// without news from the nodes.
	switchRecheck = 10 * time.Second
)

// cleanSwitchStatus bounds what a node reports about its side of a network
// switch (ADR 0050): known modes and steps, peer names that are node names,
// and a printable error. Anything else is nil.
func cleanSwitchStatus(st *armadav1.NetworkSwitchStatus) *armadav1.NetworkSwitchStatus {
	if st == nil {
		return nil
	}
	if st.GetTo() != store.NetworkPlain && st.GetTo() != store.NetworkWireGuard ||
		st.GetStep() != store.SwitchPrepare && st.GetStep() != store.SwitchMove {
		return nil
	}
	out := &armadav1.NetworkSwitchStatus{To: st.GetTo(), Step: st.GetStep(), Ready: st.GetReady()}
	for _, name := range st.GetUnreached() {
		if len(out.Unreached) == maxSwitchUnreached {
			break
		}
		if spec.ValidateName(name) == nil {
			out.Unreached = append(out.Unreached, name)
		}
	}
	if e := st.GetError(); e != "" {
		out.Error = cleanMessage(e)
		out.Ready = false
	}
	return out
}

// switchStatus returns the latest side of a network switch nodeID reported.
func (u *usageStore) switchStatus(nodeID string) *armadav1.NetworkSwitchStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.nodes[nodeID].netSwitch
}

// switchProgress works out which nodes the step of n's switch waits for:
// every node with a subnet that has connected and is not lost, until it
// reports the step done. A node that never connected gets the cluster's
// mode when it does; a lost one when it returns.
func (s *Server) switchProgress(n store.Network, nodes []store.Node, now time.Time) *armadav1.NetworkSwitchProgress {
	sw := n.Switch
	p := &armadav1.NetworkSwitchProgress{From: n.Mode, To: sw.To, Step: sw.Step, SinceUnix: sw.Since.Unix()}
	var waiting []*armadav1.NodeSwitchWait
	for _, node := range nodes {
		if node.Subnet == "" || node.LastSeen.IsZero() || nodeLost(node, now, s.nodeLostTimeout) {
			continue
		}
		s.mu.Lock()
		sess := s.sessions[node.ID]
		s.mu.Unlock()
		w := &armadav1.NodeSwitchWait{Node: node.ID}
		switch {
		case sess == nil:
			w.Disconnected = true
		case !sess.netSwitch:
			w.Unsupported = true
		default:
			st := s.usage.switchStatus(node.ID)
			if st.GetTo() == sw.To && st.GetStep() == sw.Step && st.GetReady() {
				continue
			}
			if st.GetTo() == sw.To && st.GetStep() == sw.Step {
				w.Unreached, w.Error = st.GetUnreached(), st.GetError()
			}
		}
		waiting = append(waiting, w)
	}
	slices.SortFunc(waiting, func(a, b *armadav1.NodeSwitchWait) int { return strings.Compare(a.Node, b.Node) })
	p.WaitingTotal = int32(len(waiting)) //nolint:gosec // bounded by the nodes of the cluster
	if len(waiting) > maxSwitchWaiting {
		waiting = waiting[:maxSwitchWaiting]
	}
	p.Waiting = waiting
	return p
}

// advanceSwitch takes a network switch (ADR 0050) to its next step once
// no node holds the current one up, and returns the network as it is now.
func (s *Server) advanceSwitch(ctx context.Context, rc *reconcileRun, nodes []store.Node) error {
	n, err := s.store.GetNetwork(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil || n.Switch == nil {
		return err
	}
	s.wakeAfter(switchRecheck)
	if p := s.switchProgress(n, nodes, rc.now); p.WaitingTotal > 0 {
		return nil
	}
	err = s.store.AdvanceNetworkSwitch(ctx, n.Switch.To, n.Switch.Step)
	if errors.Is(err, store.ErrConflict) {
		return nil // changed since it was read; the next pass sees it
	}
	if err != nil {
		return err
	}
	if n.Switch.Step == store.SwitchPrepare {
		s.log.Info("every node reaches its peers over the target transport; moving the routes", "from", n.Mode, "to", n.Switch.To)
		s.record(ctx, store.Event{Kind: eventNode, Object: "*", Reason: "NetworkSwitchMoving",
			Message: fmt.Sprintf("every node reaches its peers over %s; routing over it", n.Switch.To)})
		return nil
	}
	s.log.Info("the cluster network switched", "from", n.Mode, "to", n.Switch.To)
	s.record(ctx, store.Event{Kind: eventNode, Object: "*", Reason: "NetworkSwitched",
		Message: fmt.Sprintf("the cluster network switched from %s to %s", n.Mode, n.Switch.To)})
	return nil
}

// setNetwork starts a switch of the cluster network's mode (ADR 0050), or
// gives one up during its prepare step. A switch needs every connected
// node's agent to know it; the store refuses a mesh, a cluster without a
// network, and a second switch.
func (s *Server) setNetwork(ctx context.Context, to string) error {
	if to != store.NetworkPlain && to != store.NetworkWireGuard {
		return status.Errorf(codes.InvalidArgument, "a running cluster switches its network to %s or %s, not %q", store.NetworkPlain, store.NetworkWireGuard, to)
	}
	n, err := s.store.GetNetwork(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return status.Error(codes.FailedPrecondition, "this cluster has no cluster network (it was created before ADR 0025); its mode cannot be switched")
	}
	if err != nil {
		return storeErr(err)
	}
	starting := n.Switch == nil && to != n.Mode
	if starting {
		s.mu.Lock()
		var old []string
		for id, sess := range s.sessions {
			if !sess.netSwitch {
				old = append(old, id)
			}
		}
		s.mu.Unlock()
		if len(old) > 0 {
			slices.Sort(old)
			return status.Errorf(codes.FailedPrecondition, "these nodes run a version that cannot switch the network's mode; upgrade them first: %s", strings.Join(old, ", "))
		}
	}
	if err := s.store.StartNetworkSwitch(ctx, to, actor(ctx)); err != nil {
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrPrecondition) {
			return status.Error(codes.FailedPrecondition, err.Error())
		}
		return storeErr(err)
	}
	switch {
	case starting:
		s.log.Info("switching the cluster network", "from", n.Mode, "to", to, "by", actor(ctx))
		s.record(ctx, store.Event{Kind: eventNode, Object: "*", Reason: "NetworkSwitchStarted",
			Message: fmt.Sprintf("switching the cluster network from %s to %s", n.Mode, to)})
	case n.Switch != nil && to == n.Mode:
		s.log.Info("gave up switching the cluster network", "to", n.Switch.To, "by", actor(ctx))
		s.record(ctx, store.Event{Kind: eventNode, Object: "*", Reason: "NetworkSwitchGivenUp",
			Message: fmt.Sprintf("gave up switching the cluster network to %s; staying on %s", n.Switch.To, n.Mode)})
	}
	return nil
}
