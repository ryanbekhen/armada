package server

import (
	"slices"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/store"
)

// maxRuntimeOthers bounds the nodes ClusterStatus names that are not on
// armada-node yet (ADR 0054).
const maxRuntimeOthers = 20

// maxImagesToPull bounds a node's count of images to pull again.
const maxImagesToPull = 1 << 20

// cleanRuntimeStatus bounds what a node says about how it runs
// containers: a runtime the leader does not know is dropped.
func cleanRuntimeStatus(st *armadav1.RuntimeStatus) *armadav1.RuntimeStatus {
	switch st.GetAgent() {
	case runtime.AgentContainerd:
		out := &armadav1.RuntimeStatus{Agent: st.GetAgent()}
		if e := st.GetMoveError(); e != "" {
			out.MoveError = cleanMessage(e)
		}
		return out
	case runtime.AgentSupervisorGo:
		return &armadav1.RuntimeStatus{Agent: st.GetAgent()}
	case runtime.AgentSupervisorRust:
	default:
		return nil
	}
	out := &armadav1.RuntimeStatus{
		Agent: st.GetAgent(), Converting: st.GetConverting(),
		ImagesToPull: max(0, min(st.GetImagesToPull(), maxImagesToPull)),
	}
	if e := st.GetError(); e != "" {
		out.Error, out.Converting = cleanMessage(e), true
	}
	return out
}

// runtimeOf returns the latest RuntimeStatus nodeID reported, if recent.
func (u *usageStore) runtimeOf(nodeID string, now time.Time) *armadav1.RuntimeStatus {
	n, ok := u.node(nodeID, now)
	if !ok {
		return nil
	}
	return n.runtime
}

// runtimeMoved reports whether a node runs containers through armada-node
// with nothing left of Go's image store or images to pull again.
func runtimeMoved(st *armadav1.RuntimeStatus) bool {
	return st.GetAgent() == runtime.AgentSupervisorRust && !st.GetConverting() && st.GetImagesToPull() == 0
}

// runtimeProgress is where the nodes' move to armada-node stands (ADR
// 0054), from their latest reports.
func (s *Server) runtimeProgress(nodes []store.Node, now time.Time) *armadav1.RuntimeProgress {
	p := &armadav1.RuntimeProgress{Nodes: int32(len(nodes))} //nolint:gosec // bounded by the store
	var others []*armadav1.NodeRuntime
	for _, n := range nodes {
		st := s.usage.runtimeOf(n.ID, now)
		if runtimeMoved(st) {
			p.Moved++
			continue
		}
		others = append(others, &armadav1.NodeRuntime{Node: n.ID, Status: st})
	}
	slices.SortFunc(others, func(a, b *armadav1.NodeRuntime) int {
		switch {
		case a.Node < b.Node:
			return -1
		case a.Node > b.Node:
			return 1
		}
		return 0
	})
	p.OthersTotal = int32(len(others)) //nolint:gosec // bounded by the store
	if len(others) > maxRuntimeOthers {
		others = others[:maxRuntimeOthers]
	}
	p.Others = others
	return p
}
