package server

import (
	"context"
	"fmt"

	"github.com/ryanbekhen/armada/internal/store"
)

// placementMessage explains, when no node can take more replicas of app
// (ADR 0014), why it has fewer replicas of its target revision than desired
// or why some stay on nodes it may no longer use; it returns "" when there
// is room or nothing is waiting.
func placementMessage(ctx context.Context, revs *revisionCache, nodes []store.Node, all []store.Replica, app store.App) string {
	target, err := revs.get(ctx, app.TargetRevision)
	if err != nil {
		return ""
	}
	fit := eligible(nodes, target.Spec)
	allowed := map[string]bool{}
	for _, n := range fit {
		allowed[n.ID] = true
	}
	live, stuck := 0, 0
	for _, r := range all {
		if r.App == app.Name && r.Revision == app.TargetRevision && !r.Draining() {
			live++
			if !allowed[r.NodeID] {
				stuck++
			}
		}
	}
	if live >= app.Replicas && stuck == 0 {
		return ""
	}
	var why string
	switch {
	case len(fit) == 0 && target.Spec.Placement.String() != "":
		why = fmt.Sprintf("no ready node matches the placement (%s)", target.Spec.Placement.String())
	case len(fit) == 0:
		why = "no ready node accepts the app (every ready node is cordoned or restricted)"
	default:
		if _, ok := pickNode(fit, all, app.Name, target.Spec.MemoryBytes(), revs.memory(ctx)); ok {
			return ""
		}
		why = fmt.Sprintf("%d node(s) may run the app, none has %s of memory free", len(fit), humanMemory(target.Spec.MemoryBytes()))
	}
	if live < app.Replicas {
		return "waiting for a node: " + why
	}
	return fmt.Sprintf("%d replica(s) stay on nodes the app may no longer use until one is free: %s", stuck, why)
}

func humanMemory(b int64) string {
	switch {
	case b >= 1<<30 && b%(1<<30) == 0:
		return fmt.Sprintf("%dGi", b>>30)
	case b >= 1<<20:
		return fmt.Sprintf("%dMi", b>>20)
	}
	return fmt.Sprintf("%d bytes", b)
}
