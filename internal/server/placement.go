package server

import (
	"context"
	"fmt"

	"github.com/ryanbekhen/armada/internal/store"
)

// placementMessage explains why app has fewer replicas of its target
// revision than desired when no node can take more (ADR 0014); it returns
// "" when there is room or nothing is missing.
func placementMessage(ctx context.Context, revs *revisionCache, nodes []store.Node, all []store.Replica, app store.App) string {
	live := 0
	for _, r := range all {
		if r.App == app.Name && r.Revision == app.TargetRevision && !r.Draining() {
			live++
		}
	}
	if live >= app.Replicas {
		return ""
	}
	target, err := revs.get(ctx, app.TargetRevision)
	if err != nil {
		return ""
	}
	fit := eligible(nodes, target.Spec)
	if len(fit) == 0 {
		if req := target.Spec.Placement.String(); req != "" {
			return fmt.Sprintf("waiting for a node: no ready node matches the placement (%s)", req)
		}
		return "waiting for a node: no ready node accepts the app (every ready node is cordoned or restricted)"
	}
	if _, ok := pickNode(fit, all, app.Name, target.Spec.MemoryBytes(), revs.memory(ctx)); !ok {
		return fmt.Sprintf("waiting for a node: %d node(s) may run the app, none has %s of memory free", len(fit), humanMemory(target.Spec.MemoryBytes()))
	}
	return ""
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
