package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/ryanbekhen/armada/internal/store"
)

// placementMessage explains, when no node can take more replicas of app
// (ADR 0014), why it has fewer replicas of its target revision than desired
// or why some stay on nodes it may no longer use; it returns "" when there
// is room or nothing is waiting. nodes carry their allocatable capacity.
func placementMessage(ctx context.Context, revs *revisionCache, nodes []store.Node, all []store.Replica, app store.App) string {
	target, err := revs.get(ctx, app.TargetRevision)
	if err != nil {
		return ""
	}
	fit := eligible(nodes, target)
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
	case len(fit) == 0:
		why = noNodeReason(nodes, target)
	default:
		want, reserved := reservation(target), revs.reserved(ctx)
		if _, ok := pickNode(fit, all, nil, want, reserved); ok {
			return ""
		}
		// Name what is short: CPU, memory, or only the two together.
		short := want.String()
		if _, ok := pickNode(fit, all, nil, resources{mem: want.mem}, reserved); !ok {
			short = humanMemory(want.mem) + " of memory"
		} else if _, ok := pickNode(fit, all, nil, resources{cpu: want.cpu}, reserved); !ok {
			short = humanCPU(want.cpu) + " of CPU"
		}
		why = fmt.Sprintf("%d node(s) may run the app, none has %s free", len(fit), short)
	}
	if live < app.Replicas {
		return "waiting for a node: " + why
	}
	return fmt.Sprintf("%d replica(s) stay on nodes the app may no longer use until one is free: %s", stuck, why)
}

// noNodeReason explains why no node is eligible for rev.
func noNodeReason(nodes []store.Node, rev store.Revision) string {
	labelled := 0
	for _, n := range nodes {
		if n.State != store.NodeReady || n.Cordoned {
			continue
		}
		if placementAllows(n, store.Revision{Spec: rev.Spec}) {
			labelled++
		}
	}
	switch {
	case labelled > 0:
		return fmt.Sprintf("no ready node can run the image, which is built for %s", strings.Join(rev.Platforms, ", "))
	case rev.Spec.Placement.String() != "":
		return fmt.Sprintf("no ready node matches the placement (%s)", rev.Spec.Placement.String())
	}
	return "no ready node accepts the app (every ready node is cordoned or restricted)"
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
