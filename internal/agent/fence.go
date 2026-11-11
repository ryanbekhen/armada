package agent

import (
	"context"
	"strconv"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// Fencing (ADR 0041): a replica whose volumes fail over to another node
// stops once its agent has been cut off from the control plane for the time
// the server set, before the server restores the volumes elsewhere. The
// cluster never has two copies of a volume written at once, even when this
// node is only cut off and still reachable by clients.

// fencedMessage is a fenced replica's status.
const fencedMessage = "stopped: cut off from the control plane, so its volumes may be restored on another node"

// maxFenceAfter bounds the label read back from a container.
const maxFenceAfter = 7 * 24 * 3600

// setContact records whether the agent has a session with the server.
func (a *Agent) setContact(up bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.contactUp = up
	if !up {
		a.contactLost = time.Now()
	}
}

// cutOff is how long the agent has been without a session: since the last
// one ended, or since it started.
func (a *Agent) cutOff() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.contactUp {
		return 0
	}
	since := a.contactLost
	if since.IsZero() {
		since = a.began
	}
	return time.Since(since)
}

// fenced reports whether s must not run now.
func (a *Agent) fenced(s *armadav1.ReplicaSpec) bool {
	n := s.GetFenceAfterSeconds()
	return n > 0 && a.cutOff() >= time.Duration(n)*time.Second
}

func (a *Agent) markFenced(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fencedIDs[id] = true
}

// unfence forgets a fenced container and reports whether it was one.
func (a *Agent) unfence(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	was := a.fencedIDs[id]
	delete(a.fencedIDs, id)
	return was
}

// fenceUnassigned stops containers that carry a fence time before the agent
// has an assignment, such as after a restart while the control plane is
// out of reach: Reconcile leaves everything alone until then.
func (a *Agent) fenceUnassigned(ctx context.Context) {
	a.mu.Lock()
	assigned := a.desired != nil
	a.mu.Unlock()
	if assigned {
		return
	}
	cut := a.cutOff()
	if cut == 0 {
		return
	}
	cs, err := a.cfg.Driver.List(ctx, map[string]string{runtime.LabelManaged: "true"})
	if err != nil {
		return
	}
	for _, c := range cs {
		v, ok := c.Labels[runtime.LabelFenceAfter]
		if !ok || stopped(c.State) {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > maxFenceAfter || cut < time.Duration(n)*time.Second {
			continue
		}
		a.log.Warn("stopping a replica cut off from the control plane", "replica", c.Labels[runtime.LabelReplica])
		_ = a.cfg.Driver.Stop(ctx, c.ID, volumeStopGrace)
		a.markFenced(c.ID)
	}
}
