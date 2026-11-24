package agent

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// moveRuntimeTimeout bounds one move of the node to the supervisor runtime:
// stopping and removing every container, then recording the runtime.
const moveRuntimeTimeout = 10 * time.Minute

// moveRuntime moves the node to the runtime the leader names (ADR 0054,
// "The runtime's move", step 4), once nothing of the node's assignment
// runs: Config.PrepareRuntimeMove first readies what the node needs right
// after its restart (its proxy's image) while everything still runs, then
// Config.MoveRuntime removes every container (the node's proxy too),
// records the runtime, and restarts the node's service, which ends this
// process. Why it did not is reported with the node's runtime until the
// next request. One move runs at a time; a request while one runs, or
// after one succeeded, is ignored.
func (a *Agent) moveRuntime(ctx context.Context, m *armadav1.MoveRuntime) {
	if a.cfg.MoveRuntime == nil || !a.moving.CompareAndSwap(false, true) {
		return
	}
	err := a.tryMoveRuntime(context.WithoutCancel(ctx), m.GetTo())
	if err != nil {
		a.log.Warn("did not move the node to another runtime", "to", m.GetTo(), "err", err)
		a.moveErr.Store(err.Error())
		a.moving.Store(false)
		return
	}
	a.moveErr.Store("")
}

func (a *Agent) tryMoveRuntime(ctx context.Context, to string) error {
	ctx, cancel := context.WithTimeout(ctx, moveRuntimeTimeout)
	defer cancel()
	if a.cfg.PrepareRuntimeMove != nil {
		// Checked first, so a node that cannot move does no work for it.
		// The preparation runs outside reconcileMu: the node's proxy keeps
		// following the cluster meanwhile.
		if err := a.movable(); err != nil {
			return err
		}
		a.cfg.PrepareRuntimeMove(ctx, to)
	}
	// No replica starts while the containers go.
	a.reconcileMu.Lock()
	defer a.reconcileMu.Unlock()
	if err := a.movable(); err != nil {
		return err
	}
	a.log.Warn("moving this node to the supervisor runtime: removing its containers, its proxy's too, and restarting the service", "to", to)
	return a.cfg.MoveRuntime(ctx, to)
}

// movable says why the node cannot move to another runtime now, or nil.
func (a *Agent) movable() error {
	a.mu.Lock()
	left, assigned := movableLeft(a.desired)
	a.mu.Unlock()
	switch {
	case !assigned:
		return fmt.Errorf("no assignment from the control plane yet")
	case len(left) > 0:
		more := ""
		if len(left) > 5 {
			left, more = left[:5], fmt.Sprintf(" and %d more", len(left)-5)
		}
		return fmt.Errorf("replicas are still assigned to this node: %s%s", strings.Join(left, ", "), more)
	case a.volumeOps.Load() > 0:
		return fmt.Errorf("a volume operation runs on this node")
	}
	return nil
}

// movableLeft returns the replicas of an assignment that keep a node from
// moving to another runtime, sorted: every one but finished job attempts,
// whose containers are only kept for their logs. assigned is false before
// the first assignment.
func movableLeft(desired map[string]*armadav1.ReplicaSpec) (left []string, assigned bool) {
	if desired == nil {
		return nil, false
	}
	for id, r := range desired {
		if !r.GetJob().GetDone() {
			left = append(left, id)
		}
	}
	slices.Sort(left)
	return left, true
}

// setRuntimeMovePlan hands what the leader plans for the node's runtime to
// Config.OnRuntimeMove when it changes.
func (a *Agent) setRuntimeMovePlan(p *armadav1.RuntimeMovePlan) {
	if a.cfg.OnRuntimeMove == nil {
		return
	}
	a.mu.Lock()
	same := a.movePlanSet && proto.Equal(a.movePlan, p)
	a.movePlan, a.movePlanSet = p, true
	a.mu.Unlock()
	if !same {
		a.cfg.OnRuntimeMove(p)
	}
}

// withMoveError adds why the node last did not move to another runtime to
// its runtime status.
func (a *Agent) withMoveError(st *armadav1.RuntimeStatus) *armadav1.RuntimeStatus {
	if st == nil || st.GetAgent() != runtime.AgentContainerd {
		return st
	}
	if e, _ := a.moveErr.Load().(string); e != "" {
		st.MoveError = e
	}
	return st
}
