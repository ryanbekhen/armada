package agent

import (
	"context"
	"strconv"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/store"
)

// attempt runs one attempt of a job run (ADR 0019). Its container runs
// once: it is never restarted, and when it exits its exit code is
// reported. A done attempt is stopped if it still runs, never started, and
// kept for its logs until the server drops it. It returns nil when there
// is nothing to report.
func (a *Agent) attempt(ctx context.Context, s *armadav1.ReplicaSpec, hash string, c runtime.Container, ok bool) *armadav1.ReplicaState {
	done := s.GetJob().GetDone()
	if ok && c.State == runtime.StateCreated && !done {
		// Created but never started (the agent stopped in between): the
		// job has not run yet, so starting it afresh runs it once.
		a.remove(ctx, c.ID)
		ok = false
	}
	if !ok {
		if done {
			return nil
		}
		var err error
		c, err = a.start(ctx, s, hash, a.cfg.Driver.Pull)
		if err == nil && a.cfg.Unpublished && a.cfg.Network != nil {
			a.applyNetworkNow(ctx)
		}
		if err != nil {
			a.log.Error("start job attempt failed", "replica", s.GetId(), "err", err)
			return &armadav1.ReplicaState{Id: s.GetId(), State: store.ReplicaFailed, Message: err.Error()}
		}
	}
	if !stopped(c.State) {
		if !done {
			return a.state(ctx, s, c)
		}
		a.log.Info("stopping job attempt", "replica", s.GetId())
		if err := a.cfg.Driver.Stop(ctx, c.ID, stopGrace); err != nil {
			a.log.Warn("stop failed", "container", c.ID, "err", err)
		}
	}
	// Listing does not include the exit code.
	full, err := a.cfg.Driver.Inspect(ctx, c.ID)
	if err != nil {
		return &armadav1.ReplicaState{Id: s.GetId(), State: store.ReplicaExited, ContainerId: c.ID, Message: "exit code unknown: " + err.Error()}
	}
	if !stopped(full.State) {
		return a.state(ctx, s, full)
	}
	// The attempt ends with the job's own container: its sidecars stop
	// with it (ADR 0038).
	if len(full.Members) > 0 {
		if err := a.cfg.Driver.Stop(ctx, c.ID, stopGrace); err != nil {
			a.log.Warn("stop sidecars failed", "container", c.ID, "err", err)
		}
	}
	// The kept container is only for its logs: its address goes back at once,
	// so finished runs do not fill the node's subnet.
	if nr, ok := a.cfg.Driver.(runtime.NetworkReleaser); ok {
		if err := nr.ReleaseNetwork(ctx, c.ID); err != nil {
			a.log.Warn("release network", "container", c.ID, "err", err)
		}
	}
	st := a.state(ctx, s, full)
	st.State, st.Finished, st.ExitCode = store.ReplicaExited, true, int32(full.ExitCode) //nolint:gosec // exit codes are small
	st.Message = "exited with code " + strconv.Itoa(full.ExitCode)
	// An init container that failed ends the attempt with its exit code;
	// the job's own container never ran (ADR 0038).
	if down := memberDown(s, full); down != "" {
		st.Message = down
		if m, ok := full.FailedInit(); ok {
			st.ExitCode = int32(m.ExitCode) //nolint:gosec // exit codes are small
		}
	}
	return st
}
