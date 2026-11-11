package agent

import (
	"context"
	"errors"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/store"
)

// Held replicas (ADR 0023): during a rollout of an app with volumes, the
// server first sends the new replica held. The agent pulls its images and
// says so, but starts nothing while the old replica still uses the volume;
// the server lifts the hold once that one is gone, and the start only
// creates containers.
const (
	// holdPullTimeout bounds one attempt to pull a held replica's images.
	holdPullTimeout = 30 * time.Minute
	// holdRetry is how long a failed pull waits before the next attempt.
	holdRetry = 30 * time.Second
)

// heldPull is the pull of one held replica's images.
type heldPull struct {
	done     bool
	err      error
	failedAt time.Time
	// platforms the image has when it has none for this node.
	platforms []string
}

// held reports a held replica's state and pulls its images in the
// background, once, or again a while after a failure.
func (a *Agent) held(ctx context.Context, s *armadav1.ReplicaSpec) *armadav1.ReplicaState {
	id := s.GetId()
	st := &armadav1.ReplicaState{Id: id}
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.holds[id]
	if p != nil && p.err != nil && time.Since(p.failedAt) >= holdRetry {
		p = nil
	}
	switch {
	case p == nil:
		p = &heldPull{}
		a.holds[id] = p
		go a.pullHeld(ctx, s, p)
		fallthrough
	case !p.done:
		st.State, st.Message = store.ReplicaPulling, "pulling its images; it starts once the old replica stops"
	case p.err != nil:
		st.State, st.Message, st.ImagePlatforms = store.ReplicaFailed, p.err.Error(), p.platforms
	default:
		st.State, st.Message = store.ReplicaPulled, "images pulled; it starts once the old replica stops"
		st.ImageDigest = a.digests[s.GetImage()]
		st.ImagePlatforms = a.platforms[s.GetImage()]
	}
	return st
}

func (a *Agent) pullHeld(ctx context.Context, s *armadav1.ReplicaSpec, p *heldPull) {
	ctx, cancel := context.WithTimeout(ctx, holdPullTimeout)
	defer cancel()
	img, err := a.cfg.Driver.Pull(ctx, s.GetImage(), registryAuth(s))
	var platforms []string
	if pe := (*runtime.PlatformError)(nil); errors.As(err, &pe) {
		platforms = pe.Have
	}
	if err == nil {
		a.mu.Lock()
		if img.Ref != "" {
			a.digests[s.GetImage()] = img.Ref
		}
		if len(img.Platforms) > 0 {
			a.platforms[s.GetImage()] = img.Platforms
		}
		a.mu.Unlock()
		if hasMembers(s) {
			err = a.pullMembers(ctx, s, a.cfg.Driver.Pull)
		}
	}
	if err != nil {
		a.log.Warn("pull held replica's images failed", "replica", s.GetId(), "err", err)
	} else {
		a.log.Info("pulled held replica's images", "replica", s.GetId())
	}
	a.mu.Lock()
	p.done, p.err, p.platforms = true, err, platforms
	if err != nil {
		p.failedAt = time.Now()
	}
	a.mu.Unlock()
	a.Trigger()
}

// forgetHolds drops the pulls of replicas that are no longer held.
func (a *Agent) forgetHolds(desired map[string]*armadav1.ReplicaSpec) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id := range a.holds {
		if s, ok := desired[id]; !ok || !s.GetHold() {
			delete(a.holds, id)
		}
	}
}
