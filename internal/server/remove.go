package server

import (
	"context"
	"slices"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

// RemoveApp starts removing an app. The reconciler drains its replicas and
// then removes it, so requests in progress finish as in any other rollout.
func (s *Server) RemoveApp(ctx context.Context, req *armadav1.RemoveAppRequest) (*armadav1.RemoveAppResponse, error) {
	if err := accessFrom(ctx).app(req.GetApp()); err != nil {
		return nil, err
	}
	if err := s.store.MarkAppRemoving(ctx, req.GetApp(), actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("removing app", "app", req.GetApp(), "by", actor(ctx))
	s.record(ctx, store.Event{Kind: eventApp, Object: req.GetApp(), App: req.GetApp(), Reason: "Removing", Message: "by " + actor(ctx)})
	s.Trigger()
	return &armadav1.RemoveAppResponse{}, nil
}

// reconcileRemoval drains the replicas of an app being removed and, when none
// is left, removes the app. It reports whether the app is gone.
func (s *Server) reconcileRemoval(ctx context.Context, rc *reconcileRun, app store.App, all []store.Replica) ([]store.Replica, bool, error) {
	var err error
	for _, r := range slices.Clone(all) {
		if r.App != app.Name {
			continue
		}
		if r.Draining() {
			all, err = s.finishDrain(ctx, rc, all, r)
		} else {
			all, err = s.retire(ctx, rc, all, r)
		}
		if err != nil {
			return nil, false, err
		}
	}
	if slices.ContainsFunc(all, func(r store.Replica) bool { return r.App == app.Name }) {
		return all, false, nil
	}
	if err := s.store.DeleteApp(ctx, app.Name); err != nil {
		return nil, false, err
	}
	s.log.Info("removed app", "app", app.Name)
	s.record(ctx, store.Event{Kind: eventApp, Object: app.Name, App: app.Name, Reason: "Removed"})
	return all, true, nil
}
