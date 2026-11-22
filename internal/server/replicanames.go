package server

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// maxChoices bounds the names an error lists as choices.
const maxChoices = 20

// shortReplica is the name `armada replica list` prints for a replica: the
// part of its ID after the last hyphen (ADR 0052).
func shortReplica(id string) string {
	return id[strings.LastIndexByte(id, '-')+1:]
}

// findReplica finds the replica of app a person named: its ID, or its
// short name. An error lists the app's replicas by short name.
func findReplica(app string, reps []store.Replica, name string) (store.Replica, error) {
	var found []store.Replica
	for _, r := range reps {
		if r.ID == name {
			return r, nil
		}
		if shortReplica(r.ID) == name {
			found = append(found, r)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		names := make([]string, 0, len(reps))
		for _, r := range reps {
			names = append(names, shortReplica(r.ID))
		}
		if len(names) == 0 {
			return store.Replica{}, status.Errorf(codes.NotFound, "%s has no replicas", app)
		}
		return store.Replica{}, status.Errorf(codes.NotFound, "%s has no replica %q; its replicas: %s", app, name, choices(names))
	}
	ids := make([]string, 0, len(found))
	for _, r := range found {
		ids = append(ids, r.ID)
	}
	return store.Replica{}, status.Errorf(codes.InvalidArgument, "%q names more than one replica of %s; give the full ID: %s", name, app, choices(ids))
}

// specContainers are the containers of a replica of sp: "app" and its
// sidecars, then its init containers (ADR 0038).
func specContainers(sp *spec.App) (running, inits []string) {
	running = []string{spec.MainContainer}
	if sp == nil {
		return running, nil
	}
	for _, c := range sp.Sidecars {
		running = append(running, c.Name)
	}
	for _, c := range sp.InitContainers {
		inits = append(inits, c.Name)
	}
	return running, inits
}

// checkContainer refuses a container no revision of revs has, naming the
// ones they have; exec takes only running ones (no init containers).
func (s *Server) checkContainer(ctx context.Context, app, name string, revs []string, exec bool) error {
	if name == "" || name == spec.MainContainer {
		return nil
	}
	var running, inits []string
	for _, n := range revs {
		rev, err := s.store.GetRevision(ctx, n)
		if err != nil {
			return storeErr(err)
		}
		r, i := specContainers(rev.Spec)
		for _, c := range r {
			if !slices.Contains(running, c) {
				running = append(running, c)
			}
		}
		for _, c := range i {
			if !slices.Contains(inits, c) {
				inits = append(inits, c)
			}
		}
	}
	switch {
	case slices.Contains(running, name):
		return nil
	case slices.Contains(inits, name) && !exec:
		return nil
	case slices.Contains(inits, name):
		return status.Errorf(codes.FailedPrecondition, "%s is an init container of %s and runs only before the app starts; see its output with armada app logs %s --container %s", name, app, app, name)
	}
	all := running
	if !exec {
		all = append(slices.Clone(running), inits...)
	}
	return status.Errorf(codes.NotFound, "%s has no container %q; its containers: %s", app, name, choices(all))
}

// choices lists names for an error, at most maxChoices of them.
func choices(names []string) string {
	names = slices.Clone(names)
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) > maxChoices {
		return strings.Join(names[:maxChoices], ", ") + fmt.Sprintf(", and %d more", len(names)-maxChoices)
	}
	return strings.Join(names, ", ")
}
