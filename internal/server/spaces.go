package server

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// CreateSpace records a new space (ADR 0026).
func (s *Server) CreateSpace(ctx context.Context, req *armadav1.CreateSpaceRequest) (*armadav1.SpaceInfo, error) {
	name := req.GetName()
	if !spec.ValidSpace(name) {
		return nil, status.Error(codes.InvalidArgument, "invalid space name: use lowercase letters, digits, and single hyphens, starting with a letter, at most 30 characters")
	}
	acc := accessFrom(ctx)
	if !acc.creates() {
		return nil, status.Errorf(codes.PermissionDenied, "%s may not create spaces", acc.id)
	}
	// Whoever creates a space without cluster-admin becomes its admin
	// (ADR 0033).
	var by *store.Principal
	if !acc.admin() {
		by = acc.p
	}
	p, err := s.store.CreateSpace(ctx, name, actor(ctx), by)
	if err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("space created", "space", name, "by", actor(ctx))
	info := spaceInfo(p, 0)
	info.NetworkIsolation, err = s.isolated(ctx, name)
	if err != nil {
		return nil, storeErr(err)
	}
	return info, nil
}

// isolated reports whether the cluster network keeps space's containers
// apart (ADR 0026).
func (s *Server) isolated(ctx context.Context, space string) (bool, error) {
	def, others, err := s.isolation(ctx)
	if space == spec.DefaultSpace {
		return def, err
	}
	return others, err
}

// isolation reports whether the default space and the others are
// isolated: never without a cluster network, always for spaces other
// than default, and for default once a cluster-admin turns it on.
func (s *Server) isolation(ctx context.Context) (def, others bool, err error) {
	n, err := s.store.GetNetwork(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return n.IsolateDefault, true, nil
}

// ListSpaces lists every space with the number of apps and jobs in it.
func (s *Server) ListSpaces(ctx context.Context, _ *armadav1.ListSpacesRequest) (*armadav1.ListSpacesResponse, error) {
	ps, err := s.store.ListSpaces(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	// Apps and jobs both count; their IDs name the space.
	ids, err := s.store.ListAppIDs(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	count := map[string]int32{}
	for _, id := range ids {
		if p, _, ok := spec.SplitAppID(id); ok {
			count[p]++
		}
	}
	isolateDefault, isolateOthers, err := s.isolation(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	acc := accessFrom(ctx)
	resp := &armadav1.ListSpacesResponse{}
	for _, p := range ps {
		if acc.space(p.Name) != nil {
			continue
		}
		info := spaceInfo(p, count[p.Name])
		info.NetworkIsolation = isolateOthers
		if p.Name == spec.DefaultSpace {
			info.NetworkIsolation = isolateDefault
		}
		resp.Spaces = append(resp.Spaces, info)
	}
	return resp, nil
}

// UpdateSpace changes the default space's network isolation (ADR 0026).
// cluster-admin only.
func (s *Server) UpdateSpace(ctx context.Context, req *armadav1.UpdateSpaceRequest) (*armadav1.SpaceInfo, error) {
	name := req.GetName()
	if name == "" {
		name = spec.DefaultSpace
	}
	if !spec.ValidSpace(name) {
		return nil, status.Error(codes.InvalidArgument, "invalid space name")
	}
	if !accessFrom(ctx).admin() {
		return nil, status.Error(codes.PermissionDenied, "only cluster-admin changes space settings")
	}
	if req.NetworkIsolation != nil && !req.GetNetworkIsolation() && name != spec.DefaultSpace {
		return nil, status.Errorf(codes.InvalidArgument, "space %s is always isolated; only the default space can turn network isolation off", name)
	}
	p, err := s.store.GetSpace(ctx, name)
	if err != nil {
		return nil, storeErr(err)
	}
	if req.NetworkIsolation != nil {
		on := req.GetNetworkIsolation()
		if name == spec.DefaultSpace {
			if err := s.store.SetDefaultIsolation(ctx, on, actor(ctx)); err != nil {
				return nil, storeErr(err)
			}
			s.log.Info("default space network isolation changed", "on", on, "by", actor(ctx))
			s.Trigger()
		}
	}
	info := spaceInfo(p, 0)
	if info.NetworkIsolation, err = s.isolated(ctx, name); err != nil {
		return nil, storeErr(err)
	}
	return info, nil
}

// DeleteSpace removes an empty space.
func (s *Server) DeleteSpace(ctx context.Context, req *armadav1.DeleteSpaceRequest) (*armadav1.DeleteSpaceResponse, error) {
	name := req.GetName()
	if !spec.ValidSpace(name) {
		return nil, status.Error(codes.InvalidArgument, "invalid space name")
	}
	acc := accessFrom(ctx)
	if err := acc.space(name); err != nil {
		return nil, err
	}
	if !acc.creates() {
		return nil, status.Errorf(codes.PermissionDenied, "%s may not delete spaces", acc.id)
	}
	if err := s.store.DeleteSpace(ctx, name, actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.usage.forgetSpace(name)
	s.log.Info("space removed", "space", name, "by", actor(ctx))
	return &armadav1.DeleteSpaceResponse{}, nil
}

func spaceInfo(p store.Space, apps int32) *armadav1.SpaceInfo {
	info := &armadav1.SpaceInfo{Name: p.Name, CreatedBy: p.CreatedBy, Apps: apps}
	if !p.CreatedAt.IsZero() {
		info.CreatedAt = timestamppb.New(p.CreatedAt)
	}
	return info
}
