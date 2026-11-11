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

// CreateProject records a new project (ADR 0026).
func (s *Server) CreateProject(ctx context.Context, req *armadav1.CreateProjectRequest) (*armadav1.ProjectInfo, error) {
	name := req.GetName()
	if !spec.ValidProject(name) {
		return nil, status.Error(codes.InvalidArgument, "invalid project name: use lowercase letters, digits, and single hyphens, starting with a letter, at most 30 characters")
	}
	acc := accessFrom(ctx)
	if !acc.creates() {
		return nil, status.Errorf(codes.PermissionDenied, "%s may not create projects", acc.id)
	}
	// Whoever creates a project without cluster-admin becomes its admin
	// (ADR 0033).
	var by *store.Principal
	if !acc.admin() {
		by = acc.p
	}
	p, err := s.store.CreateProject(ctx, name, actor(ctx), by)
	if err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("project created", "project", name, "by", actor(ctx))
	info := projectInfo(p, 0)
	info.NetworkIsolation, err = s.isolated(ctx, name)
	if err != nil {
		return nil, storeErr(err)
	}
	return info, nil
}

// isolated reports whether the cluster network keeps project's containers
// apart (ADR 0026).
func (s *Server) isolated(ctx context.Context, project string) (bool, error) {
	def, others, err := s.isolation(ctx)
	if project == spec.DefaultProject {
		return def, err
	}
	return others, err
}

// isolation reports whether the default project and the others are
// isolated: never without a cluster network, always for projects other
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

// ListProjects lists every project with the number of apps and jobs in it.
func (s *Server) ListProjects(ctx context.Context, _ *armadav1.ListProjectsRequest) (*armadav1.ListProjectsResponse, error) {
	ps, err := s.store.ListProjects(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	// Apps and jobs both count; their IDs name the project.
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
	resp := &armadav1.ListProjectsResponse{}
	for _, p := range ps {
		if acc.project(p.Name) != nil {
			continue
		}
		info := projectInfo(p, count[p.Name])
		info.NetworkIsolation = isolateOthers
		if p.Name == spec.DefaultProject {
			info.NetworkIsolation = isolateDefault
		}
		resp.Projects = append(resp.Projects, info)
	}
	return resp, nil
}

// UpdateProject changes the default project's network isolation (ADR 0026).
// cluster-admin only.
func (s *Server) UpdateProject(ctx context.Context, req *armadav1.UpdateProjectRequest) (*armadav1.ProjectInfo, error) {
	name := req.GetName()
	if name == "" {
		name = spec.DefaultProject
	}
	if !spec.ValidProject(name) {
		return nil, status.Error(codes.InvalidArgument, "invalid project name")
	}
	if !accessFrom(ctx).admin() {
		return nil, status.Error(codes.PermissionDenied, "only cluster-admin changes project settings")
	}
	if req.NetworkIsolation != nil && !req.GetNetworkIsolation() && name != spec.DefaultProject {
		return nil, status.Errorf(codes.InvalidArgument, "project %s is always isolated; only the default project can turn network isolation off", name)
	}
	p, err := s.store.GetProject(ctx, name)
	if err != nil {
		return nil, storeErr(err)
	}
	if req.NetworkIsolation != nil {
		on := req.GetNetworkIsolation()
		if name == spec.DefaultProject {
			if err := s.store.SetDefaultIsolation(ctx, on, actor(ctx)); err != nil {
				return nil, storeErr(err)
			}
			s.log.Info("default project network isolation changed", "on", on, "by", actor(ctx))
			s.Trigger()
		}
	}
	info := projectInfo(p, 0)
	if info.NetworkIsolation, err = s.isolated(ctx, name); err != nil {
		return nil, storeErr(err)
	}
	return info, nil
}

// DeleteProject removes an empty project.
func (s *Server) DeleteProject(ctx context.Context, req *armadav1.DeleteProjectRequest) (*armadav1.DeleteProjectResponse, error) {
	name := req.GetName()
	if !spec.ValidProject(name) {
		return nil, status.Error(codes.InvalidArgument, "invalid project name")
	}
	acc := accessFrom(ctx)
	if err := acc.project(name); err != nil {
		return nil, err
	}
	if !acc.creates() {
		return nil, status.Errorf(codes.PermissionDenied, "%s may not delete projects", acc.id)
	}
	if err := s.store.DeleteProject(ctx, name, actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.usage.forgetProject(name)
	s.log.Info("project removed", "project", name, "by", actor(ctx))
	return &armadav1.DeleteProjectResponse{}, nil
}

func projectInfo(p store.Project, apps int32) *armadav1.ProjectInfo {
	info := &armadav1.ProjectInfo{Name: p.Name, CreatedBy: p.CreatedBy, Apps: apps}
	if !p.CreatedAt.IsZero() {
		info.CreatedAt = timestamppb.New(p.CreatedAt)
	}
	return info
}
