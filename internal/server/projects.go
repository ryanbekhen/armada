package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// CreateProject records a new project (ADR 0029).
func (s *Server) CreateProject(ctx context.Context, req *armadav1.CreateProjectRequest) (*armadav1.ProjectInfo, error) {
	name := req.GetName()
	if !spec.ValidProject(name) {
		return nil, status.Error(codes.InvalidArgument, "invalid project name: use lowercase letters, digits, and single hyphens, starting with a letter, at most 30 characters")
	}
	acc := accessFrom(ctx)
	if !acc.admin() && acc.automation() == "" {
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}
	if !acc.admin() && !acc.scope.CreateProjects {
		return nil, status.Errorf(codes.PermissionDenied, "%s may not create projects", acc.id)
	}
	p, err := s.store.CreateProject(ctx, name, actor(ctx), acc.automation())
	if err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("project created", "project", name, "by", actor(ctx))
	return projectInfo(p, 0), nil
}

// ListProjects lists every project with the number of apps and jobs in it.
func (s *Server) ListProjects(ctx context.Context, _ *armadav1.ListProjectsRequest) (*armadav1.ListProjectsResponse, error) {
	ps, err := s.store.ListProjects(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	apps, err := s.store.ListApps(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	count := map[string]int32{}
	for _, a := range apps {
		if p, _, ok := spec.SplitAppID(a.Name); ok {
			count[p]++
		}
	}
	acc := accessFrom(ctx)
	resp := &armadav1.ListProjectsResponse{}
	for _, p := range ps {
		if acc.project(p.Name) != nil {
			continue
		}
		resp.Projects = append(resp.Projects, projectInfo(p, count[p.Name]))
	}
	return resp, nil
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
	if !acc.admin() && !acc.scope.CreateProjects {
		return nil, status.Errorf(codes.PermissionDenied, "%s may not remove projects", acc.id)
	}
	if err := s.store.DeleteProject(ctx, name, actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
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
