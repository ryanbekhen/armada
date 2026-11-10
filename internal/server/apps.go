package server

import (
	"cmp"
	"context"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// Bounds of the app listings (ADR 0032).
const (
	maxAppsPage  = 500
	maxAttention = 20
	appReady     = "ready"
	appProgress  = "progressing"
	appFailing   = "failing"
	appIdle      = "idle"
	defaultScope = spec.DefaultProject
)

// appSummaries builds a summary for each app (not job) the caller sees,
// reading the store once for all of them.
func (s *Server) appSummaries(ctx context.Context, keep func(store.App) bool) ([]*armadav1.AppSummary, error) {
	acc := accessFrom(ctx)
	apps, err := s.store.ListApps(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	reps, err := s.store.ListReplicas(ctx, store.ReplicaFilter{})
	if err != nil {
		return nil, storeErr(err)
	}
	ready := map[string]int{}
	for _, r := range reps {
		if r.Ready && !r.Draining() && !r.Done {
			ready[r.App]++
		}
	}
	src := s.urlSource(ctx)
	var out []*armadav1.AppSummary
	for _, a := range apps {
		if a.Spec.IsJob() || !acc.sees(a.Name) || !keep(a) {
			continue
		}
		sum := &armadav1.AppSummary{
			Name: a.Name, Project: cmp.Or(a.Spec.Project, defaultScope), Image: a.Spec.Image, Revision: a.ActiveRevision,
			Ready: int32(min(ready[a.Name], 1<<30)), Desired: int32(a.Replicas), //nolint:gosec // bounded above and by spec.MaxReplicas
		}
		if a.Spec.Ingress != nil {
			sum.Ingress = a.Spec.Ingress.Type
		}
		if urls := appURLsFrom(a, src); len(urls) > 0 {
			sum.Url = urls[0]
		}
		switch {
		case a.Removing:
			sum.State, sum.Message = appProgress, "being removed"
		case a.RolloutState == store.RolloutFailed:
			sum.State, sum.Message = appFailing, a.RolloutMessage
		case a.Rolling():
			sum.State, sum.Message = appProgress, "rolling out "+a.TargetRevision
		case a.Replicas == 0:
			sum.State = appIdle
		case int(sum.Ready) < a.Replicas:
			sum.State, sum.Message = appFailing, "not every replica is ready"
		default:
			sum.State = appReady
		}
		out = append(out, sum)
	}
	slices.SortFunc(out, func(x, y *armadav1.AppSummary) int { return cmp.Compare(x.Name, y.Name) })
	return out, nil
}

// ListApps lists apps one summary each, in one project or every project the
// caller sees, a page at a time.
func (s *Server) ListApps(ctx context.Context, req *armadav1.ListAppsRequest) (*armadav1.ListAppsResponse, error) {
	acc := accessFrom(ctx)
	project := cmp.Or(req.GetProject(), defaultScope)
	if !req.GetAllProjects() {
		if err := acc.project(req.GetProject()); err != nil {
			return nil, err
		}
	}
	size := int(req.GetPageSize())
	if size <= 0 || size > maxAppsPage {
		size = maxAppsPage
	}
	all, err := s.appSummaries(ctx, func(a store.App) bool {
		return req.GetAllProjects() || cmp.Or(a.Spec.Project, defaultScope) == project
	})
	if err != nil {
		return nil, err
	}
	start := 0
	if t := req.GetPageToken(); t != "" {
		start, _ = slices.BinarySearchFunc(all, t, func(x *armadav1.AppSummary, t string) int { return cmp.Compare(x.Name, t) })
		for start < len(all) && all[start].Name <= t {
			start++
		}
	}
	end := min(start+size, len(all))
	resp := &armadav1.ListAppsResponse{Apps: all[start:end]}
	if end < len(all) {
		resp.NextPageToken = all[end-1].Name
	}
	return resp, nil
}

// ClusterStatus summarizes the cluster: counts, and the apps and nodes that
// need attention, bounded however large the cluster is.
func (s *Server) ClusterStatus(ctx context.Context, _ *armadav1.ClusterStatusRequest) (*armadav1.ClusterStatusResponse, error) {
	if !accessFrom(ctx).admin() {
		return nil, status.Error(codes.PermissionDenied, "the cluster's status needs cluster-admin")
	}
	apps, err := s.appSummaries(ctx, func(store.App) bool { return true })
	if err != nil {
		return nil, err
	}
	resp := &armadav1.ClusterStatusResponse{Apps: int32(len(apps))} //nolint:gosec // bounded by the store
	for _, a := range apps {
		switch a.State {
		case appReady, appIdle:
			resp.AppsReady++
			continue
		case appProgress:
			resp.AppsProgressing++
		case appFailing:
			resp.AppsFailing++
		}
		resp.AttentionTotal++
		if len(resp.Attention) < maxAttention {
			resp.Attention = append(resp.Attention, a)
		}
	}
	all, err := s.store.ListApps(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	for _, a := range all {
		if a.Spec.IsJob() {
			resp.Jobs++
		}
	}
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	for _, n := range nodes {
		resp.Nodes++
		if n.State == store.NodeReady && !nodeLost(n, s.now(), s.nodeLostTimeout) {
			resp.NodesReady++
		} else {
			resp.NodesNotReady = append(resp.NodesNotReady, n.ID)
		}
	}
	return resp, nil
}

// GetAppSpec returns the spec an app or job runs (its target revision) as a
// file holds it, ready to import elsewhere (ADR 0032).
func (s *Server) GetAppSpec(ctx context.Context, req *armadav1.GetAppSpecRequest) (*armadav1.GetAppSpecResponse, error) {
	if err := accessFrom(ctx).app(req.GetApp()); err != nil {
		return nil, err
	}
	a, err := s.store.GetApp(ctx, req.GetApp())
	if err != nil {
		return nil, storeErr(err)
	}
	rev, err := s.store.GetRevision(ctx, a.TargetRevision)
	if err != nil {
		return nil, storeErr(err)
	}
	out, err := rev.Spec.Export()
	if err != nil {
		return nil, status.Error(codes.Internal, "export the spec")
	}
	return &armadav1.GetAppSpecResponse{Spec: out, Revision: rev.Name}, nil
}
