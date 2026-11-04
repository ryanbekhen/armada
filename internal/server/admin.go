package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

const (
	defaultLogTail = 100
	maxLogTail     = 10000
	attachTimeout  = 10 * time.Second
)

func storeErr(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return status.Error(codes.NotFound, err.Error())
	}
	if errors.Is(err, store.ErrConflict) {
		return status.Error(codes.AlreadyExists, err.Error())
	}
	if errors.Is(err, store.ErrPrecondition) {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	if errors.Is(err, store.ErrNotLeader) {
		return status.Error(codes.Unavailable, err.Error())
	}
	return status.Error(codes.Internal, "internal error")
}

func actor(ctx context.Context) string {
	id, _ := IdentityFrom(ctx)
	return id.String()
}

// Deploy validates a spec and records it as the app's active revision.
func (s *Server) Deploy(ctx context.Context, req *armadav1.DeployRequest) (*armadav1.DeployResponse, error) {
	acc := accessFrom(ctx)
	if err := acc.project(req.GetProject()); err != nil {
		return nil, err
	}
	app, err := spec.ParseIn(req.GetSpec(), req.GetProject())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := acc.placement(app); err != nil {
		return nil, err
	}
	rev, created, err := s.store.Deploy(ctx, app, actor(ctx))
	if err != nil {
		s.log.Error("deploy failed", "app", app.ID(), "err", err)
		return nil, storeErr(err)
	}
	s.log.Info("deployed", "app", app.ID(), "revision", rev.Name, "new_revision", created, "by", actor(ctx))
	switch {
	case app.MultipleRevisions():
		// No rollout: the traffic applies at once (ADR 0024).
		msg := "image " + app.Image
		if a, err := s.store.GetApp(ctx, app.ID()); err == nil {
			msg = trafficMessage(a.Traffic)
		}
		if created {
			msg += "; new revision " + rev.Name
		}
		s.record(ctx, store.Event{Kind: eventApp, Object: app.ID(), App: app.ID(), Reason: "TrafficChanged", Message: msg})
	case created && app.IsJob():
		s.record(ctx, store.Event{Kind: eventJob, Object: app.ID(), App: app.ID(), Reason: "Deployed", Message: "new runs use " + rev.Name + " (image " + app.Image + ")"})
	case created:
		s.record(ctx, store.Event{Kind: eventRollout, Object: rev.Name, App: app.ID(), Reason: "Started", Message: "rolling out " + rev.Name + " (image " + app.Image + ")"})
	}
	s.Trigger()
	return &armadav1.DeployResponse{App: app.ID(), Revision: rev.Name}, nil
}

// Scale sets an app's desired replica count until its next deploy.
func (s *Server) Scale(ctx context.Context, req *armadav1.ScaleRequest) (*armadav1.ScaleResponse, error) {
	if err := accessFrom(ctx).app(req.GetApp()); err != nil {
		return nil, err
	}
	n := int(req.GetReplicas())
	if n < 1 || n > spec.MaxReplicas {
		return nil, status.Errorf(codes.InvalidArgument, "replicas must be between 1 and %d", spec.MaxReplicas)
	}
	if err := s.store.SetReplicas(ctx, req.GetApp(), n, actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("scaled", "app", req.GetApp(), "replicas", n, "by", actor(ctx))
	s.Trigger()
	return &armadav1.ScaleResponse{}, nil
}

// SetTraffic changes how an app in multiple revision mode splits requests
// until its next deploy (ADR 0024).
func (s *Server) SetTraffic(ctx context.Context, req *armadav1.SetTrafficRequest) (*armadav1.SetTrafficResponse, error) {
	if err := accessFrom(ctx).app(req.GetApp()); err != nil {
		return nil, err
	}
	if len(req.GetTraffic()) > spec.MaxTrafficTargets {
		return nil, status.Errorf(codes.InvalidArgument, "at most %d revisions", spec.MaxTrafficTargets)
	}
	var want []spec.TrafficTarget
	for _, t := range req.GetTraffic() {
		want = append(want, spec.TrafficTarget{Revision: t.GetRevision(), Weight: int(t.GetWeight())})
	}
	got, err := s.store.SetTraffic(ctx, req.GetApp(), want, actor(ctx))
	if err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("traffic changed", "app", req.GetApp(), "by", actor(ctx))
	s.record(ctx, store.Event{Kind: eventApp, Object: req.GetApp(), App: req.GetApp(), Reason: "TrafficChanged", Message: trafficMessage(got)})
	s.Trigger()
	resp := &armadav1.SetTrafficResponse{}
	for _, t := range got {
		resp.Traffic = append(resp.Traffic, &armadav1.TrafficTarget{Revision: t.Revision, Weight: int32(t.Weight), Label: t.Label}) //nolint:gosec // 0 to 100
	}
	return resp, nil
}

// trafficMessage describes traffic for events: "web--r3 90%, web--r4 10%".
func trafficMessage(traffic []spec.TrafficTarget) string {
	parts := make([]string, 0, len(traffic))
	for _, t := range traffic {
		parts = append(parts, fmt.Sprintf("%s %d%%", t.Revision, t.Weight))
	}
	return strings.Join(parts, ", ")
}

// ListRevisions lists an app's retained revisions, newest first.
func (s *Server) ListRevisions(ctx context.Context, req *armadav1.ListRevisionsRequest) (*armadav1.ListRevisionsResponse, error) {
	if err := accessFrom(ctx).app(req.GetApp()); err != nil {
		return nil, err
	}
	app, err := s.store.GetApp(ctx, req.GetApp())
	if err != nil {
		return nil, storeErr(err)
	}
	revs, err := s.store.ListRevisions(ctx, app.Name)
	if err != nil {
		return nil, storeErr(err)
	}
	resp := &armadav1.ListRevisionsResponse{}
	for _, r := range revs {
		resp.Revisions = append(resp.Revisions, &armadav1.RevisionInfo{
			Name: r.Name, Image: r.Spec.Image, ImageDigest: r.ImageDigest, CreatedAt: timestamppb.New(r.CreatedAt),
			Active: r.Name == app.ActiveRevision, Target: r.Name == app.TargetRevision, Platforms: r.Platforms,
		})
	}
	return resp, nil
}

// Rollback rolls an app out to an earlier revision. Without a revision it
// cancels a rollout in progress, or else returns to the revision before the
// active one.
func (s *Server) Rollback(ctx context.Context, req *armadav1.RollbackRequest) (*armadav1.RollbackResponse, error) {
	if err := accessFrom(ctx).app(req.GetApp()); err != nil {
		return nil, err
	}
	app, err := s.store.GetApp(ctx, req.GetApp())
	if err != nil {
		return nil, storeErr(err)
	}
	target := req.GetRevision()
	if target == "" {
		if target, err = s.previousRevision(ctx, app); err != nil {
			return nil, err
		}
	}
	rev, err := s.store.Rollback(ctx, app.Name, target, actor(ctx))
	if err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("rollback", "app", app.Name, "revision", rev.Name, "by", actor(ctx))
	s.record(ctx, store.Event{Kind: eventRollout, Object: rev.Name, App: app.Name, Reason: "RolledBack", Message: "rolling back to " + rev.Name})
	s.Trigger()
	return &armadav1.RollbackResponse{Revision: rev.Name}, nil
}

func (s *Server) previousRevision(ctx context.Context, app store.App) (string, error) {
	if app.Rolling() {
		return app.ActiveRevision, nil
	}
	revs, err := s.store.ListRevisions(ctx, app.Name)
	if err != nil {
		return "", storeErr(err)
	}
	var activeSeq int
	for _, r := range revs {
		if r.Name == app.ActiveRevision {
			activeSeq = r.Seq
		}
	}
	for _, r := range revs { // newest first
		if r.Seq < activeSeq {
			return r.Name, nil
		}
	}
	return "", status.Errorf(codes.FailedPrecondition, "app %s has no earlier revision to roll back to", app.Name)
}

// Status reports apps, replicas, and nodes.
func (s *Server) Status(ctx context.Context, req *armadav1.StatusRequest) (*armadav1.StatusResponse, error) {
	acc := accessFrom(ctx)
	var apps []store.App
	if req.GetApp() != "" {
		if err := acc.app(req.GetApp()); err != nil {
			return nil, err
		}
		a, err := s.store.GetApp(ctx, req.GetApp())
		if err != nil {
			return nil, storeErr(err)
		}
		if a.Spec.IsJob() {
			return nil, status.Errorf(codes.FailedPrecondition, "%s is a job; see `armada job runs %s`", a.Name, a.Name)
		}
		apps = []store.App{a}
	} else {
		var err error
		if apps, err = s.store.ListApps(ctx); err != nil {
			return nil, storeErr(err)
		}
		apps = slices.DeleteFunc(apps, func(a store.App) bool { return !acc.sees(a.Name) })
	}

	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	all, err := s.store.ListReplicas(ctx, store.ReplicaFilter{})
	if err != nil {
		return nil, storeErr(err)
	}
	revs := &revisionCache{store: s.store, m: map[string]store.Revision{}}
	sched, err := s.allocatable(ctx, nodes)
	if err != nil {
		return nil, storeErr(err)
	}

	resp := &armadav1.StatusResponse{}
	for _, a := range apps {
		if a.Spec.IsJob() {
			continue // `armada job list`
		}
		var reps []store.Replica
		for _, r := range all {
			if r.App == a.Name {
				reps = append(reps, r)
			}
		}
		as := &armadav1.AppStatus{
			Name: a.Name, Image: a.Spec.Image, ActiveRevision: a.ActiveRevision,
			DesiredReplicas:  int32(a.Replicas), //nolint:gosec // bounded by spec.MaxReplicas
			Ingress:          a.Spec.Ingress.Type,
			Urls:             s.appURLs(ctx, a),
			TargetRevision:   a.TargetRevision,
			RolloutState:     a.RolloutState,
			RolloutMessage:   a.RolloutMessage,
			PlacementMessage: placementMessage(ctx, revs, sched, all, a),
		}
		if !a.Rolling() {
			shares := trafficShares(a.Replicas, a.Traffic)
			total := 0
			for i, t := range a.Traffic {
				//nolint:gosec // weights are 0 to 100, shares bounded by spec.MaxReplicas
				as.Traffic = append(as.Traffic, &armadav1.TrafficTarget{Revision: t.Revision, Weight: int32(t.Weight), Label: t.Label,
					Urls: s.labelURLs(ctx, a, t.Label), Replicas: int32(shares[i])})
				total += shares[i]
			}
			if total > 0 {
				as.DesiredReplicas = int32(total)
			}
		}
		if a.Spec.Autoscaled() {
			as.Autoscale = s.scaler.status(a.Name)
			if as.Autoscale == nil {
				lo, hi := a.Spec.ScaleBounds()
				as.Autoscale = &armadav1.Autoscale{Min: int32(lo), Max: int32(hi), Message: "waiting for the first evaluation"} //nolint:gosec // bounded by spec.MaxReplicas
			}
		}
		for _, r := range reps {
			as.Replicas = append(as.Replicas, &armadav1.ReplicaStatus{
				Id: r.ID, Revision: r.Revision, NodeId: r.NodeID, State: r.State,
				Message: r.Message, Address: r.Address, UpdatedAt: timestamppb.New(r.UpdatedAt),
				Ready: r.Ready, Draining: r.Draining(),
			})
		}
		resp.Apps = append(resp.Apps, as)
	}

	for _, n := range nodes {
		state := n.State
		if nodeLost(n, s.now(), s.nodeLostTimeout) {
			state = nodeStateLost
		}
		ns := &armadav1.NodeStatus{Id: n.ID, PrivateIp: n.PrivateIP, State: state, CpuMillis: n.CPUMillis, MemoryBytes: n.MemoryBytes, Cordoned: n.Cordoned, Version: n.Version,
			Labels: n.AllLabels(), Restricted: n.Restricted, Sandbox: n.Sandbox, Egress: n.Egress}
		if !n.LastSeen.IsZero() {
			ns.LastSeen = timestamppb.New(n.LastSeen)
		}
		if !n.CertNotAfter.IsZero() {
			ns.CertExpiresAt = timestamppb.New(n.CertNotAfter)
		}
		resp.Nodes = append(resp.Nodes, ns)
	}
	if !acc.admin() {
		// Nodes are the cluster's, not a project's.
		resp.Nodes = nil
	}
	return resp, nil
}

// Logs streams logs from an app's replicas by asking each replica's agent to
// push them.
func (s *Server) Logs(req *armadav1.LogsRequest, stream armadav1.AdminService_LogsServer) error {
	if err := accessFrom(stream.Context()).app(req.GetApp()); err != nil {
		return err
	}
	ctx := stream.Context()
	app, err := s.store.GetApp(ctx, req.GetApp())
	if err != nil {
		return storeErr(err)
	}
	reps, err := s.store.ListReplicas(ctx, store.ReplicaFilter{App: req.GetApp()})
	if err != nil {
		return storeErr(err)
	}
	switch {
	case req.GetRun() != 0 && !app.Spec.IsJob():
		return status.Errorf(codes.InvalidArgument, "%s is an app; --run is for jobs", app.Name)
	case app.Spec.IsJob() && req.GetReplica() == "":
		replica, err := s.runReplica(ctx, app.Name, req.GetRun())
		if err != nil {
			return err
		}
		req.Replica = replica
	}
	if req.GetReplica() != "" {
		var only []store.Replica
		for _, r := range reps {
			if r.ID == req.GetReplica() {
				only = append(only, r)
			}
		}
		if len(only) == 0 {
			return status.Errorf(codes.NotFound, "replica %s not found in app %s", req.GetReplica(), req.GetApp())
		}
		reps = only
	}
	tail := int32(defaultLogTail)
	if t := req.GetTail(); t > 0 {
		tail = min(t, maxLogTail)
	}

	out := make(chan *armadav1.LogEntry, 64)
	var wg sync.WaitGroup
	for _, r := range reps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.relayLogs(ctx, r, req.GetFollow(), tail, out)
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	for e := range out {
		if err := stream.Send(e); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) relayLogs(ctx context.Context, r store.Replica, follow bool, tail int32, out chan<- *armadav1.LogEntry) {
	notice := func(msg string) {
		select {
		case out <- &armadav1.LogEntry{Replica: r.ID, Stream: armadav1.Stream_STREAM_STDERR, Data: []byte("[armada] " + msg + "\n")}:
		case <-ctx.Done():
		}
	}
	sess := s.session(r.NodeID)
	if sess == nil {
		notice("node " + r.NodeID + " is not connected")
		return
	}
	id, p := s.logs.register(r.NodeID)
	defer s.logs.cancel(id, p)

	ok := sess.offer(&armadav1.ServerMessage{Msg: &armadav1.ServerMessage_LogRequest{LogRequest: &armadav1.LogRequest{
		RequestId: id, ReplicaId: r.ID, Follow: follow, Tail: tail,
	}}})
	if !ok {
		notice("node " + r.NodeID + " did not accept the log request")
		return
	}
	defer sess.offer(&armadav1.ServerMessage{Msg: &armadav1.ServerMessage_LogCancel{LogCancel: &armadav1.LogCancel{RequestId: id}}})

	select {
	case <-p.attached:
	case <-time.After(attachTimeout):
		notice("node " + r.NodeID + " did not send logs")
		return
	case <-ctx.Done():
		return
	}
	for {
		select {
		case m, open := <-p.ch:
			if !open {
				return
			}
			if m.GetError() != "" {
				notice(m.GetError())
				continue
			}
			if len(m.GetData()) == 0 {
				continue
			}
			select {
			case out <- &armadav1.LogEntry{Replica: r.ID, Stream: m.GetStream(), Data: m.GetData()}:
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
