package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// Volumes (ADR 0025).
const (
	// volumeChunk is the most archive data one message carries.
	volumeChunk = 64 << 10
	// volumeUsageMaxAge is how long a node's volume measurement counts: a
	// few of its agent's one-minute measurements.
	volumeUsageMaxAge = 3*time.Minute + 30*time.Second
	// maxVolumeReports bounds the volumes in one report; a node with more
	// is reported as unmeasured.
	maxVolumeReports = 1024
	maxVolumeBytes   = 1 << 50 // 1 PiB
)

// reconcileVolumeApp converges an app whose target revision mounts volumes:
// at most one replica, always on the node its volumes are bound to, and a
// new replica only once every other replica of the app is gone, so two
// containers never write the same volume (recreate). Nothing is moved off a
// cordoned or lost node: the data is there.
func (s *Server) reconcileVolumeApp(ctx context.Context, rc *reconcileRun, app *store.App, target store.Revision, nodes []store.Node, all []store.Replica, revs *revisionCache) ([]store.Replica, error) {
	serving := func(r store.Replica) bool { return s.serving(rc, r, publishesPort(target.Spec)) }
	pinned, split, err := s.volumeNode(ctx, app.Name, target)
	if err != nil {
		return nil, err
	}

	var err2 error
	var current []store.Replica
	others := 0
	for _, r := range all {
		if r.App != app.Name {
			continue
		}
		switch {
		case r.Draining():
			if all, err2 = s.finishDrain(ctx, rc, all, r); err2 != nil {
				return nil, err2
			}
			if slices.ContainsFunc(all, func(o store.Replica) bool { return o.ID == r.ID }) {
				others++
			}
		case r.Revision == app.TargetRevision && (pinned == "" || r.NodeID == pinned):
			current = append(current, r)
		default:
			// The serving revision's replica during a rollout, or one left
			// on a node the volume is no longer bound to.
			if all, err2 = s.retire(ctx, rc, all, r); err2 != nil {
				return nil, err2
			}
			if slices.ContainsFunc(all, func(o store.Replica) bool { return o.ID == r.ID }) {
				others++
			}
		}
	}

	if app.Rolling() {
		aborted, err := s.checkRollout(ctx, rc, app, target, current, serving)
		if err != nil {
			return nil, err
		}
		if aborted {
			// The serving revision is the target again; the next pass
			// replaces this revision's replica with one of it.
			for _, r := range current {
				if all, err = s.retire(ctx, rc, all, r); err != nil {
					return nil, err
				}
			}
			return all, nil
		}
	}

	for len(current) > app.Replicas {
		victim := pickVictim(current, nil)
		if all, err = s.retire(ctx, rc, all, victim); err != nil {
			return nil, err
		}
		current = without(current, victim.ID)
	}

	byID := map[string]store.Node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	pn, known := byID[pinned]
	unavailable := !split && pinned != "" && (!known || rc.lost[pinned])
	s.condition(ctx, "volume-lost:"+app.Name, unavailable, store.Event{Kind: eventApp, Object: app.Name, App: app.Name, Node: pinned, Reason: "VolumeUnavailable",
		Message: fmt.Sprintf("its volumes are on node %s, which is unreachable or removed; it stays down until the node returns or a volume backup is restored on another node (armada volume restore --node)", pinned)})
	s.condition(ctx, "volume-cordoned:"+app.Name, known && pn.Cordoned, store.Event{Kind: eventApp, Object: app.Name, App: app.Name, Node: pinned, Reason: "VolumeOnCordonedNode",
		Message: fmt.Sprintf("node %s is cordoned, but the app keeps running there because its volumes are on it", pinned)})

	unplaced := false
	if len(current) < app.Replicas && others == 0 && !unavailable && !split {
		var fit []store.Node
		if pinned == "" {
			fit = eligible(nodes, target)
		} else if pn.State == store.NodeReady && placementAllows(pn, target) {
			// A cordoned node keeps the app whose volumes it holds.
			fit = []store.Node{pn}
		}
		node, ok := pickNode(fit, all, current, "", reservation(target), revs.reserved(ctx))
		if !ok {
			unplaced = true
		} else {
			r := store.Replica{
				ID:       fmt.Sprintf("%s-r%d-%s", app.Name, target.Seq, randomID(5)),
				App:      app.Name,
				Revision: target.Name,
				NodeID:   node.ID,
				State:    store.ReplicaPending,
			}
			err := s.store.CreateReplica(ctx, r)
			switch {
			case errors.Is(err, store.ErrPrecondition):
				// A volume was bound elsewhere meanwhile; the next pass
				// sees where.
				s.log.Warn("volume bound elsewhere", "app", app.Name, "err", err)
			case err != nil:
				return nil, err
			default:
				s.log.Info("scheduled replica", "replica", r.ID, "revision", r.Revision, "node", node.ID)
				s.record(ctx, store.Event{Kind: eventReplica, Object: r.ID, App: app.Name, Node: node.ID, Reason: "Scheduled", Message: "revision " + r.Revision + " on " + node.ID})
				current = append(current, r)
				all = append(all, r)
			}
		}
	}
	msg := "no node can fit its replica; see armada status"
	if pinned != "" {
		msg = fmt.Sprintf("its volumes are on node %s, which cannot take the replica now (not ready, out of capacity, or not allowed by its placement)", pinned)
	}
	s.condition(ctx, "unplaced:"+app.Name, unplaced, store.Event{Kind: eventApp, Object: app.Name, App: app.Name, Reason: "Unschedulable", Message: msg})
	s.condition(ctx, "no-isolation:"+app.Name, unplaced && noIsolation(nodes, target, pinned), noIsolationEvent(app.Name, eventApp, app.Name))

	if app.Rolling() && others == 0 && len(current) == app.Replicas && !slices.ContainsFunc(current, func(r store.Replica) bool { return !serving(r) }) {
		if err := s.store.CompleteRollout(ctx, app.Name, app.TargetRevision); err != nil {
			return nil, err
		}
		s.log.Info("rollout complete", "app", app.Name, "revision", app.TargetRevision)
		s.record(ctx, store.Event{Kind: eventRollout, Object: app.TargetRevision, App: app.Name, Reason: "Completed", Message: app.TargetRevision + " serves"})
		app.ActiveRevision = app.TargetRevision
		app.RolloutState = store.RolloutNone
		app.Spec = target.Spec
		s.forgetProgress(app.Name)
	}
	return all, nil
}

// volumeNode returns the node the volumes of rev's app are bound to, or ""
// if none is bound yet. Volumes bound to different nodes (after restoring
// one elsewhere) are split: the app stays unscheduled until they are
// together again.
func (s *Server) volumeNode(ctx context.Context, app string, rev store.Revision) (node string, split bool, err error) {
	vols, err := s.store.ListVolumes(ctx, app)
	if err != nil {
		return "", false, err
	}
	for _, v := range vols {
		if !slices.ContainsFunc(rev.Spec.Volumes, func(sv spec.Volume) bool { return sv.Name == v.Name }) {
			continue
		}
		if node != "" && node != v.Node {
			split = true
		}
		if node == "" {
			node = v.Node
		}
	}
	s.condition(ctx, "volume-split:"+app, split, store.Event{Kind: eventApp, Object: app, App: app, Reason: "VolumesSplit",
		Message: "its volumes are bound to different nodes; restore them onto one node (armada volume restore --node)"})
	return node, split, nil
}

// volumeUsage is a node's latest volume measurement.
type volumeUsage struct {
	at    time.Time
	bytes map[string]int64 // app/name
}

// setVolumes keeps nodeID's volume measurement. Like other usage it is
// untrusted: values are bounded, and names are checked when read.
func (u *usageStore) setVolumes(nodeID string, r *armadav1.UsageReport, at time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(r.GetVolumes()) > maxVolumeReports {
		delete(u.volumes, nodeID)
		return
	}
	m := make(map[string]int64, len(r.GetVolumes()))
	for _, v := range r.GetVolumes() {
		if spec.ValidAppID(v.GetApp()) && spec.ValidName(v.GetVolume()) {
			m[v.GetApp()+"/"+v.GetVolume()] = max(0, min(v.GetBytes(), maxVolumeBytes))
		}
	}
	u.volumes[nodeID] = volumeUsage{at: at, bytes: m}
}

// volume returns the latest size of a volume measured on nodeID.
func (u *usageStore) volume(nodeID, app, name string, now time.Time) (int64, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	v, ok := u.volumes[nodeID]
	if !ok || now.Sub(v.at) > volumeUsageMaxAge {
		return 0, false
	}
	b, ok := v.bytes[app+"/"+name]
	return b, ok
}

// mountedVolumes returns the volumes app's serving and target revisions
// mount, by name.
func (s *Server) mountedVolumes(ctx context.Context, app string) (map[string]spec.Volume, error) {
	a, err := s.store.GetApp(ctx, app)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]spec.Volume{}
	for _, rn := range []string{a.ActiveRevision, a.TargetRevision} {
		if rn == "" {
			continue
		}
		rev, err := s.store.GetRevision(ctx, rn)
		if err != nil {
			return nil, err
		}
		for _, v := range rev.Spec.Volumes {
			out[v.Name] = v
		}
	}
	return out, nil
}

// ListVolumes lists volumes, where they are, and how much they hold.
func (s *Server) ListVolumes(ctx context.Context, req *armadav1.ListVolumesRequest) (*armadav1.ListVolumesResponse, error) {
	acc := accessFrom(ctx)
	if req.GetApp() != "" {
		if err := acc.app(req.GetApp()); err != nil {
			return nil, err
		}
	}
	if req.GetApp() != "" && !spec.ValidAppID(req.GetApp()) {
		return nil, status.Error(codes.InvalidArgument, "invalid app name")
	}
	vols, err := s.store.ListVolumes(ctx, req.GetApp())
	if err != nil {
		return nil, storeErr(err)
	}
	vols = slices.DeleteFunc(vols, func(v store.Volume) bool { return !acc.sees(v.App) })
	now := s.now()
	mounted := map[string]map[string]spec.Volume{}
	resp := &armadav1.ListVolumesResponse{}
	for _, v := range vols {
		m, ok := mounted[v.App]
		if !ok {
			if m, err = s.mountedVolumes(ctx, v.App); err != nil {
				return nil, storeErr(err)
			}
			mounted[v.App] = m
		}
		out := &armadav1.Volume{App: v.App, Name: v.Name, Node: v.Node, CreatedAt: timestamppb.New(v.CreatedAt), UsedBytes: -1}
		if sv, ok := m[v.Name]; ok {
			out.InUse, out.Path = true, sv.Path
		}
		if b, ok := s.usage.volume(v.Node, v.App, v.Name, now); ok {
			out.UsedBytes = b
		}
		resp.Volumes = append(resp.Volumes, out)
	}
	return resp, nil
}

func checkVolumeArgs(app, name string) error {
	if !spec.ValidAppID(app) || !spec.ValidName(name) {
		return status.Error(codes.InvalidArgument, "invalid app or volume name")
	}
	return nil
}

// RemoveVolume deletes a volume's data on its node, then its record. A
// volume the app's spec still mounts is refused. When its node was removed
// from the cluster only the record goes.
func (s *Server) RemoveVolume(ctx context.Context, req *armadav1.RemoveVolumeRequest) (*armadav1.RemoveVolumeResponse, error) {
	if err := accessFrom(ctx).app(req.GetApp()); err != nil {
		return nil, err
	}
	if err := checkVolumeArgs(req.GetApp(), req.GetName()); err != nil {
		return nil, err
	}
	v, err := s.store.GetVolume(ctx, req.GetApp(), req.GetName())
	if err != nil {
		return nil, storeErr(err)
	}
	m, err := s.mountedVolumes(ctx, v.App)
	if err != nil {
		return nil, storeErr(err)
	}
	if _, ok := m[v.Name]; ok {
		return nil, status.Errorf(codes.FailedPrecondition, "app %s still mounts volume %s; deploy it without the volume first", v.App, v.Name)
	}
	reps, err := s.store.ListReplicas(ctx, store.ReplicaFilter{App: v.App})
	if err != nil {
		return nil, storeErr(err)
	}
	for _, r := range reps {
		rev, err := s.store.GetRevision(ctx, r.Revision)
		if err != nil {
			return nil, storeErr(err)
		}
		if slices.ContainsFunc(rev.Spec.Volumes, func(sv spec.Volume) bool { return sv.Name == v.Name }) {
			return nil, status.Errorf(codes.FailedPrecondition, "replica %s still uses volume %s; try again once it has stopped", r.ID, v.Name)
		}
	}
	if _, err := s.store.GetNode(ctx, v.Node); err == nil {
		if _, err := s.volumeOp(ctx, v.Node, &armadav1.VolumeRequest{Op: armadav1.VolumeRequest_OP_REMOVE, App: v.App, Volume: v.Name, Stop: true}); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, storeErr(err)
	}
	if err := s.store.DeleteVolume(ctx, v.App, v.Name, actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("volume removed", "app", v.App, "volume", v.Name, "node", v.Node, "by", actor(ctx))
	s.record(ctx, store.Event{Kind: eventApp, Object: v.App, App: v.App, Node: v.Node, Reason: "VolumeRemoved", Message: "volume " + v.Name + " removed"})
	return &armadav1.RemoveVolumeResponse{}, nil
}

// BackupVolume streams a gzipped tar of a volume from its node.
func (s *Server) BackupVolume(req *armadav1.BackupVolumeRequest, stream armadav1.AdminService_BackupVolumeServer) error {
	if err := accessFrom(stream.Context()).app(req.GetApp()); err != nil {
		return err
	}
	ctx := stream.Context()
	if err := checkVolumeArgs(req.GetApp(), req.GetName()); err != nil {
		return err
	}
	v, err := s.store.GetVolume(ctx, req.GetApp(), req.GetName())
	if err != nil {
		return storeErr(err)
	}
	if err := s.store.RecordAudit(ctx, actor(ctx), "volume.backup", v.App, fmt.Sprintf("volume=%s node=%s stop=%t", v.Name, v.Node, req.GetStop())); err != nil {
		return storeErr(err)
	}
	s.log.Info("volume backup", "app", v.App, "volume", v.Name, "node", v.Node, "stop", req.GetStop(), "by", actor(ctx))
	sess, err := s.openVolumeSession(ctx, v.Node, &armadav1.VolumeRequest{Op: armadav1.VolumeRequest_OP_BACKUP, App: v.App, Volume: v.Name, Stop: req.GetStop()})
	if err != nil {
		return err
	}
	defer sess.close()
	for {
		m, err := sess.agent.Recv()
		if err != nil {
			return status.Error(codes.Unavailable, "the node ended the backup")
		}
		switch {
		case m.GetError() != "":
			return status.Error(codes.FailedPrecondition, m.GetError())
		case len(m.GetData()) > volumeChunk:
			return status.Error(codes.DataLoss, "the node sent an oversized chunk")
		}
		if err := stream.Send(&armadav1.VolumeData{Data: m.GetData(), Done: m.GetDone()}); err != nil {
			return err
		}
		if m.GetDone() {
			s.record(ctx, store.Event{Kind: eventApp, Object: v.App, App: v.App, Node: v.Node, Reason: "VolumeBackedUp", Message: "volume " + v.Name})
			return nil
		}
	}
}

// RestoreVolume replaces a volume's contents with a gzipped tar from the
// admin, on its node or, with start.node, on another node it is then bound
// to. The agent stops the app's container on the node while it restores.
func (s *Server) RestoreVolume(stream armadav1.AdminService_RestoreVolumeServer) error {
	ctx := stream.Context()
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	start := first.GetStart()
	if start == nil {
		return status.Error(codes.InvalidArgument, "the first message must be start")
	}
	acc := accessFrom(ctx)
	if err := acc.app(start.GetApp()); err != nil {
		return err
	}
	if start.GetNode() != "" && !acc.admin() {
		return status.Error(codes.PermissionDenied, "only administrators may restore a volume onto another node")
	}
	if err := checkVolumeArgs(start.GetApp(), start.GetName()); err != nil {
		return err
	}
	app, name := start.GetApp(), start.GetName()
	v, err := s.store.GetVolume(ctx, app, name)
	bound := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return storeErr(err)
	}
	node := v.Node
	if start.GetNode() != "" && start.GetNode() != node {
		node = start.GetNode()
		if _, err := s.store.GetNode(ctx, node); err != nil {
			return storeErr(err)
		}
		// Never leave two copies that could both be written.
		if bound && s.session(v.Node) != nil {
			return status.Errorf(codes.FailedPrecondition, "node %s, which holds the volume, is connected; restore without --node", v.Node)
		}
	}
	if !bound && start.GetNode() == "" {
		return status.Errorf(codes.NotFound, "volume %s of app %s not found; name a node with --node to restore it there", name, app)
	}
	if !bound {
		m, err := s.mountedVolumes(ctx, app)
		if err != nil {
			return storeErr(err)
		}
		if _, ok := m[name]; !ok {
			return status.Errorf(codes.NotFound, "app %s has no volume %s", app, name)
		}
	}
	if err := s.store.RecordAudit(ctx, actor(ctx), "volume.restore", app, fmt.Sprintf("volume=%s node=%s", name, node)); err != nil {
		return storeErr(err)
	}
	s.log.Info("volume restore", "app", app, "volume", name, "node", node, "by", actor(ctx))
	sess, err := s.openVolumeSession(ctx, node, &armadav1.VolumeRequest{Op: armadav1.VolumeRequest_OP_RESTORE, App: app, Volume: name, Stop: true})
	if err != nil {
		return err
	}
	defer sess.close()

	result := make(chan error, 1)
	go func() {
		for {
			m, err := sess.agent.Recv()
			switch {
			case err != nil:
				result <- status.Error(codes.Unavailable, "the node ended the restore")
			case m.GetError() != "":
				result <- status.Error(codes.FailedPrecondition, m.GetError())
			case m.GetDone():
				result <- nil
			default:
				continue
			}
			return
		}
	}()
	send := func(m *armadav1.VolumeData) error {
		if !sess.send(m) {
			return status.Error(codes.Unavailable, "the node ended the restore")
		}
		return nil
	}
	for {
		m, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			if err := send(&armadav1.VolumeData{Done: true}); err != nil {
				return err
			}
			break
		}
		if err != nil {
			return err
		}
		if len(m.GetData()) > volumeChunk || m.GetStart() != nil {
			return status.Error(codes.InvalidArgument, "expected archive data of at most 64 KiB per message")
		}
		if err := send(&armadav1.VolumeData{Data: m.GetData()}); err != nil {
			select {
			case err := <-result:
				if err != nil {
					return err
				}
			default:
			}
			return err
		}
		select {
		case err := <-result:
			if err == nil {
				err = status.Error(codes.Internal, "the node finished before the archive ended")
			}
			return err
		default:
		}
	}
	select {
	case err := <-result:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	if !bound || v.Node != node {
		if err := s.store.BindVolume(ctx, app, name, node, actor(ctx)); err != nil {
			return storeErr(err)
		}
		s.Trigger()
	}
	s.record(ctx, store.Event{Kind: eventApp, Object: app, App: app, Node: node, Reason: "VolumeRestored", Message: "volume " + name + " on " + node})
	return stream.SendAndClose(&armadav1.RestoreVolumeResponse{Node: node})
}

// volumeSession is an open VolumeSession with an agent.
type volumeSession struct {
	agent armadav1.AgentService_VolumeSessionServer
	p     *pendingVolume
	id    string
	r     *volumeRouter
	// mu guards sends: none may happen once the handler has returned.
	mu   sync.Mutex
	open bool
}

func (v *volumeSession) send(m *armadav1.VolumeData) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.open && v.agent.Send(m) == nil
}

func (v *volumeSession) close() {
	v.mu.Lock()
	v.open = false
	v.mu.Unlock()
	v.r.cancel(v.id, v.p)
}

// openVolumeSession asks nodeID's agent to serve req and waits for its
// session. An error in the agent's first message is returned.
func (s *Server) openVolumeSession(ctx context.Context, nodeID string, req *armadav1.VolumeRequest) (*volumeSession, error) {
	sess := s.session(nodeID)
	if sess == nil {
		return nil, status.Errorf(codes.Unavailable, "node %s is not connected", nodeID)
	}
	id, p := s.volumes.register(nodeID)
	req.RequestId = id
	if !sess.offer(&armadav1.ServerMessage{Msg: &armadav1.ServerMessage_VolumeRequest{VolumeRequest: req}}) {
		s.volumes.cancel(id, p)
		return nil, status.Errorf(codes.Unavailable, "node %s did not accept the volume request", nodeID)
	}
	var agent armadav1.AgentService_VolumeSessionServer
	select {
	case agent = <-p.attached:
	case <-time.After(attachTimeout):
		s.volumes.cancel(id, p)
		return nil, status.Errorf(codes.Unavailable, "node %s did not start the volume session", nodeID)
	case <-ctx.Done():
		s.volumes.cancel(id, p)
		return nil, ctx.Err()
	}
	vs := &volumeSession{agent: agent, p: p, id: id, r: s.volumes, open: true}
	if e := p.first.GetError(); e != "" {
		vs.close()
		return nil, status.Error(codes.FailedPrecondition, e)
	}
	return vs, nil
}

// volumeOp runs a request whose answer is the agent's first message.
func (s *Server) volumeOp(ctx context.Context, nodeID string, req *armadav1.VolumeRequest) (*armadav1.VolumeData, error) {
	sess, err := s.openVolumeSession(ctx, nodeID, req)
	if err != nil {
		return nil, err
	}
	defer sess.close()
	if !sess.p.first.GetDone() {
		return nil, status.Error(codes.Internal, "the node did not finish the volume request")
	}
	return sess.p.first, nil
}

// VolumeSession receives the session stream for a pending volume request
// from the agent it was sent to, and holds it until the admin side is done.
func (s *Server) VolumeSession(stream armadav1.AgentService_VolumeSessionServer) error {
	id, _ := IdentityFrom(stream.Context())
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	p := s.volumes.attach(first.GetRequestId(), id.Name, first, stream)
	if p == nil {
		return status.Error(codes.PermissionDenied, "unknown volume request")
	}
	select {
	case <-p.done:
		return nil
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
}

// volumeRouter pairs admin volume requests with the agent streams that
// serve them, like execRouter.
type volumeRouter struct {
	mu      sync.Mutex
	pending map[string]*pendingVolume
}

type pendingVolume struct {
	nodeID   string
	first    *armadav1.VolumeData
	attached chan armadav1.AgentService_VolumeSessionServer
	done     chan struct{}
}

func newVolumeRouter() *volumeRouter { return &volumeRouter{pending: map[string]*pendingVolume{}} }

func (r *volumeRouter) register(nodeID string) (string, *pendingVolume) {
	id := randomID(20)
	p := &pendingVolume{nodeID: nodeID, attached: make(chan armadav1.AgentService_VolumeSessionServer, 1), done: make(chan struct{})}
	r.mu.Lock()
	r.pending[id] = p
	r.mu.Unlock()
	return id, p
}

// attach claims a pending request for nodeID with the agent's stream, once
// and only by the node it was sent to.
func (r *volumeRouter) attach(id, nodeID string, first *armadav1.VolumeData, stream armadav1.AgentService_VolumeSessionServer) *pendingVolume {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.pending[id]
	if !ok || p.nodeID != nodeID {
		return nil
	}
	delete(r.pending, id)
	p.first = first
	p.attached <- stream
	return p
}

func (r *volumeRouter) cancel(id string, p *pendingVolume) {
	r.mu.Lock()
	delete(r.pending, id)
	r.mu.Unlock()
	close(p.done)
}
