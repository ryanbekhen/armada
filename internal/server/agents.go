package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// session is one connected agent.
type session struct {
	nodeID string
	send   chan *armadav1.ServerMessage
	done   chan struct{}

	mu   sync.Mutex
	last *armadav1.Assignment
}

// offerAssignment queues a if it differs from the last one sent. If the queue
// is full the assignment is dropped and retried on the next reconcile.
func (s *session) offerAssignment(a *armadav1.Assignment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if assignmentsEqual(s.last, a) {
		return
	}
	select {
	case s.send <- &armadav1.ServerMessage{Msg: &armadav1.ServerMessage_Assignment{Assignment: a}}:
		s.last = a
	default:
	}
}

func (s *session) offer(m *armadav1.ServerMessage) bool {
	select {
	case s.send <- m:
		return true
	case <-s.done:
		return false
	case <-time.After(5 * time.Second):
		return false
	}
}

func (s *Server) session(nodeID string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[nodeID]
}

// Connect handles an agent's control stream.
func (s *Server) Connect(stream armadav1.AgentService_ConnectServer) error {
	ctx := stream.Context()
	id, _ := IdentityFrom(ctx)
	node, err := s.store.GetNode(ctx, id.Name)
	if errors.Is(err, store.ErrNotFound) {
		return status.Errorf(codes.PermissionDenied, "node %s is not registered", id.Name)
	}
	if err != nil {
		return status.Error(codes.Internal, "load node")
	}

	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "first message must be hello")
	}
	if hello.GetPrivateIp() != node.PrivateIP {
		return status.Errorf(codes.FailedPrecondition, "agent reports private IP %q but node is registered with %q", hello.GetPrivateIp(), node.PrivateIP)
	}

	sess := &session{nodeID: node.ID, send: make(chan *armadav1.ServerMessage, 64), done: make(chan struct{})}
	s.mu.Lock()
	if old := s.sessions[node.ID]; old != nil {
		close(old.done)
	}
	s.sessions[node.ID] = sess
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		current := s.sessions[node.ID] == sess
		if current {
			delete(s.sessions, node.ID)
			close(sess.done)
		}
		s.mu.Unlock()
		if current {
			s.usage.forget(node.ID)
			_ = s.store.SetNodeStatus(context.WithoutCancel(ctx), node.ID, store.NodeStatus{
				State: store.NodeUnknown, LastSeen: time.Now(), CPUMillis: hello.GetCpuMillis(), MemoryBytes: hello.GetMemoryBytes(),
				MinMemoryBytes: hello.GetMinMemoryBytes(), Jobs: hello.GetJobs(),
			})
			s.log.Info("agent disconnected", "node", node.ID)
			s.record(ctx, store.Event{Kind: eventNode, Object: node.ID, Node: node.ID, Reason: "Disconnected"})
		}
	}()

	// Self-reported and untrusted: bounded to plausible values.
	hello.CpuMillis = max(0, min(hello.GetCpuMillis(), maxNodeCPUMillis))
	hello.MemoryBytes = max(0, min(hello.GetMemoryBytes(), maxNodeMemory))
	hello.MinMemoryBytes = max(0, min(hello.GetMinMemoryBytes(), maxNodeMemory))
	// Reports rewrite the node status from node: keep what hello reported,
	// not the record as it was before this session.
	node.CPUMillis, node.MemoryBytes, node.MinMemoryBytes = hello.GetCpuMillis(), hello.GetMemoryBytes(), hello.GetMinMemoryBytes()
	node.Jobs = hello.GetJobs()
	if !validVersion(hello.GetVersion()) {
		hello.Version = ""
	}
	// Shown as the armada.os and armada.arch labels: label values only.
	if spec.CheckLabelValue(hello.GetOs()) != nil {
		hello.Os = ""
	}
	if spec.CheckLabelValue(hello.GetArch()) != nil {
		hello.Arch = ""
	}
	if spec.CheckLabelValue(hello.GetRuntime()) != nil {
		hello.Runtime = ""
	}
	if err := s.store.SetNodeStatus(ctx, node.ID, store.NodeStatus{
		State: store.NodeReady, LastSeen: time.Now(), CPUMillis: hello.GetCpuMillis(), MemoryBytes: hello.GetMemoryBytes(),
		Version: hello.GetVersion(), OS: hello.GetOs(), Arch: hello.GetArch(), Runtime: hello.GetRuntime(),
		MinMemoryBytes: hello.GetMinMemoryBytes(), Jobs: hello.GetJobs(),
	}); err != nil {
		return status.Error(codes.Internal, "update node")
	}
	s.log.Info("agent connected", "node", node.ID, "version", hello.GetVersion())
	connected := store.Event{Kind: eventNode, Object: node.ID, Node: node.ID, Reason: "Connected"}
	if hello.GetVersion() != "" {
		connected.Message = "agent " + hello.GetVersion()
	}
	s.record(ctx, connected)
	s.Trigger()

	// A stream outlives the handshake that authenticated it; end it when
	// that certificate expires so the agent reconnects with a renewed one.
	expired := time.NewTimer(time.Until(peerCertExpiry(ctx)))
	defer expired.Stop()

	errc := make(chan error, 2)
	go func() {
		for {
			select {
			case <-expired.C:
				errc <- status.Error(codes.Unauthenticated, "client certificate expired; reconnect with a renewed one")
				return
			case m := <-sess.send:
				if err := stream.Send(m); err != nil {
					errc <- err
					return
				}
			case <-sess.done:
				errc <- status.Error(codes.Aborted, "replaced by a newer connection")
				return
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			}
		}
	}()
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				errc <- err
				return
			}
			if r := m.GetReport(); r != nil {
				s.applyReport(ctx, node, r)
			}
			if u := m.GetUsage(); u != nil {
				s.usage.set(node.ID, u, s.now())
			}
		}
	}()
	err = <-errc
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// Upper bounds for the capacity a node reports about itself.
const (
	maxNodeCPUMillis = 1024 * 1000 // 1024 cores
	maxNodeMemory    = 16 << 40    // 16 TiB
)

var digestRe = regexp.MustCompile(`@sha256:[a-f0-9]{64}$`)

// applyReport stores status from an agent. Every field is treated as
// untrusted: replicas must belong to the node, addresses must be on the
// node's private IP, and digests must match the revision's repository.
func (s *Server) applyReport(ctx context.Context, node store.Node, r *armadav1.ReplicaReport) {
	if err := s.store.SetNodeStatus(ctx, node.ID, store.NodeStatus{State: store.NodeReady, LastSeen: time.Now(), CPUMillis: node.CPUMillis, MemoryBytes: node.MemoryBytes, MinMemoryBytes: node.MinMemoryBytes, Jobs: node.Jobs}); err != nil {
		s.log.Warn("update node status", "err", err)
	}
	owned, err := s.store.ListReplicas(ctx, store.ReplicaFilter{NodeID: node.ID})
	if err != nil {
		return
	}
	revOf := map[string]string{}
	prev := map[string]store.Replica{}
	for _, rep := range owned {
		revOf[rep.ID] = rep.Revision
		prev[rep.ID] = rep
	}
	changed := false

	for _, st := range r.GetReplicas() {
		rev, ok := revOf[st.GetId()]
		if !ok {
			continue // stale or foreign replica
		}
		addr := st.GetAddress()
		if addr != "" && !validReplicaAddress(addr, node.PrivateIP) {
			// %q keeps a hostile address from forging log lines.
			s.log.Warn("ignoring invalid replica address", "node", node.ID, "replica", st.GetId(), "address", fmt.Sprintf("%q", truncate(addr, 128)))
			addr = ""
		}
		next := store.ReplicaStatus{
			ID:          st.GetId(),
			State:       truncate(st.GetState(), 32),
			ContainerID: truncate(st.GetContainerId(), 128),
			Address:     addr,
			Message:     truncate(st.GetMessage(), 512),
			Ready:       st.GetReady(),
			Finished:    st.GetFinished(),
			ExitCode:    int(st.GetExitCode()),
		}
		if p := prev[next.ID]; p.State != next.State || p.Ready != (next.Ready && next.State == store.ReplicaRunning) || p.Address != next.Address || p.Finished != next.Finished {
			changed = true
		}
		err := s.store.UpdateReplicaStatus(ctx, node.ID, next)
		switch {
		case err == nil && prev[next.ID].Run == 0:
			// Job attempts are recorded by the job reconciler.
			s.replicaEvent(ctx, prev[next.ID], next)
		case err == nil:
		case !errors.Is(err, store.ErrNotFound):
			s.log.Warn("update replica status", "err", err)
		}
		if d := st.GetImageDigest(); d != "" {
			s.recordDigest(ctx, rev, d)
		}
		if ps := st.GetImagePlatforms(); len(ps) > 0 {
			s.recordPlatforms(ctx, node.ID, rev, ps)
		}
	}
	// Readiness and address changes move rollouts forward and update the
	// proxies; react now rather than at the next resync.
	if changed {
		s.Trigger()
	}
}

// recordPlatforms keeps the first valid list of image platforms an agent
// reports for a revision (ADR 0014). Each entry must be "os/arch" with both
// parts valid label values, at most spec.MaxNodeLabels of them.
func (s *Server) recordPlatforms(ctx context.Context, nodeID, revName string, reported []string) {
	rev, err := s.store.GetRevision(ctx, revName)
	if err != nil || len(rev.Platforms) > 0 {
		return
	}
	ps, ok := cleanPlatforms(reported)
	if !ok {
		s.log.Warn("ignoring invalid image platforms", "node", nodeID, "revision", revName, "count", len(reported))
		return
	}
	if err := s.store.SetRevisionPlatforms(ctx, revName, ps); err != nil {
		s.log.Warn("record image platforms", "err", err)
		return
	}
	s.log.Info("image platforms", "revision", revName, "platforms", strings.Join(ps, ","))
	s.Trigger()
}

// cleanPlatforms validates reported platforms and returns them sorted and
// without duplicates.
func cleanPlatforms(reported []string) ([]string, bool) {
	if len(reported) > spec.MaxNodeLabels {
		return nil, false
	}
	var out []string
	for _, p := range reported {
		osName, arch, ok := strings.Cut(p, "/")
		if !ok || spec.CheckLabelValue(osName) != nil || spec.CheckLabelValue(arch) != nil {
			return nil, false
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out, len(out) > 0
}

func (s *Server) recordDigest(ctx context.Context, revName, digest string) {
	rev, err := s.store.GetRevision(ctx, revName)
	if err != nil || rev.ImageDigest != "" {
		return
	}
	if !digestRe.MatchString(digest) || normalizeRepo(strings.SplitN(digest, "@", 2)[0]) != normalizeRepo(imageRepo(rev.Spec.Image)) {
		s.log.Warn("ignoring image digest that does not match revision image", "revision", revName, "digest", digest)
		return
	}
	if err := s.store.SetRevisionDigest(ctx, revName, digest); err != nil {
		s.log.Warn("record digest", "err", err)
		return
	}
	s.Trigger()
}

func imageRepo(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		return ref[:i]
	}
	slash := strings.LastIndex(ref, "/")
	if i := strings.LastIndex(ref, ":"); i > slash {
		return ref[:i]
	}
	return ref
}

func normalizeRepo(r string) string {
	r = strings.TrimPrefix(r, "docker.io/")
	return strings.TrimPrefix(r, "library/")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// PushLogs receives a log stream for a pending request from the agent that
// was asked for it.
func (s *Server) PushLogs(stream armadav1.AgentService_PushLogsServer) error {
	id, _ := IdentityFrom(stream.Context())
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	p := s.logs.attach(first.GetRequestId(), id.Name)
	if p == nil {
		return status.Error(codes.PermissionDenied, "unknown log request")
	}
	defer close(p.ch)

	msg := first
	for {
		select {
		case p.ch <- msg:
		case <-p.done:
			return stream.SendAndClose(&armadav1.PushLogsResponse{})
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		msg, err = stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&armadav1.PushLogsResponse{})
		}
		if err != nil {
			return err
		}
		if msg.GetRequestId() != "" && msg.GetRequestId() != first.GetRequestId() {
			return status.Error(codes.InvalidArgument, "request_id changed mid-stream")
		}
	}
}

// logRouter pairs admin log requests with the agent streams that serve them.
type logRouter struct {
	mu      sync.Mutex
	pending map[string]*pendingLog
}

type pendingLog struct {
	nodeID   string
	ch       chan *armadav1.LogPush // closed by PushLogs
	done     chan struct{}          // closed by the admin side
	attached chan struct{}          // closed when the agent connects
}

func newLogRouter() *logRouter { return &logRouter{pending: map[string]*pendingLog{}} }

func (r *logRouter) register(nodeID string) (string, *pendingLog) {
	id := randomID(20)
	p := &pendingLog{nodeID: nodeID, ch: make(chan *armadav1.LogPush, 16), done: make(chan struct{}), attached: make(chan struct{})}
	r.mu.Lock()
	r.pending[id] = p
	r.mu.Unlock()
	return id, p
}

// attach claims a pending request for nodeID. Each request can be attached
// once, and only by the node it was sent to.
func (r *logRouter) attach(id, nodeID string) *pendingLog {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.pending[id]
	if !ok || p.nodeID != nodeID {
		return nil
	}
	delete(r.pending, id)
	close(p.attached)
	return p
}

func (r *logRouter) cancel(id string, p *pendingLog) {
	r.mu.Lock()
	delete(r.pending, id)
	r.mu.Unlock()
	close(p.done)
}

// peerCertExpiry returns when the caller's client certificate expires.
func peerCertExpiry(ctx context.Context) time.Time {
	if p, ok := peer.FromContext(ctx); ok {
		if info, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(info.State.PeerCertificates) > 0 {
			return info.State.PeerCertificates[0].NotAfter
		}
	}
	return time.Now()
}

// validReplicaAddress accepts only "<node private IP>:<port>" in canonical
// form: the address goes into every node's proxy configuration.
func validReplicaAddress(addr, nodeIP string) bool {
	ap, err := netip.ParseAddrPort(addr)
	return err == nil && ap.Port() != 0 && ap.Addr().Zone() == "" && ap.String() == addr && ap.Addr().String() == nodeIP
}

// versionRe bounds the self-reported agent version, which ends up in the
// state and in CLI output.
var versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)

func validVersion(v string) bool { return versionRe.MatchString(v) }
