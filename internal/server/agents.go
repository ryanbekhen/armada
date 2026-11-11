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
	// certRefs: the agent takes certificates by reference (Hello).
	certRefs bool
	send     chan *armadav1.ServerMessage
	done     chan struct{}

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

	sess := &session{nodeID: node.ID, certRefs: hello.GetCertificateRefs(), send: make(chan *armadav1.ServerMessage, 64), done: make(chan struct{})}
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
				Jobs: hello.GetJobs(), Volumes: hello.GetVolumes(), Containers: hello.GetContainers(),
			})
			s.log.Info("agent disconnected", "node", node.ID)
			s.record(ctx, store.Event{Kind: eventNode, Object: node.ID, Node: node.ID, Reason: "Disconnected"})
		}
	}()

	// Self-reported and untrusted: bounded to plausible values.
	hello.CpuMillis = max(0, min(hello.GetCpuMillis(), maxNodeCPUMillis))
	hello.MemoryBytes = max(0, min(hello.GetMemoryBytes(), maxNodeMemory))
	// Reports rewrite the node status from node: keep what hello reported,
	// not the record as it was before this session.
	node.CPUMillis, node.MemoryBytes = hello.GetCpuMillis(), hello.GetMemoryBytes()
	node.Jobs, node.Volumes, node.Containers = hello.GetJobs(), hello.GetVolumes(), hello.GetContainers()
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
	// The key peers will accept this node's traffic by (ADR 0025): only a
	// well-formed one, recorded on this node's own record, which the
	// stream's certificate names.
	if !validNetworkKey(hello.GetNetworkKey()) {
		hello.NetworkKey = ""
	}
	if err := s.store.SetNodeStatus(ctx, node.ID, store.NodeStatus{
		State: store.NodeReady, LastSeen: time.Now(), CPUMillis: hello.GetCpuMillis(), MemoryBytes: hello.GetMemoryBytes(),
		Version: hello.GetVersion(), OS: hello.GetOs(), Arch: hello.GetArch(),
		Jobs: hello.GetJobs(), Volumes: hello.GetVolumes(), Containers: hello.GetContainers(),
		NetworkKey: hello.GetNetworkKey(),
	}); errors.Is(err, store.ErrConflict) {
		s.log.Warn("agent announced another node's network key", "node", node.ID)
		return status.Error(codes.FailedPrecondition, "the network key is already used by another node; remove "+fileNetworkKeyHint+" on this node and restart the agent")
	} else if err != nil {
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
				for _, e := range s.usage.outOfMemory(node.ID, u) {
					s.record(ctx, e)
				}
				if u.GetVolumesMeasured() {
					s.usage.setVolumes(node.ID, u, s.now())
				}
			}
			if w := m.GetWake(); w != nil {
				s.wakeApp(ctx, node.ID, w.GetApp())
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
	if err := s.store.SetNodeStatus(ctx, node.ID, store.NodeStatus{State: store.NodeReady, LastSeen: time.Now(), CPUMillis: node.CPUMillis, MemoryBytes: node.MemoryBytes, Jobs: node.Jobs, Volumes: node.Volumes, Containers: node.Containers}); err != nil {
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
		if addr != "" && !validReplicaAddress(addr, node.PrivateIP, node.Subnet) {
			// %q keeps a hostile address from forging log lines.
			s.log.Warn("ignoring invalid replica address", "node", node.ID, "replica", st.GetId(), "address", fmt.Sprintf("%q", truncate(addr, 128)))
			addr = ""
		}
		ip := st.GetIp()
		if ip != "" && !validReplicaIP(ip, node.Subnet) {
			s.log.Warn("ignoring invalid replica IP", "node", node.ID, "replica", st.GetId(), "ip", fmt.Sprintf("%q", truncate(ip, 64)))
			ip = ""
		}
		next := store.ReplicaStatus{
			ID:          st.GetId(),
			State:       truncate(st.GetState(), 32),
			ContainerID: truncate(st.GetContainerId(), 128),
			Address:     addr,
			IP:          ip,
			Message:     truncate(st.GetMessage(), 512),
			Ready:       st.GetReady(),
			Finished:    st.GetFinished(),
			ExitCode:    int(st.GetExitCode()),
		}
		if p := prev[next.ID]; p.State != next.State || p.Ready != (next.Ready && next.State == store.ReplicaRunning) || p.Address != next.Address || p.IP != next.IP || p.Finished != next.Finished {
			changed = true
		}
		// A report lists every replica of the node, usually to say one has
		// changed: the others cost no write.
		if !sameStatus(prev[next.ID], next) {
			err := s.store.UpdateReplicaStatus(ctx, node.ID, next)
			switch {
			case err == nil && prev[next.ID].Run == 0:
				// Job attempts are recorded by the job reconciler.
				s.replicaEvent(ctx, prev[next.ID], next)
			case err == nil:
			case !errors.Is(err, store.ErrNotFound):
				s.log.Warn("update replica status", "err", err)
			}
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

// sameStatus reports whether a report says nothing new about a replica. A
// finished job attempt keeps the exit code it was first recorded with, and a
// stopped container may report another one, which UpdateReplicaStatus ignores.
func sameStatus(have store.Replica, st store.ReplicaStatus) bool {
	return have.State == st.State && have.ContainerID == st.ContainerID && have.Address == st.Address &&
		have.IP == st.IP && have.Message == st.Message && have.Ready == (st.Ready && st.State == store.ReplicaRunning) &&
		have.Finished == st.Finished && (have.Finished || have.ExitCode == st.ExitCode)
}

// recordPlatforms keeps the first valid list of image platforms an agent
// reports for a revision (ADR 0014). Each entry must be "os/arch" with both
// parts valid label values, at most spec.MaxNodeLabels of them.
// Every report repeats what a replica's image is, for every replica of the node.
// learnedRevisions remembers what is already recorded, so that repeating it costs
// no reads: a report would otherwise read two revisions per replica.
type learnedRevisions struct {
	mu sync.Mutex
	m  map[string]uint8
}

const (
	learnedDigest uint8 = 1 << iota
	learnedPlatforms

	// maxLearned bounds the memory; forgetting only costs a read per revision.
	maxLearned = 1 << 16
)

func (l *learnedRevisions) has(rev string, what uint8) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.m[rev]&what != 0
}

func (l *learnedRevisions) add(rev string, what uint8) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil || len(l.m) >= maxLearned {
		l.m = map[string]uint8{}
	}
	l.m[rev] |= what
}

func (s *Server) recordPlatforms(ctx context.Context, nodeID, revName string, reported []string) {
	if s.learned.has(revName, learnedPlatforms) {
		return
	}
	rev, err := s.store.GetRevision(ctx, revName)
	if err != nil {
		return
	}
	if len(rev.Platforms) > 0 {
		s.learned.add(revName, learnedPlatforms)
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
	s.learned.add(revName, learnedPlatforms)
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
	if s.learned.has(revName, learnedDigest) {
		return
	}
	rev, err := s.store.GetRevision(ctx, revName)
	if err != nil {
		return
	}
	if rev.ImageDigest != "" {
		s.learned.add(revName, learnedDigest)
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
	s.learned.add(revName, learnedDigest)
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

// validReplicaAddress accepts only "<node private IP>:<port>", or with the
// cluster network "<address in the node's subnet>:<port>" (ADR 0025), in
// canonical form: the address goes into every node's proxy configuration.
// The subnet's network address (the node's tunnel end), its gateway (the
// node's bridge), and its broadcast address are never a replica's.
func validReplicaAddress(addr, nodeIP, subnet string) bool {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || ap.Port() == 0 || ap.Addr().Zone() != "" || ap.String() != addr {
		return false
	}
	if ap.Addr().String() == nodeIP {
		return true
	}
	return inNodeSubnet(ap.Addr(), subnet)
}

// validReplicaIP accepts a container address in the node's subnet, in
// canonical form: it goes into every node's firewall (ADR 0026).
func validReplicaIP(ip, subnet string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.Zone() == "" && a.String() == ip && inNodeSubnet(a, subnet)
}

// inNodeSubnet reports whether a is a container address of the node subnet:
// the network address (the node's tunnel end), the gateway (the node's
// bridge), and the broadcast address are never a replica's.
func inNodeSubnet(a netip.Addr, subnet string) bool {
	p, err := netip.ParsePrefix(subnet)
	if err != nil || !p.Addr().Is4() || !p.Contains(a) {
		return false
	}
	host := a.As4()[3] // node subnets are /24s
	return p.Bits() == 24 && host != 0 && host != 1 && host != 255
}

// versionRe bounds the self-reported agent version, which ends up in the
// state and in CLI output.
var versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)

func validVersion(v string) bool { return versionRe.MatchString(v) }
