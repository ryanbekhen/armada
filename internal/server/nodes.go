package server

import (
	"cmp"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/version"
)

const (
	defaultTokenTTL = time.Hour
	maxTokenTTL     = 24 * time.Hour
	// maxServerTokenTTL caps server tokens, which unlock the cluster keys.
	maxServerTokenTTL = time.Hour
	// defaultServerTokenTTL is a server token's lifetime unless asked.
	defaultServerTokenTTL = 15 * time.Minute
	// A mesh cluster's tokens keep its join listener open on a public
	// address (ADR 0049): short by default, at most an hour.
	defaultMeshTokenTTL = 10 * time.Minute
	maxMeshTokenTTL     = time.Hour
	minTokenTTL         = time.Minute
	// The join listener accepts unauthenticated connections, so it is
	// rate limited per source address (a burst of joinBurst, then one
	// attempt per joinRefill) and overall (joinGlobalBurst).
	joinBurst       = 5
	joinRefill      = 6 * time.Second
	joinGlobalBurst = 30
	joinGlobalRef   = time.Second
	maxCSRSize      = 4 << 10
)

// keyedLimiter keeps a token bucket per key (source IP, node), bounded in
// size: when full it starts over, which only ever makes it more lenient.
type keyedLimiter struct {
	mu      sync.Mutex
	burst   int
	refill  time.Duration
	buckets map[string]*limiter
}

const maxLimiterKeys = 4096

func newKeyedLimiter(burst int, refill time.Duration) *keyedLimiter {
	return &keyedLimiter{burst: burst, refill: refill, buckets: map[string]*limiter{}}
}

func (k *keyedLimiter) allow(key string, now time.Time) bool {
	k.mu.Lock()
	l := k.buckets[key]
	if l == nil {
		if len(k.buckets) >= maxLimiterKeys {
			k.buckets = map[string]*limiter{}
		}
		l = newLimiter(k.burst, k.refill)
		k.buckets[key] = l
	}
	k.mu.Unlock()
	return l.allow(now)
}

// limiter is a token bucket.
type limiter struct {
	mu     sync.Mutex
	tokens float64
	burst  float64
	refill time.Duration
	last   time.Time
}

func newLimiter(burst int, refill time.Duration) *limiter {
	return &limiter{tokens: float64(burst), burst: float64(burst), refill: refill, last: time.Now()}
}

func (l *limiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.After(l.last) {
		l.tokens = min(l.burst, l.tokens+float64(now.Sub(l.last))/float64(l.refill))
		l.last = now
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// joinService serves only Join, on its own listener.
// Bounds of the join listener's connections: a join is one short RPC.
const (
	joinMaxConns          = 256
	joinMaxConnsPerSource = 16
	joinIdle              = 15 * time.Second
	joinMaxAge            = 2 * time.Minute
)

type joinService struct {
	armadav1.UnimplementedJoinServiceServer
	s *Server
}

func (s *Server) serveJoin(ctx context.Context) error {
	if s.joinPublic {
		go s.gateJoin(ctx)
		return nil
	}
	l := s.joinLis
	if l == nil {
		var err error
		if l, err = net.Listen("tcp", s.joinAddr); err != nil {
			return fmt.Errorf("join listener: %w", err)
		}
	}
	stop := s.startJoin(l)
	go func() {
		<-ctx.Done()
		stop()
	}()
	s.log.Info("join listener", "addr", s.joinAddr)
	return nil
}

// joinGateEvery is how often a mesh cluster's leader looks whether join
// tokens expired, closing the join listener once none is open.
const joinGateEvery = 5 * time.Second

// joinGate is the state of a mesh cluster's join listener (ADR 0049).
type joinGate struct {
	// wake asks gateJoin to look at the tokens now (one was created or
	// redeemed).
	wake chan struct{}
	// from holds the addresses open tokens name (map[netip.Addr]bool), or
	// nil when one names none and any address may join.
	from atomic.Pointer[map[netip.Addr]bool]
}

// wakeJoin makes a mesh cluster's leader look at its join tokens now.
func (s *Server) wakeJoin() {
	select {
	case s.joinGate.wake <- struct{}{}:
	default:
	}
}

// gateJoin keeps a mesh cluster's join listener, on the leader's public
// endpoint, open only while a join token is unused and unexpired, and
// answering only the addresses those tokens name (ADR 0049).
func (s *Server) gateJoin(ctx context.Context) {
	var stop func()
	t := time.NewTicker(joinGateEvery)
	defer t.Stop()
	for {
		toks, err := s.store.OpenJoinTokens(ctx)
		if err != nil {
			if ctx.Err() == nil {
				s.log.Warn("read join tokens", "err", err)
			}
		} else {
			s.joinGate.from.Store(joinSources(toks))
			switch {
			case len(toks) > 0 && stop == nil:
				l := s.joinLis
				if l == nil {
					l, err = net.Listen("tcp", s.joinAddr)
				}
				if err != nil {
					s.log.Error("open the join listener", "addr", s.joinAddr, "err", err)
				} else {
					s.joinLis = nil
					stop = s.startJoin(&sourceFilter{Listener: l, allow: s.joinAllowed})
					s.log.Info("join listener open while a join token is", "addr", s.joinAddr)
				}
			case len(toks) == 0 && stop != nil:
				stop()
				stop = nil
				s.log.Info("join listener closed: no open join token", "addr", s.joinAddr)
			}
		}
		select {
		case <-ctx.Done():
			if stop != nil {
				stop()
			}
			return
		case <-t.C:
		case <-s.joinGate.wake:
		}
	}
}

// joinSources returns the addresses open tokens name, or nil when any
// token names none.
func joinSources(toks []store.JoinToken) *map[netip.Addr]bool {
	m := map[netip.Addr]bool{}
	for _, t := range toks {
		a, err := netip.ParseAddr(t.From)
		if err != nil {
			return nil
		}
		m[a] = true
	}
	return &m
}

// joinAllowed reports whether a connection from addr may reach a mesh
// cluster's join listener.
func (s *Server) joinAllowed(addr netip.Addr) bool {
	m := s.joinGate.from.Load()
	return m == nil || (*m)[addr.Unmap()]
}

// sourceFilter closes connections from addresses allow refuses as soon as
// they are accepted, before TLS.
type sourceFilter struct {
	net.Listener
	allow func(netip.Addr) bool
}

func (l *sourceFilter) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
		if err == nil && l.allow(ap.Addr()) {
			return c, nil
		}
		_ = c.Close()
	}
}

// startJoin serves JoinService on l until the returned function is called.
func (s *Server) startJoin(l net.Listener) func() {
	// Anyone who reaches the address may connect: bound the connections
	// before TLS, and close idle or old ones, so held connections cannot
	// use up the server process's descriptors (the token buckets below
	// only see RPCs).
	lis := newConnLimit(l, joinMaxConns, joinMaxConnsPerSource)
	idle := joinIdle
	if s.joinIdle > 0 {
		idle = s.joinIdle
	}
	g := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(s.joinTLS)),
		grpc.MaxRecvMsgSize(64<<10),
		grpc.MaxConcurrentStreams(4),
		grpc.ConnectionTimeout(10*time.Second),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: idle, MaxConnectionAge: joinMaxAge, MaxConnectionAgeGrace: 10 * time.Second, Time: idle, Timeout: 10 * time.Second}),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			if info.FullMethod != armadav1.JoinService_Join_FullMethodName && info.FullMethod != armadav1.JoinService_JoinServer_FullMethodName {
				return nil, status.Error(codes.PermissionDenied, "only joining is served here")
			}
			src := "unknown"
			if p, ok := peer.FromContext(ctx); ok {
				if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
					src = host
				}
			}
			now := time.Now()
			if !s.joinLimit.allow(src, now) || !s.joinGlobal.allow(now) {
				return nil, status.Error(codes.ResourceExhausted, "too many join attempts; try again later")
			}
			return h(ctx, req)
		}),
		grpc.StreamInterceptor(func(any, grpc.ServerStream, *grpc.StreamServerInfo, grpc.StreamHandler) error {
			return status.Error(codes.PermissionDenied, "only joining is served here")
		}),
	)
	armadav1.RegisterJoinServiceServer(g, &joinService{s: s})
	go func() {
		if err := g.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			s.log.Error("join listener stopped", "err", err)
		}
	}()
	// Stopping lets a join in flight (the one that spent the last token)
	// send its answer, for a few seconds at most.
	return func() {
		done := make(chan struct{})
		go func() {
			g.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(joinStopGrace):
			g.Stop()
		}
	}
}

// joinStopGrace bounds how long closing the join listener waits for joins
// in flight.
const joinStopGrace = 5 * time.Second

// Join registers a node presenting a valid join token and returns its
// certificate. The token secret is never logged.
func (j *joinService) Join(ctx context.Context, req *armadav1.JoinRequest) (*armadav1.JoinResponse, error) {
	s := j.s
	from := "unknown"
	if p, ok := peer.FromContext(ctx); ok {
		from = p.Addr.String()
	}
	tok, err := pki.ParseJoinToken(req.GetTokenId() + "." + req.GetTokenSecret())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid join token")
	}
	name := req.GetNodeName()
	if err := spec.ValidateName(name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "node name: %v", err)
	}
	ip, mesh, err := s.joiningAddress(ctx, req.GetPrivateIp(), req.GetNetworkKey(), req.GetEndpoint())
	if err != nil {
		return nil, err
	}
	if len(req.GetCsr()) == 0 || len(req.GetCsr()) > maxCSRSize {
		return nil, status.Error(codes.InvalidArgument, "missing or oversized CSR")
	}

	var cert pki.NodeCert
	err = s.store.RedeemJoinToken(ctx, tok.ID,
		func(hash string) bool { return pki.TokenSecretMatches(tok.Secret, hash) },
		mesh.node(name, ip),
		func() (store.NodeCert, error) {
			var err error
			cert, err = s.ca.SignNodeCSR(req.GetCsr(), name, s.nodeCertValidity)
			return store.NodeCert{Serial: cert.Serial, NotAfter: cert.NotAfter}, err
		})
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.log.Warn("join rejected: bad token", "token", tok.ID, "node", name, "from", from)
		return nil, status.Error(codes.Unauthenticated, "invalid join token")
	case errors.Is(err, store.ErrConflict):
		return nil, status.Error(codes.AlreadyExists, err.Error())
	case err != nil:
		s.log.Warn("join failed", "token", tok.ID, "node", name, "from", from, "err", err)
		return nil, status.Errorf(codes.InvalidArgument, "join failed: %v", err)
	}
	eps, err := s.endpoints(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "list servers")
	}
	n, err := s.store.GetNode(ctx, name)
	if err != nil {
		return nil, status.Error(codes.Internal, "read the new node")
	}
	mode, err := s.networkMode(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "read the cluster network")
	}
	resp := &armadav1.JoinResponse{NodeCert: cert.PEM, CaCert: s.ca.CertPEM, Servers: eps, NodeSubnet: n.Subnet, NetworkMode: mode}
	if mesh.on {
		if resp.Network, err = s.meshNetwork(ctx); err != nil {
			return nil, status.Error(codes.Internal, "read the cluster network")
		}
		resp.MeshIp = ip.String()
	}
	s.wakeJoin()
	s.log.Info("node joined", "node", name, "private_ip", ip.String(), "subnet", n.Subnet, "token", tok.ID, "version", req.GetVersion())
	s.record(ctx, store.Event{Kind: eventNode, Object: name, Node: name, Reason: "Joined", Message: "joined from " + ip.String()})
	s.Trigger()
	return resp, nil
}

// joining is how a machine joins: in a mesh cluster with its WireGuard key
// and endpoint (ADR 0049).
type joining struct {
	on            bool
	key, endpoint string
}

// node is the record of the joining machine's node.
func (j joining) node(name string, ip netip.Addr) store.Node {
	return store.Node{ID: name, PrivateIP: ip.String(), NetworkKey: j.key, Endpoint: j.endpoint}
}

// joiningAddress checks the address a machine joins with: its private IP,
// or in a mesh cluster its key and endpoint, for which it gets the lowest
// free mesh address (redeeming the token refuses one another machine took
// meanwhile).
func (s *Server) joiningAddress(ctx context.Context, privateIP, key, endpoint string) (netip.Addr, joining, error) {
	n, err := s.store.GetNetwork(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return netip.Addr{}, joining{}, status.Error(codes.Internal, "read the cluster network")
	}
	if err != nil || n.Mode != store.NetworkMesh {
		ip, err := netutil.CheckNodeIP(privateIP)
		if err != nil {
			return netip.Addr{}, joining{}, status.Errorf(codes.InvalidArgument, "private IP: %v", err)
		}
		return ip, joining{}, nil
	}
	if privateIP != "" {
		return netip.Addr{}, joining{}, status.Error(codes.InvalidArgument, "this cluster is a mesh: machines join with their endpoint, and get a mesh address")
	}
	if !validNetworkKey(key) {
		return netip.Addr{}, joining{}, status.Error(codes.InvalidArgument, "a mesh cluster needs the machine's WireGuard public key")
	}
	if _, err := netutil.CheckEndpoint(endpoint); err != nil {
		return netip.Addr{}, joining{}, status.Errorf(codes.InvalidArgument, "endpoint: %v", err)
	}
	a, err := s.store.FreeMeshAddress(ctx)
	if err != nil {
		return netip.Addr{}, joining{}, storeErr(err)
	}
	ip, err := netip.ParseAddr(a)
	if err != nil {
		return netip.Addr{}, joining{}, status.Error(codes.Internal, "mesh address")
	}
	return ip, joining{on: true, key: key, endpoint: endpoint}, nil
}

// meshNetwork is the cluster network a machine joining a mesh brings its
// tunnel up with: every node, the new one included.
func (s *Server) meshNetwork(ctx context.Context) (*armadav1.NetworkConfig, error) {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	return s.buildNetwork(ctx, nodes, nil)
}

// RenewCertificate issues a new certificate for the calling node.
func (s *Server) RenewCertificate(ctx context.Context, req *armadav1.RenewCertificateRequest) (*armadav1.RenewCertificateResponse, error) {
	id, _ := IdentityFrom(ctx)
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, "certificate renewal is disabled on this server")
	}
	if len(req.GetCsr()) == 0 || len(req.GetCsr()) > maxCSRSize {
		return nil, status.Error(codes.InvalidArgument, "missing or oversized CSR")
	}
	caller := peerCert(ctx)
	if caller == nil {
		return nil, status.Error(codes.Unauthenticated, "client certificate required")
	}
	if !s.renewLimit.allow(id.Name, time.Now()) {
		return nil, status.Error(codes.ResourceExhausted, "too many certificate renewals for this node; try again later")
	}
	cert, err := s.ca.SignNodeCSR(req.GetCsr(), id.Name, s.nodeCertValidity)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "CSR: %v", err)
	}
	if err := s.store.RecordNodeCert(ctx, id.Name, store.NodeCert{Serial: cert.Serial, NotAfter: cert.NotAfter}, pki.SerialString(caller)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("node certificate renewed", "node", id.Name, "expires", cert.NotAfter.UTC().Format(time.RFC3339))
	return &armadav1.RenewCertificateResponse{Cert: cert.PEM}, nil
}

// CreateJoinToken creates a single-use join token.
func (s *Server) CreateJoinToken(ctx context.Context, req *armadav1.CreateJoinTokenRequest) (*armadav1.CreateJoinTokenResponse, error) {
	if s.joinAddr == "" {
		return nil, status.Error(codes.FailedPrecondition, "joining is disabled on this server (no join listener)")
	}
	ttl := time.Duration(req.GetTtlSeconds()) * time.Second
	def, most := defaultTokenTTL, maxTokenTTL
	switch {
	case s.joinPublic:
		def, most = defaultMeshTokenTTL, maxMeshTokenTTL
	case req.GetServer():
		def = defaultServerTokenTTL
	}
	if ttl == 0 {
		ttl = def
	}
	if ttl < minTokenTTL || ttl > most {
		return nil, status.Errorf(codes.InvalidArgument, "token lifetime must be between %s and %s", minTokenTTL, most)
	}
	from := req.GetFrom()
	if from != "" {
		if !s.joinPublic {
			return nil, status.Error(codes.InvalidArgument, "--from is for mesh clusters, whose join listener faces the public; this one listens on the private network")
		}
		a, err := netip.ParseAddr(from)
		if err != nil || a.Zone() != "" || a.String() != from || !a.IsGlobalUnicast() {
			return nil, status.Errorf(codes.InvalidArgument, "--from %q: want the unicast IP address the machine joins from", from)
		}
	}
	if req.GetServer() {
		if s.cluster == nil || s.keys == nil {
			return nil, status.Error(codes.FailedPrecondition, "this server cannot add control plane nodes")
		}
		// A server token unlocks the CA and master keys: keep it short-lived.
		if ttl > maxServerTokenTTL {
			return nil, status.Errorf(codes.InvalidArgument, "server token lifetime must be at most %s", maxServerTokenTTL)
		}
	}
	for k, v := range req.GetLabels() {
		if err := spec.CheckAdminLabel(k, v); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	if len(req.GetLabels()) > spec.MaxNodeLabels {
		return nil, status.Errorf(codes.InvalidArgument, "at most %d labels", spec.MaxNodeLabels)
	}
	if site := req.GetSite(); site != "" {
		if err := spec.CheckLabelValue(site); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "site: %v", err)
		}
	}
	tok, err := pki.NewJoinToken()
	if err != nil {
		return nil, status.Error(codes.Internal, "generate token")
	}
	expires := s.now().Add(ttl)
	if err := s.store.CreateJoinToken(ctx, store.JoinToken{ID: tok.ID, SecretHash: tok.SecretHash(), ExpiresAt: expires, CreatedBy: actor(ctx), Server: req.GetServer(), Labels: req.GetLabels(), From: from, Site: req.GetSite()}); err != nil {
		return nil, storeErr(err)
	}
	s.wakeJoin()
	s.log.Info("join token created", "token", tok.ID, "server", req.GetServer(), "expires", expires.UTC().Format(time.RFC3339), "by", actor(ctx))
	return &armadav1.CreateJoinTokenResponse{
		Token: tok.Reveal(), CaHash: pki.CAHash(s.ca.Cert), JoinAddr: s.joinAddr, ExpiresAt: timestamppb.New(expires),
		Version: version.Get().Version,
	}, nil
}

// CordonNode marks a node (un)schedulable; replicas on a cordoned node are
// moved elsewhere.
func (s *Server) CordonNode(ctx context.Context, req *armadav1.CordonNodeRequest) (*armadav1.CordonNodeResponse, error) {
	if err := s.store.SetNodeCordoned(ctx, req.GetNode(), req.GetCordoned(), actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("node cordon", "node", req.GetNode(), "cordoned", req.GetCordoned(), "by", actor(ctx))
	reason := "Uncordoned"
	if req.GetCordoned() {
		reason = "Cordoned"
	}
	s.record(ctx, store.Event{Kind: eventNode, Object: req.GetNode(), Node: req.GetNode(), Reason: reason, Message: "by " + actor(ctx)})
	s.Trigger()
	return &armadav1.CordonNodeResponse{}, nil
}

// LabelNode sets and removes a node's admin labels (ADR 0014). Replicas
// whose node no longer matches their app's placement are moved.
func (s *Server) LabelNode(ctx context.Context, req *armadav1.LabelNodeRequest) (*armadav1.LabelNodeResponse, error) {
	if len(req.GetSet()) == 0 && len(req.GetRemove()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no labels to set or remove")
	}
	for k, v := range req.GetSet() {
		if err := spec.CheckAdminLabel(k, v); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	for _, k := range req.GetRemove() {
		if err := spec.CheckAdminLabel(k, "x"); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		if _, ok := req.GetSet()[k]; ok {
			return nil, status.Errorf(codes.InvalidArgument, "label %q is both set and removed", k)
		}
	}
	labels, err := s.store.SetNodeLabels(ctx, req.GetNode(), req.GetSet(), req.GetRemove(), actor(ctx))
	if err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("node labels", "node", req.GetNode(), "labels", len(labels), "by", actor(ctx))
	s.Trigger()
	return &armadav1.LabelNodeResponse{Labels: labels}, nil
}

// SetNodeSite moves a node to another site (ADR 0050). The site decides
// how peers reach the node, so only admins set it; the node carries it as
// the armada.site label for placement.
func (s *Server) SetNodeSite(ctx context.Context, req *armadav1.SetNodeSiteRequest) (*armadav1.SetNodeSiteResponse, error) {
	if site := req.GetSite(); site != "" {
		if err := spec.CheckLabelValue(site); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "site: %v", err)
		}
	}
	if err := s.store.SetNodeSite(ctx, req.GetNode(), req.GetSite(), actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("node site", "node", req.GetNode(), "site", req.GetSite(), "by", actor(ctx))
	s.record(ctx, store.Event{Kind: eventNode, Object: req.GetNode(), Node: req.GetNode(), Reason: "SiteChanged",
		Message: "site " + cmp.Or(req.GetSite(), "(first site)") + " by " + actor(ctx)})
	s.Trigger()
	return &armadav1.SetNodeSiteResponse{}, nil
}

// RestrictNode makes a node restricted (only apps whose placement selects
// one of its labels) or open.
func (s *Server) RestrictNode(ctx context.Context, req *armadav1.RestrictNodeRequest) (*armadav1.RestrictNodeResponse, error) {
	if err := s.store.SetNodeRestricted(ctx, req.GetNode(), req.GetRestricted(), actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("node restriction", "node", req.GetNode(), "restricted", req.GetRestricted(), "by", actor(ctx))
	s.Trigger()
	return &armadav1.RestrictNodeResponse{}, nil
}

// RemoveNode deletes a node, revokes its certificates, and disconnects its
// agent.
func (s *Server) RemoveNode(ctx context.Context, req *armadav1.RemoveNodeRequest) (*armadav1.RemoveNodeResponse, error) {
	if err := s.store.RemoveNode(ctx, req.GetNode(), req.GetForce(), actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.mu.Lock()
	if sess := s.sessions[req.GetNode()]; sess != nil {
		delete(s.sessions, req.GetNode())
		// Its last assignment runs nothing, so the agent stops the
		// replicas it ran before the session ends: its certificate is
		// revoked and it never hears from the cluster again.
		sess.endWith(&armadav1.Assignment{})
		close(sess.done)
	}
	s.mu.Unlock()
	s.log.Info("node removed", "node", req.GetNode(), "force", req.GetForce(), "by", actor(ctx))
	s.record(ctx, store.Event{Kind: eventNode, Object: req.GetNode(), Node: req.GetNode(), Reason: "Removed", Message: "by " + actor(ctx)})
	s.Trigger()
	return &armadav1.RemoveNodeResponse{}, nil
}

// peerCert returns the verified client certificate of the caller.
func peerCert(ctx context.Context) *x509.Certificate {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 || len(info.State.PeerCertificates) == 0 {
		return nil
	}
	return info.State.PeerCertificates[0]
}
