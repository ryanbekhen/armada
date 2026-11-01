package server

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

const (
	defaultTokenTTL = time.Hour
	maxTokenTTL     = 24 * time.Hour
	// maxServerTokenTTL caps server tokens, which unlock the cluster keys.
	maxServerTokenTTL = time.Hour
	minTokenTTL       = time.Minute
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
type joinService struct {
	armadav1.UnimplementedJoinServiceServer
	s *Server
}

func (s *Server) serveJoin(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.joinAddr)
	if err != nil {
		return fmt.Errorf("join listener: %w", err)
	}
	g := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(s.joinTLS)),
		grpc.MaxRecvMsgSize(64<<10),
		grpc.MaxConcurrentStreams(4),
		grpc.ConnectionTimeout(10*time.Second),
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
		<-ctx.Done()
		g.Stop()
	}()
	go func() {
		if err := g.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			s.log.Error("join listener stopped", "err", err)
		}
	}()
	s.log.Info("join listener", "addr", s.joinAddr)
	return nil
}

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
	ip, err := netutil.CheckNodeIP(req.GetPrivateIp())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "private IP: %v", err)
	}
	if len(req.GetCsr()) == 0 || len(req.GetCsr()) > maxCSRSize {
		return nil, status.Error(codes.InvalidArgument, "missing or oversized CSR")
	}

	var cert pki.NodeCert
	err = s.store.RedeemJoinToken(ctx, tok.ID,
		func(hash string) bool { return pki.TokenSecretMatches(tok.Secret, hash) },
		store.Node{ID: name, PrivateIP: ip.String()},
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
	s.log.Info("node joined", "node", name, "private_ip", ip.String(), "token", tok.ID, "version", req.GetVersion())
	s.Trigger()
	return &armadav1.JoinResponse{NodeCert: cert.PEM, CaCert: s.ca.CertPEM, Servers: eps}, nil
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
	if ttl == 0 {
		ttl = defaultTokenTTL
	}
	if ttl < minTokenTTL || ttl > maxTokenTTL {
		return nil, status.Errorf(codes.InvalidArgument, "token lifetime must be between %s and %s", minTokenTTL, maxTokenTTL)
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
	tok, err := pki.NewJoinToken()
	if err != nil {
		return nil, status.Error(codes.Internal, "generate token")
	}
	expires := s.now().Add(ttl)
	if err := s.store.CreateJoinToken(ctx, store.JoinToken{ID: tok.ID, SecretHash: tok.SecretHash(), ExpiresAt: expires, CreatedBy: actor(ctx), Server: req.GetServer()}); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("join token created", "token", tok.ID, "server", req.GetServer(), "expires", expires.UTC().Format(time.RFC3339), "by", actor(ctx))
	return &armadav1.CreateJoinTokenResponse{
		Token: tok.Reveal(), CaHash: pki.CAHash(s.ca.Cert), JoinAddr: s.joinAddr, ExpiresAt: timestamppb.New(expires),
	}, nil
}

// CordonNode marks a node (un)schedulable; replicas on a cordoned node are
// moved elsewhere.
func (s *Server) CordonNode(ctx context.Context, req *armadav1.CordonNodeRequest) (*armadav1.CordonNodeResponse, error) {
	if err := s.store.SetNodeCordoned(ctx, req.GetNode(), req.GetCordoned(), actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("node cordon", "node", req.GetNode(), "cordoned", req.GetCordoned(), "by", actor(ctx))
	s.Trigger()
	return &armadav1.CordonNodeResponse{}, nil
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
		close(sess.done)
	}
	s.mu.Unlock()
	s.log.Info("node removed", "node", req.GetNode(), "force", req.GetForce(), "by", actor(ctx))
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
