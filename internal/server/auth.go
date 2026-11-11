package server

import (
	"context"
	"crypto/x509"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

type identityKey struct{}

// IdentityFrom returns the authenticated caller stored by the interceptors.
func IdentityFrom(ctx context.Context) (pki.Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(pki.Identity)
	return id, ok
}

func (s *Server) authorize(ctx context.Context, method string) (context.Context, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 || len(info.State.PeerCertificates) == 0 {
		return nil, status.Error(codes.Unauthenticated, "client certificate required")
	}
	cert := info.State.PeerCertificates[0]
	id, err := pki.IdentityFromCert(cert)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid client identity")
	}
	if pid, ok := id.Principal(); ok {
		return s.authorizePrincipal(ctx, pid, cert, method)
	}
	if id.Kind != pki.KindNode || !strings.HasPrefix(method, "/armada.v1.AgentService/") {
		return nil, status.Errorf(codes.PermissionDenied, "%s may not call %s", id, method)
	}
	// Node certificates are only valid while recorded: removing a node
	// revokes them at once.
	ok, err = s.store.NodeCertAllowed(ctx, id.Name, pki.SerialString(cert))
	if err != nil {
		return nil, status.Error(codes.Unavailable, "check node certificate")
	}
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "certificate of %s is revoked or the node was removed", id)
	}
	return context.WithValue(ctx, identityKey{}, id), nil
}

// principalAccess reads a user's or service's roles and whether the cluster
// accepts its certificate (ADR 0033): a user's issued before their latest,
// or a deleted user's, are refused; a service's only while recorded.
func (s *Server) principalAccess(ctx context.Context, pid pki.Identity, cert *x509.Certificate) (store.Principal, bool, error) {
	if pid.Kind == pki.KindService {
		return s.store.ServiceAccess(ctx, pid.Name, pki.SerialString(cert))
	}
	return s.store.UserAccess(ctx, pid.Name, cert.NotBefore)
}

// authorizePrincipal lets a user or service call AdminService methods its
// roles allow: every method with cluster-admin, else only those in
// methodNeeds that one of its roles reaches. Its roles are read on every
// call, and each handler checks them against the projects it touches.
func (s *Server) authorizePrincipal(ctx context.Context, pid pki.Identity, cert *x509.Certificate, method string) (context.Context, error) {
	if !strings.HasPrefix(method, adminService) {
		return nil, status.Errorf(codes.PermissionDenied, "%s may not call %s", pid, method)
	}
	p, ok, err := s.principalAccess(ctx, pid, cert)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "check client certificate")
	}
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "certificate of %s is revoked, expired, or the %s was deleted", pid, pid.Kind)
	}
	acc := access{id: pid, p: &p, need: methodNeeds[method]}
	if !acc.admin() {
		n, placed := methodNeeds[method]
		if !placed {
			return nil, status.Errorf(codes.PermissionDenied, "%s may not call %s: it needs cluster-admin", pid, method)
		}
		if !acc.reaches(n) {
			return nil, status.Errorf(codes.PermissionDenied, "%s has no role that allows %s", pid, strings.TrimPrefix(method, adminService))
		}
	}
	ctx = context.WithValue(ctx, identityKey{}, pid)
	return context.WithValue(ctx, accessKey{}, acc), nil
}

func (s *Server) unaryAuth(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	ctx, err := s.authorize(ctx, info.FullMethod)
	if err != nil {
		return nil, err
	}
	if md := s.serversHeader(ctx, info.FullMethod); md != nil {
		_ = grpc.SetHeader(ctx, md)
	}
	return handler(ctx, req)
}

func (s *Server) streamAuth(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, err := s.authorize(ss.Context(), info.FullMethod)
	if err != nil {
		return err
	}
	if md := s.serversHeader(ctx, info.FullMethod); md != nil {
		_ = ss.SetHeader(md)
	}
	return handler(srv, &authedStream{ServerStream: ss, ctx: ctx})
}

// seenEndpoints are API addresses and when they were read.
type seenEndpoints struct {
	addrs []string
	at    time.Time
}

// endpointsFresh is how long addresses read for the header are used: a
// reconcile pass also refreshes them.
const endpointsFresh = 10 * time.Second

// serversHeader returns the header for an AdminService call: the control
// plane's API addresses, read again when older than endpointsFresh, or nil
// when they cannot be read.
func (s *Server) serversHeader(ctx context.Context, method string) metadata.MD {
	if !strings.HasPrefix(method, "/"+armadav1.AdminService_ServiceDesc.ServiceName+"/") {
		return nil
	}
	seen := s.endpointsSeen.Load()
	if seen == nil || time.Since(seen.at) > endpointsFresh {
		rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		eps, err := s.endpoints(rctx)
		cancel()
		if err == nil {
			seen = &seenEndpoints{addrs: eps, at: time.Now()}
			s.endpointsSeen.Store(seen)
		}
	}
	if seen == nil || len(seen.addrs) == 0 {
		return nil
	}
	return metadata.Pairs(clientconfig.ServersHeader, strings.Join(seen.addrs, ","))
}

type authedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authedStream) Context() context.Context { return s.ctx }
