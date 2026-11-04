package server

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/ryanbekhen/armada/internal/pki"
)

type identityKey struct{}

// IdentityFrom returns the authenticated caller stored by the interceptors.
func IdentityFrom(ctx context.Context) (pki.Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(pki.Identity)
	return id, ok
}

// requiredKind maps service prefixes to the identity kind allowed to call
// them. Methods outside these services are denied.
var requiredKind = map[string]string{
	"/armada.v1.AdminService/": pki.KindAdmin,
	"/armada.v1.AgentService/": pki.KindNode,
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
	if id.Kind == pki.KindNode {
		// Node certificates are only valid while recorded: removing a node
		// revokes them at once.
		ok, err := s.store.NodeCertAllowed(ctx, id.Name, pki.SerialString(cert))
		if err != nil {
			return nil, status.Error(codes.Unavailable, "check node certificate")
		}
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "certificate of %s is revoked or the node was removed", id)
		}
	}
	if id.Kind == pki.KindAutomation {
		return s.authorizeAutomation(ctx, id, pki.SerialString(cert), method)
	}
	for prefix, kind := range requiredKind {
		if strings.HasPrefix(method, prefix) {
			if id.Kind != kind {
				return nil, status.Errorf(codes.PermissionDenied, "%s may not call %s", id, method)
			}
			return context.WithValue(ctx, identityKey{}, id), nil
		}
	}
	return nil, status.Errorf(codes.PermissionDenied, "unknown method %s", method)
}

// authorizeAutomation lets an automation identity call only the methods in
// automationMethods, and only while its certificate is recorded. Its scope
// is read from the store on every call and checked by each handler.
func (s *Server) authorizeAutomation(ctx context.Context, id pki.Identity, serial, method string) (context.Context, error) {
	scope, ok, err := s.store.AutomationScope(ctx, id.Name, serial)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "check automation certificate")
	}
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "certificate of %s is revoked, expired, or the identity was removed", id)
	}
	if !automationMethods[method] {
		return nil, status.Errorf(codes.PermissionDenied, "%s may not call %s", id, method)
	}
	ctx = context.WithValue(ctx, identityKey{}, id)
	return context.WithValue(ctx, scopeKey{}, scope), nil
}

func (s *Server) unaryAuth(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	ctx, err := s.authorize(ctx, info.FullMethod)
	if err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (s *Server) streamAuth(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, err := s.authorize(ss.Context(), info.FullMethod)
	if err != nil {
		return err
	}
	return handler(srv, &authedStream{ServerStream: ss, ctx: ctx})
}

type authedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authedStream) Context() context.Context { return s.ctx }
