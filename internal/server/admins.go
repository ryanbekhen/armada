package server

import (
	"context"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
)

// Administrators (ADR 0028): each person gets a certificate under their own
// name, so the audit log says who did what and one person's access can be
// taken back. Only administrators manage them, never automation identities
// (default deny) or the server's internal context.

// callerAdmin returns the calling administrator's name.
func callerAdmin(ctx context.Context) (string, error) {
	acc := accessFrom(ctx)
	if acc.id.Kind != pki.KindAdmin {
		return "", status.Error(codes.PermissionDenied, "only administrators manage administrators")
	}
	return acc.id.Name, nil
}

// AddAdmin signs an administrator certificate for name from the CSR and
// records it, so certificates the name was given earlier stop working.
func (s *Server) AddAdmin(ctx context.Context, req *armadav1.AddAdminRequest) (*armadav1.IssueMetricsCertificateResponse, error) {
	me, err := callerAdmin(ctx)
	if err != nil {
		return nil, err
	}
	name := req.GetName()
	if !pki.ValidName(name) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid administrator name %q: letters, digits, '.', '_', '-', at most 63", name)
	}
	if name == me {
		return nil, status.Error(codes.InvalidArgument, "that is you: renew your own certificate with `armada admin renew`")
	}
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, "this server cannot issue certificates")
	}
	cert, err := s.ca.SignAdminCSR(req.GetCsr(), name)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign certificate: %v", err)
	}
	if err := s.store.AddAdmin(ctx, name, cert.NotBefore, actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("added administrator", "name", name, "by", me, "serial", cert.Serial)
	return &armadav1.IssueMetricsCertificateResponse{Cert: cert.PEM, CaCert: s.ca.CertPEM, ExpiresAt: timestamppb.New(cert.NotAfter)}, nil
}

// ListAdmins lists the administrators on record.
func (s *Server) ListAdmins(ctx context.Context, _ *armadav1.ListAdminsRequest) (*armadav1.ListAdminsResponse, error) {
	me, err := callerAdmin(ctx)
	if err != nil {
		return nil, err
	}
	admins, err := s.store.ListAdmins(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	out := &armadav1.ListAdminsResponse{You: me}
	for _, a := range admins {
		info := &armadav1.AdminInfo{Name: a.Name, AddedBy: a.AddedBy, Removed: a.Removed}
		if !a.AddedAt.IsZero() {
			info.AddedAt = timestamppb.New(a.AddedAt)
		}
		out.Admins = append(out.Admins, info)
	}
	slices.SortFunc(out.Admins, func(a, b *armadav1.AdminInfo) int { return strings.Compare(a.GetName(), b.GetName()) })
	return out, nil
}

// RemoveAdmin revokes every certificate of an administrator. Callers cannot
// remove themselves, so one administrator is always left.
func (s *Server) RemoveAdmin(ctx context.Context, req *armadav1.RemoveAdminRequest) (*armadav1.RemoveAdminResponse, error) {
	me, err := callerAdmin(ctx)
	if err != nil {
		return nil, err
	}
	name := req.GetName()
	if !pki.ValidName(name) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid administrator name %q", name)
	}
	if name == me {
		return nil, status.Error(codes.InvalidArgument, "you cannot remove yourself; another administrator can")
	}
	if err := s.store.RemoveAdmin(ctx, name, actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("removed administrator", "name", name, "by", me)
	return &armadav1.RemoveAdminResponse{}, nil
}
