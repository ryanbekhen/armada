package server

import (
	"context"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

// SetAutomation creates an automation identity (ADR 0026) or replaces its
// scope.
func (s *Server) SetAutomation(ctx context.Context, req *armadav1.SetAutomationRequest) (*armadav1.AutomationInfo, error) {
	a := store.Automation{Name: req.GetName(), Projects: req.GetProjects(), CreateProjects: req.GetCreateProjects(), Quota: quotaFrom(req.GetQuota())}
	if len(req.GetLabels()) > 0 {
		a.Labels = map[string][]string{}
		for _, l := range req.GetLabels() {
			a.Labels[l.GetKey()] = append(a.Labels[l.GetKey()], l.GetValues()...)
		}
	}
	if err := store.CheckAutomation(a); err != nil {
		if code := storeErr(err); status.Code(code) != codes.Internal {
			return nil, code
		}
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	got, err := s.store.SetAutomation(ctx, a, actor(ctx))
	if err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("automation identity set", "name", got.Name, "projects", got.Projects, "create_projects", got.CreateProjects, "by", actor(ctx))
	return automationInfo(got), nil
}

// ListAutomations lists the automation identities.
func (s *Server) ListAutomations(ctx context.Context, _ *armadav1.ListAutomationsRequest) (*armadav1.ListAutomationsResponse, error) {
	all, err := s.store.ListAutomations(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	resp := &armadav1.ListAutomationsResponse{}
	for _, a := range all {
		resp.Automations = append(resp.Automations, automationInfo(a))
	}
	return resp, nil
}

// DeleteAutomation removes an automation identity and so revokes its
// certificates at once.
func (s *Server) DeleteAutomation(ctx context.Context, req *armadav1.DeleteAutomationRequest) (*armadav1.DeleteAutomationResponse, error) {
	if err := s.store.DeleteAutomation(ctx, req.GetName(), actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("automation identity removed", "name", req.GetName(), "by", actor(ctx))
	return &armadav1.DeleteAutomationResponse{}, nil
}

// IssueAutomationCertificate signs a certificate for an existing
// automation identity from the tool's CSR.
func (s *Server) IssueAutomationCertificate(ctx context.Context, req *armadav1.IssueAutomationCertificateRequest) (*armadav1.IssueAutomationCertificateResponse, error) {
	if _, err := s.store.GetAutomation(ctx, req.GetName()); err != nil {
		return nil, storeErr(err)
	}
	return s.issueAutomation(ctx, req.GetName(), req.GetCsr(), "")
}

// RenewAutomationCertificate gives the calling automation identity a new
// certificate and revokes its others, as a node renews its own.
func (s *Server) RenewAutomationCertificate(ctx context.Context, req *armadav1.RenewAutomationCertificateRequest) (*armadav1.IssueAutomationCertificateResponse, error) {
	acc := accessFrom(ctx)
	if acc.automation() == "" {
		return nil, status.Error(codes.PermissionDenied, "only an automation identity renews its own certificate; administrators use IssueAutomationCertificate")
	}
	serial, err := peerSerial(ctx)
	if err != nil {
		return nil, err
	}
	return s.issueAutomation(ctx, acc.automation(), req.GetCsr(), serial)
}

func (s *Server) issueAutomation(ctx context.Context, name string, csr []byte, keep string) (*armadav1.IssueAutomationCertificateResponse, error) {
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, "this server cannot issue certificates")
	}
	cert, err := s.ca.SignAutomationCSR(csr, name)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign certificate: %v", err)
	}
	if err := s.store.RecordAutomationCert(ctx, name, store.NodeCert{Serial: cert.Serial, NotAfter: cert.NotAfter}, keep, actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("issued automation certificate", "name", name, "serial", cert.Serial, "by", actor(ctx))
	return &armadav1.IssueAutomationCertificateResponse{Cert: cert.PEM, CaCert: s.ca.CertPEM, ExpiresAt: timestamppb.New(cert.NotAfter)}, nil
}

// peerSerial returns the serial of the caller's client certificate.
func peerSerial(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no peer")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return "", status.Error(codes.Unauthenticated, "client certificate required")
	}
	return pki.SerialString(info.State.PeerCertificates[0]), nil
}

func automationInfo(a store.Automation) *armadav1.AutomationInfo {
	out := &armadav1.AutomationInfo{Name: a.Name, Projects: a.Projects, CreateProjects: a.CreateProjects, CreatedBy: a.CreatedBy,
		Certificates: int32(len(a.Certs)), Quota: quotaProto(a.Quota)} //nolint:gosec // at most store.MaxAutomationCerts
	if !a.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(a.CreatedAt)
	}
	for _, c := range a.Certs {
		if out.CertExpiresAt == nil || c.NotAfter.After(out.CertExpiresAt.AsTime()) {
			out.CertExpiresAt = timestamppb.New(c.NotAfter)
		}
	}
	keys := make([]string, 0, len(a.Labels))
	for k := range a.Labels {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		out.Labels = append(out.Labels, &armadav1.LabelAllowance{Key: k, Values: a.Labels[k]})
	}
	return out
}
