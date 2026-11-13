package server

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// Access control (ADR 0033): users and services, and the roles they hold.
// Only cluster-admin calls these methods (they are not in methodNeeds),
// except RenewOwnCertificate.

// checkName validates a principal's kind and name: users are named like
// certificates, services like apps.
func checkName(kind, name string) error {
	switch kind {
	case store.KindUser:
		if !pki.ValidName(name) {
			return status.Errorf(codes.InvalidArgument, "invalid user name %q: letters, digits, '.', '_', '-', at most 63", name)
		}
	case store.KindService:
		if !spec.ValidName(name) {
			return status.Errorf(codes.InvalidArgument, "invalid service name %q: lowercase letters, digits, and single hyphens", name)
		}
	default:
		return status.Errorf(codes.InvalidArgument, "unknown kind %q: user or service", kind)
	}
	return nil
}

// notSelf refuses a change a caller would make to itself.
func notSelf(ctx context.Context, kind, name, what string) error {
	if id, _ := IdentityFrom(ctx); id.Kind == kind && id.Name == name {
		return status.Errorf(codes.InvalidArgument, "you cannot %s yourself; another cluster-admin can", what)
	}
	return nil
}

func grantsFrom(in []*armadav1.RoleAssignment) ([]store.Grant, error) {
	out := make([]store.Grant, 0, len(in))
	for _, r := range in {
		g := store.Grant{Role: r.GetRole(), Space: r.GetSpace()}
		if err := checkGrant(g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

func checkGrant(g store.Grant) error {
	if err := store.CheckGrant(g); err != nil {
		if errors.Is(err, store.ErrPrecondition) {
			return status.Error(codes.FailedPrecondition, err.Error())
		}
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}

func labelsFrom(in []*armadav1.LabelAllowance) (map[string][]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := map[string][]string{}
	for _, l := range in {
		out[l.GetKey()] = append(out[l.GetKey()], l.GetValues()...)
	}
	if err := store.CheckLabels(out); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return out, nil
}

func certResponse(s *Server, c pki.NodeCert) *armadav1.IssueMetricsCertificateResponse {
	return &armadav1.IssueMetricsCertificateResponse{Cert: c.PEM, CaCert: s.ca.CertPEM, ExpiresAt: timestamppb.New(c.NotAfter)}
}

func (s *Server) canSign() error {
	if s.ca == nil {
		return status.Error(codes.FailedPrecondition, "this server cannot issue certificates")
	}
	return nil
}

// CreateUser records a user with their first roles and signs a certificate
// for the key in the CSR.
func (s *Server) CreateUser(ctx context.Context, req *armadav1.CreateUserRequest) (*armadav1.IssueMetricsCertificateResponse, error) {
	name := req.GetName()
	if err := checkName(store.KindUser, name); err != nil {
		return nil, err
	}
	if err := notSelf(ctx, store.KindUser, name, "create"); err != nil {
		return nil, err
	}
	roles, err := grantsFrom(req.GetRoles())
	if err != nil {
		return nil, err
	}
	labels, err := labelsFrom(req.GetLabels())
	if err != nil {
		return nil, err
	}
	if err := s.canSign(); err != nil {
		return nil, err
	}
	cert, err := s.ca.SignUserCSR(req.GetCsr(), name)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign certificate: %v", err)
	}
	p, err := s.store.CreateUser(ctx, store.Principal{Name: name, Since: cert.NotBefore, Roles: roles, Labels: labels}, actor(ctx))
	if err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("created user", "name", name, "roles", len(p.Roles), "by", actor(ctx), "serial", cert.Serial)
	return certResponse(s, cert), nil
}

// IssueUserCertificate gives a user a new certificate; the ones issued
// earlier stop working.
func (s *Server) IssueUserCertificate(ctx context.Context, req *armadav1.IssuePrincipalCertificateRequest) (*armadav1.IssueMetricsCertificateResponse, error) {
	name := req.GetName()
	if err := checkName(store.KindUser, name); err != nil {
		return nil, err
	}
	if err := notSelf(ctx, store.KindUser, name, "replace the certificate of"); err != nil {
		return nil, status.Error(codes.InvalidArgument, "renew your own certificate with `armada rbac user renew`")
	}
	if _, err := s.store.GetPrincipal(ctx, store.KindUser, name); err != nil {
		return nil, storeErr(err)
	}
	if err := s.canSign(); err != nil {
		return nil, err
	}
	cert, err := s.ca.SignUserCSR(req.GetCsr(), name)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign certificate: %v", err)
	}
	if err := s.store.SetUserSince(ctx, name, cert.NotBefore, actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("issued user certificate", "name", name, "by", actor(ctx), "serial", cert.Serial)
	return certResponse(s, cert), nil
}

// CreateService records a service with its first roles.
func (s *Server) CreateService(ctx context.Context, req *armadav1.CreateServiceRequest) (*armadav1.Principal, error) {
	name := req.GetName()
	if err := checkName(store.KindService, name); err != nil {
		return nil, err
	}
	roles, err := grantsFrom(req.GetRoles())
	if err != nil {
		return nil, err
	}
	labels, err := labelsFrom(req.GetLabels())
	if err != nil {
		return nil, err
	}
	p, err := s.store.CreateService(ctx, store.Principal{Name: name, Roles: roles, Labels: labels}, actor(ctx))
	if err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("created service", "name", name, "roles", len(p.Roles), "by", actor(ctx))
	return principalInfo(p), nil
}

// IssueServiceCertificate signs a certificate for an existing service from
// the tool's CSR.
func (s *Server) IssueServiceCertificate(ctx context.Context, req *armadav1.IssuePrincipalCertificateRequest) (*armadav1.IssueMetricsCertificateResponse, error) {
	if err := checkName(store.KindService, req.GetName()); err != nil {
		return nil, err
	}
	if _, err := s.store.GetPrincipal(ctx, store.KindService, req.GetName()); err != nil {
		return nil, storeErr(err)
	}
	return s.issueService(ctx, req.GetName(), req.GetCsr(), "")
}

func (s *Server) issueService(ctx context.Context, name string, csr []byte, keep string) (*armadav1.IssueMetricsCertificateResponse, error) {
	if err := s.canSign(); err != nil {
		return nil, err
	}
	cert, err := s.ca.SignServiceCSR(csr, name)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign certificate: %v", err)
	}
	if err := s.store.RecordServiceCert(ctx, name, store.NodeCert{Serial: cert.Serial, NotAfter: cert.NotAfter}, keep, actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("issued service certificate", "name", name, "serial", cert.Serial, "by", actor(ctx))
	return certResponse(s, cert), nil
}

// RenewOwnCertificate gives the calling user or service a new certificate.
// A service's other certificates are revoked, as a node's are; a user's
// stay valid until they expire.
func (s *Server) RenewOwnCertificate(ctx context.Context, req *armadav1.RenewOwnCertificateRequest) (*armadav1.IssueMetricsCertificateResponse, error) {
	acc := accessFrom(ctx)
	if acc.p == nil {
		return nil, status.Error(codes.PermissionDenied, "only users and services renew their own certificates")
	}
	if acc.id.Kind == pki.KindService {
		serial, err := peerSerial(ctx)
		if err != nil {
			return nil, err
		}
		return s.issueService(ctx, acc.id.Name, req.GetCsr(), serial)
	}
	if err := s.canSign(); err != nil {
		return nil, err
	}
	cert, err := s.ca.SignUserCSR(req.GetCsr(), acc.id.Name)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign certificate: %v", err)
	}
	if err := s.store.RecordAudit(ctx, actor(ctx), "user.certificate", acc.id.Name, "serial="+cert.Serial); err != nil {
		return nil, storeErr(err)
	}
	// A user the CA signed outside the API shows up in listings.
	if err := s.store.KnowUser(ctx, acc.id.Name); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("renewed user certificate", "name", acc.id.Name, "serial", cert.Serial)
	return certResponse(s, cert), nil
}

// ListPrincipals lists users and services with their roles.
func (s *Server) ListPrincipals(ctx context.Context, req *armadav1.ListPrincipalsRequest) (*armadav1.ListPrincipalsResponse, error) {
	if k := req.GetKind(); k != "" && k != store.KindUser && k != store.KindService {
		return nil, status.Errorf(codes.InvalidArgument, "unknown kind %q: user or service", k)
	}
	all, err := s.store.ListPrincipals(ctx, req.GetKind())
	if err != nil {
		return nil, storeErr(err)
	}
	id, _ := IdentityFrom(ctx)
	out := &armadav1.ListPrincipalsResponse{YouKind: id.Kind, You: id.Name}
	for _, p := range all {
		out.Principals = append(out.Principals, principalInfo(p))
	}
	return out, nil
}

// UpdatePrincipal replaces the node labels a principal's apps may require.
func (s *Server) UpdatePrincipal(ctx context.Context, req *armadav1.UpdatePrincipalRequest) (*armadav1.Principal, error) {
	if err := checkName(req.GetKind(), req.GetName()); err != nil {
		return nil, err
	}
	labels, err := labelsFrom(req.GetLabels())
	if err != nil {
		return nil, err
	}
	p, err := s.store.SetPrincipalLabels(ctx, req.GetKind(), req.GetName(), labels, actor(ctx))
	if err != nil {
		return nil, storeErr(err)
	}
	return principalInfo(p), nil
}

// DeletePrincipal revokes every certificate of a user or service. Callers
// cannot delete themselves, so a cluster-admin is always left.
func (s *Server) DeletePrincipal(ctx context.Context, req *armadav1.DeletePrincipalRequest) (*armadav1.DeletePrincipalResponse, error) {
	if err := checkName(req.GetKind(), req.GetName()); err != nil {
		return nil, err
	}
	if err := notSelf(ctx, req.GetKind(), req.GetName(), "delete"); err != nil {
		return nil, err
	}
	if err := s.store.DeletePrincipal(ctx, req.GetKind(), req.GetName(), actor(ctx)); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("deleted principal", "kind", req.GetKind(), "name", req.GetName(), "by", actor(ctx))
	return &armadav1.DeletePrincipalResponse{}, nil
}

func assignment(req *armadav1.AssignmentRequest) (store.Grant, error) {
	if err := checkName(req.GetKind(), req.GetName()); err != nil {
		return store.Grant{}, err
	}
	g := store.Grant{Role: req.GetRole().GetRole(), Space: req.GetRole().GetSpace()}
	return g, checkGrant(g)
}

// CreateAssignment gives a principal a role.
func (s *Server) CreateAssignment(ctx context.Context, req *armadav1.AssignmentRequest) (*armadav1.Principal, error) {
	g, err := assignment(req)
	if err != nil {
		return nil, err
	}
	p, err := s.store.Assign(ctx, req.GetKind(), req.GetName(), g, actor(ctx))
	if err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("assigned role", "kind", req.GetKind(), "name", req.GetName(), "role", g.String(), "by", actor(ctx))
	return principalInfo(p), nil
}

// DeleteAssignment takes a role back. A caller keeps its own
// cluster-admin.
func (s *Server) DeleteAssignment(ctx context.Context, req *armadav1.AssignmentRequest) (*armadav1.Principal, error) {
	g, err := assignment(req)
	if err != nil {
		return nil, err
	}
	if g.Role == store.RoleClusterAdmin {
		if err := notSelf(ctx, req.GetKind(), req.GetName(), "take cluster-admin from"); err != nil {
			return nil, err
		}
	}
	p, err := s.store.Unassign(ctx, req.GetKind(), req.GetName(), g, actor(ctx))
	if err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("unassigned role", "kind", req.GetKind(), "name", req.GetName(), "role", g.String(), "by", actor(ctx))
	return principalInfo(p), nil
}

var roleInfo = []*armadav1.RoleInfo{
	{Name: store.RoleViewer, Cluster: true, Space: true,
		Description: "See apps, jobs, revisions, specs, secret names, domains, volumes, logs, usage, and events"},
	{Name: store.RoleDeployer, Space: true,
		Description: "What a viewer may, and deploy, scale, roll back, split traffic, set secrets, run jobs, verify domains"},
	{Name: store.RoleAdmin, Space: true,
		Description: "What a deployer may, and exec, back up, restore, and delete volumes, delete apps and jobs"},
	{Name: store.RoleSpaceCreator, Cluster: true,
		Description: "Create spaces (becoming admin of each), and delete empty ones it is admin of"},
	{Name: store.RoleClusterAdmin, Cluster: true,
		Description: "Everything: nodes, servers, cluster settings, join tokens, metrics credentials, and access control"},
}

// ListRoles lists the built-in roles and the methods each allows.
func (s *Server) ListRoles(context.Context, *armadav1.ListRolesRequest) (*armadav1.ListRolesResponse, error) {
	out := &armadav1.ListRolesResponse{}
	for _, r := range roleInfo {
		info := &armadav1.RoleInfo{Name: r.GetName(), Description: r.GetDescription(), Cluster: r.GetCluster(), Space: r.GetSpace()}
		for m, n := range methodNeeds {
			if roleAllows(r.GetName(), n) {
				info.Methods = append(info.Methods, strings.TrimPrefix(m, adminService))
			}
		}
		slices.Sort(info.Methods)
		if r.GetName() == store.RoleClusterAdmin {
			info.Methods = []string{"*"}
		}
		out.Roles = append(out.Roles, info)
	}
	return out, nil
}

// roleAllows reports whether role alone allows a method of need.
func roleAllows(role string, n need) bool {
	switch n {
	case needSelf:
		return true
	case needCreateSpaces:
		return role == store.RoleSpaceCreator
	case needView, needDeploy, needAdmin:
		return roleLevel[role] >= n
	}
	return false
}

func principalInfo(p store.Principal) *armadav1.Principal {
	out := &armadav1.Principal{Kind: p.Kind, Name: p.Name, CreatedBy: p.CreatedBy, Removed: p.Removed,
		Certificates: int32(len(p.Certs))} //nolint:gosec // at most store.MaxServiceCerts
	if !p.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(p.CreatedAt)
	}
	for _, g := range p.Roles {
		out.Roles = append(out.Roles, &armadav1.RoleAssignment{Role: g.Role, Space: g.Space})
	}
	for _, c := range p.Certs {
		if out.CertExpiresAt == nil || c.NotAfter.After(out.CertExpiresAt.AsTime()) {
			out.CertExpiresAt = timestamppb.New(c.NotAfter)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(p.Labels)) {
		out.Labels = append(out.Labels, &armadav1.LabelAllowance{Key: k, Values: p.Labels[k]})
	}
	return out
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
