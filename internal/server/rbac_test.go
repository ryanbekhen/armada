package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

// dialService connects as service:name with a certificate recorded for it
// (unless record is false).
func (c *cluster) dialService(name string, record bool) (*grpc.ClientConn, string) {
	c.t.Helper()
	return c.dialServiceKind(pki.KindService, name, record)
}

// dialServiceKind is dialService with a certificate of kind, so the kind
// of earlier releases (automation) can be tried.
func (c *cluster) dialServiceKind(kind, name string, record bool) (*grpc.ClientConn, string) {
	c.t.Helper()
	id := pki.Identity{Kind: kind, Name: name}
	certPEM, keyPEM, err := c.ca.Issue(pki.IssueRequest{Identity: id, Client: true})
	if err != nil {
		c.t.Fatal(err)
	}
	cert, _ := pki.ParseCertPEM(certPEM)
	serial := pki.SerialString(cert)
	if record {
		if err := c.store.RecordServiceCert(c.ctx, name, store.NodeCert{Serial: serial, NotAfter: cert.NotAfter}, "", "user:test"); err != nil {
			c.t.Fatal(err)
		}
	}
	return c.dialPEM(certPEM, keyPEM), serial
}

// serviceCluster has spaces a and b, the app web in default, a, and b,
// and service:portal with admin in a.
func serviceCluster(t *testing.T) (*cluster, armadav1.AdminServiceClient, *grpc.ClientConn) {
	t.Helper()
	c := newCluster(t)
	for _, p := range []string{"a", "b"} {
		if _, err := c.admin.CreateSpace(c.ctx, &armadav1.CreateSpaceRequest{Name: p}); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"", "a", "b"} {
		if _, err := c.admin.Deploy(c.ctx, &armadav1.DeployRequest{Spec: []byte(webSpec("nginx:1", 1)), Space: p}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.admin.CreateService(c.ctx, &armadav1.CreateServiceRequest{Name: "portal", Roles: []*armadav1.RoleAssignment{{Role: "admin", Space: "a"}},
		Labels: []*armadav1.LabelAllowance{{Key: "tier", Values: []string{"shared"}}}}); err != nil {
		t.Fatal(err)
	}
	conn, _ := c.dialService("portal", true)
	return c, armadav1.NewAdminServiceClient(conn), conn
}

func wantCode(t *testing.T, what string, err error, code codes.Code) {
	t.Helper()
	if status.Code(err) != code {
		t.Errorf("%s: %v, want %s", what, err, code)
	}
}

// streamErr returns the error a server stream ends with.
func streamErr[T any](s interface{ Recv() (T, error) }, err error) error {
	if err != nil {
		return err
	}
	for {
		if _, err := s.Recv(); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func TestServiceUnrecordedCertificate(t *testing.T) {
	t.Parallel()
	c, _, _ := serviceCluster(t)
	conn, _ := c.dialService("portal", false)
	_, err := armadav1.NewAdminServiceClient(conn).Status(c.ctx, &armadav1.StatusRequest{App: "web.a"})
	wantCode(t, "unrecorded certificate", err, codes.Unauthenticated)
	conn, _ = c.dialService("ghost", false)
	_, err = armadav1.NewAdminServiceClient(conn).Status(c.ctx, &armadav1.StatusRequest{})
	wantCode(t, "identity that does not exist", err, codes.Unauthenticated)
}

// Every AdminService method outside methodNeeds is refused before its
// handler runs for a principal without cluster-admin, including methods
// added later.
func TestRoleMethodsDefaultDeny(t *testing.T) {
	t.Parallel()
	c, _, conn := serviceCluster(t)
	desc := armadav1.AdminService_ServiceDesc
	known := map[string]bool{}
	for _, m := range desc.Methods {
		full := "/" + desc.ServiceName + "/" + m.MethodName
		known[full] = true
		if _, placed := methodNeeds[full]; placed {
			continue
		}
		err := conn.Invoke(c.ctx, full, &emptypb.Empty{}, &emptypb.Empty{})
		wantCode(t, full, err, codes.PermissionDenied)
	}
	for _, sd := range desc.Streams {
		full := "/" + desc.ServiceName + "/" + sd.StreamName
		known[full] = true
		if _, placed := methodNeeds[full]; placed {
			continue
		}
		s, err := conn.NewStream(c.ctx, &sd, full)
		if err == nil {
			if sd.ClientStreams {
				_ = s.CloseSend()
			} else {
				_ = s.SendMsg(&emptypb.Empty{})
				_ = s.CloseSend()
			}
			err = s.RecvMsg(&emptypb.Empty{})
		}
		wantCode(t, full, err, codes.PermissionDenied)
	}
	for m := range methodNeeds {
		if !known[m] {
			t.Errorf("methodNeeds names %s, which AdminService does not have", m)
		}
	}
	// The agent API is out of reach too.
	_, err := armadav1.NewAgentServiceClient(conn).RenewCertificate(c.ctx, &armadav1.RenewCertificateRequest{Csr: []byte("x")})
	wantCode(t, "agent API", err, codes.PermissionDenied)
}

// Every method a space role allows refuses apps of the default space
// and of spaces the principal holds no role in.
func TestRoleOutOfScope(t *testing.T) {
	t.Parallel()
	c, p, _ := serviceCluster(t)
	ctx := c.ctx
	for _, app := range []string{"web", "web.b", "ghost.b", "bad..id"} {
		calls := map[string]func() error{
			"Scale":         func() error { _, err := p.Scale(ctx, &armadav1.ScaleRequest{App: app, Replicas: 2}); return err },
			"SetTraffic":    func() error { _, err := p.SetTraffic(ctx, &armadav1.SetTrafficRequest{App: app}); return err },
			"ListRevisions": func() error { _, err := p.ListRevisions(ctx, &armadav1.ListRevisionsRequest{App: app}); return err },
			"Rollback":      func() error { _, err := p.Rollback(ctx, &armadav1.RollbackRequest{App: app}); return err },
			"SetSecret": func() error {
				_, err := p.SetSecret(ctx, &armadav1.SetSecretRequest{App: app, Name: "pw", Value: []byte("x")})
				return err
			},
			"ListSecrets": func() error { _, err := p.ListSecrets(ctx, &armadav1.ListSecretsRequest{App: app}); return err },
			"DeleteSecret": func() error {
				_, err := p.DeleteSecret(ctx, &armadav1.DeleteSecretRequest{App: app, Name: "pw"})
				return err
			},
			"RunJob":      func() error { _, err := p.RunJob(ctx, &armadav1.RunJobRequest{Job: app}); return err },
			"ListJobRuns": func() error { _, err := p.ListJobRuns(ctx, &armadav1.ListJobRunsRequest{Job: app}); return err },
			"CancelJob":   func() error { _, err := p.CancelJob(ctx, &armadav1.CancelJobRequest{Job: app}); return err },
			"DeleteJob":   func() error { _, err := p.DeleteJob(ctx, &armadav1.DeleteJobRequest{Job: app}); return err },
			"RemoveApp":   func() error { _, err := p.RemoveApp(ctx, &armadav1.RemoveAppRequest{App: app}); return err },
			"RemoveVolume": func() error {
				_, err := p.RemoveVolume(ctx, &armadav1.RemoveVolumeRequest{App: app, Name: "data"})
				return err
			},
			"Status":      func() error { _, err := p.Status(ctx, &armadav1.StatusRequest{App: app}); return err },
			"Top":         func() error { _, err := p.Top(ctx, &armadav1.TopRequest{App: app}); return err },
			"ListDomains": func() error { _, err := p.ListDomains(ctx, &armadav1.ListDomainsRequest{App: app}); return err },
			"ListVolumes": func() error { _, err := p.ListVolumes(ctx, &armadav1.ListVolumesRequest{App: app}); return err },
			"Logs": func() error {
				s, err := p.Logs(ctx, &armadav1.LogsRequest{App: app})
				return streamErr[*armadav1.LogEntry](s, err)
			},
			"Events": func() error {
				s, err := p.Events(ctx, &armadav1.EventsRequest{App: app})
				return streamErr[*armadav1.EventInfo](s, err)
			},
			"BackupVolume": func() error {
				s, err := p.BackupVolume(ctx, &armadav1.BackupVolumeRequest{App: app, Name: "data"})
				return streamErr[*armadav1.VolumeData](s, err)
			},
			"Exec": func() error {
				s, err := p.Exec(ctx)
				if err != nil {
					return err
				}
				if err := s.Send(&armadav1.ExecClientMessage{Msg: &armadav1.ExecClientMessage_Start{Start: &armadav1.ExecStart{App: app, Cmd: []string{"sh"}}}}); err != nil {
					return err
				}
				_, err = s.Recv()
				return err
			},
			"RestoreVolume": func() error {
				s, err := p.RestoreVolume(ctx)
				if err != nil {
					return err
				}
				if err := s.Send(&armadav1.RestoreVolumeMessage{Msg: &armadav1.RestoreVolumeMessage_Start{Start: &armadav1.RestoreVolumeStart{App: app, Name: "data"}}}); err != nil {
					return err
				}
				_, err = s.CloseAndRecv()
				return err
			},
		}
		for name, call := range calls {
			wantCode(t, name+" "+app, call(), codes.PermissionDenied)
		}
	}
	for _, space := range []string{"", "default", "b", "missing"} {
		_, err := p.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte(webSpec("nginx:2", 1)), Space: space})
		wantCode(t, "Deploy into "+space, err, codes.PermissionDenied)
	}
	_, err := p.Events(ctx, &armadav1.EventsRequest{Node: "n1"})
	if err == nil {
		s, _ := p.Events(ctx, &armadav1.EventsRequest{Node: "n1"})
		err = streamErr[*armadav1.EventInfo](s, nil)
	}
	wantCode(t, "Events of a node", err, codes.PermissionDenied)
	for _, name := range []string{"b", "default"} {
		_, err := p.DeleteSpace(ctx, &armadav1.DeleteSpaceRequest{Name: name})
		wantCode(t, "DeleteSpace "+name, err, codes.PermissionDenied)
	}
	_, err = p.CreateSpace(ctx, &armadav1.CreateSpaceRequest{Name: "c"})
	wantCode(t, "CreateSpace without permission", err, codes.PermissionDenied)
}

func TestRoleInScope(t *testing.T) {
	t.Parallel()
	c, p, _ := serviceCluster(t)
	ctx := c.ctx

	if _, err := p.Scale(ctx, &armadav1.ScaleRequest{App: "web.a", Replicas: 2}); err != nil {
		t.Fatalf("scale its app: %v", err)
	}
	if _, err := p.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte(webSpec("nginx:2", 1)), Space: "a"}); err != nil {
		t.Fatalf("deploy into its space: %v", err)
	}
	if _, err := p.ListRevisions(ctx, &armadav1.ListRevisionsRequest{App: "web.a"}); err != nil {
		t.Errorf("revisions: %v", err)
	}

	// Listings hold only its spaces, and no nodes.
	st, err := p.Status(ctx, &armadav1.StatusRequest{})
	if err != nil || len(st.Apps) != 1 || st.Apps[0].Name != "web.a" || len(st.Nodes) != 0 {
		t.Fatalf("status: %v %v", st, err)
	}
	top, err := p.Top(ctx, &armadav1.TopRequest{})
	if err != nil || len(top.Nodes) != 0 || slices.ContainsFunc(top.Replicas, func(r *armadav1.ReplicaTop) bool { return r.App != "web.a" }) {
		t.Errorf("top: %v %v", top, err)
	}
	ps, err := p.ListSpaces(ctx, &armadav1.ListSpacesRequest{})
	if err != nil || len(ps.Spaces) != 1 || ps.Spaces[0].Name != "a" {
		t.Errorf("spaces: %v %v", ps, err)
	}
	s, err := p.Events(ctx, &armadav1.EventsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for {
		e, err := s.Recv()
		if err != nil {
			break
		}
		if e.App != "web.a" {
			t.Errorf("event of another app or the cluster: %v", e)
		}
	}

	// Placement may only name the labels of its scope.
	placed := func(label string) string {
		return webSpec("nginx:3", 1) + "placement:\n  require:\n    " + label + "\n"
	}
	if _, err := p.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte(placed("tier: dedicated")), Space: "a"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("placement outside the scope: %v", err)
	}
	if _, err := p.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte(placed("tier: shared")), Space: "a"}); err != nil {
		t.Errorf("placement inside the scope: %v", err)
	}
	if _, err := p.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte(placed("armada.arch: arm64")), Space: "a"}); err != nil {
		t.Errorf("placement on a reported label: %v", err)
	}

	// With space-creator, it creates spaces it is then admin of, and
	// deletes them.
	if _, err := c.admin.CreateAssignment(ctx, &armadav1.AssignmentRequest{Kind: "service", Name: "portal", Role: &armadav1.RoleAssignment{Role: "space-creator"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateSpace(ctx, &armadav1.CreateSpaceRequest{Name: "c"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := p.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte(webSpec("nginx:1", 1)), Space: "c"}); err != nil {
		t.Fatalf("deploy into the created space: %v", err)
	}
	if _, err := p.DeleteSpace(ctx, &armadav1.DeleteSpaceRequest{Name: "b"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("remove a space outside the scope: %v", err)
	}
	if _, err := p.RemoveApp(ctx, &armadav1.RemoveAppRequest{App: "web.c"}); err != nil {
		t.Fatal(err)
	}
	c.eventually("web.c gone", func() bool {
		_, err := c.store.GetApp(ctx, "web.c")
		return errors.Is(err, store.ErrNotFound)
	})
	if _, err := p.DeleteSpace(ctx, &armadav1.DeleteSpaceRequest{Name: "c"}); err != nil {
		t.Errorf("delete the created space: %v", err)
	}
}

func TestServiceRenewAndRevoke(t *testing.T) {
	t.Parallel()
	c, p, _ := serviceCluster(t)
	ctx := c.ctx
	// Another certificate of the identity, say one that leaked.
	// The kind of earlier releases is the same service.
	otherConn, _ := c.dialServiceKind(pki.KindAutomation, "portal", true)
	other := armadav1.NewAdminServiceClient(otherConn)
	if _, err := other.Status(ctx, &armadav1.StatusRequest{App: "web.a"}); err != nil {
		t.Fatal(err)
	}

	_, csr, err := pki.NewCSR(pki.Identity{Kind: pki.KindService, Name: "portal"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.RenewOwnCertificate(ctx, &armadav1.RenewOwnCertificateRequest{Csr: csr})
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := pki.ParseCertPEM(resp.Cert)
	if id, _ := pki.IdentityFromCert(cert); id.String() != "service:portal" {
		t.Errorf("renewed identity %v", id)
	}
	// The renewal revoked every other certificate; the one that asked
	// stays valid until it expires, so the tool can switch over.
	_, err = other.Status(ctx, &armadav1.StatusRequest{App: "web.a"})
	wantCode(t, "other certificate after renewal", err, codes.Unauthenticated)
	if _, err := p.Status(ctx, &armadav1.StatusRequest{App: "web.a"}); err != nil {
		t.Errorf("renewing certificate: %v", err)
	}

	// cluster-admin issues one for a service that exists only.
	if _, err := c.admin.IssueServiceCertificate(ctx, &armadav1.IssuePrincipalCertificateRequest{Name: "ghost", Csr: csr}); status.Code(err) != codes.NotFound {
		t.Errorf("issue for a missing service: %v", err)
	}
	if _, err := c.admin.IssueServiceCertificate(ctx, &armadav1.IssuePrincipalCertificateRequest{Name: "portal", Csr: csr}); err != nil {
		t.Errorf("issue: %v", err)
	}
	conn, _ := c.dialService("portal", true)
	p = armadav1.NewAdminServiceClient(conn)
	if _, err := p.Status(ctx, &armadav1.StatusRequest{App: "web.a"}); err != nil {
		t.Fatal(err)
	}
	// Deleting the service cuts it off at once.
	if _, err := c.admin.DeletePrincipal(ctx, &armadav1.DeletePrincipalRequest{Kind: "service", Name: "portal"}); err != nil {
		t.Fatal(err)
	}
	_, err = p.Status(ctx, &armadav1.StatusRequest{App: "web.a"})
	wantCode(t, "after removal", err, codes.Unauthenticated)

	// Roles are validated.
	for _, bad := range []*armadav1.CreateServiceRequest{
		{Name: "x", Roles: []*armadav1.RoleAssignment{{Role: "deployer", Space: "default"}}},
		{Name: "x", Roles: []*armadav1.RoleAssignment{{Role: "admin", Space: "missing"}}},
		{Name: "x", Roles: []*armadav1.RoleAssignment{{Role: "cluster-admin", Space: "a"}}},
		{Name: "x", Roles: []*armadav1.RoleAssignment{{Role: "owner"}}},
		{Name: "x", Labels: []*armadav1.LabelAllowance{{Key: "tier"}}},
		{Name: "Bad"},
	} {
		if _, err := c.admin.CreateService(ctx, bad); err == nil || strings.Contains(err.Error(), "internal") {
			t.Errorf("CreateService(%v) = %v", bad, err)
		}
	}
}

// newUser creates a user with roles through the API and connects as them.
func (c *cluster) newUser(name string, roles ...*armadav1.RoleAssignment) armadav1.AdminServiceClient {
	c.t.Helper()
	keyPEM, csr, err := pki.NewCSR(pki.Identity{Kind: pki.KindUser, Name: "anyone"})
	if err != nil {
		c.t.Fatal(err)
	}
	resp, err := c.admin.CreateUser(c.ctx, &armadav1.CreateUserRequest{Name: name, Csr: csr, Roles: roles})
	if err != nil {
		c.t.Fatal(err)
	}
	cert, _ := pki.ParseCertPEM(resp.GetCert())
	if id, _ := pki.IdentityFromCert(cert); id.String() != "user:"+name {
		c.t.Errorf("issued %v: the name comes from the request, not the CSR", id)
	}
	return armadav1.NewAdminServiceClient(c.dialPEM(resp.GetCert(), keyPEM))
}

// Each space role allows its level and refuses the next.
func TestSpaceRoleLevels(t *testing.T) {
	t.Parallel()
	c, _, _ := serviceCluster(t)
	ctx := c.ctx
	viewer := c.newUser("vera", &armadav1.RoleAssignment{Role: "viewer", Space: "a"})
	deployer := c.newUser("dan", &armadav1.RoleAssignment{Role: "deployer", Space: "a"})
	everywhere := c.newUser("eve", &armadav1.RoleAssignment{Role: "viewer"})

	for name, u := range map[string]armadav1.AdminServiceClient{"viewer": viewer, "deployer": deployer} {
		if st, err := u.Status(ctx, &armadav1.StatusRequest{}); err != nil || len(st.Apps) != 1 || len(st.Nodes) != 0 {
			t.Errorf("%s status: %v %v", name, st, err)
		}
		if _, err := u.GetAppSpec(ctx, &armadav1.GetAppSpecRequest{App: "web.a"}); err != nil {
			t.Errorf("%s spec: %v", name, err)
		}
		if _, err := u.GetAppSpec(ctx, &armadav1.GetAppSpecRequest{App: "web.b"}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s spec in b: %v", name, err)
		}
	}
	_, err := viewer.Scale(ctx, &armadav1.ScaleRequest{App: "web.a", Replicas: 2})
	wantCode(t, "viewer scales", err, codes.PermissionDenied)
	_, err = viewer.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte(webSpec("nginx:2", 1)), Space: "a"})
	wantCode(t, "viewer deploys", err, codes.PermissionDenied)
	if _, err := deployer.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte(webSpec("nginx:2", 1)), Space: "a"}); err != nil {
		t.Errorf("deployer deploys: %v", err)
	}
	if _, err := deployer.Rollback(ctx, &armadav1.RollbackRequest{App: "web.a"}); err != nil {
		t.Errorf("deployer rolls back: %v", err)
	}
	_, err = deployer.RemoveApp(ctx, &armadav1.RemoveAppRequest{App: "web.a"})
	wantCode(t, "deployer removes an app", err, codes.PermissionDenied)
	s, err := deployer.Exec(ctx)
	if err == nil {
		_ = s.Send(&armadav1.ExecClientMessage{Msg: &armadav1.ExecClientMessage_Start{Start: &armadav1.ExecStart{App: "web.a", Cmd: []string{"sh"}}}})
		_, err = s.Recv()
	}
	wantCode(t, "deployer execs", err, codes.PermissionDenied)
	_, err = deployer.CreateSpace(ctx, &armadav1.CreateSpaceRequest{Name: "d"})
	wantCode(t, "deployer creates a space", err, codes.PermissionDenied)

	// viewer over the cluster sees every space, the default one too,
	// but no nodes, and changes nothing.
	st, err := everywhere.Status(ctx, &armadav1.StatusRequest{})
	if err != nil || len(st.Apps) != 3 || len(st.Nodes) != 0 {
		t.Errorf("cluster viewer status: %v %v", st, err)
	}
	_, err = everywhere.Scale(ctx, &armadav1.ScaleRequest{App: "web", Replicas: 2})
	wantCode(t, "cluster viewer scales", err, codes.PermissionDenied)
	_, err = everywhere.ClusterStatus(ctx, &armadav1.ClusterStatusRequest{})
	wantCode(t, "cluster viewer, cluster status", err, codes.PermissionDenied)

	// A user with no role reaches nothing.
	none := c.newUser("nobody")
	_, err = none.Status(ctx, &armadav1.StatusRequest{})
	wantCode(t, "no role", err, codes.PermissionDenied)
	if _, err := none.RenewOwnCertificate(ctx, &armadav1.RenewOwnCertificateRequest{Csr: []byte("x")}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no role still renews its own certificate: %v", err)
	}

	// Roles change at once.
	if _, err := c.admin.CreateAssignment(ctx, &armadav1.AssignmentRequest{Kind: "user", Name: "vera", Role: &armadav1.RoleAssignment{Role: "deployer", Space: "a"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := viewer.Scale(ctx, &armadav1.ScaleRequest{App: "web.a", Replicas: 2}); err != nil {
		t.Errorf("after deployer was given: %v", err)
	}
	if _, err := c.admin.DeleteAssignment(ctx, &armadav1.AssignmentRequest{Kind: "user", Name: "vera", Role: &armadav1.RoleAssignment{Role: "deployer", Space: "a"}}); err != nil {
		t.Fatal(err)
	}
	_, err = viewer.Scale(ctx, &armadav1.ScaleRequest{App: "web.a", Replicas: 1})
	wantCode(t, "after deployer was taken back", err, codes.PermissionDenied)
}

func TestUsers(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	ctx := c.ctx
	works := func(conn armadav1.AdminServiceClient) error {
		_, err := conn.Status(ctx, &armadav1.StatusRequest{})
		return err
	}

	// A certificate bob held before he was created; whole seconds apart,
	// as certificates encode them. Users not on record have cluster-admin,
	// as administrators of earlier releases did.
	oldBob := armadav1.NewAdminServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindUser, Name: "bob"}))
	if err := works(oldBob); err != nil {
		t.Fatalf("names not on record: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)

	// ryan (an admin certificate not on record) creates bob as cluster-admin.
	bob := c.newUser("bob", &armadav1.RoleAssignment{Role: "cluster-admin"})
	if err := works(bob); err != nil {
		t.Errorf("bob's new certificate: %v", err)
	}
	if err := works(oldBob); status.Code(err) != codes.Unauthenticated {
		t.Errorf("bob's older certificate: %v", err)
	}
	_, csr, _ := pki.NewCSR(pki.Identity{Kind: pki.KindUser, Name: "x"})
	if _, err := c.admin.CreateUser(ctx, &armadav1.CreateUserRequest{Name: "bob", Csr: csr}); status.Code(err) != codes.AlreadyExists {
		t.Errorf("creating bob twice: %v", err)
	}
	for name, req := range map[string]*armadav1.CreateUserRequest{
		"self":       {Name: "ryan", Csr: csr},
		"bad name":   {Name: "bob smith", Csr: csr},
		"empty":      {Name: "", Csr: csr},
		"garbage":    {Name: "carol", Csr: []byte("not a csr")},
		"space role": {Name: "carol", Csr: csr, Roles: []*armadav1.RoleAssignment{{Role: "deployer"}}},
	} {
		if _, err := c.admin.CreateUser(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The list names bob, his role, who created him, and the caller.
	list, err := bob.ListPrincipals(ctx, &armadav1.ListPrincipalsRequest{Kind: "user"})
	if err != nil {
		t.Fatal(err)
	}
	if list.GetYou() != "bob" || list.GetYouKind() != "user" || len(list.GetPrincipals()) != 1 ||
		list.GetPrincipals()[0].GetCreatedBy() != "user:ryan" || list.GetPrincipals()[0].GetRoles()[0].GetRole() != "cluster-admin" {
		t.Errorf("list: %v", list)
	}

	// A new certificate for bob revokes the one before.
	keyPEM, csr2, _ := pki.NewCSR(pki.Identity{Kind: pki.KindUser, Name: "x"})
	time.Sleep(1100 * time.Millisecond)
	resp, err := c.admin.IssueUserCertificate(ctx, &armadav1.IssuePrincipalCertificateRequest{Name: "bob", Csr: csr2})
	if err != nil {
		t.Fatal(err)
	}
	if err := works(bob); status.Code(err) != codes.Unauthenticated {
		t.Errorf("bob's replaced certificate: %v", err)
	}
	bob = armadav1.NewAdminServiceClient(c.dialPEM(resp.GetCert(), keyPEM))

	// bob deletes ryan: every certificate of ryan is refused at once, and
	// nobody deletes themselves or drops their own cluster-admin.
	if _, err := bob.DeletePrincipal(ctx, &armadav1.DeletePrincipalRequest{Kind: "user", Name: "bob"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("deleting yourself: %v", err)
	}
	if _, err := bob.DeleteAssignment(ctx, &armadav1.AssignmentRequest{Kind: "user", Name: "bob", Role: &armadav1.RoleAssignment{Role: "cluster-admin"}}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("dropping your own cluster-admin: %v", err)
	}
	if _, err := bob.DeletePrincipal(ctx, &armadav1.DeletePrincipalRequest{Kind: "user", Name: "ryan"}); err != nil {
		t.Fatal(err)
	}
	if err := works(c.admin); status.Code(err) != codes.Unauthenticated {
		t.Errorf("deleted ryan: %v", err)
	}
	fresh := armadav1.NewAdminServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindUser, Name: "ryan"}))
	if err := works(fresh); status.Code(err) != codes.Unauthenticated {
		t.Errorf("a new certificate of deleted ryan: %v", err)
	}
	if _, err := fresh.RenewOwnCertificate(ctx, &armadav1.RenewOwnCertificateRequest{Csr: csr}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("deleted ryan renews: %v", err)
	}

	// Only cluster-admin manages access; other identities are refused.
	c.addNode("n1", "127.0.0.1")
	dan := c.newUserBy(bob, "dan", &armadav1.RoleAssignment{Role: "space-creator"})
	for _, other := range []armadav1.AdminServiceClient{
		dan,
		armadav1.NewAdminServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: "n1"})),
		armadav1.NewAdminServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindMetrics, Name: "p"})),
	} {
		_, err := other.CreateUser(ctx, &armadav1.CreateUserRequest{Name: "mallory", Csr: csr})
		if code := status.Code(err); code != codes.PermissionDenied {
			t.Errorf("creates a user: %v", err)
		}
		_, err = other.CreateAssignment(ctx, &armadav1.AssignmentRequest{Kind: "user", Name: "dan", Role: &armadav1.RoleAssignment{Role: "cluster-admin"}})
		if code := status.Code(err); code != codes.PermissionDenied {
			t.Errorf("gives itself cluster-admin: %v", err)
		}
	}
	if err := works(bob); err != nil {
		t.Errorf("bob after the refused calls: %v", err)
	}
}

// newUserBy is newUser with another cluster-admin.
func (c *cluster) newUserBy(admin armadav1.AdminServiceClient, name string, roles ...*armadav1.RoleAssignment) armadav1.AdminServiceClient {
	c.t.Helper()
	keyPEM, csr, _ := pki.NewCSR(pki.Identity{Kind: pki.KindUser, Name: name})
	resp, err := admin.CreateUser(c.ctx, &armadav1.CreateUserRequest{Name: name, Csr: csr, Roles: roles})
	if err != nil {
		c.t.Fatal(err)
	}
	return armadav1.NewAdminServiceClient(c.dialPEM(resp.GetCert(), keyPEM))
}

func TestRenewOwnUserCertificate(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	// An admin certificate of an earlier release renews into a user one.
	admin := armadav1.NewAdminServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindAdmin, Name: "alice"}))
	keyPEM, csr, _ := pki.NewCSR(pki.Identity{Kind: pki.KindAdmin, Name: "mallory"})
	resp, err := admin.RenewOwnCertificate(c.ctx, &armadav1.RenewOwnCertificateRequest{Csr: csr})
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := pki.ParseCertPEM(resp.GetCert())
	if id, _ := pki.IdentityFromCert(cert); id.String() != "user:alice" || time.Until(cert.NotAfter) < 300*24*time.Hour {
		t.Errorf("issued %v until %v", id, cert.NotAfter)
	}
	renewed := armadav1.NewAdminServiceClient(c.dialPEM(resp.GetCert(), keyPEM))
	if _, err := renewed.Status(c.ctx, &armadav1.StatusRequest{}); err != nil {
		t.Errorf("renewed certificate refused: %v", err)
	}
	// alice is on record now, with the cluster-admin she had.
	if p, err := c.store.GetPrincipal(c.ctx, store.KindUser, "alice"); err != nil || !p.Has(store.Grant{Role: store.RoleClusterAdmin}) {
		t.Errorf("record: %+v %v", p, err)
	}
	if _, err := admin.RenewOwnCertificate(c.ctx, &armadav1.RenewOwnCertificateRequest{Csr: []byte("not a csr")}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("garbage CSR: %v", err)
	}
	c.addNode("n1", "127.0.0.1")
	for _, id := range []pki.Identity{{Kind: pki.KindNode, Name: "n1"}, {Kind: pki.KindMetrics, Name: "p"}} {
		other := armadav1.NewAdminServiceClient(c.dial(c.ca, id))
		if _, err := other.RenewOwnCertificate(c.ctx, &armadav1.RenewOwnCertificateRequest{Csr: csr}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%v: %v", id, err)
		}
	}
}

func TestMetricsNeedsClusterAdmin(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	state := func(id pki.Identity) (*tls.ConnectionState, *x509.Certificate) {
		certPEM, _, err := c.ca.Issue(pki.IssueRequest{Identity: id, Client: true})
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := pki.ParseCertPEM(certPEM)
		return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}, cert
	}
	ctx := context.Background()
	alice, _ := state(pki.Identity{Kind: pki.KindAdmin, Name: "alice"})
	metrics, _ := state(pki.Identity{Kind: pki.KindMetrics, Name: "p"})
	if !c.srv.metricsAllowed(ctx, alice) || !c.srv.metricsAllowed(ctx, metrics) {
		t.Fatal("cluster-admin or metrics certificate refused")
	}
	if node, _ := state(pki.Identity{Kind: pki.KindNode, Name: "n1"}); c.srv.metricsAllowed(ctx, node) {
		t.Error("node certificate scrapes")
	}
	if _, err := c.store.CreateService(ctx, store.Principal{Name: "ci", Roles: []store.Grant{{Role: store.RoleViewer}}}, "user:ryan"); err != nil {
		t.Fatal(err)
	}
	ci, cert := state(pki.Identity{Kind: pki.KindService, Name: "ci"})
	if err := c.store.RecordServiceCert(ctx, "ci", store.NodeCert{Serial: pki.SerialString(cert), NotAfter: cert.NotAfter}, "", "user:ryan"); err != nil {
		t.Fatal(err)
	}
	if c.srv.metricsAllowed(ctx, ci) {
		t.Error("a viewer scrapes")
	}
	if _, err := c.store.Assign(ctx, store.KindService, "ci", store.Grant{Role: store.RoleClusterAdmin}, "user:ryan"); err != nil {
		t.Fatal(err)
	}
	if !c.srv.metricsAllowed(ctx, ci) {
		t.Error("a cluster-admin service is refused")
	}
	if err := c.store.DeletePrincipal(ctx, store.KindUser, "alice", "user:ryan"); err != nil {
		t.Fatal(err)
	}
	if c.srv.metricsAllowed(ctx, alice) {
		t.Error("deleted user scrapes")
	}
}

func TestListRoles(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	resp, err := c.admin.ListRoles(c.ctx, &armadav1.ListRolesRequest{})
	if err != nil || len(resp.Roles) != len(store.Roles) {
		t.Fatalf("%v %v", resp, err)
	}
	methods := map[string][]string{}
	for _, r := range resp.Roles {
		methods[r.Name] = r.Methods
	}
	for role, m := range map[string]string{"viewer": "Logs", "deployer": "Deploy", "admin": "Exec", "space-creator": "CreateSpace"} {
		if !slices.Contains(methods[role], m) {
			t.Errorf("%s lacks %s: %v", role, m, methods[role])
		}
	}
	if slices.Contains(methods["viewer"], "Deploy") || slices.Contains(methods["deployer"], "Exec") || slices.Contains(methods["admin"], "CreateUser") {
		t.Error("a role lists a method above it")
	}
}
