package server

import (
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

// dialAutomation connects as automation:name with a certificate recorded
// for it (unless record is false).
func (c *cluster) dialAutomation(name string, record bool) (*grpc.ClientConn, string) {
	c.t.Helper()
	id := pki.Identity{Kind: pki.KindAutomation, Name: name}
	certPEM, keyPEM, err := c.ca.Issue(pki.IssueRequest{Identity: id, Client: true})
	if err != nil {
		c.t.Fatal(err)
	}
	cert, _ := pki.ParseCertPEM(certPEM)
	serial := pki.SerialString(cert)
	if record {
		if err := c.store.RecordAutomationCert(c.ctx, name, store.NodeCert{Serial: serial, NotAfter: cert.NotAfter}, "", "admin:test"); err != nil {
			c.t.Fatal(err)
		}
	}
	return c.dialPEM(certPEM, keyPEM), serial
}

// automationCluster has projects a and b, the app web in default, a, and
// b, and automation:portal managing a.
func automationCluster(t *testing.T) (*cluster, armadav1.AdminServiceClient, *grpc.ClientConn) {
	t.Helper()
	c := newCluster(t)
	for _, p := range []string{"a", "b"} {
		if _, err := c.admin.CreateProject(c.ctx, &armadav1.CreateProjectRequest{Name: p}); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"", "a", "b"} {
		if _, err := c.admin.Deploy(c.ctx, &armadav1.DeployRequest{Spec: []byte(webSpec("nginx:1", 1)), Project: p}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.admin.SetAutomation(c.ctx, &armadav1.SetAutomationRequest{Name: "portal", Projects: []string{"a"},
		Labels: []*armadav1.LabelAllowance{{Key: "tier", Values: []string{"shared"}}}}); err != nil {
		t.Fatal(err)
	}
	conn, _ := c.dialAutomation("portal", true)
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

func TestAutomationUnrecordedCertificate(t *testing.T) {
	t.Parallel()
	c, _, _ := automationCluster(t)
	conn, _ := c.dialAutomation("portal", false)
	_, err := armadav1.NewAdminServiceClient(conn).Status(c.ctx, &armadav1.StatusRequest{App: "web.a"})
	wantCode(t, "unrecorded certificate", err, codes.Unauthenticated)
	conn, _ = c.dialAutomation("ghost", false)
	_, err = armadav1.NewAdminServiceClient(conn).Status(c.ctx, &armadav1.StatusRequest{})
	wantCode(t, "identity that does not exist", err, codes.Unauthenticated)
}

// Every AdminService method outside automationMethods is refused before
// its handler runs, including methods added later.
func TestAutomationMethodsDefaultDeny(t *testing.T) {
	t.Parallel()
	c, _, conn := automationCluster(t)
	desc := armadav1.AdminService_ServiceDesc
	known := map[string]bool{}
	for _, m := range desc.Methods {
		full := "/" + desc.ServiceName + "/" + m.MethodName
		known[full] = true
		if automationMethods[full] {
			continue
		}
		err := conn.Invoke(c.ctx, full, &emptypb.Empty{}, &emptypb.Empty{})
		wantCode(t, full, err, codes.PermissionDenied)
	}
	for _, sd := range desc.Streams {
		full := "/" + desc.ServiceName + "/" + sd.StreamName
		known[full] = true
		if automationMethods[full] {
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
	for m := range automationMethods {
		if !known[m] {
			t.Errorf("automationMethods names %s, which AdminService does not have", m)
		}
	}
	// The agent API is out of reach too.
	_, err := armadav1.NewAgentServiceClient(conn).RenewCertificate(c.ctx, &armadav1.RenewCertificateRequest{Csr: []byte("x")})
	wantCode(t, "agent API", err, codes.PermissionDenied)
}

// Every method an automation identity may call refuses apps of the
// default project and of projects outside its scope.
func TestAutomationOutOfScope(t *testing.T) {
	t.Parallel()
	c, p, _ := automationCluster(t)
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
	for _, project := range []string{"", "default", "b", "missing"} {
		_, err := p.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte(webSpec("nginx:2", 1)), Project: project})
		wantCode(t, "Deploy into "+project, err, codes.PermissionDenied)
	}
	_, err := p.Events(ctx, &armadav1.EventsRequest{Node: "n1"})
	if err == nil {
		s, _ := p.Events(ctx, &armadav1.EventsRequest{Node: "n1"})
		err = streamErr[*armadav1.EventInfo](s, nil)
	}
	wantCode(t, "Events of a node", err, codes.PermissionDenied)
	for _, name := range []string{"b", "default"} {
		_, err := p.DeleteProject(ctx, &armadav1.DeleteProjectRequest{Name: name})
		wantCode(t, "DeleteProject "+name, err, codes.PermissionDenied)
	}
	_, err = p.CreateProject(ctx, &armadav1.CreateProjectRequest{Name: "c"})
	wantCode(t, "CreateProject without permission", err, codes.PermissionDenied)
	_, err = c.admin.RenewAutomationCertificate(ctx, &armadav1.RenewAutomationCertificateRequest{Csr: []byte("x")})
	wantCode(t, "administrator renewing", err, codes.PermissionDenied)
}

func TestAutomationInScope(t *testing.T) {
	t.Parallel()
	c, p, _ := automationCluster(t)
	ctx := c.ctx

	if _, err := p.Scale(ctx, &armadav1.ScaleRequest{App: "web.a", Replicas: 2}); err != nil {
		t.Fatalf("scale its app: %v", err)
	}
	if _, err := p.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte(webSpec("nginx:2", 1)), Project: "a"}); err != nil {
		t.Fatalf("deploy into its project: %v", err)
	}
	if _, err := p.ListRevisions(ctx, &armadav1.ListRevisionsRequest{App: "web.a"}); err != nil {
		t.Errorf("revisions: %v", err)
	}

	// Listings hold only its projects, and no nodes.
	st, err := p.Status(ctx, &armadav1.StatusRequest{})
	if err != nil || len(st.Apps) != 1 || st.Apps[0].Name != "web.a" || len(st.Nodes) != 0 {
		t.Fatalf("status: %v %v", st, err)
	}
	top, err := p.Top(ctx, &armadav1.TopRequest{})
	if err != nil || len(top.Nodes) != 0 || slices.ContainsFunc(top.Replicas, func(r *armadav1.ReplicaTop) bool { return r.App != "web.a" }) {
		t.Errorf("top: %v %v", top, err)
	}
	ps, err := p.ListProjects(ctx, &armadav1.ListProjectsRequest{})
	if err != nil || len(ps.Projects) != 1 || ps.Projects[0].Name != "a" {
		t.Errorf("projects: %v %v", ps, err)
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
	if _, err := p.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte(placed("tier: dedicated")), Project: "a"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("placement outside the scope: %v", err)
	}
	if _, err := p.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte(placed("tier: shared")), Project: "a"}); err != nil {
		t.Errorf("placement inside the scope: %v", err)
	}
	if _, err := p.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte(placed("armada.arch: arm64")), Project: "a"}); err != nil {
		t.Errorf("placement on a reported label: %v", err)
	}

	// With the permission, it creates projects it then manages, and
	// removes them.
	if _, err := c.admin.SetAutomation(ctx, &armadav1.SetAutomationRequest{Name: "portal", Projects: []string{"a"}, CreateProjects: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateProject(ctx, &armadav1.CreateProjectRequest{Name: "c"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := p.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte(webSpec("nginx:1", 1)), Project: "c"}); err != nil {
		t.Fatalf("deploy into the created project: %v", err)
	}
	if _, err := p.DeleteProject(ctx, &armadav1.DeleteProjectRequest{Name: "b"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("remove a project outside the scope: %v", err)
	}
}

func TestAutomationRenewAndRevoke(t *testing.T) {
	t.Parallel()
	c, p, _ := automationCluster(t)
	ctx := c.ctx
	// Another certificate of the identity, say one that leaked.
	otherConn, _ := c.dialAutomation("portal", true)
	other := armadav1.NewAdminServiceClient(otherConn)
	if _, err := other.Status(ctx, &armadav1.StatusRequest{App: "web.a"}); err != nil {
		t.Fatal(err)
	}

	_, csr, err := pki.NewCSR(pki.Identity{Kind: pki.KindAutomation, Name: "portal"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.RenewAutomationCertificate(ctx, &armadav1.RenewAutomationCertificateRequest{Csr: csr})
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := pki.ParseCertPEM(resp.Cert)
	if id, _ := pki.IdentityFromCert(cert); id.String() != "automation:portal" {
		t.Errorf("renewed identity %v", id)
	}
	// The renewal revoked every other certificate; the one that asked
	// stays valid until it expires, so the tool can switch over.
	_, err = other.Status(ctx, &armadav1.StatusRequest{App: "web.a"})
	wantCode(t, "other certificate after renewal", err, codes.Unauthenticated)
	if _, err := p.Status(ctx, &armadav1.StatusRequest{App: "web.a"}); err != nil {
		t.Errorf("renewing certificate: %v", err)
	}

	// An administrator issues one for an identity that exists only.
	if _, err := c.admin.IssueAutomationCertificate(ctx, &armadav1.IssueAutomationCertificateRequest{Name: "ghost", Csr: csr}); status.Code(err) != codes.NotFound {
		t.Errorf("issue for a missing identity: %v", err)
	}
	conn, _ := c.dialAutomation("portal", true)
	p = armadav1.NewAdminServiceClient(conn)
	if _, err := p.Status(ctx, &armadav1.StatusRequest{App: "web.a"}); err != nil {
		t.Fatal(err)
	}
	// Removing the identity cuts it off at once.
	if _, err := c.admin.DeleteAutomation(ctx, &armadav1.DeleteAutomationRequest{Name: "portal"}); err != nil {
		t.Fatal(err)
	}
	_, err = p.Status(ctx, &armadav1.StatusRequest{App: "web.a"})
	wantCode(t, "after removal", err, codes.Unauthenticated)

	// Scopes are validated.
	for _, bad := range []*armadav1.SetAutomationRequest{
		{Name: "x", Projects: []string{"default"}},
		{Name: "x", Projects: []string{"missing"}},
		{Name: "Bad"},
	} {
		if _, err := c.admin.SetAutomation(ctx, bad); err == nil || strings.Contains(err.Error(), "internal") {
			t.Errorf("SetAutomation(%v) = %v", bad, err)
		}
	}
}
