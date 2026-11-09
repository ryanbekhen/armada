package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
)

func TestAdministrators(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	ctx := c.ctx
	works := func(conn armadav1.AdminServiceClient) error {
		_, err := conn.Status(ctx, &armadav1.StatusRequest{})
		return err
	}

	// A certificate bob held before he was added; whole seconds apart, as
	// certificates encode them.
	oldBob := armadav1.NewAdminServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindAdmin, Name: "bob"}))
	if err := works(oldBob); err != nil {
		t.Fatalf("names not on record work as before: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)

	// ryan (not on record, like an admin from an older release) adds bob.
	keyPEM, csr, err := pki.NewCSR(pki.Identity{Kind: pki.KindAdmin, Name: "mallory"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.admin.AddAdmin(ctx, &armadav1.AddAdminRequest{Name: "bob", Csr: csr})
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := pki.ParseCertPEM(resp.GetCert())
	if id, _ := pki.IdentityFromCert(cert); id.String() != "admin:bob" {
		t.Errorf("issued %v: the name comes from the request, not the CSR", id)
	}
	bob := armadav1.NewAdminServiceClient(c.dialPEM(resp.GetCert(), keyPEM))
	if err := works(bob); err != nil {
		t.Errorf("bob's new certificate: %v", err)
	}
	if err := works(oldBob); status.Code(err) != codes.Unauthenticated {
		t.Errorf("bob's older certificate: %v", err)
	}
	if _, err := c.admin.AddAdmin(ctx, &armadav1.AddAdminRequest{Name: "bob", Csr: csr}); status.Code(err) != codes.AlreadyExists && status.Code(err) != codes.FailedPrecondition && status.Code(err) != codes.Aborted {
		t.Errorf("adding bob twice: %v", err)
	}

	// Bad requests.
	for name, req := range map[string]*armadav1.AddAdminRequest{
		"self":     {Name: "ryan", Csr: csr},
		"bad name": {Name: "bob smith", Csr: csr},
		"empty":    {Name: "", Csr: csr},
		"garbage":  {Name: "carol", Csr: []byte("not a csr")},
	} {
		if _, err := c.admin.AddAdmin(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The list names bob and who added him, and the caller.
	list, err := bob.ListAdmins(ctx, &armadav1.ListAdminsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if list.GetYou() != "bob" || len(list.GetAdmins()) != 1 || list.GetAdmins()[0].GetAddedBy() != "admin:ryan" {
		t.Errorf("list: %v", list)
	}

	// bob removes ryan: every certificate of ryan is refused at once.
	if _, err := bob.RemoveAdmin(ctx, &armadav1.RemoveAdminRequest{Name: "bob"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("removing yourself: %v", err)
	}
	if _, err := bob.RemoveAdmin(ctx, &armadav1.RemoveAdminRequest{Name: "ryan"}); err != nil {
		t.Fatal(err)
	}
	if err := works(c.admin); status.Code(err) != codes.Unauthenticated {
		t.Errorf("removed ryan: %v", err)
	}
	fresh := armadav1.NewAdminServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindAdmin, Name: "ryan"}))
	if err := works(fresh); status.Code(err) != codes.Unauthenticated {
		t.Errorf("a new certificate of removed ryan: %v", err)
	}
	if _, err := fresh.RenewAdminCertificate(ctx, &armadav1.RenewAdminCertificateRequest{Csr: csr}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("removed ryan renews: %v", err)
	}

	// Only administrators manage administrators.
	c.addNode("n1", "127.0.0.1")
	for _, id := range []pki.Identity{{Kind: pki.KindNode, Name: "n1"}, {Kind: pki.KindMetrics, Name: "p"}, {Kind: pki.KindAutomation, Name: "ci"}} {
		other := armadav1.NewAdminServiceClient(c.dial(c.ca, id))
		_, err := other.AddAdmin(ctx, &armadav1.AddAdminRequest{Name: "eve", Csr: csr})
		if code := status.Code(err); code != codes.PermissionDenied && code != codes.Unauthenticated {
			t.Errorf("%v adds an admin: %v", id, err)
		}
		if _, err := other.RemoveAdmin(ctx, &armadav1.RemoveAdminRequest{Name: "bob"}); status.Code(err) != codes.PermissionDenied && status.Code(err) != codes.Unauthenticated {
			t.Errorf("%v removes an admin: %v", id, err)
		}
	}
	if err := works(bob); err != nil {
		t.Errorf("bob after the refused calls: %v", err)
	}
}

func TestMetricsRefusesRemovedAdmin(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	state := func(id pki.Identity) *tls.ConnectionState {
		certPEM, _, err := c.ca.Issue(pki.IssueRequest{Identity: id, Client: true})
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := pki.ParseCertPEM(certPEM)
		return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
	}
	ctx := context.Background()
	alice := state(pki.Identity{Kind: pki.KindAdmin, Name: "alice"})
	if !c.srv.metricsAllowed(ctx, alice) || !c.srv.metricsAllowed(ctx, state(pki.Identity{Kind: pki.KindMetrics, Name: "p"})) {
		t.Fatal("admin or metrics certificate refused")
	}
	if c.srv.metricsAllowed(ctx, state(pki.Identity{Kind: pki.KindNode, Name: "n1"})) {
		t.Error("node certificate scrapes")
	}
	if err := c.store.RemoveAdmin(ctx, "alice", "admin:ryan"); err != nil {
		t.Fatal(err)
	}
	if c.srv.metricsAllowed(ctx, alice) {
		t.Error("removed admin scrapes")
	}
}
