package server

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
)

// testStreamRecheck is how often test streams check their access again.
const testStreamRecheck = 100 * time.Millisecond

// streamCluster has spaces b and c.
func streamCluster(t *testing.T) *cluster {
	t.Helper()
	c := newCluster(t)
	for _, sp := range []string{"b", "c"} {
		if _, err := c.admin.CreateSpace(c.ctx, &armadav1.CreateSpaceRequest{Name: sp}); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// endsWith waits for a stream to end and checks its code.
func endsWith[T any](t *testing.T, what string, s interface{ Recv() (T, error) }, code codes.Code) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		for {
			if _, err := s.Recv(); err != nil {
				done <- err
				return
			}
		}
	}()
	select {
	case err := <-done:
		if status.Code(err) != code {
			t.Errorf("%s: stream ended with %v, want %s", what, err, code)
		}
	case <-time.After(10 * time.Second):
		t.Errorf("%s: stream still open", what)
	}
}

func (c *cluster) deployIn(space, name string) {
	c.t.Helper()
	if _, err := c.admin.Deploy(c.ctx, &armadav1.DeployRequest{Spec: []byte("name: " + name + "\nimage: nginx:1\n"), Space: space}); err != nil {
		c.t.Fatal(err)
	}
}

// An events follow keeps to the access the caller has now: it ends once
// the caller is deleted or no role lets it see events, and stops showing
// a space whose role was taken back.
func TestEventsFollowEndsWithAccess(t *testing.T) {
	t.Parallel()
	c := streamCluster(t)
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	follow := func(u armadav1.AdminServiceClient) armadav1.AdminService_EventsClient {
		t.Helper()
		s, err := u.Events(ctx, &armadav1.EventsRequest{Follow: true, SinceSeconds: 1})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	viewer := func(space string) *armadav1.RoleAssignment {
		return &armadav1.RoleAssignment{Role: "viewer", Space: space}
	}

	// The role taken back: the method is no longer reached.
	dina := follow(c.newUser("dina", viewer("b")))
	c.deployIn("b", "first")
	if e, err := dina.Recv(); err != nil || e.GetApp() != "first.b" {
		t.Fatalf("first event: %v %v", e, err)
	}
	if _, err := c.admin.DeleteAssignment(c.ctx, &armadav1.AssignmentRequest{Kind: "user", Name: "dina", Role: viewer("b")}); err != nil {
		t.Fatal(err)
	}
	endsWith(t, "role taken back", dina, codes.PermissionDenied)

	// The user deleted: the certificate is refused.
	fay := follow(c.newUser("fay", viewer("b")))
	if _, err := c.admin.DeletePrincipal(c.ctx, &armadav1.DeletePrincipalRequest{Kind: "user", Name: "fay"}); err != nil {
		t.Fatal(err)
	}
	endsWith(t, "user deleted", fay, codes.Unauthenticated)

	// One of two spaces taken back: the stream stays, without that space.
	erin := follow(c.newUser("erin", viewer("b"), viewer("c")))
	if _, err := c.admin.DeleteAssignment(c.ctx, &armadav1.AssignmentRequest{Kind: "user", Name: "erin", Role: viewer("b")}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * testStreamRecheck)
	c.deployIn("b", "hidden")
	c.deployIn("c", "shown")
	for {
		e, err := erin.Recv()
		if err != nil {
			t.Fatalf("erin's stream: %v", err)
		}
		if e.GetApp() == "hidden.b" {
			t.Fatal("an event of a space whose role was taken back reached the stream")
		}
		if e.GetApp() == "shown.c" {
			break
		}
	}
}

// A stream ends when the client certificate expires.
func TestStreamEndsAtCertificateExpiry(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	certPEM, keyPEM, err := c.ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindUser, Name: "ryan"}, Client: true, Validity: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	short := armadav1.NewAdminServiceClient(c.dialPEM(certPEM, keyPEM))
	s, err := short.Events(c.ctx, &armadav1.EventsRequest{Follow: true, SinceSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	endsWith(t, "certificate expired", s, codes.Unauthenticated)
}

// A logs follow ends once the caller may no longer see the app, also
// while another role still lets it call Logs.
func TestLogsFollowEndsWithAccess(t *testing.T) {
	t.Parallel()
	c := streamCluster(t)
	c.addNode("n1", "127.0.0.1")
	if _, err := c.admin.Deploy(c.ctx, &armadav1.DeployRequest{Spec: []byte(webSpec("nginx:1", 1)), Space: "b"}); err != nil {
		t.Fatal(err)
	}
	c.eventually("1 running", func() bool { return len(c.running("web.b")) == 1 })
	gus := c.newUser("gus", &armadav1.RoleAssignment{Role: "viewer", Space: "b"}, &armadav1.RoleAssignment{Role: "viewer", Space: "c"})
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	s, err := gus.Logs(ctx, &armadav1.LogsRequest{App: "web.b", Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	if e, err := s.Recv(); err != nil || len(e.GetData()) == 0 {
		t.Fatalf("first entry: %v %v", e, err)
	}
	if _, err := c.admin.DeleteAssignment(c.ctx, &armadav1.AssignmentRequest{Kind: "user", Name: "gus", Role: &armadav1.RoleAssignment{Role: "viewer", Space: "b"}}); err != nil {
		t.Fatal(err)
	}
	endsWith(t, "space role taken back", s, codes.PermissionDenied)
}
