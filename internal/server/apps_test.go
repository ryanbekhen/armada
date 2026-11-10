package server

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

func TestListAppsAndClusterStatus(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	admin := c.srv.internalContext(c.ctx)
	if _, err := c.st.CreateProject(c.ctx, "shop", "t", ""); err != nil {
		t.Fatal(err)
	}
	for i := range 7 {
		c.deploy(fmt.Sprintf("name: app%d\nimage: nginx:1\n", i))
	}
	sp, err := spec.ParseIn([]byte("name: cart\nimage: nginx:1\n"), "shop")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.st.Deploy(c.ctx, sp, "t"); err != nil {
		t.Fatal(err)
	}
	c.reconcile()

	// Pages of three over the default project, in name order.
	var names []string
	token := ""
	for range 5 {
		resp, err := c.srv.ListApps(admin, &armadav1.ListAppsRequest{PageSize: 3, PageToken: token})
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range resp.Apps {
			names = append(names, a.Name)
		}
		if token = resp.NextPageToken; token == "" {
			break
		}
	}
	if strings.Join(names, ",") != "app0,app1,app2,app3,app4,app5,app6" {
		t.Errorf("default project pages: %v", names)
	}
	resp, err := c.srv.ListApps(admin, &armadav1.ListAppsRequest{Project: "shop"})
	if err != nil || len(resp.Apps) != 1 || resp.Apps[0].Name != "cart.shop" || resp.Apps[0].Project != "shop" {
		t.Errorf("shop: %v %v", resp, err)
	}
	if resp, _ := c.srv.ListApps(admin, &armadav1.ListAppsRequest{AllProjects: true}); len(resp.GetApps()) != 8 {
		t.Errorf("all projects: %d apps", len(resp.GetApps()))
	}

	// Nothing is ready yet: every app needs attention, bounded.
	st, err := c.srv.ClusterStatus(admin, &armadav1.ClusterStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Apps != 8 || st.AttentionTotal != 8 || st.Nodes != 1 || st.NodesReady != 1 {
		t.Errorf("cluster status %+v", st)
	}
	c.serveAll()
	st, _ = c.srv.ClusterStatus(admin, &armadav1.ClusterStatusRequest{})
	if st.AppsReady != 8 || st.AttentionTotal != 0 {
		t.Errorf("after serving: %+v", st)
	}

	// An automation identity sees only its projects, never the cluster.
	auto := withIdentity(c, pki.Identity{Kind: pki.KindAutomation, Name: "ci"}, store.Automation{Name: "ci", Projects: []string{"shop"}})
	if resp, err := c.srv.ListApps(auto, &armadav1.ListAppsRequest{AllProjects: true}); err != nil || len(resp.Apps) != 1 {
		t.Errorf("automation listing: %v %v", resp, err)
	}
	if _, err := c.srv.ListApps(auto, &armadav1.ListAppsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("automation in default: %v", err)
	}
	if _, err := c.srv.ClusterStatus(auto, &armadav1.ClusterStatusRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("automation cluster status: %v", err)
	}
}

func TestGetAppSpecAndDeployChecks(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	admin := c.srv.internalContext(c.ctx)
	in := "name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n"
	if _, err := c.srv.Deploy(admin, &armadav1.DeployRequest{Spec: []byte(in), MustCreate: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.srv.Deploy(admin, &armadav1.DeployRequest{Spec: []byte(in), MustCreate: true}); status.Code(err) != codes.AlreadyExists {
		t.Errorf("create twice: %v", err)
	}
	if _, err := c.srv.Deploy(admin, &armadav1.DeployRequest{Spec: []byte("name: ghost\nimage: nginx:1\n"), MustExist: true}); status.Code(err) != codes.NotFound {
		t.Errorf("update of a missing app: %v", err)
	}
	got, err := c.srv.GetAppSpec(admin, &armadav1.GetAppSpecRequest{App: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != "web--r1" || !strings.Contains(string(got.Spec), "image: nginx:1") {
		t.Errorf("spec %s at %s", got.Spec, got.Revision)
	}
	// An update from r1 works once; a second one from r1 lost the race.
	next := strings.Replace(string(got.Spec), "nginx:1", "nginx:2", 1)
	if _, err := c.srv.Deploy(admin, &armadav1.DeployRequest{Spec: []byte(next), MustExist: true, BaseRevision: "web--r1"}); err != nil {
		t.Fatal(err)
	}
	stale := strings.Replace(string(got.Spec), "nginx:1", "nginx:3", 1)
	if _, err := c.srv.Deploy(admin, &armadav1.DeployRequest{Spec: []byte(stale), MustExist: true, BaseRevision: "web--r1"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("update from a stale revision: %v", err)
	}
}

// withIdentity is c's context as the given caller with an automation scope.
func withIdentity(c *clockServer, id pki.Identity, scope store.Automation) context.Context {
	ctx := context.WithValue(c.ctx, identityKey{}, id)
	return context.WithValue(ctx, scopeKey{}, scope)
}
