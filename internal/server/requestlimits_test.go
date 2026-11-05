package server

import (
	"testing"

	"google.golang.org/grpc/codes"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// A project's request limits reach every backend of its apps, at once and
// without a deploy; other projects' apps stay unlimited (ADR 0026).
func TestRequestLimitsReachTheProxy(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	if _, err := c.admin.CreateProject(c.ctx, &armadav1.CreateProjectRequest{Name: "shop", Quota: &armadav1.Quota{RequestRate: 200, Connections: 50}}); err != nil {
		t.Fatal(err)
	}
	web := "name: web\nimage: nginx:1\ningress:\n  type: internal\n  port: 80\n"
	for _, project := range []string{"shop", "default"} {
		if _, err := c.admin.Deploy(c.ctx, &armadav1.DeployRequest{Spec: []byte(web), Project: project}); err != nil {
			t.Fatal(err)
		}
	}
	limits := func() map[string][2]int {
		t.Helper()
		apps, err := c.store.ListApps(c.ctx)
		if err != nil {
			t.Fatal(err)
		}
		px, err := c.srv.buildProxy(c.ctx, apps, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := px.Validate(); err != nil {
			t.Fatal(err)
		}
		out := map[string][2]int{}
		for _, be := range px.Backends {
			out[be.Name] = [2]int{be.RequestRate, be.Connections}
		}
		return out
	}
	got := limits()
	if got["web.shop"] != [2]int{200, 50} || got["web"] != [2]int{0, 0} {
		t.Fatalf("limits = %v", got)
	}
	// A changed quota applies to the running app.
	if _, err := c.admin.UpdateProject(c.ctx, &armadav1.UpdateProjectRequest{Name: "shop", Quota: &armadav1.Quota{RequestRate: 10}}); err != nil {
		t.Fatal(err)
	}
	if got := limits(); got["web.shop"] != [2]int{10, 0} {
		t.Errorf("after the change = %v", got)
	}
	_, err := c.admin.UpdateProject(c.ctx, &armadav1.UpdateProjectRequest{Name: "shop", Quota: &armadav1.Quota{Connections: -1}})
	wantCode(t, "negative connections", err, codes.InvalidArgument)
}
