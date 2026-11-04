package server

import (
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

func (c *clockServer) deployIn(project, y string) store.Revision {
	c.t.Helper()
	sp, err := spec.ParseIn([]byte(y), project)
	if err != nil {
		c.t.Fatal(err)
	}
	rev, _, err := c.st.Deploy(c.ctx, sp, "t")
	if err != nil {
		c.t.Fatal(err)
	}
	c.reconcile()
	return rev
}

func (c *clockServer) setSandbox(node string, on bool) {
	c.t.Helper()
	if err := c.st.SetNodeStatus(c.ctx, node, store.NodeStatus{State: store.NodeReady, LastSeen: c.clock, Sandbox: on}); err != nil {
		c.t.Fatal(err)
	}
}

func (c *clockServer) hasEvent(reason, app string) bool {
	c.t.Helper()
	evs, err := c.st.ListEvents(c.ctx, time.Time{})
	if err != nil {
		c.t.Fatal(err)
	}
	return slices.ContainsFunc(evs, func(e store.Event) bool { return e.Reason == reason && e.App == app })
}

// Replicas of a sandboxed project run only on nodes that announced the
// sandbox, and get it in their spec; the default project's still run
// anywhere (ADR 0029).
func TestSandboxedProjectPlacement(t *testing.T) {
	t.Parallel()
	c := placementSetup(t, nil, nil)
	c.setSandbox("n1", false)
	c.setSandbox("n2", true)
	if _, err := c.st.CreateProject(c.ctx, "shop", "", "t", ""); err != nil {
		t.Fatal(err)
	}
	rev := c.deployIn("shop", "name: web\nimage: nginx:1\nscale:\n  min: 3\n")
	if !rev.Sandboxed() {
		t.Fatalf("revision isolation = %q", rev.Isolation)
	}
	byNode := map[string]int{}
	for _, r := range c.replicas() {
		byNode[r.NodeID]++
		rs, err := replicaSpec(r, rev, nil)
		if err != nil || !rs.GetSandbox() {
			t.Errorf("replica %s spec sandbox = %v (%v)", r.ID, rs.GetSandbox(), err)
		}
	}
	if byNode["n1"] != 0 || byNode["n2"] != 3 {
		t.Fatalf("replicas by node = %v, want all on n2", byNode)
	}

	def := c.deployIn("default", "name: api\nimage: nginx:1\nscale:\n  min: 2\n")
	if def.Sandboxed() {
		t.Error("default project sandboxed")
	}
	for _, r := range c.replicas() {
		if r.App == "api" {
			if rs, _ := replicaSpec(r, def, nil); rs.GetSandbox() {
				t.Errorf("default replica %s sandboxed", r.ID)
			}
		}
	}
	if c.hasEvent("NoIsolation", "web.shop") {
		t.Error("NoIsolation while a node runs the sandbox")
	}
}

// With no node that runs the sandbox, nothing is placed at a weaker level:
// the app waits, and status and events say why.
func TestSandboxedProjectWithoutSandboxNodes(t *testing.T) {
	t.Parallel()
	c := placementSetup(t, nil, nil)
	if _, err := c.st.CreateProject(c.ctx, "shop", "", "t", ""); err != nil {
		t.Fatal(err)
	}
	c.deployIn("shop", "name: web\nimage: nginx:1\nscale:\n  min: 2\n")
	for _, r := range c.replicas() {
		if r.App == "web.shop" {
			t.Fatalf("replica %s placed on %s without the sandbox", r.ID, r.NodeID)
		}
	}
	nodes, _ := c.st.ListNodes(c.ctx)
	all, _ := c.st.ListReplicas(c.ctx, store.ReplicaFilter{})
	app, err := c.st.GetApp(c.ctx, "web.shop")
	if err != nil {
		t.Fatal(err)
	}
	msg := placementMessage(c.ctx, &revisionCache{store: c.st, m: map[string]store.Revision{}}, nodes, all, app)
	if !strings.Contains(msg, "sandboxed") {
		t.Errorf("placement message = %q", msg)
	}
	if !c.hasEvent("NoIsolation", "web.shop") {
		t.Error("no NoIsolation event")
	}
	// A node gains the sandbox: the replicas go there.
	c.setSandbox("n1", true)
	c.advance(time.Second)
	n := 0
	for _, r := range c.replicas() {
		if r.App == "web.shop" {
			n++
			if r.NodeID != "n1" {
				t.Errorf("replica on %s", r.NodeID)
			}
		}
	}
	if n != 2 {
		t.Errorf("%d replicas after a sandbox node appeared", n)
	}
}

func TestProjectIsolationAPI(t *testing.T) {
	t.Parallel()
	c, auto, _ := automationCluster(t)
	level := func(p string) string {
		t.Helper()
		resp, err := c.admin.ListProjects(c.ctx, &armadav1.ListProjectsRequest{})
		if err != nil {
			t.Fatal(err)
		}
		for _, info := range resp.Projects {
			if info.Name == p {
				return info.Isolation
			}
		}
		t.Fatalf("no project %s", p)
		return ""
	}
	if level("default") != spec.IsolationContainer {
		t.Errorf("default = %q", level("default"))
	}
	info, err := c.admin.CreateProject(c.ctx, &armadav1.CreateProjectRequest{Name: "sb"})
	if err != nil || info.Isolation != spec.IsolationSandbox {
		t.Fatalf("create: %v %v", info, err)
	}
	if info, err := c.admin.CreateProject(c.ctx, &armadav1.CreateProjectRequest{Name: "plain", Isolation: spec.IsolationContainer}); err != nil || info.Isolation != spec.IsolationContainer {
		t.Fatalf("admin create with container: %v %v", info, err)
	}
	for _, bad := range []string{spec.IsolationVM, "gvisor"} {
		_, err := c.admin.CreateProject(c.ctx, &armadav1.CreateProjectRequest{Name: "x", Isolation: bad})
		wantCode(t, "create with "+bad, err, codes.InvalidArgument)
		_, err = c.admin.UpdateProject(c.ctx, &armadav1.UpdateProjectRequest{Name: "sb", Isolation: bad})
		wantCode(t, "set "+bad, err, codes.InvalidArgument)
	}
	info, err = c.admin.UpdateProject(c.ctx, &armadav1.UpdateProjectRequest{Name: "default", Isolation: spec.IsolationSandbox})
	if err != nil || info.Isolation != spec.IsolationSandbox || level("default") != spec.IsolationSandbox {
		t.Fatalf("default to sandbox: %v %v", info, err)
	}
	_, err = c.admin.UpdateProject(c.ctx, &armadav1.UpdateProjectRequest{Name: "ghost", Isolation: spec.IsolationSandbox})
	wantCode(t, "missing project", err, codes.NotFound)

	// Automation identities create sandboxed projects only, and never
	// change a level, not even of their own projects.
	if _, err := c.admin.SetAutomation(c.ctx, &armadav1.SetAutomationRequest{Name: "portal", Projects: []string{"a"}, CreateProjects: true}); err != nil {
		t.Fatal(err)
	}
	_, err = auto.CreateProject(c.ctx, &armadav1.CreateProjectRequest{Name: "mine", Isolation: spec.IsolationContainer})
	wantCode(t, "automation create with container", err, codes.PermissionDenied)
	if info, err := auto.CreateProject(c.ctx, &armadav1.CreateProjectRequest{Name: "mine"}); err != nil || info.Isolation != spec.IsolationSandbox {
		t.Fatalf("automation create: %v %v", info, err)
	}
	_, err = auto.UpdateProject(c.ctx, &armadav1.UpdateProjectRequest{Name: "mine", Isolation: spec.IsolationContainer})
	wantCode(t, "automation lowers its project", err, codes.PermissionDenied)
	if level("mine") != spec.IsolationSandbox {
		t.Error("automation changed the level")
	}
}
