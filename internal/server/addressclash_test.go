package server

import (
	"cmp"
	"slices"
	"strings"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

// A replica its agent recreates after the machine restarted is reported
// starting with no address: it leaves the proxy at once, nothing else is
// placed for it, and it serves again from its new address, counted as a
// restart (T21).
func TestRecreatedReplicaLeavesTheProxy(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	c.deploy("name: web\nimage: nginx:1\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 2\n")
	node, err := c.st.GetNode(c.ctx, "n1")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range c.replicas() {
		ids = append(ids, r.ID)
	}
	slices.Sort(ids)
	report := func(states ...*armadav1.ReplicaState) {
		t.Helper()
		c.srv.applyReport(c.ctx, node, &armadav1.ReplicaReport{Replicas: states})
		c.advance(10 * time.Second)
	}
	running := func(id, container, addr string) *armadav1.ReplicaState {
		return &armadav1.ReplicaState{Id: id, State: store.ReplicaRunning, Ready: true, ContainerId: container, Address: addr}
	}
	servers := func() []string {
		t.Helper()
		apps, _ := c.st.ListApps(c.ctx)
		reps, _ := c.st.ListReplicas(c.ctx, store.ReplicaFilter{})
		px, err := c.srv.buildProxy(c.ctx, apps, reps)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, s := range px.Backends[0].Servers {
			out = append(out, s.Name+"@"+s.Address)
		}
		slices.Sort(out)
		return out
	}
	report(running(ids[0], "c1", "10.0.0.2:32001"), running(ids[1], "c2", "10.0.0.2:32002"))
	if got := servers(); len(got) != 2 {
		t.Fatalf("servers before the reboot = %v", got)
	}

	report(&armadav1.ReplicaState{Id: ids[0], State: store.ReplicaStarting, ContainerId: "c1", Message: store.RestartNote + "the machine restarted"},
		running(ids[1], "c2", "10.0.0.2:32002"))
	if got := servers(); !slices.Equal(got, []string{ids[1] + "@10.0.0.2:32002"}) {
		t.Errorf("servers while one is recreated = %v", got)
	}
	if n := len(c.replicas()); n != 2 {
		t.Errorf("%d replicas while one is recreated, want 2", n)
	}

	// The new container's first report carries the restart note.
	restarted := running(ids[0], "c3", "10.0.0.2:32003")
	restarted.Message = store.RestartNote + "the machine restarted"
	report(restarted, running(ids[1], "c2", "10.0.0.2:32002"))
	if got := servers(); !slices.Equal(got, []string{ids[0] + "@10.0.0.2:32003", ids[1] + "@10.0.0.2:32002"}) {
		t.Errorf("servers after the restart = %v", got)
	}
	for _, r := range c.replicas() {
		if r.ID == ids[0] && (r.Restarts != 1 || r.LastRestart != "the machine restarted") {
			t.Errorf("restart recorded as %d %q", r.Restarts, r.LastRestart)
		}
	}
}

// Two apps whose replicas claim one address (one of them stale: a node that
// restarted handed it to another container) both stay out of the proxy, so
// one app's requests never reach the other (T21); each app says why once.
func TestProxyLeavesOutAnAddressTwoAppsClaim(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	if _, err := c.admin.CreateSpace(c.ctx, &armadav1.CreateSpaceRequest{Name: "shop"}); err != nil {
		t.Fatal(err)
	}
	for space, name := range map[string]string{"default": "web", "shop": "db"} {
		sp := "name: " + name + "\nimage: nginx:1\ningress:\n  type: internal\n  port: 8080\n"
		if _, err := c.admin.Deploy(c.ctx, &armadav1.DeployRequest{Spec: []byte(sp), Space: space}); err != nil {
			t.Fatal(err)
		}
	}
	apps, err := c.store.ListApps(c.ctx)
	if err != nil {
		t.Fatal(err)
	}
	rev := map[string]string{}
	for _, a := range apps {
		rev[a.Name] = cmp.Or(a.ActiveRevision, a.TargetRevision)
	}
	at := func(id, app, addr string) store.Replica {
		host, _, _ := strings.Cut(addr, ":")
		return store.Replica{ID: id, App: app, Revision: rev[app], NodeID: "n1", State: store.ReplicaRunning, Ready: true, Address: addr, IP: host}
	}
	servers := func(replicas ...store.Replica) map[string][]string {
		t.Helper()
		px, err := c.srv.buildProxy(c.ctx, apps, replicas)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string][]string{}
		for _, b := range px.Backends {
			for _, s := range b.Servers {
				out[b.Name] = append(out[b.Name], s.Name)
			}
		}
		return out
	}
	conflicts := func() []string {
		t.Helper()
		var out []string
		for _, e := range listEvents(t, c.store) {
			if e.Reason == "AddressConflict" {
				out = append(out, e.App)
			}
		}
		slices.Sort(out)
		return out
	}

	// web's replica is stale: its node restarted and gave its address to
	// db's new replica.
	got := servers(at("web-r1-a", "web", "10.120.0.2:8080"), at("web-r1-b", "web", "10.120.0.3:8080"), at("db.shop-r1-a", "db.shop", "10.120.0.2:8080"))
	if !slices.Equal(got["web"], []string{"web-r1-b"}) || len(got["db.shop"]) != 0 {
		t.Errorf("servers with one address claimed twice = %v", got)
	}
	if ev := conflicts(); !slices.Equal(ev, []string{"db.shop", "web"}) {
		t.Errorf("conflict events = %v", ev)
	}
	// The same container IP on another port is the same clash.
	got = servers(at("web-r1-a", "web", "10.120.0.2:8080"), at("db.shop-r1-a", "db.shop", "10.120.0.2:9090"))
	if len(got["web"]) != 0 || len(got["db.shop"]) != 0 {
		t.Errorf("servers with one IP claimed twice = %v", got)
	}
	// Once the stale one reports its new address, both serve again; the
	// conflict was recorded once per app.
	got = servers(at("web-r1-a", "web", "10.120.0.4:8080"), at("db.shop-r1-a", "db.shop", "10.120.0.2:8080"))
	if !slices.Equal(got["web"], []string{"web-r1-a"}) || !slices.Equal(got["db.shop"], []string{"db.shop-r1-a"}) {
		t.Errorf("servers after the conflict cleared = %v", got)
	}
	if ev := conflicts(); len(ev) != 2 {
		t.Errorf("conflict events = %v", ev)
	}
	// Two replicas of one app may claim one address for a moment (a
	// replacement races the report): no conflict.
	got = servers(at("web-r1-a", "web", "10.120.0.4:8080"), at("web-r1-b", "web", "10.120.0.4:8080"))
	if len(got["web"]) != 2 {
		t.Errorf("servers of one app sharing an address = %v", got)
	}
}
