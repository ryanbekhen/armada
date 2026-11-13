package server

import (
	"net/netip"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

func TestValidReplicaIP(t *testing.T) {
	t.Parallel()
	sub := "10.120.3.0/24"
	if !validReplicaIP("10.120.3.7", sub) {
		t.Error("container address rejected")
	}
	for _, ip := range []string{
		"10.120.4.7",   // another node's subnet
		"10.120.3.0",   // the tunnel end
		"10.120.3.1",   // the bridge
		"10.120.3.255", // broadcast
		"10.0.0.2",     // the private IP
		"10.120.3.7:80",
		"010.120.3.7",
		"::ffff:10.120.3.7",
		"10.120.3.7%eth0",
		"",
	} {
		if validReplicaIP(ip, sub) {
			t.Errorf("%q accepted", ip)
		}
	}
	if validReplicaIP("10.120.3.7", "") {
		t.Error("accepted on a node without a subnet")
	}
}

func TestNetworkEndpoints(t *testing.T) {
	t.Parallel()
	subnets := map[string]string{"n1": "10.120.0.0/24", "n2": "10.120.1.0/24"}
	got := networkEndpoints([]store.Replica{
		{ID: "web-r1-a", App: "web", NodeID: "n1", IP: "10.120.0.5"},
		{ID: "api-r1-a", App: "api.shop", NodeID: "n2", IP: "10.120.1.5"},
		{ID: "no-ip", App: "web", NodeID: "n1"},
		{ID: "done", App: "job", NodeID: "n1", IP: "10.120.0.6", Done: true},
		// Not in its node's subnet (the node moved, or a bad record).
		{ID: "elsewhere", App: "web", NodeID: "n2", IP: "10.120.0.7"},
		{ID: "no-subnet", App: "web", NodeID: "n3", IP: "10.120.0.8"},
		// Two apps claim one address: neither gets it.
		{ID: "x-r1-a", App: "x", NodeID: "n1", IP: "10.120.0.9"},
		{ID: "y-r1-a", App: "y", NodeID: "n1", IP: "10.120.0.9"},
		// Two replicas of one app may (a replacement races the report).
		{ID: "z-r1-a", App: "z", NodeID: "n1", IP: "10.120.0.10"},
		{ID: "z-r1-b", App: "z", NodeID: "n1", IP: "10.120.0.10"},
	}, subnets)
	want := []*armadav1.NetworkEndpoint{
		{Address: "10.120.0.10", App: "z"},
		{Address: "10.120.0.5", App: "web"},
		{Address: "10.120.1.5", App: "api.shop"},
	}
	if len(got) != len(want) {
		t.Fatalf("endpoints = %v", got)
	}
	for i := range want {
		if !proto.Equal(got[i], want[i]) {
			t.Errorf("endpoint %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestNetworkIsolationSetting(t *testing.T) {
	t.Parallel()
	c, auto, _ := serviceCluster(t)
	isolation := func(p string) bool {
		t.Helper()
		resp, err := c.admin.ListSpaces(c.ctx, &armadav1.ListSpacesRequest{})
		if err != nil {
			t.Fatal(err)
		}
		for _, info := range resp.Spaces {
			if info.Name == p {
				return info.NetworkIsolation
			}
		}
		t.Fatalf("no space %s", p)
		return false
	}
	on, off := true, false
	// Without a cluster network nothing is isolated, and the default
	// space cannot be.
	if isolation("a") || isolation("default") {
		t.Error("isolated without a cluster network")
	}
	_, err := c.admin.UpdateSpace(c.ctx, &armadav1.UpdateSpaceRequest{Name: "default", NetworkIsolation: &on})
	wantCode(t, "isolate default without a network", err, codes.FailedPrecondition)

	if err := c.store.InitNetwork(c.ctx, store.Network{Mode: store.NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	if !isolation("a") || isolation("default") {
		t.Error("with a network: other spaces isolated, default not")
	}
	info, err := c.admin.UpdateSpace(c.ctx, &armadav1.UpdateSpaceRequest{Name: "default", NetworkIsolation: &on})
	if err != nil || !info.NetworkIsolation || !isolation("default") {
		t.Fatalf("isolate default: %v %v", info, err)
	}
	if n, _ := c.store.GetNetwork(c.ctx); !n.IsolateDefault {
		t.Error("not stored")
	}
	if _, err := c.admin.UpdateSpace(c.ctx, &armadav1.UpdateSpaceRequest{Name: "default", NetworkIsolation: &off}); err != nil || isolation("default") {
		t.Errorf("turn it off: %v", err)
	}
	// Other spaces are always isolated.
	_, err = c.admin.UpdateSpace(c.ctx, &armadav1.UpdateSpaceRequest{Name: "a", NetworkIsolation: &off})
	wantCode(t, "turn off for a space", err, codes.InvalidArgument)
	_, err = c.admin.UpdateSpace(c.ctx, &armadav1.UpdateSpaceRequest{Name: "ghost", NetworkIsolation: &on})
	wantCode(t, "missing space", err, codes.NotFound)
	_, err = c.admin.UpdateSpace(c.ctx, &armadav1.UpdateSpaceRequest{Name: "Bad;Name", NetworkIsolation: &on})
	wantCode(t, "invalid name", err, codes.InvalidArgument)
	// Automation identities never change it, not even for their spaces.
	_, err = auto.UpdateSpace(c.ctx, &armadav1.UpdateSpaceRequest{Name: "a", NetworkIsolation: &on})
	wantCode(t, "service", err, codes.PermissionDenied)
	_, err = auto.UpdateSpace(c.ctx, &armadav1.UpdateSpaceRequest{Name: "default", NetworkIsolation: &off})
	wantCode(t, "service on default", err, codes.PermissionDenied)
}

func TestInternalRulesCarryAllow(t *testing.T) {
	t.Parallel()
	if got := allowedCallers("db.shop", nil); got != nil {
		t.Errorf("no allow = %v", got)
	}
	if got := allowedCallers("db.shop", []string{"api", "worker"}); !slices.Equal(got, []string{"db.shop", "api.shop", "worker.shop"}) {
		t.Errorf("space allow = %v", got)
	}
	if got := allowedCallers("db", []string{"api"}); !slices.Equal(got, []string{"db", "api"}) {
		t.Errorf("default allow = %v", got)
	}

	c := newCluster(t)
	if _, err := c.admin.CreateSpace(c.ctx, &armadav1.CreateSpaceRequest{Name: "shop"}); err != nil {
		t.Fatal(err)
	}
	spec := "name: db\nimage: nginx:1\ningress:\n  type: internal\n  port: 80\n  allow: [api]\n"
	if _, err := c.admin.Deploy(c.ctx, &armadav1.DeployRequest{Spec: []byte(spec), Space: "shop"}); err != nil {
		t.Fatal(err)
	}
	apps, err := c.store.ListApps(c.ctx)
	if err != nil {
		t.Fatal(err)
	}
	px, err := c.srv.buildProxy(c.ctx, apps, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := px.Validate(); err != nil {
		t.Fatalf("proxy config: %v", err)
	}
	found := false
	for _, r := range px.Rules {
		if r.Host == "db.shop.internal" {
			found = true
			if !slices.Equal(r.Allow, []string{"db.shop", "api.shop"}) {
				t.Errorf("allow = %v", r.Allow)
			}
		}
	}
	if !found {
		t.Error("no internal rule for db.shop")
	}
}
