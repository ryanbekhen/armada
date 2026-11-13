package server

import (
	"net/netip"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

// An internal TCP app (ADR 0039) needs the cluster network, gets a TCP route
// with its callers and a backend with no HTTP settings, no internal HTTP
// rule, and a tcp:// URL.
func TestIngressTCP(t *testing.T) {
	t.Parallel()
	db := "name: db\nimage: postgres:17\ningress:\n  type: internal\n  protocol: tcp\n  port: 5432\n  allow: [api]\n" +
		"probes:\n  readiness:\n    path: /ready\n    port: 8080\n"
	old := newCluster(t)
	_, err := old.admin.Deploy(old.ctx, &armadav1.DeployRequest{Spec: []byte(db)})
	wantCode(t, "without a cluster network", err, codes.FailedPrecondition)

	c := newCluster(t)
	if err := c.store.InitNetwork(c.ctx, store.Network{Mode: store.NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	c.addNode("n1", "127.0.0.1")
	c.deploy(db)
	c.deploy("name: cache\nimage: redis:8\ningress:\n  type: internal\n  protocol: tcp\n  port: 6379\n")
	_, err = c.admin.Deploy(c.ctx, &armadav1.DeployRequest{Spec: []byte("name: other\nimage: postgres:17\ningress:\n  type: internal\n  protocol: tcp\n  port: 5432\n")})
	wantCode(t, "a port of another app of the space", err, codes.AlreadyExists)

	c.eventually("tcp routes on n1", func() bool { return len(c.proxyOn("n1").TCP) == 2 })
	cfg := c.proxyOn("n1")
	for _, r := range cfg.TCP {
		switch r.Backend {
		case "db":
			if r.Port != 5432 || !slices.Equal(r.Allow, []string{"db", "api"}) {
				t.Errorf("db route = %+v", r)
			}
		case "cache":
			if r.Port != 6379 || r.Allow != nil {
				t.Errorf("cache route = %+v", r)
			}
		default:
			t.Errorf("unexpected route %+v", r)
		}
	}
	for _, b := range cfg.Backends {
		if b.Name == "db" && (b.HealthPath != "" || !b.LocalFirst || b.Wake || b.TimeoutSeconds != 0) {
			t.Errorf("db backend = %+v", b)
		}
	}
	for _, r := range cfg.Rules {
		if r.Backend == "db" || r.Backend == "cache" {
			t.Errorf("HTTP rule for a TCP app: %+v", r)
		}
	}
	if got := tcpPorts(cfg.ToProto()); !slices.Equal(got, []uint32{5432, 6379}) {
		t.Errorf("network ports = %v", got)
	}
	st, err := c.admin.Status(c.ctx, &armadav1.StatusRequest{App: "db"})
	if err != nil {
		t.Fatal(err)
	}
	if urls := st.Apps[0].Urls; !slices.Equal(urls, []string{"tcp://db.internal:5432"}) {
		t.Errorf("urls = %v", urls)
	}
}
