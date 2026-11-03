package server

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"google.golang.org/grpc"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/store/storetest"
)

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestMetrics(t *testing.T) {
	t.Parallel()
	addr := freeTCPAddr(t)
	c := newCluster(t, func(cfg *Config) { cfg.MetricsAddr = addr; cfg.Name = "s1" })
	d := c.addNode("n1", "127.0.0.1")
	c.deploy(webSpec("nginx:1", 2) + "resources:\n  cpu: 250m\n  memory: 128Mi\n")
	c.eventually("2 running", func() bool { return len(c.running("web")) == 2 })
	for _, r := range c.running("web") {
		d.SetUsage(r.Id, runtime.Stats{MemoryBytes: 50 << 20})
	}

	// A metrics certificate from the caller's own key.
	keyPEM, csr, err := pki.NewCSR(pki.Identity{Kind: pki.KindMetrics, Name: "prometheus"})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := c.admin.IssueMetricsCertificate(c.ctx, &armadav1.IssueMetricsCertificateRequest{Name: "prometheus", Csr: csr})
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(issued.GetExpiresAt().AsTime()) < 300*24*time.Hour {
		t.Errorf("expires at %v", issued.GetExpiresAt().AsTime())
	}
	scrape := func(certPEM, keyPEM []byte) (int, string, error) {
		cfg, err := pki.ClientTLS(issued.GetCaCert(), certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
		resp, err := hc.Get("https://" + addr + "/metrics")
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), nil
	}

	want := []string{
		`armada_server_leader{server="s1"} 1`,
		`armada_agents_connected 1`,
		`armada_app_replicas_desired{app="web"} 2`,
		`armada_app_replicas_ready{app="web"} 2`,
		`armada_app_rollout{app="web",state="idle"} 1`,
		`armada_node_ready{node="n1"} 1`,
		`armada_node_replicas{node="n1"} 2`,
		`armada_node_cpu_reserved_cores{node="n1"} 0.5`,
		`armada_node_memory_usage_bytes{node="n1"} 1.048576e+08`,
		`armada_replica_cpu_limit_cores{app="web"`,
		`armada_replica_memory_usage_bytes{app="web"`,
		`armada_reconcile_duration_seconds_count`,
		`go_goroutines`,
	}
	var body string
	c.eventually("metrics with usage", func() bool {
		code, b, err := scrape(issued.GetCert(), keyPEM)
		body = b
		return err == nil && code == http.StatusOK && strings.Contains(b, `armada_node_memory_usage_bytes{node="n1"} 1.048576e+08`)
	})
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("metrics lack %q", w)
		}
	}

	// Admin certificates may scrape too; node certificates may not.
	adminCert, adminKey, _ := c.ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindAdmin, Name: "ryan"}, Client: true})
	if code, _, err := scrape(adminCert, adminKey); err != nil || code != http.StatusOK {
		t.Errorf("admin scrape: %d, %v", code, err)
	}
	nodeCert, nodeKey, _ := c.ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindNode, Name: "n1"}, Client: true})
	if code, _, err := scrape(nodeCert, nodeKey); err != nil || code != http.StatusForbidden {
		t.Errorf("node scrape: %d, %v", code, err)
	}
	// A certificate from another CA, and none at all, fail the handshake.
	other, _ := pki.NewCA("other")
	otherCert, otherKey, _ := other.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindMetrics, Name: "prometheus"}, Client: true})
	if _, _, err := scrape(otherCert, otherKey); err == nil {
		t.Error("certificate from another CA accepted")
	}
	pool, _ := pki.ClientTLS(issued.GetCaCert(), issued.GetCert(), keyPEM)
	noCert := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool.RootCAs, ServerName: pki.ServerName}
	if resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: noCert}, Timeout: 5 * time.Second}).Get("https://" + addr + "/metrics"); err == nil {
		resp.Body.Close()
		t.Error("scrape without a client certificate accepted")
	}

	// The metrics certificate cannot call the API.
	cfg, _ := pki.ClientTLS(issued.GetCaCert(), issued.GetCert(), keyPEM)
	conn, err := grpc.NewClient(c.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := armadav1.NewAdminServiceClient(conn).Status(c.ctx, &armadav1.StatusRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("metrics certificate on the API: %v", err)
	}
}

func TestIssueMetricsCertificateRefusesBadInput(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	_, csr, _ := pki.NewCSR(pki.Identity{Kind: pki.KindMetrics, Name: "p"})
	for name, req := range map[string]*armadav1.IssueMetricsCertificateRequest{
		"bad name":    {Name: "../etc", Csr: csr},
		"empty name":  {Name: "", Csr: csr},
		"garbage CSR": {Name: "p", Csr: []byte("not a csr")},
	} {
		if _, err := c.admin.IssueMetricsCertificate(c.ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMetricsAddrMustBePrivate(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("test")
	certPEM, keyPEM, _ := ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindServer, Name: "armada"}, DNSNames: []string{pki.ServerName}, Server: true})
	tlsCfg, _ := pki.ServerTLS(ca.CertPEM, certPEM, keyPEM)
	st := storetest.Open(t)
	if _, err := New(Config{Store: st, TLS: tlsCfg, MetricsAddr: "10.0.0.5:9100"}); err != nil {
		t.Fatalf("private address refused: %v", err)
	}
	for _, addr := range []string{"0.0.0.0:9100", ":9100", "8.8.8.8:9100"} {
		if _, err := New(Config{Store: st, TLS: tlsCfg, MetricsAddr: addr}); err == nil || !strings.Contains(err.Error(), "metrics") {
			t.Errorf("%s: %v", addr, err)
		}
	}
}
