package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/proxy"
	"github.com/ryanbekhen/armada/internal/store"
)

// noTXT resolves nothing, so tests never touch real DNS.
type noTXT struct{}

func (noTXT) LookupTXT(context.Context, string) ([]string, error) {
	return nil, errors.New("no such host")
}

type fakeTXT struct {
	mu      sync.Mutex
	records map[string][]string
}

func (f *fakeTXT) set(name string, values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[name] = values
}

func (f *fakeTXT) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.records[name]; ok {
		return r, nil
	}
	return nil, errors.New("no such host")
}

// fakeCerts issues certificates instantly for names in issue.
type fakeCerts struct {
	mu       sync.Mutex
	wildcard bool
	managed  []string
	issued   map[string][]byte
}

func (f *fakeCerts) Manage(_ context.Context, names []string, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.managed = slices.Clone(names)
	return nil
}

func (f *fakeCerts) Certificate(_ context.Context, name string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.issued[name]
	return b, ok
}

func (f *fakeCerts) issue(t *testing.T, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued[name] = testCertPEM(t)
}

func (f *fakeCerts) Managed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.managed)
}

func (f *fakeCerts) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/acme-challenge/tok" {
			_, _ = io.WriteString(w, "tok.key")
			return
		}
		http.NotFound(w, r)
	})
}

func (f *fakeCerts) SupportsWildcard() bool { return f.wildcard }

func testCertPEM(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})...)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

const ingressApp = `name: web
image: nginx:1
ingress:
  type: external
  port: 80
  domains: [example.org]
probes:
  readiness:
    path: /healthz
`

func (c *cluster) proxyOn(node string) proxy.Config {
	_, cfg := c.proxies[node].Applied()
	return cfg
}

// hosts returns the public hosts a node routes.
func hosts(cfg proxy.Config) []string {
	var out []string
	for _, r := range cfg.Rules {
		if !r.Internal {
			out = append(out, r.Host)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func TestIngressRoutingAndDomainVerification(t *testing.T) {
	t.Parallel()
	txt := &fakeTXT{records: map[string][]string{}}
	certs := &fakeCerts{issued: map[string][]byte{}}
	acme := freeAddr(t)
	c := newCluster(t, func(cfg *Config) {
		cfg.Resolver = txt
		cfg.Certs = certs
		cfg.ACMEAddr = acme
		cfg.ACMEEmail = "ops@example.org"
		cfg.VerifyInterval = 50 * time.Millisecond
	})
	c.addNode("n1", "10.0.0.2")
	c.addNode("n2", "10.0.0.3")

	if _, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetRootDomain: true, Config: &armadav1.ClusterConfig{RootDomain: "Apps.Example.ORG"}}); err != nil {
		t.Fatal(err)
	}
	cc, _ := c.admin.GetClusterConfig(c.ctx, &armadav1.GetClusterConfigRequest{})
	if cc.RootDomain != "apps.example.org" || cc.AcmeEmail != "ops@example.org" {
		t.Errorf("cluster config = %v", cc)
	}

	c.deploy(ingressApp)
	c.eventually("replica running", func() bool { return len(c.running("web")) == 1 })
	addr := c.running("web")[0].Address

	// Every node routes <app>.<root> to the running replica; the custom
	// domain is not routed until it is verified.
	for _, n := range []string{"n1", "n2"} {
		c.eventually("proxy on "+n, func() bool {
			cfg := c.proxyOn(n)
			return len(cfg.Backends) == 1 && len(cfg.Backends[0].Servers) == 1
		})
		cfg := c.proxyOn(n)
		if got := hosts(cfg); !slices.Equal(got, []string{"web.apps.example.org"}) {
			t.Errorf("%s hosts = %v", n, got)
		}
		if cfg.Backends[0].Servers[0].Address != addr || cfg.Backends[0].HealthPath != "/healthz" || cfg.ACMEAddress != acme {
			t.Errorf("%s proxy = %+v", n, cfg)
		}
	}

	ds, err := c.admin.ListDomains(c.ctx, &armadav1.ListDomainsRequest{})
	if err != nil || len(ds.Domains) != 1 {
		t.Fatalf("ListDomains = %v, %v", ds, err)
	}
	d := ds.Domains[0]
	if d.Verified || d.TxtName != "_armada-verify.example.org" || len(d.TxtValue) != 32 || !slices.Equal(d.Apps, []string{"web"}) {
		t.Errorf("domain = %v", d)
	}

	// A wrong token does not verify.
	txt.set("_armada-verify.example.org", "someone-else")
	// The background loop may be finishing a lookup from before the record
	// changed, and its message may replace this call's once.
	c.eventually("wrong token reported", func() bool {
		wrong, err := c.admin.VerifyDomain(c.ctx, &armadav1.VerifyDomainRequest{Name: "example.org"})
		if err != nil || wrong.Verified {
			t.Fatalf("VerifyDomain(wrong) = %v, %v", wrong, err)
		}
		return strings.Contains(wrong.Message, "expected token")
	})

	// The right token is picked up by the background loop.
	txt.set("_armada-verify.example.org", "unrelated", d.TxtValue)
	c.eventually("custom domain routed", func() bool {
		return slices.Equal(hosts(c.proxyOn("n1")), []string{"example.org", "web.apps.example.org"})
	})

	// Certificates are requested for every routed host and shipped once issued.
	if m := certs.Managed(); !slices.Equal(m, []string{"example.org", "web.apps.example.org"}) {
		t.Errorf("managed = %v", m)
	}
	certs.issue(t, "example.org")
	c.srv.Trigger()
	c.eventually("certificate on n2", func() bool {
		cfg := c.proxyOn("n2")
		return len(cfg.Certificates) == 1 && cfg.Certificates[0].Name == "example.org"
	})
	// Agents fetch it by reference (Hello.certificate_refs): what reaches
	// the proxy is the certificate itself.
	if pem, _ := certs.Certificate(c.ctx, "example.org"); !bytes.Equal(c.proxyOn("n2").Certificates[0].PEM, pem) {
		t.Error("the proxy did not get the certificate's PEM")
	}
	got, _ := c.admin.VerifyDomain(c.ctx, &armadav1.VerifyDomainRequest{Name: "example.org"})
	if !got.Verified || !got.TlsReady {
		t.Errorf("domain after issuance = %v", got)
	}

	st, _ := c.admin.Status(c.ctx, &armadav1.StatusRequest{App: "web"})
	if urls := st.Apps[0].Urls; !slices.Equal(urls, []string{"https://web.apps.example.org/", "https://example.org/"}) {
		t.Errorf("urls = %v", urls)
	}

	// The ACME responder serves challenges on the private address.
	resp, err := http.Get("http://" + acme + "/.well-known/acme-challenge/tok") //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "tok.key" {
		t.Errorf("challenge body = %q", body)
	}

	if _, err := c.admin.VerifyDomain(c.ctx, &armadav1.VerifyDomainRequest{Name: "ghost.id"}); status.Code(err) != codes.NotFound {
		t.Errorf("verify unknown = %v", err)
	}
}

func TestWildcardCertificateCoversAppHosts(t *testing.T) {
	t.Parallel()
	certs := &fakeCerts{issued: map[string][]byte{}, wildcard: true}
	c := newCluster(t, func(cfg *Config) { cfg.Certs = certs; cfg.ACMEAddr = freeAddr(t) })
	c.addNode("n1", "10.0.0.2")
	if _, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetRootDomain: true, Config: &armadav1.ClusterConfig{RootDomain: "apps.example.org"}}); err != nil {
		t.Fatal(err)
	}
	c.deploy(ingressApp)
	c.eventually("certificates managed", func() bool { return len(certs.Managed()) > 0 })
	// <app>.<root> is covered by the wildcard; the unverified custom domain
	// gets nothing.
	if m := certs.Managed(); !slices.Equal(m, []string{"*.apps.example.org"}) {
		t.Errorf("managed = %v", m)
	}
}

// A verified custom domain one label under the root domain is served with the
// wildcard certificate, so it is TLS-ready once the wildcard is issued.
func TestWildcardCoversCustomDomain(t *testing.T) {
	t.Parallel()
	certs := &fakeCerts{issued: map[string][]byte{}, wildcard: true}
	txt := &fakeTXT{records: map[string][]string{}}
	c := newCluster(t, func(cfg *Config) { cfg.Certs = certs; cfg.ACMEAddr = freeAddr(t); cfg.Resolver = txt })
	c.addNode("n1", "10.0.0.2")
	if _, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetRootDomain: true, Config: &armadav1.ClusterConfig{RootDomain: "example.org"}}); err != nil {
		t.Fatal(err)
	}
	c.deploy(strings.Replace(ingressApp, "domains: [example.org]", "domains: [shop.example.org, a.b.example.org]", 1))
	ds, err := c.admin.ListDomains(c.ctx, &armadav1.ListDomainsRequest{})
	if err != nil || len(ds.Domains) != 2 {
		t.Fatalf("ListDomains = %v, %v", ds, err)
	}
	for _, d := range ds.Domains {
		txt.set(d.TxtName, d.TxtValue)
	}
	certs.issue(t, "*.example.org")
	for _, tc := range []struct {
		name  string
		ready bool
	}{{"shop.example.org", true}, {"a.b.example.org", false}} {
		d, err := c.admin.VerifyDomain(c.ctx, &armadav1.VerifyDomainRequest{Name: tc.name})
		if err != nil || !d.Verified || d.TlsReady != tc.ready {
			t.Errorf("%s = %v, %v (want TLS ready %v)", tc.name, d, err, tc.ready)
		}
	}
	for host, want := range map[string]bool{"shop.example.org": true, "example.org": false, "a.b.example.org": false, "xexample.org": false, ".example.org": false} {
		if got := underWildcard(host, "example.org"); got != want {
			t.Errorf("underWildcard(%q) = %v", host, got)
		}
	}
}

func TestClusterConfigAndConflicts(t *testing.T) {
	t.Parallel()
	c := newCluster(t)

	for _, bad := range []string{"-bad.id", "example..org", "example.org\n  bind :22", "*.example.org", "localhost"} {
		_, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetRootDomain: true, Config: &armadav1.ClusterConfig{RootDomain: bad}})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("root domain %q: err = %v", bad, err)
		}
	}
	// Clearing the root domain is allowed.
	if _, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetRootDomain: true, Config: &armadav1.ClusterConfig{}}); err != nil {
		t.Error(err)
	}
	events, _ := c.store.ListAudit(c.ctx, 10)
	if len(events) == 0 || events[0].Action != "cluster.root_domain" || events[0].Actor != "admin:ryan" {
		t.Errorf("audit = %+v", events)
	}

	c.deploy(ingressApp)
	_, err := c.admin.Deploy(c.ctx, &armadav1.DeployRequest{Spec: []byte(strings.Replace(ingressApp, "name: web", "name: other", 1))})
	if status.Code(err) != codes.AlreadyExists || !strings.Contains(err.Error(), "example.org/") {
		t.Errorf("conflicting deploy err = %v", err)
	}
	ds, _ := c.admin.ListDomains(c.ctx, &armadav1.ListDomainsRequest{App: "nope"})
	if len(ds.Domains) != 0 {
		t.Errorf("filter by app = %v", ds.Domains)
	}
}

func TestNewRejectsUnsafeACMEAddr(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("t")
	crt, key, _ := ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindServer, Name: "a"}, Server: true})
	tlsCfg, _ := pki.ServerTLS(ca.CertPEM, crt, key)
	base := Config{Store: &store.Etcd{}, TLS: tlsCfg, Certs: &fakeCerts{}}

	for _, addr := range []string{"0.0.0.0:7480", "[::]:7480", "8.8.8.8:7480", "10.0.0.1:0", "", "nope"} {
		cfg := base
		cfg.ACMEAddr = addr
		if _, err := New(cfg); err == nil {
			t.Errorf("ACMEAddr %q accepted", addr)
		}
	}
	base.ACMEAddr = "10.0.0.1:7480"
	if _, err := New(base); err != nil {
		t.Errorf("private ACMEAddr rejected: %v", err)
	}
}

func TestInternalIngress(t *testing.T) {
	t.Parallel()
	certs := &fakeCerts{issued: map[string][]byte{}}
	acme := freeAddr(t)
	c := newCluster(t, func(cfg *Config) {
		cfg.Certs = certs
		cfg.ACMEAddr = acme
		cfg.ACMEEmail = "ops@example.org"
	})
	c.addNode("n1", "10.0.0.2")
	if _, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetRootDomain: true, Config: &armadav1.ClusterConfig{RootDomain: "apps.example.org"}}); err != nil {
		t.Fatal(err)
	}
	c.deploy("name: shop-api\nimage: nginx:1\ningress:\n  type: internal\n  port: 8080\n  routes:\n    - path: /v1\n      stripPrefix: true\n")
	c.deploy(webSpec("nginx:1", 1))
	c.eventually("both apps in the proxy", func() bool {
		cfg := c.proxyOn("n1")
		return len(cfg.Backends) == 2 && len(cfg.Backends[0].Servers) == 1 && len(cfg.Backends[1].Servers) == 1
	})
	cfg := c.proxyOn("n1")
	var internal []proxy.Rule
	for _, r := range cfg.Rules {
		if r.Internal {
			internal = append(internal, r)
		}
	}
	slices.SortFunc(internal, func(a, b proxy.Rule) int { return strings.Compare(a.Host, b.Host) })
	want := []proxy.Rule{
		{Host: "shop-api.internal", PathPrefix: "/v1", StripPrefix: true, Backend: "shop-api", Internal: true},
		{Host: "web.internal", PathPrefix: "/", Backend: "web", Internal: true},
	}
	if !reflect.DeepEqual(internal, want) {
		t.Errorf("internal rules = %+v", internal)
	}
	// The internal app gets no public name and no certificate.
	if got := hosts(cfg); !slices.Equal(got, []string{"web.apps.example.org"}) {
		t.Errorf("public hosts = %v", got)
	}
	if m := certs.Managed(); slices.ContainsFunc(m, func(n string) bool { return strings.Contains(n, "shop-api") || strings.HasSuffix(n, ".internal") }) {
		t.Errorf("certificates requested for %v", m)
	}
	st, err := c.admin.Status(c.ctx, &armadav1.StatusRequest{App: "shop-api"})
	if err != nil || len(st.Apps) != 1 || !slices.Equal(st.Apps[0].Urls, []string{"http://shop-api.internal/v1"}) {
		t.Errorf("status = %v, %v", st, err)
	}
}

func TestTrustedProxies(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	if _, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetRootDomain: true, Config: &armadav1.ClusterConfig{RootDomain: "apps.example.org"}}); err != nil {
		t.Fatal(err)
	}
	cc, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetTrustedProxies: true, Config: &armadav1.ClusterConfig{TrustedProxies: []string{"198.51.100.9/24", "192.0.2.0/24"}}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0/24", "198.51.100.0/24"}
	if !slices.Equal(cc.GetTrustedProxies(), want) {
		t.Errorf("trusted = %v, want %v", cc.GetTrustedProxies(), want)
	}
	// Setting one field leaves the other alone.
	if cc.GetRootDomain() != "apps.example.org" {
		t.Errorf("root domain = %q", cc.GetRootDomain())
	}
	cc, err = c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetRootDomain: true, Config: &armadav1.ClusterConfig{}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cc.GetTrustedProxies(), want) {
		t.Errorf("clearing the root domain changed trusted proxies: %v", cc.GetTrustedProxies())
	}
	if events, _ := c.store.ListAudit(c.ctx, 10); len(events) < 2 || events[1].Action != "cluster.trusted_proxies" || events[1].Target != "cluster" {
		t.Errorf("audit = %+v", events)
	}
	cfg, err := c.srv.buildProxy(c.ctx, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.TrustedProxies, want) {
		t.Errorf("proxy config = %v, want %v", cfg.TrustedProxies, want)
	}
	for _, bad := range [][]string{{"0.0.0.0/0"}, {"::/0"}, {"192.0.2.1"}, {"192.0.2.0/24 bind :22"}} {
		_, err := c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetTrustedProxies: true, Config: &armadav1.ClusterConfig{TrustedProxies: bad}})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%v: err = %v", bad, err)
		}
	}
	cc, err = c.admin.SetClusterConfig(c.ctx, &armadav1.SetClusterConfigRequest{SetTrustedProxies: true, Config: &armadav1.ClusterConfig{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(cc.GetTrustedProxies()) != 0 {
		t.Errorf("not cleared: %v", cc.GetTrustedProxies())
	}
}
