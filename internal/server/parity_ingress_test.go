package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	clientv3 "go.etcd.io/etcd/client/v3"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/certs"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/store/storetest"
)

// Scenarios of ingress and certificates (ADR 0055, pull request 14), run
// against both servers by runParity: the proxy configuration of every
// assignment (backends and rules of external, internal, sticky, CORS,
// client address, scale-to-zero, labelled, and TCP apps, the trusted
// proxies and PROXY protocol sources without the container ranges, plain
// HTTP), the ports of internal TCP apps in the network, addresses two
// apps claim and routes another app holds, custom domains with their TXT
// proof, and certificates: what the manager is asked to manage (wildcards
// and apps' own DNS tokens), certificates read from certmagic's storage
// in etcd and kept until obtained again, by reference for agents that
// fetch them, GetCertificates, and the last valid configuration kept when
// a pass's own is not. Obtaining certificates is the second part of pull
// request 14: the managers here only read what a scenario stores.

const (
	// parityACMECA is the directory the certificates are stored under
	// (its issuer key).
	parityACMECA = "https://acme.test:14000/dir"
)

// acmePrefix is where certmagic's data of a scenario's run lives, outside
// the keyspace the transcripts record.
func (sc *scenario) acmePrefix() string {
	return strings.Replace(sc.pfx, "/test/", "/test-acme/", 1)
}

// parityCerts is the certificate manager of the scenarios: certificates
// from certmagic's storage, and what it was last asked to manage.
type parityCerts struct {
	storage  *certs.EtcdStorage
	issuer   string
	wildcard bool
	mu       sync.Mutex
	managed  map[string]any
}

func (p *parityCerts) Manage(_ context.Context, names []string, root string, dns map[string]certs.DNS) error {
	keys := map[string]any{}
	for n, d := range dns {
		keys[n] = d.Key()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.managed = map[string]any{"names": slices.Clone(names), "root": root, "dns": keys}
	return nil
}

func (p *parityCerts) Certificate(ctx context.Context, name string) ([]byte, bool) {
	crt, err := p.storage.Load(ctx, certmagic.StorageKeys.SiteCert(p.issuer, name))
	if err != nil {
		return nil, false
	}
	key, err := p.storage.Load(ctx, certmagic.StorageKeys.SitePrivateKey(p.issuer, name))
	if err != nil {
		return nil, false
	}
	out := append([]byte{}, crt...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(out, key...), true
}

func (p *parityCerts) HTTPHandler() http.Handler { return http.NotFoundHandler() }
func (p *parityCerts) SupportsWildcard() bool    { return p.wildcard }

func (p *parityCerts) last() map[string]any {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.managed
}

// goStorage is certmagic's storage of the run, as Go's server reads it.
func (sc *scenario) goStorage() *certs.EtcdStorage {
	sc.t.Helper()
	s, err := certs.NewEtcdStorage(storetest.Client(), sc.acmePrefix())
	if err != nil {
		sc.t.Fatal(err)
	}
	return s
}

// storeCert stores a certificate and its key for name as certmagic does,
// through Go's storage: the Rust server serves what Go's manager stored.
func (sc *scenario) storeCert(name string, crt, key []byte) {
	sc.t.Helper()
	s := sc.goStorage()
	issuer := (&certmagic.ACMEIssuer{CA: parityACMECA}).IssuerKey()
	if err := s.Store(sc.ctx, certmagic.StorageKeys.SiteCert(issuer, name), crt); err != nil {
		sc.t.Fatal(err)
	}
	if err := s.Store(sc.ctx, certmagic.StorageKeys.SitePrivateKey(issuer, name), key); err != nil {
		sc.t.Fatal(err)
	}
}

// storeBundle stores fixture bundle i for name.
func (sc *scenario) storeBundle(name string, i int) {
	sc.storeCert(name, sc.fx.bundles[i][0], sc.fx.bundles[i][1])
}

// setTXT publishes TXT records for both servers' resolvers.
func (sc *scenario) setTXT(name string, values ...string) {
	if sc.rec != nil {
		sc.rec.add(map[string]any{"op": "txt", "name": name, "values": sc.rec.input(values)})
	}
	sc.txt.set(name, values...)
	if r, ok := sc.sut.(*rustServer); ok {
		r.do(map[string]any{"op": "txt", "name": name, "values": values})
	}
}

// setRoot sets the root domain.
func (sc *scenario) setRoot(root string) {
	sc.t.Helper()
	cc, err := sc.admin.SetClusterConfig(sc.ctx, &armadav1.SetClusterConfigRequest{SetRootDomain: true, Config: &armadav1.ClusterConfig{RootDomain: root}})
	sc.answer("root domain "+root, cc, err)
}

// ingressAgent records a ready node and connects its agent; refs is
// Hello.certificate_refs.
func (sc *scenario) ingressAgent(id, ip string, refs bool) *parityAgent {
	sc.t.Helper()
	sc.node(id, ip, 8000, 16<<30, nil)
	a, err := sc.connectAgent(id, sc.nodeAgent(id), &armadav1.Hello{PrivateIp: ip, CpuMillis: 8000, MemoryBytes: 16 << 30, Containers: true, CertificateRefs: refs})
	if err != nil {
		sc.t.Fatal(err)
	}
	return a
}

// proxyNote records the proxy configuration and the TCP ports of each
// agent's latest assignment.
func (sc *scenario) proxyNote(label string, agents ...*parityAgent) {
	sc.t.Helper()
	for _, a := range agents {
		as := a.assignment()
		sc.note(label+" "+a.id+" proxy", as.GetProxy())
		sc.note(label+" "+a.id+" tcp ports", as.GetNetwork().GetTcpPorts())
	}
}

// domainToken names a domain's random token in the transcripts and
// returns it.
func (sc *scenario) domainToken(name string) string {
	sc.t.Helper()
	d, err := sc.st.GetDomain(sc.ctx, name)
	if err != nil {
		sc.t.Fatal(err)
	}
	sc.alias(d.Token, "<token of "+name+">")
	return d.Token
}

func (sc *scenario) domains(label string, c armadav1.AdminServiceClient, app string) {
	sc.t.Helper()
	resp, err := c.ListDomains(sc.ctx, &armadav1.ListDomainsRequest{App: app})
	sc.answer(label, resp, err)
}

func (sc *scenario) verify(label string, c armadav1.AdminServiceClient, name string) {
	sc.t.Helper()
	resp, err := c.VerifyDomain(sc.ctx, &armadav1.VerifyDomainRequest{Name: name})
	sc.answer(label, resp, err)
}

// proveDomain publishes a domain's token and verifies it.
func (sc *scenario) proveDomain(label, name string) {
	sc.t.Helper()
	sc.setTXT(TXTPrefix+name, sc.domainToken(name))
	sc.verify(label, sc.admin, name)
}

func (sc *scenario) setCluster(label string, req *armadav1.SetClusterConfigRequest) {
	sc.t.Helper()
	cc, err := sc.admin.SetClusterConfig(sc.ctx, req)
	sc.answer(label, cc, err)
}

const parityIngressWeb = `name: web
image: nginx:1
ingress:
  type: external
  port: 80
  domains: [example.org, www.example.org]
  routes:
    - path: /
    - path: /api
      stripPrefix: true
  timeout: 30s
  ipAllow: [192.0.2.0/24, {range: 198.51.100.7, name: office}]
  cors:
    allowOrigins: [https://a.test]
    allowCredentials: true
    maxAge: 1h
probes:
  readiness:
    path: /healthz
scale:
  min: 2
`

// External, internal, sticky, and scale-to-zero apps; custom domains and
// their TXT proof; a traffic split with a label; the trusted proxies and
// PROXY protocol sources; and an app's removal, through agents with and
// without certificate references.
func TestParityIngressRoutes(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		sc.setRoot("apps.test")
		n1 := sc.ingressAgent("n1", "10.0.0.11", false)
		n2 := sc.ingressAgent("n2", "10.0.0.12", true)
		sc.deploy("web", parityIngressWeb)
		sc.deploy("api", "name: api\nimage: api:1\ningress:\n  type: internal\n  port: 8080\n  allow: [web]\n")
		sc.deploy("sticky", "name: sticky\nimage: s:1\ningress:\n  type: external\n  port: 80\n  sticky: true\n  ipDeny: [203.0.113.0/24]\n")
		sc.deploy("lazy", "name: lazy\nimage: l:1\ningress:\n  type: external\n  port: 80\nscale:\n  min: 0\n  max: 3\n  rules:\n    - type: http\n      concurrent: 10\n")
		sc.deploy("worker", "name: worker\nimage: w:1\n")
		sc.domainToken("example.org")
		sc.domainToken("www.example.org")
		sc.pass("placed")
		sc.proxyNote("placed", n1)
		for _, app := range []string{"web", "api", "sticky", "lazy", "worker"} {
			sc.serve(app)
		}
		sc.pass("served")
		sc.proxyNote("served", n1, n2)

		sc.domains("domains", sc.admin, "")
		sc.domains("domains of web", sc.admin, "web")
		sc.verify("no record", sc.admin, "example.org")
		tok := sc.domainToken("example.org")
		sc.setTXT(TXTPrefix+"example.org", "wrong")
		sc.verify("wrong record", sc.admin, "example.org")
		sc.setTXT(TXTPrefix+"example.org", "other", " "+tok+" ")
		sc.verify("verified", sc.admin, "example.org")
		sc.verify("again", sc.admin, "example.org")
		sc.verify("unknown", sc.admin, "nope.example")
		sc.pass("after verify")
		sc.proxyNote("verified", n1)

		split := strings.Replace(parityIngressWeb, "scale:\n  min: 2\n", "scale:\n  min: 2\nrevisions:\n  mode: multiple\n  traffic:\n    - revision: latest\n      weight: 20\n      label: canary\n    - revision: web--r1\n      weight: 80\n", 1)
		split = strings.Replace(split, "image: nginx:1", "image: nginx:2", 1)
		sc.deploy("web split", split)
		sc.pass("split")
		sc.serve("web")
		sc.pass("split served")
		sc.proxyNote("split", n1, n2)

		sc.setCluster("trusted", &armadav1.SetClusterConfigRequest{SetTrustedProxies: true, Config: &armadav1.ClusterConfig{TrustedProxies: []string{"10.0.0.0/8", "192.0.2.9/24"}}})
		sc.setCluster("trusted containers only", &armadav1.SetClusterConfigRequest{SetTrustedProxies: true, Config: &armadav1.ClusterConfig{TrustedProxies: []string{"10.121.0.0/25"}}})
		sc.setCluster("trusted everything", &armadav1.SetClusterConfigRequest{SetTrustedProxies: true, Config: &armadav1.ClusterConfig{TrustedProxies: []string{"0.0.0.0/0"}}})
		sc.setCluster("trusted bad", &armadav1.SetClusterConfigRequest{SetTrustedProxies: true, Config: &armadav1.ClusterConfig{TrustedProxies: []string{"10.0.0.1/33"}}})
		sc.setCluster("proxy protocol", &armadav1.SetClusterConfigRequest{SetProxyProtocol: true, Config: &armadav1.ClusterConfig{ProxyProtocol: []string{"192.0.2.10/32", "10.121.0.0/16"}}})
		cc, err := sc.admin.GetClusterConfig(sc.ctx, &armadav1.GetClusterConfigRequest{})
		sc.answer("cluster config", cc, err)
		sc.pass("settings")
		sc.proxyNote("settings", n2)

		_, err = sc.admin.RemoveApp(sc.ctx, &armadav1.RemoveAppRequest{App: "sticky"})
		sc.note("remove sticky", err)
		sc.pass("removing")
		sc.later("removed", time.Minute)
		sc.proxyNote("removed", n1)
		sc.keyspace("keyspace")
	})
}

// Internal TCP apps on a cluster network (their ports in the network and
// routes per space), and the plain HTTP of a cluster without
// certificates.
func TestParityIngressTCP(t *testing.T) {
	runParity(t, parityConfig{plainHTTP: true}, func(sc *scenario) {
		sc.initNetwork(parityPlain)
		if _, err := sc.st.CreateSpace(sc.ctx, "team", "user:ryan", nil); err != nil {
			t.Fatal(err)
		}
		sc.setRoot("apps.test")
		n1 := sc.ingressAgent("n1", "10.0.0.11", true)
		sc.deploy("db", "name: db\nimage: pg:1\ningress:\n  type: internal\n  protocol: tcp\n  port: 5432\n  allow: [web]\n")
		_, err := sc.admin.Deploy(sc.ctx, &armadav1.DeployRequest{Space: "team", Spec: []byte("name: db\nimage: pg:1\ningress:\n  type: internal\n  protocol: tcp\n  port: 5432\n")})
		sc.note("db of team", err)
		_, err = sc.admin.Deploy(sc.ctx, &armadav1.DeployRequest{Space: "team", Spec: []byte("name: cache\nimage: redis:1\ningress:\n  type: internal\n  protocol: tcp\n  port: 6379\n")})
		sc.note("cache of team", err)
		_, err = sc.admin.Deploy(sc.ctx, &armadav1.DeployRequest{Space: "team", Spec: []byte("name: other\nimage: pg:1\ningress:\n  type: internal\n  protocol: tcp\n  port: 6379\n")})
		sc.note("second app on a port", err)
		sc.deploy("web", "name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n")
		sc.pass("placed")
		for i, app := range []string{"db", "db.team", "cache.team", "web"} {
			for j, r := range sc.replicasOf(app) {
				n, err := sc.st.GetNode(sc.ctx, r.NodeID)
				if err != nil {
					t.Fatal(err)
				}
				sc.setIP(r, fmt.Sprintf("%s.%d", strings.TrimSuffix(n.Subnet, ".0/24"), 10+i*10+j))
			}
		}
		sc.pass("served")
		sc.proxyNote("served", n1)
		st, err := sc.admin.Status(sc.ctx, &armadav1.StatusRequest{})
		sc.answer("status", st, err)
		sc.keyspace("keyspace")
	})
}

// Addresses two apps' replicas claim stay out of the proxy, and a custom
// domain naming another app's host under the root domain is left out with
// a RouteConflict; viewers of a space see its domains only.
func TestParityIngressConflicts(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		for _, bad := range []string{"-bad.id", "example..org", "example.org\n  bind :22", "*.example.org", "localhost"} {
			sc.setRoot(bad)
		}
		sc.setRoot("")
		sc.setRoot("apps.test")
		if _, err := sc.st.CreateSpace(sc.ctx, "team", "user:ryan", nil); err != nil {
			t.Fatal(err)
		}
		if _, err := sc.st.CreateUser(sc.ctx, store.Principal{Name: "vera", Since: sc.clock.now().Add(-time.Hour), Roles: []store.Grant{{Role: store.RoleViewer, Space: "team"}}}, "user:ryan"); err != nil {
			t.Fatal(err)
		}
		if _, err := sc.st.CreateUser(sc.ctx, store.Principal{Name: "dana", Since: sc.clock.now().Add(-time.Hour), Roles: []store.Grant{{Role: store.RoleDeployer, Space: "team"}}}, "user:ryan"); err != nil {
			t.Fatal(err)
		}
		vera := sc.adminClient(pki.Identity{Kind: pki.KindUser, Name: "vera"})
		dana := sc.adminClient(pki.Identity{Kind: pki.KindUser, Name: "dana"})
		n1 := sc.ingressAgent("n1", "10.0.0.11", false)
		sc.deploy("a", "name: a\nimage: a:1\ningress:\n  type: external\n  port: 80\n")
		sc.deploy("b", "name: b\nimage: b:1\ningress:\n  type: external\n  port: 80\n  domains: [a.apps.test, b.example.org]\n")
		_, err := sc.admin.Deploy(sc.ctx, &armadav1.DeployRequest{Space: "team", Spec: []byte("name: c\nimage: c:1\ningress:\n  type: external\n  port: 80\n  domains: [c.example.org]\n")})
		sc.note("c of team", err)
		_, err = sc.admin.Deploy(sc.ctx, &armadav1.DeployRequest{Space: "team", Spec: []byte("name: d\nimage: d:1\ningress:\n  type: external\n  port: 80\n  domains: [b.example.org]\n")})
		sc.note("domain of another space", err)
		_, err = sc.admin.Deploy(sc.ctx, &armadav1.DeployRequest{Spec: []byte("name: e\nimage: e:1\ningress:\n  type: external\n  port: 80\n  domains: [b.example.org]\n")})
		sc.note("domain and path of another app", err)
		_, err = sc.admin.Deploy(sc.ctx, &armadav1.DeployRequest{Spec: []byte("name: f\nimage: f:1\ningress:\n  type: external\n  port: 80\n  domains: [b.example.org]\n  routes:\n    - path: /f\n")})
		sc.note("another path of the domain", err)
		sc.domains("domains of nope", sc.admin, "nope")
		sc.pass("placed")
		for _, app := range []string{"a", "b", "c.team"} {
			sc.serve(app)
		}
		sc.proveDomain("verify a.apps.test", "a.apps.test")
		sc.proveDomain("verify b.example.org", "b.example.org")
		sc.domainToken("c.example.org")
		sc.pass("served")
		sc.proxyNote("served", n1)

		// a's replica and c's claim one address: both leave the proxy.
		ra, rc := sc.replicaOf("a-"), sc.replicaOf("c.team-")
		st := store.ReplicaStatus{ID: rc.ID, State: store.ReplicaRunning, Ready: true, ContainerID: "c-" + rc.ID, Address: ra.Address}
		if err := sc.st.UpdateReplicaStatus(sc.ctx, rc.NodeID, st); err != nil {
			t.Fatal(err)
		}
		sc.pass("clash")
		sc.proxyNote("clash", n1)
		sc.report(rc, store.ReplicaRunning, true, "")
		sc.pass("clash over")
		sc.proxyNote("clash over", n1)

		sc.domains("vera domains", vera, "")
		sc.domains("vera domains of a", vera, "a")
		sc.verify("vera verifies", vera, "c.example.org")
		sc.verify("dana verifies another space's", dana, "b.example.org")
		sc.setTXT(TXTPrefix+"c.example.org", sc.domainToken("c.example.org"))
		sc.verify("dana verifies", dana, "c.example.org")
		sc.pass("verified")
		sc.proxyNote("verified", n1)
		sc.keyspace("keyspace")
	})
}

// Certificates without wildcards: what the manager is asked to manage,
// certificates stored by Go's manager served by either server, in full
// or by reference, kept until obtained again, GetCertificates, domains'
// TLS readiness, and the last valid configuration kept while a stored
// bundle is broken.
func TestParityIngressCertificates(t *testing.T) {
	runParity(t, parityConfig{certs: true}, func(sc *scenario) {
		sc.setRoot("apps.test")
		n1 := sc.ingressAgent("n1", "10.0.0.11", false)
		n2 := sc.ingressAgent("n2", "10.0.0.12", true)
		sc.deploy("web", "name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n  domains: [example.org]\n")
		sc.deploy("api", "name: api\nimage: api:1\ningress:\n  type: internal\n  port: 80\n")
		sc.domainToken("example.org")
		sc.pass("placed")
		sc.serve("web")
		sc.serve("api")
		sc.pass("served")
		sc.note("managed", sc.sut.managed())
		sc.proxyNote("no certificates", n1, n2)

		sc.storeBundle("web.apps.test", 0)
		sc.pass("stored")
		sc.proxyNote("stored", n1, n2)
		agent := armadav1.NewAgentServiceClient(sc.dial(pki.Identity{Kind: pki.KindNode, Name: "n2"}))
		get := func(label string, names ...string) {
			resp, err := agent.GetCertificates(sc.ctx, &armadav1.GetCertificatesRequest{Names: names})
			sc.answer(label, resp, err)
		}
		get("get", "web.apps.test", "web.apps.test", "example.org", "api.apps.test")
		many := make([]string, 257)
		for i := range many {
			many[i] = fmt.Sprintf("h%d.apps.test", i)
		}
		get("get too many", many...)

		// Kept until obtained again.
		sc.storeBundle("web.apps.test", 1)
		sc.pass("renewed")
		sc.proxyNote("renewed, kept", n1)
		sc.sut.certEvent("web.apps.test", "")
		sc.sut.certEvent("example.org", "acme: rate limited")
		sc.pass("obtained")
		sc.proxyNote("obtained", n1, n2)
		get("get renewed", "web.apps.test")

		sc.domains("domains", sc.admin, "")
		sc.proveDomain("verify", "example.org")
		sc.pass("verified")
		sc.note("managed verified", sc.sut.managed())
		sc.storeBundle("example.org", 0)
		sc.domains("domains ready", sc.admin, "")

		// A broken bundle: the nodes keep the last valid configuration.
		sc.storeCert("example.org", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), []byte("not a key"))
		sc.sut.certEvent("example.org", "")
		sc.deploy("blog", "name: blog\nimage: b:1\ningress:\n  type: external\n  port: 80\n")
		sc.pass("broken")
		sc.serve("blog")
		sc.pass("broken served")
		sc.proxyNote("broken", n1, n2)
		sc.storeBundle("example.org", 1)
		sc.sut.certEvent("example.org", "")
		sc.pass("fixed")
		sc.proxyNote("fixed", n1, n2)
		get("get fixed", "example.org", "blog.apps.test")
		sc.keyspace("keyspace")
	})
}

// Wildcard certificates and apps' own DNS tokens (ADR 0047): hosts one
// label under the root domain share *.root, labels with it, and custom
// domains get their app's token, DNSTokenUnavailable while it is missing.
func TestParityIngressWildcard(t *testing.T) {
	runParity(t, parityConfig{certs: true, wildcard: true, masterKey: true}, func(sc *scenario) {
		sc.setRoot("apps.test")
		n1 := sc.ingressAgent("n1", "10.0.0.11", true)
		secret := func(app, key, v string) {
			_, err := sc.admin.SetSecret(sc.ctx, &armadav1.SetSecretRequest{App: app, Name: key, Value: []byte(v)})
			sc.note("secret "+app+" "+key, err)
		}
		secret("shop", "cf-token", "tok-shop-1\n")
		secret("shop", "other", "x")
		sc.deploy("shop", "name: shop\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n  domains: [shop.net, www.shop.net, sub.apps.test]\n  dns: {provider: cloudflare, tokenSecretRef: cf-token}\n")
		sc.deploy("blog", "name: blog\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n  domains: [blog.net]\nscale:\n  min: 1\nrevisions:\n  mode: multiple\n  traffic:\n    - revision: latest\n      weight: 100\n      label: beta\n")
		// mail's token cannot be read (its version is gone from the
		// store); its node has no agent, so no assignment needs it.
		sc.node("n2", "10.0.0.12", 8000, 16<<30, map[string]string{"role": "mail"})
		secret("mail", "cf-token", "tok-mail")
		sc.deploy("mail", "name: mail\nimage: m:1\ningress:\n  type: external\n  port: 80\n  domains: [mail.net]\n  dns: {provider: cloudflare, tokenSecretRef: cf-token}\nplacement:\n  require:\n    role: mail\n")
		sc.rec.skip("a secret deleted under the server")
		if _, err := storetest.Client().Delete(sc.ctx, sc.pfx+"secrets/mail/", clientv3.WithPrefix()); err != nil {
			t.Fatal(err)
		}
		sc.pass("placed")
		sc.serve("shop")
		sc.serve("blog")
		sc.serve("mail")
		for _, d := range []string{"shop.net", "www.shop.net", "sub.apps.test", "blog.net", "mail.net"} {
			sc.proveDomain("verify "+d, d)
		}
		sc.pass("verified")
		sc.note("managed", sc.sut.managed())
		sc.storeBundle("*.apps.test", 0)
		sc.storeBundle("shop.net", 1)
		sc.sut.certEvent("*.apps.test", "")
		sc.domains("domains", sc.admin, "")
		sc.pass("stored")
		sc.proxyNote("stored", n1)

		// The token's key goes, then a new one comes with a new revision.
		_, err := sc.admin.DeleteSecret(sc.ctx, &armadav1.DeleteSecretRequest{App: "shop", Name: "cf-token"})
		sc.note("delete token", err)
		secret("shop", "cf-token", "tok-shop-2")
		sc.deploy("shop again", "name: shop\nimage: nginx:1\nenv: [{name: V, value: \"2\"}]\ningress:\n  type: external\n  port: 80\n  domains: [shop.net, www.shop.net, sub.apps.test]\n  dns: {provider: cloudflare, tokenSecretRef: cf-token}\n")
		sc.pass("new token")
		sc.serve("shop")
		sc.later("rolled out", time.Minute)
		sc.later("old one gone", time.Minute)
		sc.note("managed new token", sc.sut.managed())
		sc.keyspace("keyspace")
	})
}

// certmagic's storage in etcd shared by both servers' managers: what one
// stores the other reads, and a lock one takes holds against the other.
// With the Rust server, its program stores and locks through armada-server's
// EtcdStorage while Go's storage reads and locks on the same prefix.
func TestParityCertificateStorage(t *testing.T) {
	runParity(t, parityConfig{certs: true}, func(sc *scenario) {
		r, rust := sc.sut.(*rustServer)
		gs := sc.goStorage()
		issuer := (&certmagic.ACMEIssuer{CA: parityACMECA}).IssuerKey()
		pc := &parityCerts{storage: gs, issuer: issuer}
		want := append(append([]byte{}, sc.fx.bundles[0][0]...), sc.fx.bundles[0][1]...)
		if rust {
			m := r.do(map[string]any{"op": "storeCert", "name": "*.apps.test", "cert": string(sc.fx.bundles[0][0]), "key": string(sc.fx.bundles[0][1])})
			if m["error"] != nil {
				t.Fatalf("storeCert: %v", m["error"])
			}
		} else {
			sc.storeBundle("*.apps.test", 0)
		}
		got, ok := pc.Certificate(sc.ctx, "*.apps.test")
		sc.note("go reads", ok && bytes.Equal(got, want))
		sc.storeBundle("example.org", 1)
		if rust {
			m := r.do(map[string]any{"op": "loadCert", "name": "example.org"})
			want1 := string(sc.fx.bundles[1][0]) + string(sc.fx.bundles[1][1])
			sc.note("rust reads", m["value"] == want1)
		} else {
			sc.note("rust reads", true)
		}
		keys, err := gs.List(sc.ctx, "certificates", true)
		sc.note("keys", keys)
		sc.note("list", err)

		// A lock Go holds keeps the other side waiting until it is released.
		lock := func(name string) <-chan error {
			done := make(chan error, 1)
			go func() {
				if rust {
					m := r.do(map[string]any{"op": "lock", "name": name})
					if m["error"] != nil {
						done <- fmt.Errorf("%v", m["error"])
						return
					}
					done <- nil
					return
				}
				other := sc.goStorage()
				done <- other.Lock(sc.ctx, name)
				t.Cleanup(func() { _ = other.Unlock(context.Background(), name); _ = other.Close() })
			}()
			return done
		}
		if err := gs.Lock(sc.ctx, "issue_cert_example.org"); err != nil {
			t.Fatal(err)
		}
		done := lock("issue_cert_example.org")
		select {
		case err := <-done:
			t.Fatalf("%s: took the lock Go holds (%v)", sc.sut.kind(), err)
		case <-time.After(500 * time.Millisecond):
			sc.note("waits for the lock", true)
		}
		if err := gs.Unlock(sc.ctx, "issue_cert_example.org"); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			sc.note("takes it once released", err)
		case <-time.After(10 * time.Second):
			t.Fatal("the lock was not taken")
		}
		ctx, cancel := context.WithTimeout(sc.ctx, 500*time.Millisecond)
		err = gs.Lock(ctx, "issue_cert_example.org")
		cancel()
		sc.note("go waits for the other's lock", err != nil)
		if rust {
			if m := r.do(map[string]any{"op": "unlock", "name": "issue_cert_example.org"}); m["error"] != nil {
				t.Fatalf("unlock: %v", m["error"])
			}
		}
		_ = gs.Close()
	})
}
