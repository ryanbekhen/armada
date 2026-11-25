package agent

import (
	"crypto/sha256"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/proxy"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// pemRef names a certificate by reference, as the leader sends it.
func pemRef(name string, pem []byte) *armadav1.ProxyCertificate {
	sum := sha256.Sum256(pem)
	return &armadav1.ProxyCertificate{Name: name, Sha256: sum[:]}
}

// ingressConfig is a proxy configuration routing web, api.shop, and db.
func ingressConfig(certs ...*armadav1.ProxyCertificate) *armadav1.ProxyConfig {
	return &armadav1.ProxyConfig{
		Backends: []*armadav1.ProxyBackend{
			{Name: "web", Servers: []*armadav1.ProxyServer{{Name: "web-r1-a", Address: "10.0.0.2:31000"}}},
			{Name: "api.shop"}, {Name: "db"},
		},
		Rules: []*armadav1.ProxyRule{
			{Host: "web.example.org", PathPrefix: "/", Backend: "web"},
			{Host: "web.internal", PathPrefix: "/", Backend: "web", Internal: true},
			{Host: "api.shop.internal", PathPrefix: "/", Backend: "api.shop", Internal: true},
			{Host: "api.shop.internal", PathPrefix: "/v1", Backend: "api.shop", Internal: true},
		},
		TcpRoutes:    []*armadav1.ProxyTCPRoute{{Port: 5432, Backend: "db"}},
		Certificates: certs,
	}
}

// The proxy, network, resolver, certificate, and runtime move paths of
// the agent (ADR 0055, item 16b) on the parity harness, ported from this
// package's tests of applyProxy, the network pass, withCertificates,
// rotateNetworkKey, moveRuntime, and the usage loop's load and peers.
func TestAgentParityIngress(t *testing.T) {
	t.Parallel()
	pemA, pemB := []byte("pem a"), []byte("pem b")
	scenarios := []struct {
		name string
		opts func(*parityOpts)
		body func(p *parityRun)
	}{
		{"proxy and its names", func(o *parityOpts) { o.proxy, o.dns = true, "10.120.0.1" }, func(p *parityRun) {
			p.f.set(func(f *pfake) { f.in.certs["web.example.org"] = pemA })
			web := []*armadav1.ReplicaSpec{pr("web-r1-a", "nginx:1", 8080)}
			p.a.assign(&armadav1.Assignment{Replicas: web,
				Proxy: ingressConfig(pemRef("web.example.org", pemA), &armadav1.ProxyCertificate{Name: "inline", Pem: pemB})})
			p.reconcile("applied with its certificates, names resolved")
			p.reconcile("unchanged: only its health")
			p.f.set(func(f *pfake) { f.in.healthErr = "haproxy is not running" })
			p.reconcile("unhealthy: applied again from the cache")
			p.f.set(func(f *pfake) { f.in.healthErr, f.in.proxyErr = "", "haproxy -c failed" })
			p.a.assign(&armadav1.Assignment{Replicas: web, Proxy: ingressConfig()})
			p.reconcile("a failure is retried")
			p.f.set(func(f *pfake) { f.in.proxyErr = "" })
			p.reconcile("retried")
			p.a.assign(&armadav1.Assignment{Replicas: web})
			p.reconcile("an assignment without a proxy keeps the last")
			p.a.assign(&armadav1.Assignment{Replicas: web, Proxy: &armadav1.ProxyConfig{}})
			p.reconcile("no internal names")
		}},
		{"certificates by reference", func(o *parityOpts) { o.proxy = true }, func(p *parityRun) {
			p.f.set(func(f *pfake) { f.in.certs["a.example.org"], f.in.certs["b.example.org"] = pemA, pemB })
			assign := func(certs ...*armadav1.ProxyCertificate) {
				p.a.assign(&armadav1.Assignment{Replicas: []*armadav1.ReplicaSpec{}, Proxy: ingressConfig(certs...)})
			}
			assign(pemRef("a.example.org", pemA), pemRef("b.example.org", pemB))
			p.reconcile("both fetched")
			renewed := []byte("pem a2")
			p.f.set(func(f *pfake) { f.in.certs["a.example.org"] = renewed })
			assign(pemRef("a.example.org", renewed))
			p.reconcile("the renewed one fetched again, the other forgotten")
			assign(pemRef("a.example.org", []byte("what the assignment named")))
			p.reconcile("another digest: not applied")
			assign(pemRef("c.example.org", []byte("c")))
			p.reconcile("missing: not applied")
			p.f.set(func(f *pfake) { f.in.certErr = "rpc error: code = Unavailable desc = no leader" })
			assign(pemRef("b.example.org", pemB))
			p.reconcile("the control plane fails: not applied")
		}},
		{"proxy before strays", func(o *parityOpts) { o.proxy = true }, func(p *parityRun) {
			s := pr("web-r1-a", "nginx:1", 0)
			p.f.add(adopted(s, "a1", parityT0.Add(-time.Minute)))
			p.f.add(adopted(pr("gone-r1-a", "nginx:1", 0), "gone", parityT0.Add(-time.Minute)))
			p.a.assign(&armadav1.Assignment{Replicas: []*armadav1.ReplicaSpec{s}, Proxy: &armadav1.ProxyConfig{PlainHttp: true}})
			p.reconcile("the proxy applied while the stray still ran")
		}},
		{"network with unpublished replicas", func(o *parityOpts) {
			o.proxy, o.network, o.unpublished, o.bridge, o.dns = true, true, true, "10.120.0.", "10.120.0.1"
		}, func(p *parityRun) {
			web := noProbe(pr("web-r1-a", "nginx:1", 8080))
			api := noProbe(pr("api.shop-r1-a", "api:1", 9000))
			api.App = "api.shop"
			p.reconcile("no assignment: no network")
			p.a.assign(&armadav1.Assignment{Replicas: []*armadav1.ReplicaSpec{web, api},
				Network: &armadav1.NetworkConfig{Mode: "plain", ClusterCidr: "10.120.0.0/16"}, Proxy: &armadav1.ProxyConfig{}})
			p.until("ready", func(r *armadav1.ReplicaReport) bool {
				return report(r, web.Id).GetReady() && report(r, api.Id).GetReady()
			})
			p.f.set(func(f *pfake) { f.in.netErr, f.in.clientsErr = "add route: file exists", "set map failed" })
			p.reconcile("a failure, logged once")
			p.reconcile("the same failure")
			p.f.setState("armada-api.shop-r1-a-1", runtime.StateExited, 1)
			p.f.set(func(f *pfake) { f.in.netErr, f.in.clientsErr = "", "" })
			p.reconcile("applied again, the exited container left out")
			p.a.assign(&armadav1.Assignment{Replicas: []*armadav1.ReplicaSpec{web}})
			p.reconcile("an assignment without a network keeps the last")
		}},
		{"network with published replicas", func(o *parityOpts) { o.network = true }, func(p *parityRun) {
			p.a.assign(&armadav1.Assignment{Replicas: []*armadav1.ReplicaSpec{pr("web-r1-a", "nginx:1", 8080)},
				Network: &armadav1.NetworkConfig{Mode: "wireguard"}})
			p.reconcile("no containers given")
		}},
		{"network key rotation", func(o *parityOpts) { o.network, o.networkKey = true, "key-0" }, func(p *parityRun) {
			hello := func(name string) {
				h := p.a.hello()
				h.Version = "VERSION"
				p.note("hello "+name, compact(h))
			}
			hello("first")
			p.other("rotated", func(a agentUnderTest) { a.rotate() })
			hello("with the new key")
			p.f.set(func(f *pfake) { f.in.keyErr = "write network.key: read-only file system" })
			p.other("rotation fails", func(a agentUnderTest) { a.rotate() })
			hello("the key kept")
		}},
		{"runtime move", func(o *parityOpts) { o.move = true }, func(p *parityRun) {
			p.f.set(func(f *pfake) { f.agentStatus = runtime.AgentStatus{Agent: runtime.AgentContainerd} })
			p.other("before an assignment", func(a agentUnderTest) { a.move("supervisor") })
			p.sample("why it did not move")
			var many []*armadav1.ReplicaSpec
			for i := range 7 {
				many = append(many, pr("web-r1-"+string(rune('a'+i)), "nginx:1", 0))
			}
			plan := &armadav1.RuntimeMovePlan{State: "queued", Reason: "waiting for its turn"}
			p.a.assign(&armadav1.Assignment{Replicas: many, RuntimeMove: plan})
			p.reconcile("started, the plan handed over")
			p.a.assign(&armadav1.Assignment{Replicas: many, RuntimeMove: plan})
			p.other("the same plan is not handed again", func(agentUnderTest) {})
			p.other("replicas assigned", func(a agentUnderTest) { a.move("supervisor") })
			p.sample("why it did not move")
			job := pr("j-j1-a", "busybox", 0)
			job.Job = &armadav1.JobAttempt{Done: true}
			p.a.assign(&armadav1.Assignment{Replicas: []*armadav1.ReplicaSpec{job}, RuntimeMove: &armadav1.RuntimeMovePlan{State: "moving"}})
			p.reconcile("drained")
			p.f.set(func(f *pfake) { f.in.moveErr = "systemctl restart: exit status 1" })
			p.other("the move fails", func(a agentUnderTest) { a.move("supervisor") })
			p.sample("why it did not move")
			p.f.set(func(f *pfake) { f.in.moveErr = "" })
			p.other("moved", func(a agentUnderTest) { a.move("supervisor") })
			p.sample("no error left")
			p.other("once moved, asked again", func(a agentUnderTest) { a.move("supervisor") })
			p.a.assign(&armadav1.Assignment{Replicas: []*armadav1.ReplicaSpec{job}})
			p.other("no plan", func(agentUnderTest) {})
		}},
		{"usage with load and peers", func(o *parityOpts) { o.proxy, o.network = true, true }, func(p *parityRun) {
			p.f.set(func(f *pfake) {
				f.in.load["web-r1-a"] = proxy.ServerLoad{InFlight: 2, Total: 10}
				f.in.load["web-r1-b"] = proxy.ServerLoad{Total: 4}
				f.in.peers, f.in.userspace = []string{"n2", "n3"}, true
			})
			p.sample("first: totals only")
			p.f.set(func(f *pfake) {
				f.in.load["web-r1-a"] = proxy.ServerLoad{Total: 12}
				f.in.load["web-r1-b"] = proxy.ServerLoad{Total: 1}
				f.in.load["web-r1-c"] = proxy.ServerLoad{InFlight: 1}
				f.in.switching = &armadav1.NetworkSwitchStatus{To: "wireguard", Step: "prepare", Ready: true}
				f.in.peers = nil
			})
			p.sample("requests since, a counter that went back, a switch")
			p.f.set(func(f *pfake) { f.in.loadErr = "show stat: connection refused" })
			p.sample("unreadable load")
		}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			opts := defaultOpts()
			opts.stats = false
			if sc.opts != nil {
				sc.opts(&opts)
			}
			runAgentParity(t, opts, sc.body)
		})
	}
}
