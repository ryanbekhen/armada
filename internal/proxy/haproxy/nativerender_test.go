package haproxy

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ryanbekhen/armada/internal/proxy"
)

// randomConfig builds a configuration that passes Validate with the
// renderer's features mixed at random.
func randomConfig(r *rand.Rand) proxy.Config {
	pick := func(n int) bool { return r.IntN(n) == 0 }
	spaces := []string{"", ".shop", ".staging"}
	var cfg proxy.Config
	if pick(2) {
		cfg.ACMEAddress = "10.0.0.1:7480"
	}
	cfg.PlainHTTP = pick(4)
	if pick(3) {
		cfg.TrustedProxies = []string{"173.245.48.0/20", "2400:cb00::/32"}[:1+r.IntN(2)]
	}
	if pick(4) {
		cfg.ProxyProtocol = []string{"10.0.9.0/24"}
	}
	nb := r.IntN(8)
	tcpUsed := map[string]bool{} // space/port
	for i := range nb {
		name := fmt.Sprintf("app%d%s", i, spaces[r.IntN(len(spaces))])
		be := proxy.Backend{Name: name, LocalFirst: pick(2), Sticky: pick(5)}
		for j := range r.IntN(5) {
			addr := []string{"10.0.0.2", "10.0.0.3", "10.120.0.7", "10.120.1.4"}[r.IntN(4)]
			s := proxy.Server{Name: fmt.Sprintf("%s-r1-%c", name, 'a'+j), Address: fmt.Sprintf("%s:%d", addr, 30000+r.IntN(1000))}
			if pick(4) {
				s.Weight = 1 + r.IntN(256)
			}
			be.Servers = append(be.Servers, s)
		}
		isTCP := pick(5)
		if isTCP {
			port := []int{5432, 6379, 9000}[r.IntN(3)]
			key := proxy.BackendSpace(name) + "/" + fmt.Sprint(port)
			if !tcpUsed[key] {
				tcpUsed[key] = true
				route := proxy.TCPRoute{Port: port, Backend: name}
				if pick(2) {
					route.Allow = []string{name}
				}
				cfg.TCP = append(cfg.TCP, route)
				be.Sticky = false
				cfg.Backends = append(cfg.Backends, be)
				continue
			}
		}
		if pick(3) {
			be.HealthPath = "/healthz"
		}
		if pick(4) {
			be.TimeoutSeconds = 1 + r.IntN(600)
		}
		external := pick(2)
		if external {
			switch r.IntN(4) {
			case 0:
				be.IPAllow = []string{"192.0.2.0/24", "2001:db8::/32"}
			case 1:
				be.IPDeny = []string{"198.51.100.7/32"}
			}
			if pick(3) {
				be.CORS = &proxy.CORS{Origins: []string{"https://a.example.com"}, Methods: []string{"GET", "POST"}}
				if pick(2) {
					be.CORS = &proxy.CORS{Origins: []string{"*"}, Methods: []string{"GET"}, Headers: []string{"X-Token"}, Expose: []string{"X-Id"}, MaxAgeSeconds: 600}
				} else if pick(2) {
					be.CORS.Credentials = true
				}
			}
			if pick(4) && len(be.Servers) == 0 {
				be.Wake = true
			}
			host := fmt.Sprintf("h%d.example.org", i)
			cfg.Rules = append(cfg.Rules, proxy.Rule{Host: host, PathPrefix: "/", Backend: name})
			if pick(2) {
				cfg.Rules = append(cfg.Rules, proxy.Rule{Host: "example.org", PathPrefix: fmt.Sprintf("/p%d", i), StripPrefix: pick(2), Backend: name})
			}
			if pick(3) {
				cfg.Certificates = append(cfg.Certificates, proxy.Certificate{Name: host})
			}
		}
		if !external || pick(2) {
			rule := proxy.Rule{Host: name + ".internal", PathPrefix: "/", Backend: name, Internal: true}
			if pick(3) {
				rule.Allow = []string{name}
			}
			cfg.Rules = append(cfg.Rules, rule)
			if pick(3) {
				cfg.Rules = append(cfg.Rules, proxy.Rule{Host: name + ".internal", PathPrefix: "/v1", StripPrefix: true, Backend: name, Internal: true})
			}
		}
		cfg.Backends = append(cfg.Backends, be)
	}
	return cfg
}

// nodeOptions are the kinds of node a configuration renders for.
var nodeOptions = []renderOptions{
	{},
	{PrivateIP: "10.0.0.2"},
	{PrivateIP: "10.0.0.2", InternalIP: "172.17.0.1"},
	{PrivateIP: "10.0.0.2", InternalIP: "10.120.0.1", Subnet: "10.120.0.0/24"},
	{PrivateIP: "10.0.0.2", InternalIP: "10.120.0.1", Subnet: "10.120.0.0/24", BusyTCP: []int{6379}},
}

func sameRendered(t *testing.T, what string, got, want rendered) {
	t.Helper()
	if !bytes.Equal(got.config, want.config) {
		t.Fatalf("%s: haproxy.cfg differs:\n armada-node:\n%s\n Go:\n%s", what, got.config, want.config)
	}
	if want.config == nil {
		return
	}
	if !slices.Equal(slices.Sorted(maps.Keys(got.routes)), slices.Sorted(maps.Keys(want.routes))) {
		t.Fatalf("%s: route maps %v, Go %v", what, slices.Sorted(maps.Keys(got.routes)), slices.Sorted(maps.Keys(want.routes)))
	}
	for name, b := range want.routes {
		if !bytes.Equal(got.routes[name], b) {
			t.Fatalf("%s: %s differs:\n%s\n Go:\n%s", what, name, got.routes[name], b)
		}
	}
	if !bytes.Equal(got.local, want.local) {
		t.Fatalf("%s: local.map differs:\n%s\n Go:\n%s", what, got.local, want.local)
	}
}

// armada-node proxy render (node/src/proxy) must write what the Go renderer
// writes. CI sets ARMADA_NODE_BIN (make node).
func TestArmadaNodeRenderMatchesGo(t *testing.T) {
	bin := os.Getenv("ARMADA_NODE_BIN")
	rec := newRenderRecorder()
	if bin == "" && rec == nil {
		t.Skip("ARMADA_NODE_BIN is not set (make node)")
	}
	ctx := context.Background()
	check := func(what string, cfg proxy.Config, opts renderOptions) {
		t.Helper()
		layout := assignLayout(nil, cfg, opts.node())
		if rec != nil {
			rec.add(t, what, cfg, layout, opts, renderGo(cfg, layout, opts))
			return
		}
		got, err := renderNative(ctx, bin, cfg, layout, opts)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		sameRendered(t, what, got, renderGo(cfg, layout, opts))
	}
	named := map[string]proxy.Config{
		"sample": sampleConfig(t), "callers": callersConfig(t), "plain": plainConfig(),
		"ip rules": ipRulesConfig(), "proxy protocol": proxyProtocolConfig(), "tcp": tcpConfig(), "empty": {},
	}
	for name, cfg := range named {
		for i, opts := range nodeOptions {
			check(fmt.Sprintf("%s, node %d", name, i), cfg, opts)
		}
	}
	// A value that is not one token: neither renders.
	bad := sampleConfig(t)
	bad.Rules[0].Host = "example.org\n    server evil 1.2.3.4:80"
	check("unsafe", bad, nodeOptions[1])

	r := rand.New(rand.NewPCG(1, 2))
	valid := 0
	for i := range 400 {
		cfg := randomConfig(r)
		if err := cfg.Validate(); err != nil {
			continue
		}
		valid++
		check(fmt.Sprintf("random %d", i), cfg, nodeOptions[i%len(nodeOptions)])
	}
	rec.write(t)
	t.Logf("%d random configurations compared", valid)
	if valid < 200 {
		t.Fatalf("only %d of 400 random configurations were valid", valid)
	}
}

// A runtime pack whose armada-node fails leaves the rendering to Go.
func TestRenderFallsBack(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "armada-node")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'armada-node: unknown command' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg, opts := sampleConfig(t), nodeOptions[2]
	layout := assignLayout(nil, cfg, opts.node())
	got, err := renderWith(context.Background(), bin, cfg, layout, opts)
	if err == nil {
		t.Fatal("no error from a failing armada-node")
	}
	sameRendered(t, "fallback", got, renderGo(cfg, layout, opts))
}
