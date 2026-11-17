package haproxy

import (
	"context"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/proxy"
)

// proxyProtocolConfig is plainConfig with load balancers that send the
// PROXY protocol.
func proxyProtocolConfig() proxy.Config {
	cfg := plainConfig()
	cfg.ProxyProtocol = []string{"10.0.0.0/24", "2001:db8::/64"}
	return cfg
}

// Load balancers that send the PROXY protocol: both public frontends read
// the header from them first, before TLS and before any rule that looks at
// the client's address; nothing else reads it.
func TestRenderProxyProtocol(t *testing.T) {
	t.Parallel()
	const line = "    tcp-request connection expect-proxy layer4 if { src 10.0.0.0/24 2001:db8::/64 }"
	for _, plain := range []bool{false, true} {
		cfg := proxyProtocolConfig()
		cfg.PlainHTTP = plain
		out := ipRendered(cfg)
		for _, name := range []string{"http", "https"} {
			fe := frontendOf(out, name)
			lines := strings.Split(fe, "\n")
			if len(lines) < 3 || lines[2] != line {
				t.Errorf("plain=%v: frontend %s does not read the header right after bind:\n%s", plain, name, fe)
			}
		}
		if n := strings.Count(out, "expect-proxy"); n != 2 {
			t.Errorf("plain=%v: expect-proxy %d times, want 2 (public frontends only)", plain, n)
		}
	}
	if out := ipRendered(ipRulesConfig()); strings.Contains(out, "expect-proxy") {
		t.Error("expect-proxy without PROXY protocol sources")
	}
	// A value that is not a plain token never reaches the file.
	bad := ipRulesConfig()
	bad.ProxyProtocol = []string{"10.0.0.0/8 } || { always_true"}
	if safeConfig(bad, renderOptions{}) {
		t.Error("safeConfig accepted HAProxy syntax in a PROXY protocol source")
	}
}

func TestProxyProtocolChangeReloads(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, e, _, _ := newDriver(t)
	cfg := proxy.Config{Backends: []proxy.Backend{{Name: "web", Servers: []proxy.Server{{Name: "web-1", Address: "10.0.0.2:80"}}}}}
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	e.running = true
	for _, sources := range [][]string{{"10.0.0.0/24"}, {"10.0.0.0/24", "10.0.1.0/24"}, nil} {
		before := e.reloads
		cfg.ProxyProtocol = sources
		if err := d.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if e.reloads != before+1 {
			t.Errorf("%v: reloads = %d, want 1", sources, e.reloads-before)
		}
	}
}
