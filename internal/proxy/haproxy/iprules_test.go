package haproxy

import (
	"context"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/proxy"
)

// ipRulesConfig has an app open only to two ranges (scaled to zero, so its
// wake backend too), one closed to a range, a revision label of the first,
// and one with no rules, behind trusted proxies.
func ipRulesConfig() proxy.Config {
	srv := func(n, a string) []proxy.Server { return []proxy.Server{{Name: n, Address: a}} }
	return proxy.Config{
		TrustedProxies: []string{"173.245.48.0/20", "2400:cb00::/32"},
		Backends: []proxy.Backend{
			{Name: "admin", Wake: true, IPAllow: []string{"203.0.113.0/24", "2001:db8::/32"}, Servers: srv("admin-r1-a", "10.0.0.2:8080")},
			{Name: "canary--admin", IPAllow: []string{"203.0.113.0/24", "2001:db8::/32"}, Servers: srv("admin-r2-a", "10.0.0.3:8080")},
			{Name: "shop", IPDeny: []string{"198.51.100.7/32"}, Servers: srv("shop-r1-a", "10.0.0.2:8081")},
			{Name: "open", Servers: srv("open-r1-a", "10.0.0.2:8082")},
		},
		Rules: []proxy.Rule{
			{Host: "admin.example.org", PathPrefix: "/", Backend: "admin"},
			{Host: "canary--admin.example.org", PathPrefix: "/", Backend: "canary--admin"},
			{Host: "admin.internal", PathPrefix: "/", Backend: "admin", Internal: true},
			{Host: "shop.example.org", PathPrefix: "/", Backend: "shop"},
			{Host: "open.example.org", PathPrefix: "/", Backend: "open"},
		},
	}
}

// ipRendered renders cfg with an internal frontend.
func ipRendered(c proxy.Config) string {
	opts := renderOptions{PrivateIP: "10.0.0.2", InternalIP: "10.120.0.1"}
	return string(render(c, assignLayout(nil, c, opts.node()), opts))
}

// ipFrontends returns the public and internal frontends, without backends.
func ipFrontends(out string) (https, internal string) {
	if i := strings.Index(out, "\nbackend "); i >= 0 {
		out = out[:i]
	}
	https = out[strings.Index(out, "frontend https"):]
	if i := strings.Index(https, "frontend internal"); i >= 0 {
		https, internal = https[:i], https[i:]
	}
	return https, internal
}

func TestRenderIPRulesGolden(t *testing.T) {
	t.Parallel()
	cfg := ipRulesConfig()
	opts := renderOptions{PrivateIP: "10.0.0.2", InternalIP: "172.17.0.1"}
	golden(t, "iprules.cfg", render(cfg, assignLayout(nil, cfg, opts.node()), opts))
}

// The client address: the connection's, unless a trusted proxy connected,
// then the last X-Forwarded-For entry that is not a trusted proxy, and
// unknown (refused) otherwise. No other header is read.
func TestRenderClientAddress(t *testing.T) {
	t.Parallel()
	https, internal := ipFrontends(ipRendered(ipRulesConfig()))
	for _, want := range []string{
		"http-request set-var(txn.ext) bool(true)\n",
		"http-request set-var(txn.client) src\n",
		"http-request unset-var(txn.client) if trusted_proxy\n",
		"http-request set-var(txn.client) req.hdr_ip(X-Forwarded-For,-1) if trusted_proxy\n",
		"http-request set-var(txn.client) req.hdr_ip(X-Forwarded-For,-4) if trusted_proxy { var(txn.client) -m ip 173.245.48.0/20 2400:cb00::/32 }\n",
		"http-request unset-var(txn.client) if trusted_proxy { var(txn.client) -m ip 173.245.48.0/20 2400:cb00::/32 }\n",
	} {
		if !strings.Contains(https, want) {
			t.Errorf("public frontend lacks %q:\n%s", want, https)
		}
	}
	// The trusted proxies' headers are dropped for everyone else first.
	if strings.Index(https, "del-header X-Forwarded-For unless trusted_proxy") > strings.Index(https, "set-var(txn.client)") {
		t.Error("the client address is read before untrusted headers are removed")
	}
	for _, h := range []string{"Forwarded", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP"} {
		if strings.Contains(https, "hdr_ip("+h) || strings.Contains(https, "hdr("+h) {
			t.Errorf("the client address is read from %s", h)
		}
	}
	if strings.Contains(internal, "txn.ext") || strings.Contains(internal, "txn.client") {
		t.Errorf("the internal frontend marks requests as external:\n%s", internal)
	}

	// Without trusted proxies, only the connection counts.
	cfg := ipRulesConfig()
	cfg.TrustedProxies = nil
	https, _ = ipFrontends(ipRendered(cfg))
	if !strings.Contains(https, "set-var(txn.client) src\n") || strings.Contains(https, "X-Forwarded-For,") {
		t.Errorf("no trusted proxies, yet X-Forwarded-For is read:\n%s", https)
	}

	// Without any rule, nothing changes.
	cfg = ipRulesConfig()
	for i := range cfg.Backends {
		cfg.Backends[i].IPAllow, cfg.Backends[i].IPDeny = nil, nil
	}
	if out := ipRendered(cfg); strings.Contains(out, "txn.client") {
		t.Error("client address rules rendered with no app using them")
	}
}

func TestRenderIPRulesBackends(t *testing.T) {
	t.Parallel()
	out := ipRendered(ipRulesConfig())
	backend := func(name string) string {
		i := strings.Index(out, "backend "+name+"\n")
		if i < 0 {
			t.Fatalf("no backend %s", name)
		}
		rest := out[i:]
		if j := strings.Index(rest[1:], "\nbackend "); j >= 0 {
			rest = rest[:j+1]
		}
		return rest
	}
	allow := "http-request deny deny_status 403 if { var(txn.ext) -m bool } !{ var(txn.client) -m ip 203.0.113.0/24 2001:db8::/32 }\n"
	for _, b := range []string{"be_admin", wakeBackendName("admin"), "be_canary--admin"} {
		if !strings.Contains(backend(b), allow) {
			t.Errorf("%s lacks the allow rule:\n%s", b, backend(b))
		}
	}
	shop := backend("be_shop")
	for _, want := range []string{
		"http-request deny deny_status 403 if { var(txn.ext) -m bool } !{ var(txn.client) -m found }\n",
		"http-request deny deny_status 403 if { var(txn.ext) -m bool } { var(txn.client) -m ip 198.51.100.7/32 }\n",
	} {
		if !strings.Contains(shop, want) {
			t.Errorf("be_shop lacks %q:\n%s", want, shop)
		}
	}
	if strings.Contains(backend("be_open"), "deny") {
		t.Error("an app without rules refuses clients")
	}
	// The rule comes before anything else in the backend.
	if lines := strings.Split(backend("be_admin"), "\n"); !strings.HasPrefix(strings.TrimSpace(lines[1]), "http-request deny") {
		t.Errorf("the rule is not the backend's first:\n%s", backend("be_admin"))
	}
}

func TestValidateIPRules(t *testing.T) {
	t.Parallel()
	base := func(allow, deny []string) proxy.Config {
		return proxy.Config{Backends: []proxy.Backend{{Name: "web", IPAllow: allow, IPDeny: deny}}}
	}
	for name, cfg := range map[string]proxy.Config{
		"both":          base([]string{"203.0.113.0/24"}, []string{"198.51.100.0/24"}),
		"unmasked":      base([]string{"203.0.113.7/24"}, nil),
		"bare address":  base([]string{"203.0.113.7"}, nil),
		"everything":    base([]string{"0.0.0.0/0"}, nil),
		"directive":     base([]string{"203.0.113.0/24 }\n    server x 1.2.3.4:80"}, nil),
		"acl smuggling": base(nil, []string{"203.0.113.0/24 } || { always_true"}),
		"zone":          base([]string{"fe80::1%eth0/128"}, nil),
		"mapped":        base([]string{"::ffff:203.0.113.0/120"}, nil),
		"too many":      base(make([]string, 65), nil),
	} {
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := base([]string{"203.0.113.0/24", "2001:db8::/32", "203.0.113.7/32"}, nil).Validate(); err != nil {
		t.Errorf("valid rules refused: %v", err)
	}
}

// Changing who may reach an app reloads the proxy: the rules live in the
// configuration, and stale ones would keep applying.
func TestIPRulesChangeReloads(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, e, _, _ := newDriver(t)
	cfg := proxy.Config{Backends: []proxy.Backend{{Name: "web", Servers: []proxy.Server{{Name: "web-1", Address: "10.0.0.2:80"}}}}}
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	e.running = true
	for _, step := range []struct{ allow, deny []string }{
		{allow: []string{"203.0.113.0/24"}},
		{allow: []string{"203.0.113.0/24", "198.51.100.0/24"}},
		{deny: []string{"198.51.100.0/24"}},
		{},
	} {
		before := e.reloads
		cfg.Backends[0].IPAllow, cfg.Backends[0].IPDeny = step.allow, step.deny
		if err := d.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if e.reloads != before+1 {
			t.Errorf("%+v: reloads = %d, want 1", step, e.reloads-before)
		}
	}
}

// FuzzRenderIPRules renders client address rules and trusted proxies from
// arbitrary input: whatever Validate lets through renders as one rule per
// line, with balanced braces and no other directive.
func FuzzRenderIPRules(f *testing.F) {
	f.Add("203.0.113.0/24", "198.51.100.0/24", "173.245.48.0/20", true)
	f.Add("203.0.113.0/24 } || { always_true", "", "", true)
	f.Add("2001:db8::/32\n    bind :22", "", "2400:cb00::/32", false)
	f.Fuzz(func(t *testing.T, rule, rule2, trusted string, allow bool) {
		be := proxy.Backend{Name: "web", Wake: true, Servers: []proxy.Server{{Name: "r", Address: "10.0.0.2:80"}}}
		if allow {
			be.IPAllow = []string{rule, rule2}
		} else {
			be.IPDeny = []string{rule, rule2}
		}
		cfg := proxy.Config{Backends: []proxy.Backend{be}, Rules: []proxy.Rule{{Host: "web.example.org", PathPrefix: "/", Backend: "web"}}}
		if trusted != "" {
			cfg.TrustedProxies = []string{trusted}
		}
		if cfg.Validate() != nil {
			return
		}
		out := render(cfg, assignLayout(nil, cfg, renderOptions{}.node()), renderOptions{})
		if out == nil {
			t.Fatal("valid config refused")
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Count(line, "{") != strings.Count(line, "}") {
				t.Fatalf("unbalanced ACL braces in %q", line)
			}
			if strings.Contains(line, "deny_status") && !strings.HasPrefix(line, "    http-request deny deny_status 403 if { var(txn.ext) -m bool } ") {
				t.Fatalf("unexpected rule %q", line)
			}
		}
	})
}

// A node checks its own replicas every 2 seconds and other nodes' every 15,
// and real request failures make the checks fast for any of them.
func TestRenderHealthCheckIntervals(t *testing.T) {
	t.Parallel()
	cfg := proxy.Config{Backends: []proxy.Backend{{Name: "web", Servers: []proxy.Server{
		{Name: "web-local", Address: "10.0.0.2:8080"},
		{Name: "web-subnet", Address: "10.120.0.5:80"},
		{Name: "web-remote", Address: "10.0.0.3:8080"},
		{Name: "web-remote-subnet", Address: "10.120.1.5:80"},
	}}}}
	opts := renderOptions{PrivateIP: "10.0.0.2", Subnet: "10.120.0.0/24"}
	out := string(render(cfg, assignLayout(nil, cfg, opts.node()), opts))
	if !strings.Contains(out, "    default-server check inter 2s fastinter 1s fall 2 rise 2 observe layer4 error-limit 2 on-error fastinter\n") {
		t.Errorf("default checks:\n%s", out)
	}
	for addr, remote := range map[string]bool{"10.0.0.2:8080": false, "10.120.0.5:80": false, "10.0.0.3:8080": true, "10.120.1.5:80": true} {
		var line string
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, " "+addr) {
				line = l
			}
		}
		if strings.HasSuffix(line, " inter 15s") != remote {
			t.Errorf("%s (remote %v): %q", addr, remote, line)
		}
	}
	// Without the node's address, nothing is known to be remote.
	out = string(render(cfg, assignLayout(nil, cfg, renderOptions{}.node()), renderOptions{}))
	if strings.Contains(out, "inter 15s") {
		t.Error("servers checked slowly on a node that does not know its address")
	}
}
