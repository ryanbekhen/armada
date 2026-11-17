package haproxy

import (
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/proxy"
)

// plainConfig is ipRulesConfig without certificates, with a sticky app.
func plainConfig() proxy.Config {
	cfg := ipRulesConfig()
	cfg.PlainHTTP = true
	cfg.Backends[2].Sticky = true
	return cfg
}

func TestRenderPlainHTTPGolden(t *testing.T) {
	t.Parallel()
	cfg := plainConfig()
	opts := renderOptions{PrivateIP: "10.0.0.2", InternalIP: "172.17.0.1"}
	golden(t, "plain.cfg", render(cfg, assignLayout(nil, cfg, opts.node()), opts))
}

// frontendOf returns one frontend section of a rendered configuration.
func frontendOf(out, name string) string {
	i := strings.Index(out, "\nfrontend "+name+"\n")
	if i < 0 {
		return ""
	}
	sec := out[i+1:]
	if j := strings.Index(sec, "\n\n"); j >= 0 {
		sec = sec[:j]
	}
	return sec
}

// Without certificates port 80 routes like port 443, with the same client
// address handling, instead of redirecting; with them it only redirects.
func TestRenderPlainHTTP(t *testing.T) {
	t.Parallel()
	plain := ipRendered(plainConfig())
	http := frontendOf(plain, "http")
	https := frontendOf(plain, "https")
	if strings.Contains(http, "redirect") {
		t.Errorf("plain HTTP still redirects:\n%s", http)
	}
	for _, want := range []string{
		"http-request set-header X-Forwarded-Proto http",
		"acl trusted_proxy src 173.245.48.0/20 2400:cb00::/32",
		"http-request del-header X-Forwarded-For unless trusted_proxy",
		"http-request del-header X-Forwarded-Host",
		"http-request del-header X-Real-IP",
		"http-request set-header X-Real-IP %[var(txn.client)] if { var(txn.client) -m found }",
		"use_backend %[var(txn.route)] if { var(txn.route) -m beg be_ }",
		"default_backend be_armada_notfound",
	} {
		if !strings.Contains(http, want) {
			t.Errorf("frontend http lacks %q:\n%s", want, http)
		}
	}
	// Port 80 does what 443 does, apart from the scheme.
	body := func(sec string) string { return sec[strings.Index(sec, "\n    http-request"):] }
	if strings.ReplaceAll(body(http), "X-Forwarded-Proto http\n", "X-Forwarded-Proto https\n") != body(https) {
		t.Errorf("port 80 routes differently from 443:\n%s\n---\n%s", http, https)
	}
	// Internal routes stay off both public frontends.
	if strings.Contains(http, "admin.internal") {
		t.Error("an internal route reached port 80")
	}
	// The sticky cookie must come back over plain HTTP.
	if strings.Contains(plain, "httponly secure") || !strings.Contains(plain, "insert indirect nocache httponly attr") {
		t.Error("sticky cookie in plain mode keeps the secure attribute")
	}

	tlsCfg := plainConfig()
	tlsCfg.PlainHTTP = false
	tls := ipRendered(tlsCfg)
	if http := frontendOf(tls, "http"); !strings.Contains(http, "http-request redirect scheme https code 301") || strings.Contains(http, "use_backend") {
		t.Errorf("with certificates port 80 must only redirect:\n%s", http)
	}
	if !strings.Contains(tls, "httponly secure") {
		t.Error("sticky cookie lost the secure attribute with certificates")
	}

	// An ACME responder keeps its challenges on port 80 either way.
	acme := plainConfig()
	acme.ACMEAddress = "10.0.0.9:7480"
	if http := frontendOf(ipRendered(acme), "http"); !strings.Contains(http, "use_backend be_armada_acme if acme") || strings.Contains(http, "redirect") {
		t.Errorf("plain HTTP with ACME:\n%s", http)
	}
}

// Turning certificates off or on reloads the proxy.
func TestSignaturePlainHTTP(t *testing.T) {
	t.Parallel()
	cfg := plainConfig()
	opts := renderOptions{PrivateIP: "10.0.0.2"}
	layout := assignLayout(nil, cfg, opts.node())
	other := cfg
	other.PlainHTTP = false
	if signature(cfg, layout, opts) == signature(other, layout, opts) {
		t.Error("PlainHTTP is not in the signature")
	}
}
