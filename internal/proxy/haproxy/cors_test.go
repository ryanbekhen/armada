package haproxy

import (
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/proxy"
)

func TestRenderCORS(t *testing.T) {
	t.Parallel()
	cfg := proxy.Config{Backends: []proxy.Backend{
		{Name: "api", Wake: true, CORS: &proxy.CORS{Origins: []string{"https://app.example.org", "http://localhost:3000"}, Methods: []string{"GET", "POST"},
			Headers: []string{"Content-Type", "Authorization"}, Expose: []string{"X-Request-Id"}, MaxAgeSeconds: 600, Credentials: true},
			Servers: []proxy.Server{{Name: "api-1", Address: "10.0.0.2:80"}}},
		{Name: "pub", CORS: &proxy.CORS{Origins: []string{"*"}, Methods: []string{"GET"}}, Servers: []proxy.Server{{Name: "pub-1", Address: "10.0.0.2:81"}}},
		{Name: "plain", Servers: []proxy.Server{{Name: "plain-1", Address: "10.0.0.2:82"}}},
	}}
	out := ipRendered(cfg)
	section := func(name string) string {
		s := out[strings.Index(out, "backend "+name+"\n"):]
		return s[:strings.Index(s, "\n\n")]
	}
	api := section("be_api")
	for _, want := range []string{
		"http-request set-var(txn.cors) req.hdr(Origin) if { req.hdr(Origin) -m str https://app.example.org http://localhost:3000 }\n",
		`http-request return status 204 hdr Access-Control-Allow-Origin %[var(txn.cors)] hdr Access-Control-Allow-Methods "GET, POST" hdr Access-Control-Allow-Headers "Content-Type, Authorization" hdr Access-Control-Max-Age 600 hdr Access-Control-Allow-Credentials true hdr Vary Origin if METH_OPTIONS { var(txn.cors) -m found } { req.hdr(Access-Control-Request-Method) -m found }` + "\n",
		"http-response set-header Access-Control-Allow-Origin %[var(txn.cors)] if { var(txn.cors) -m found }\n",
		"http-response set-header Access-Control-Allow-Credentials true if { var(txn.cors) -m found }\n",
		`http-response set-header Access-Control-Expose-Headers "X-Request-Id" if { var(txn.cors) -m found }` + "\n",
	} {
		if !strings.Contains(api, want) {
			t.Errorf("be_api lacks %q:\n%s", want, api)
		}
	}
	// A preflight never wakes an app scaled to zero.
	if !strings.Contains(section(wakeBackendName("api")), "http-request return status 204") {
		t.Error("the wake backend does not answer preflights")
	}
	pub := section("be_pub")
	if !strings.Contains(pub, "http-request set-var(txn.cors) str(*) if { req.hdr(Origin) -m found }") || strings.Contains(pub, "Credentials") {
		t.Errorf("open policy:\n%s", pub)
	}
	if strings.Contains(section("be_plain"), "cors") {
		t.Error("a backend without a policy has CORS rules")
	}
}

func TestValidateCORS(t *testing.T) {
	t.Parallel()
	ok := proxy.CORS{Origins: []string{"https://app.example.org"}, Methods: []string{"GET"}}
	for name, mutate := range map[string]func(c *proxy.CORS){
		"no origins":            func(c *proxy.CORS) { c.Origins = nil },
		"injected origin":       func(c *proxy.CORS) { c.Origins = []string{"https://a.example.org }\n    server x 1.2.3.4:80"} },
		"origin with path":      func(c *proxy.CORS) { c.Origins = []string{"https://a.example.org/x"} },
		"origin with space":     func(c *proxy.CORS) { c.Origins = []string{"https://a.example.org https://b.example.org"} },
		"star with credentials": func(c *proxy.CORS) { c.Origins, c.Credentials = []string{"*"}, true },
		"star with others":      func(c *proxy.CORS) { c.Origins = []string{"*", "https://a.example.org"} },
		"bad method":            func(c *proxy.CORS) { c.Methods = []string{"GET\" hdr X y"} },
		"no methods":            func(c *proxy.CORS) { c.Methods = nil },
		"quoted header":         func(c *proxy.CORS) { c.Headers = []string{"X-A\", \"X-B"} },
		"expose with space":     func(c *proxy.CORS) { c.Expose = []string{"X A"} },
		"max age out of range":  func(c *proxy.CORS) { c.MaxAgeSeconds = 86401 },
	} {
		c := ok
		mutate(&c)
		cfg := proxy.Config{Backends: []proxy.Backend{{Name: "web", CORS: &c}}}
		if cfg.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	cfg := proxy.Config{Backends: []proxy.Backend{{Name: "web", CORS: &ok}}}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid policy refused: %v", err)
	}
}
