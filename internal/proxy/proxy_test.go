package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

func testPEM(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})...)
}

func validConfig(t *testing.T) Config {
	return Config{
		ACMEAddress: "10.0.0.1:7480",
		Backends: []Backend{
			{Name: "web", HealthPath: "/healthz", Servers: []Server{{Name: "web-r1-a", Address: "10.0.0.2:32768"}}},
			{Name: "api", Servers: []Server{{Name: "api-r1-a", Address: "10.0.0.3:32769"}}},
		},
		Rules: []Rule{
			{Host: "example.org", PathPrefix: "/", Backend: "web"},
			{Host: "example.org", PathPrefix: "/api", StripPrefix: true, Backend: "api"},
			{Host: "api.internal", PathPrefix: "/", Backend: "api", Internal: true},
		},
		Certificates: []Certificate{{Name: "example.org", PEM: testPEM(t)}, {Name: "*.apps.example.org", PEM: testPEM(t)}},
	}
}

func TestValidateAccepts(t *testing.T) {
	t.Parallel()
	if err := validConfig(t).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Config{}).Validate(); err != nil {
		t.Errorf("empty config: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Config){
		"public acme address":          func(c *Config) { c.ACMEAddress = "8.8.8.8:80" },
		"bad acme address":             func(c *Config) { c.ACMEAddress = "nope" },
		"backend name injection":       func(c *Config) { c.Backends[0].Name = "web\n  bind :9999" },
		"backend name uppercase":       func(c *Config) { c.Backends[0].Name = "Web" },
		"duplicate backend":            func(c *Config) { c.Backends[1].Name = "web" },
		"health path injection":        func(c *Config) { c.Backends[0].HealthPath = "/h\nhttp-request deny" },
		"health path space":            func(c *Config) { c.Backends[0].HealthPath = "/h HTTP/1.1" },
		"server public address":        func(c *Config) { c.Backends[0].Servers[0].Address = "1.2.3.4:80" },
		"server address garbage":       func(c *Config) { c.Backends[0].Servers[0].Address = "10.0.0.2:80 backup" },
		"server port zero":             func(c *Config) { c.Backends[0].Servers[0].Address = "10.0.0.2:0" },
		"server duplicate name":        func(c *Config) { c.Backends[0].Servers = append(c.Backends[0].Servers, c.Backends[0].Servers[0]) },
		"rule host injection":          func(c *Config) { c.Rules[0].Host = "example.org }\n  use_backend x" },
		"server address with zone":     func(c *Config) { c.Backends[0].Servers[0].Address = "[fd00::1%x\n    global x]:80" },
		"server address non-canonical": func(c *Config) { c.Backends[0].Servers[0].Address = "[fd00:0::1]:80" },
		"rule host uppercase":          func(c *Config) { c.Rules[0].Host = "Example.org" },
		"public rule for .internal":    func(c *Config) { c.Rules[0].Host = "web.internal" },
		"internal rule, public host":   func(c *Config) { c.Rules[2].Host = "example.org" },
		"internal rule, nested host":   func(c *Config) { c.Rules[2].Host = "a.b.api.internal" },
		"internal rule, default host":  func(c *Config) { c.Rules[2].Host = "api.default.internal" },
		"backend in default project":   func(c *Config) { c.Backends[0].Name = "web.default" },
		"backend with two dots":        func(c *Config) { c.Backends[0].Name = "web.a.b" },
		"internal rule injection":      func(c *Config) { c.Rules[2].Host = "api }\n  use_backend x.internal" },
		"certificate for .internal":    func(c *Config) { c.Certificates[0].Name = "api.internal" },
		"rule path injection":          func(c *Config) { c.Rules[1].PathPrefix = "/api } || { always_true" },
		"rule path regex":              func(c *Config) { c.Rules[1].PathPrefix = "/a(b)" },
		"rule unknown backend":         func(c *Config) { c.Rules[0].Backend = "ghost" },
		"rule strip root":              func(c *Config) { c.Rules[0].StripPrefix = true },
		"callers on a public rule":     func(c *Config) { c.Rules[0].Allow = []string{"web"} },
		"caller of another project":    func(c *Config) { c.Rules[2].Allow = []string{"api", "web.staging"} },
		"caller injection":             func(c *Config) { c.Rules[2].Allow = []string{"web }\n  use_backend x"} },
		"caller with a space":          func(c *Config) { c.Rules[2].Allow = []string{"web api"} },
		"caller is a label host":       func(c *Config) { c.Rules[2].Allow = []string{"canary--web"} },
		"too many callers": func(c *Config) {
			for i := range 40 {
				c.Rules[2].Allow = append(c.Rules[2].Allow, fmt.Sprintf("app%d", i))
			}
		},
		"rule duplicate":      func(c *Config) { c.Rules[1].PathPrefix = "/" },
		"cert name traversal": func(c *Config) { c.Certificates[0].Name = "../../etc/passwd" },
		"cert name slash":     func(c *Config) { c.Certificates[0].Name = "a/b.com" },
		"cert duplicate":      func(c *Config) { c.Certificates[1].Name = c.Certificates[0].Name },
		"cert without key": func(c *Config) {
			c.Certificates[0].PEM = c.Certificates[0].PEM[:strings.Index(string(c.Certificates[0].PEM), "-----BEGIN PRIVATE")]
		},
		"cert with two keys": func(c *Config) {
			c.Certificates[0].PEM = append(c.Certificates[0].PEM, c.Certificates[0].PEM[strings.Index(string(c.Certificates[0].PEM), "-----BEGIN PRIVATE"):]...)
		},
		"cert trailing garbage": func(c *Config) { c.Certificates[0].PEM = append(c.Certificates[0].PEM, "\nglobal\n"...) },
		"cert unexpected block": func(c *Config) {
			c.Certificates[0].PEM = append(c.Certificates[0].PEM, pem.EncodeToMemory(&pem.Block{Type: "X", Bytes: []byte{1}})...)
		},
		"too many servers":        func(c *Config) { c.Backends[0].Servers = make([]Server, MaxServers+1) },
		"too many backends":       func(c *Config) { c.Backends = make([]Backend, MaxBackends+1) },
		"cert bundle too large":   func(c *Config) { c.Certificates[0].PEM = make([]byte, maxCertificatePEM+1) },
		"wildcard in rule host":   func(c *Config) { c.Rules[0].Host = "*.example.org" },
		"double wildcard on cert": func(c *Config) { c.Certificates[1].Name = "*.*.example.org" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := validConfig(t)
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Error("Validate() accepted invalid config")
			}
		})
	}
}

func TestProtoRoundTrip(t *testing.T) {
	t.Parallel()

	c := validConfig(t)
	p := c.ToProto()
	back := FromProto(p)
	if !proto.Equal(p, back.ToProto()) {
		t.Error("proto round trip changed config")
	}
	if got := FromProto(nil); len(got.Backends) != 0 {
		t.Error("FromProto(nil) not empty")
	}
}

func TestCertificateFileName(t *testing.T) {
	t.Parallel()

	if got := (Certificate{Name: "*.apps.example.org"}).FileName(); got != "_wildcard.apps.example.org.pem" {
		t.Errorf("FileName = %q", got)
	}
	if got := (Certificate{Name: "example.org"}).FileName(); got != "example.org.pem" {
		t.Errorf("FileName = %q", got)
	}
}

// Apps of other projects are named by their ID (ADR 0026).
func TestValidateProjectApps(t *testing.T) {
	c := validConfig(t)
	c.Backends[1].Name = "api.staging"
	c.Backends = append(c.Backends, Backend{Name: "canary--api.staging", Servers: []Server{{Name: "api-r2-a", Address: "10.0.0.4:32770"}}})
	c.Rules[1].Backend = "api.staging"
	c.Rules[2] = Rule{Host: "api.staging.internal", PathPrefix: "/", Backend: "api.staging", Internal: true}
	c.Rules = append(c.Rules, Rule{Host: "canary--api.staging.internal", PathPrefix: "/", Backend: "canary--api.staging", Internal: true})
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	// Callers of a project's internal rule, the label's too, are apps of
	// that project.
	c.Rules[2].Allow = []string{"api.staging", "web.staging"}
	c.Rules[len(c.Rules)-1].Allow = c.Rules[2].Allow
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Rules[2].Allow = []string{"api.staging", "web"}
	if err := c.Validate(); err == nil {
		t.Error("caller of the default project accepted for a staging app")
	}
	for backend, want := range map[string]string{"web": "default", "web.staging": "staging", "canary--web.staging": "staging", "canary--web": "default", "Web": "", "web.default": ""} {
		if got := BackendProject(backend); got != want {
			t.Errorf("BackendProject(%q) = %q, want %q", backend, got, want)
		}
	}
}

func TestParseTrustedProxies(t *testing.T) {
	t.Parallel()
	got, err := ParseTrustedProxies([]string{"198.51.100.7/24", "2001:db8::1/32", "192.0.2.1/32", "198.51.100.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1/32", "198.51.100.0/24", "2001:db8::/32"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "192.0.2.1", "example.org", "", "192.0.2.0/24 bind :22", "192.0.2.0/24\n    bind :22", "192.0.2.0/33"} {
		if _, err := ParseTrustedProxies([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ParseTrustedProxies(slices.Repeat([]string{"192.0.2.0/24"}, MaxTrustedProxies+1)); err == nil {
		t.Error("too many prefixes accepted")
	}
	if err := (Config{TrustedProxies: []string{"0.0.0.0/0"}}).Validate(); err == nil {
		t.Error("Validate accepted a prefix matching every address")
	}
}
