// Package proxy defines the ingress configuration pushed to every node and
// the Driver interface implemented by proxy backends (HAProxy in v0.1, Nginx
// planned for v0.2).
package proxy

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/spec"
)

// Driver applies ingress configuration to the local proxy.
type Driver interface {
	// Apply makes the proxy serve cfg. On failure the previous configuration
	// stays active.
	Apply(ctx context.Context, cfg Config) error
	// Health reports whether the proxy is running and responsive.
	Health(ctx context.Context) error
}

// LoadReader is implemented by drivers that can count the requests in
// progress per server, which the autoscaler uses (ADR 0022).
type LoadReader interface {
	// Load returns the requests in progress (being served or queued) per
	// server name, for every server the proxy routes to.
	Load(ctx context.Context) (map[string]int64, error)
}

// Config is the complete ingress configuration for a node.
type Config struct {
	Backends     []Backend
	Rules        []Rule
	Certificates []Certificate
	// ACMEAddress is the control plane's HTTP-01 responder (private ip:port).
	ACMEAddress string
}

// Backend is one app's set of replicas.
type Backend struct {
	Name       string
	Servers    []Server
	HealthPath string
}

// Server is one replica.
type Server struct {
	Name    string
	Address string
}

// Rule routes requests for Host whose path is PathPrefix or starts with
// PathPrefix + "/" to Backend. Internal rules serve <app>.internal on the
// internal frontend only; the others serve the public frontends only.
type Rule struct {
	Host        string
	PathPrefix  string
	StripPrefix bool
	Backend     string
	Internal    bool
}

// Certificate is a PEM bundle (chain + key) for Name, which may be a
// wildcard ("*.apps.example.com").
type Certificate struct {
	Name string
	PEM  []byte
}

// FileName returns a filesystem-safe name for the certificate.
func (c Certificate) FileName() string {
	return strings.Replace(c.Name, "*", "_wildcard", 1) + ".pem"
}

// FromProto converts the wire format.
func FromProto(p *armadav1.ProxyConfig) Config {
	var c Config
	if p == nil {
		return c
	}
	c.ACMEAddress = p.GetAcmeChallengeAddress()
	for _, b := range p.GetBackends() {
		be := Backend{Name: b.GetName(), HealthPath: b.GetHealthPath()}
		for _, s := range b.GetServers() {
			be.Servers = append(be.Servers, Server{Name: s.GetName(), Address: s.GetAddress()})
		}
		c.Backends = append(c.Backends, be)
	}
	for _, r := range p.GetRules() {
		c.Rules = append(c.Rules, Rule{Host: r.GetHost(), PathPrefix: r.GetPathPrefix(), StripPrefix: r.GetStripPrefix(), Backend: r.GetBackend(), Internal: r.GetInternal()})
	}
	for _, crt := range p.GetCertificates() {
		c.Certificates = append(c.Certificates, Certificate{Name: crt.GetName(), PEM: crt.GetPem()})
	}
	return c
}

// ToProto converts to the wire format.
func (c Config) ToProto() *armadav1.ProxyConfig {
	p := &armadav1.ProxyConfig{AcmeChallengeAddress: c.ACMEAddress}
	for _, b := range c.Backends {
		pb := &armadav1.ProxyBackend{Name: b.Name, HealthPath: b.HealthPath}
		for _, s := range b.Servers {
			pb.Servers = append(pb.Servers, &armadav1.ProxyServer{Name: s.Name, Address: s.Address})
		}
		p.Backends = append(p.Backends, pb)
	}
	for _, r := range c.Rules {
		p.Rules = append(p.Rules, &armadav1.ProxyRule{Host: r.Host, PathPrefix: r.PathPrefix, StripPrefix: r.StripPrefix, Backend: r.Backend, Internal: r.Internal})
	}
	for _, crt := range c.Certificates {
		p.Certificates = append(p.Certificates, &armadav1.ProxyCertificate{Name: crt.Name, Pem: crt.PEM})
	}
	return p
}

// Limits on what a single configuration may contain.
const (
	MaxBackends       = 1000
	MaxServers        = 100
	MaxRules          = 5000
	MaxCertificates   = 2000
	maxCertificatePEM = 64 << 10
)

// Validate re-checks every field that reaches generated proxy configuration.
// The server validates specs too; this is defense in depth against a bug or a
// compromised control plane injecting configuration directives.
func (c Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.ACMEAddress != "" {
		ap, err := netip.ParseAddrPort(c.ACMEAddress)
		if err != nil || !netutil.IsPrivate(ap.Addr()) {
			add("acme address %q must be a private ip:port", c.ACMEAddress)
		}
	}
	if len(c.Backends) > MaxBackends || len(c.Rules) > MaxRules || len(c.Certificates) > MaxCertificates {
		add("configuration exceeds size limits")
		return errors.Join(errs...)
	}

	backends := map[string]bool{}
	for _, b := range c.Backends {
		if err := spec.ValidateName(b.Name); err != nil {
			add("backend %q: invalid name", b.Name)
			continue
		}
		if backends[b.Name] {
			add("duplicate backend %q", b.Name)
		}
		backends[b.Name] = true
		if b.HealthPath != "" {
			if err := spec.ValidateProbePath(b.HealthPath); err != nil {
				add("backend %s: health path: %v", b.Name, err)
			}
		}
		if len(b.Servers) > MaxServers {
			add("backend %s: too many servers", b.Name)
		}
		seen := map[string]bool{}
		for _, s := range b.Servers {
			ap, err := netip.ParseAddrPort(s.Address)
			// The canonical-form check rejects anything the parser tolerates
			// but HAProxy would read differently (zones, stray bytes).
			if err != nil || !netutil.IsPrivate(ap.Addr()) || ap.Port() == 0 || ap.String() != s.Address {
				add("backend %s: server address %q must be a private ip:port", b.Name, s.Address)
			}
			if s.Name == "" || seen[s.Name] {
				add("backend %s: missing or duplicate server name", b.Name)
			}
			seen[s.Name] = true
		}
	}

	routes := map[string]bool{}
	for _, r := range c.Rules {
		if r.Internal {
			// Only <app>.internal, never a public name on the internal side.
			name, ok := strings.CutSuffix(r.Host, spec.InternalSuffix)
			if !ok || spec.ValidateName(name) != nil {
				add("internal rule host %q must be <app>%s", r.Host, spec.InternalSuffix)
			}
		} else if err := spec.ValidateDomain(r.Host); err != nil {
			add("rule host %q: %v", r.Host, err)
		}
		if err := spec.ValidateRoutePath(r.PathPrefix); err != nil {
			add("rule path %q: %v", r.PathPrefix, err)
		}
		if r.PathPrefix == "/" && r.StripPrefix {
			add("rule %s/: cannot strip the root path", r.Host)
		}
		if !backends[r.Backend] {
			add("rule %s%s: unknown backend %q", r.Host, r.PathPrefix, r.Backend)
		}
		key := r.Host + r.PathPrefix
		if routes[key] {
			add("duplicate rule for %s", key)
		}
		routes[key] = true
	}

	certs := map[string]bool{}
	for _, crt := range c.Certificates {
		if err := spec.ValidateDomain(strings.TrimPrefix(crt.Name, "*.")); err != nil {
			add("certificate %q: invalid name", crt.Name)
		}
		if certs[crt.Name] {
			add("duplicate certificate %q", crt.Name)
		}
		certs[crt.Name] = true
		if err := checkPEM(crt.PEM); err != nil {
			add("certificate %s: %v", crt.Name, err)
		}
	}
	return errors.Join(errs...)
}

// checkPEM requires at least one certificate followed by exactly one private
// key and nothing else.
func checkPEM(b []byte) error {
	if len(b) > maxCertificatePEM {
		return errors.New("bundle too large")
	}
	var certs, keys int
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			certs++
		case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY":
			keys++
		default:
			return fmt.Errorf("unexpected PEM block %q", block.Type)
		}
	}
	if strings.TrimSpace(string(rest)) != "" {
		return errors.New("trailing data after PEM blocks")
	}
	if certs == 0 || keys != 1 {
		return errors.New("bundle must contain a certificate chain and one private key")
	}
	return nil
}
