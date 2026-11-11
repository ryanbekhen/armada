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
	"slices"
	"strings"
	"time"

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

const (
	// WakeHeader names the app a request on the agent's wake socket is for
	// (ADR 0021). Only the proxy sets it, overwriting any value from the
	// client.
	WakeHeader = "X-Armada-Wake"
	// WakeTimeout is how long a request for an app scaled to zero waits for
	// a replica.
	WakeTimeout = 60 * time.Second
	// MaxTimeoutSeconds bounds Backend.TimeoutSeconds.
	MaxTimeoutSeconds = 3600
)

// ClientSetter is implemented by drivers whose internal frontend checks
// who calls (ADR 0026).
type ClientSetter interface {
	// SetClients maps the addresses of this node's containers to their app
	// IDs; an address not in the map reaches no internal route.
	SetClients(ctx context.Context, clients map[netip.Addr]string) error
}

// LoadReader is implemented by drivers that can count the requests in
// progress per server, which the autoscaler uses (ADR 0020).
type LoadReader interface {
	// Load returns, per server name for every server the proxy routes to,
	// the requests in progress (being served or queued) and the total
	// requests sent to it so far.
	Load(ctx context.Context) (map[string]ServerLoad, error)
}

// ServerLoad is one server's load.
type ServerLoad struct {
	InFlight int64
	// Total counts requests; it keeps growing across reloads, and may start
	// over when the proxy crashes or the agent restarts.
	Total int64
}

// Config is the complete ingress configuration for a node.
type Config struct {
	Backends     []Backend
	Rules        []Rule
	Certificates []Certificate
	// ACMEAddress is the control plane's HTTP-01 responder (private ip:port).
	ACMEAddress string
	// TrustedProxies are the prefixes whose requests keep the client address
	// headers they carry (ClientAddressHeaders). Requests from anywhere else
	// lose them, so a client cannot claim another address.
	TrustedProxies []string
}

// ClientAddressHeaders are the headers applications read a client's address
// from, set by proxies. They are only believed from TrustedProxies.
var ClientAddressHeaders = []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP"}

// Backend is one app's set of replicas.
type Backend struct {
	Name       string
	Servers    []Server
	HealthPath string
	// Wake routes requests to the agent's wake socket while no server is
	// up, so an app scaled to zero starts on demand (ADR 0021).
	Wake bool
	// LocalFirst makes each node's proxy prefer the replicas on its own
	// node (ADR 0024).
	LocalFirst bool
	// TimeoutSeconds is how long a request may wait for an answer; 0 means
	// the proxy's default.
	TimeoutSeconds int
	// IPAllow lets only clients in these prefixes reach the backend through
	// the public frontend; IPDeny refuses those in them. At most one is set,
	// as masked prefixes (ADR 0035).
	IPAllow []string
	IPDeny  []string
	// CORS is the app's cross-origin policy; nil for none (ADR 0037).
	CORS *CORS
}

// CORS is what the proxy answers browsers about other origins.
type CORS struct {
	Origins, Methods, Headers, Expose []string
	MaxAgeSeconds                     int
	Credentials                       bool
}

// Server is one replica.
type Server struct {
	Name    string
	Address string
	// Weight is the server's share of its backend's requests, 1 to
	// MaxWeight; 0 means 1 (traffic splitting, ADR 0022).
	Weight int
}

// MaxWeight is the largest server weight.
const MaxWeight = 256

// EffectiveWeight is the weight the proxy applies.
func (s Server) EffectiveWeight() int {
	if s.Weight == 0 {
		return 1
	}
	return s.Weight
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
	// Allow, for internal rules on nodes that know their callers, lists
	// the app IDs that may call (the app itself included); empty lets
	// every app of the backend's project (ADR 0026).
	Allow []string
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

// BackendProject returns the project of the app a backend serves (a
// backend is named by the app ID, or <label>--<app ID> for a revision
// label), or "" for an invalid name.
func BackendProject(backend string) string {
	if _, id, labelled := strings.Cut(backend, "--"); labelled {
		backend = id
	}
	p, _, ok := spec.SplitAppID(backend)
	if !ok {
		return ""
	}
	return p
}

// FromProto converts the wire format.
func FromProto(p *armadav1.ProxyConfig) Config {
	var c Config
	if p == nil {
		return c
	}
	c.ACMEAddress = p.GetAcmeChallengeAddress()
	c.TrustedProxies = p.GetTrustedProxies()
	for _, b := range p.GetBackends() {
		be := Backend{Name: b.GetName(), HealthPath: b.GetHealthPath(), Wake: b.GetWake(), LocalFirst: b.GetLocalFirst(), TimeoutSeconds: int(min(b.GetTimeoutSeconds(), MaxTimeoutSeconds+1)),
			IPAllow: b.GetIpAllow(), IPDeny: b.GetIpDeny()}
		if c := b.GetCors(); c != nil {
			be.CORS = &CORS{Origins: c.GetOrigins(), Methods: c.GetMethods(), Headers: c.GetHeaders(), Expose: c.GetExpose(),
				MaxAgeSeconds: int(min(c.GetMaxAgeSeconds(), MaxCORSMaxAgeSeconds+1)), Credentials: c.GetCredentials()}
		}
		for _, s := range b.GetServers() {
			be.Servers = append(be.Servers, Server{Name: s.GetName(), Address: s.GetAddress(), Weight: int(min(s.GetWeight(), MaxWeight+1))})
		}
		c.Backends = append(c.Backends, be)
	}
	for _, r := range p.GetRules() {
		c.Rules = append(c.Rules, Rule{Host: r.GetHost(), PathPrefix: r.GetPathPrefix(), StripPrefix: r.GetStripPrefix(), Backend: r.GetBackend(), Internal: r.GetInternal(), Allow: r.GetAllow()})
	}
	for _, crt := range p.GetCertificates() {
		c.Certificates = append(c.Certificates, Certificate{Name: crt.GetName(), PEM: crt.GetPem()})
	}
	return c
}

// ToProto converts to the wire format.
func (c Config) ToProto() *armadav1.ProxyConfig {
	p := &armadav1.ProxyConfig{AcmeChallengeAddress: c.ACMEAddress, TrustedProxies: c.TrustedProxies}
	for _, b := range c.Backends {
		pb := &armadav1.ProxyBackend{Name: b.Name, HealthPath: b.HealthPath, Wake: b.Wake, LocalFirst: b.LocalFirst, TimeoutSeconds: uint32(max(min(b.TimeoutSeconds, MaxTimeoutSeconds), 0)),
			IpAllow: b.IPAllow, IpDeny: b.IPDeny}
		if c := b.CORS; c != nil {
			pb.Cors = &armadav1.ProxyCORS{Origins: c.Origins, Methods: c.Methods, Headers: c.Headers, Expose: c.Expose,
				MaxAgeSeconds: uint32(max(min(c.MaxAgeSeconds, MaxCORSMaxAgeSeconds), 0)), Credentials: c.Credentials}
		}
		for _, s := range b.Servers {
			pb.Servers = append(pb.Servers, &armadav1.ProxyServer{Name: s.Name, Address: s.Address, Weight: uint32(max(s.Weight, 0))}) //nolint:gosec // bounded by Validate
		}
		p.Backends = append(p.Backends, pb)
	}
	for _, r := range c.Rules {
		p.Rules = append(p.Rules, &armadav1.ProxyRule{Host: r.Host, PathPrefix: r.PathPrefix, StripPrefix: r.StripPrefix, Backend: r.Backend, Internal: r.Internal, Allow: r.Allow})
	}
	for _, crt := range c.Certificates {
		p.Certificates = append(p.Certificates, &armadav1.ProxyCertificate{Name: crt.Name, Pem: crt.PEM})
	}
	return p
}

// MaxLoadEntries bounds the busy replicas in one usage report: an agent
// with more reports its load as unmeasured, and the server takes no more.
const MaxLoadEntries = 20000

// Limits on what a single configuration may contain.
const (
	// The limits bound what a compromised control plane can make an agent
	// render, far above what a cluster needs: a backend per app and labelled
	// revision, a rule per host and route.
	MaxBackends     = 100_000
	MaxRules        = 1_000_000
	MaxCertificates = 100_000
	// MaxServers leaves room for an app at spec.MaxReplicas while a rollout
	// or a move adds replicas next to the ones that serve.
	MaxServers        = 2 * spec.MaxReplicas
	maxCertificatePEM = 64 << 10
	// MaxTrustedProxies bounds the prefixes of TrustedProxies.
	MaxTrustedProxies = 64
)

// ParseTrustedProxies checks prefixes of proxies in front of the nodes and
// returns them in canonical form, sorted and without duplicates. A prefix
// that matches every address is refused: it would let any client claim any
// address.
func ParseTrustedProxies(prefixes []string) ([]string, error) {
	if len(prefixes) > MaxTrustedProxies {
		return nil, fmt.Errorf("at most %d trusted proxies", MaxTrustedProxies)
	}
	out := make([]string, 0, len(prefixes))
	for _, s := range prefixes {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: want an address prefix such as 192.0.2.0/24", s)
		}
		if pfx.Bits() == 0 {
			return nil, fmt.Errorf("trusted proxy %q matches every address", s)
		}
		out = append(out, pfx.Masked().String())
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// MaxCORSMaxAgeSeconds bounds how long browsers may keep a preflight answer.
const MaxCORSMaxAgeSeconds = 86400

// validCORS re-checks a policy before its values reach the configuration.
func validCORS(c *CORS) error {
	if c == nil {
		return nil
	}
	if len(c.Origins) == 0 || len(c.Origins) > spec.MaxCORSOrigins {
		return errors.New("cors: 1 to 32 origins")
	}
	for _, o := range c.Origins {
		if (o != "*" || len(c.Origins) > 1 || c.Credentials) && !spec.ValidCORSOrigin(o) {
			return fmt.Errorf("cors: invalid origin %q", o)
		}
	}
	if len(c.Methods) == 0 {
		return errors.New("cors: no methods")
	}
	for _, m := range c.Methods {
		if !slices.Contains(spec.CORSMethodNames, m) {
			return fmt.Errorf("cors: invalid method %q", m)
		}
	}
	for _, list := range [][]string{c.Headers, c.Expose} {
		if len(list) > spec.MaxCORSHeaders {
			return errors.New("cors: too many headers")
		}
		for _, h := range list {
			if !spec.ValidCORSHeader(h) {
				return fmt.Errorf("cors: invalid header %q", h)
			}
		}
	}
	if c.MaxAgeSeconds < 0 || c.MaxAgeSeconds > MaxCORSMaxAgeSeconds {
		return errors.New("cors: max age out of range")
	}
	return nil
}

// validIPRules checks a backend's client address rules: one kind, bounded,
// each a masked prefix written the way it is rendered.
func validIPRules(b Backend) error {
	if len(b.IPAllow) > 0 && len(b.IPDeny) > 0 {
		return errors.New("both allowed and denied client addresses")
	}
	for _, list := range [][]string{b.IPAllow, b.IPDeny} {
		if len(list) > spec.MaxIPRanges {
			return errors.New("too many client address rules")
		}
		for _, s := range list {
			p, err := spec.ParseIPRange(s)
			if err != nil || p.String() != s {
				return fmt.Errorf("client address rule %q is not a canonical prefix", s)
			}
		}
	}
	return nil
}

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
	if _, err := ParseTrustedProxies(c.TrustedProxies); err != nil {
		add("%v", err)
	}
	if len(c.Backends) > MaxBackends || len(c.Rules) > MaxRules || len(c.Certificates) > MaxCertificates {
		add("configuration exceeds size limits")
		return errors.Join(errs...)
	}

	backends := map[string]bool{}
	for _, b := range c.Backends {
		if b.TimeoutSeconds < 0 || b.TimeoutSeconds > MaxTimeoutSeconds {
			return fmt.Errorf("backend %s: timeout %d out of range", b.Name, b.TimeoutSeconds)
		}
		if !spec.ValidHostName(b.Name) {
			add("backend %q: invalid name", b.Name)
			continue
		}
		if backends[b.Name] {
			add("duplicate backend %q", b.Name)
		}
		backends[b.Name] = true
		if err := validIPRules(b); err != nil {
			add("backend %s: %v", b.Name, err)
		}
		if err := validCORS(b.CORS); err != nil {
			add("backend %s: %v", b.Name, err)
		}
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
			if s.Weight < 0 || s.Weight > MaxWeight {
				add("backend %s: server weight must be between 1 and %d", b.Name, MaxWeight)
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
			if !ok || !spec.ValidHostName(name) {
				add("internal rule host %q must be <app>%s or <label>--<app>%s", r.Host, spec.InternalSuffix, spec.InternalSuffix)
			}
		} else if err := spec.ValidateDomain(r.Host); err != nil {
			add("rule host %q: %v", r.Host, err)
		}
		if err := spec.ValidateRoutePath(r.PathPrefix); err != nil {
			add("rule path %q: %v", r.PathPrefix, err)
		}
		if len(r.Allow) > 0 && !r.Internal {
			add("rule %s%s: only internal rules have callers", r.Host, r.PathPrefix)
		}
		if len(r.Allow) > spec.MaxAllow+1 {
			add("rule %s%s: too many callers", r.Host, r.PathPrefix)
		}
		project := BackendProject(r.Backend)
		for _, a := range r.Allow {
			if p, _, ok := spec.SplitAppID(a); !ok || p != project {
				add("rule %s%s: caller %q is not an app of project %s", r.Host, r.PathPrefix, a, project)
			}
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
