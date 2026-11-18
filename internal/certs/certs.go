// Package certs obtains and renews TLS certificates on the control plane
// with ACME (certmagic). Certificates are then distributed to every node's
// proxy as PEM bundles.
package certs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// Manager is what the server needs from certificate management.
type Manager interface {
	// Manage makes names the set of managed certificates: new names are
	// obtained and renewed, names no longer listed stop being requested and
	// renewed. It is idempotent and returns without waiting for issuance.
	// A name in dns uses DNS-01 with those credentials (an app's custom
	// domain, ADR 0047); with a DNS provider, root and the names under it
	// use DNS-01; every other name uses HTTP-01.
	Manage(ctx context.Context, names []string, root string, dns map[string]DNS) error
	// Certificate returns the chain followed by the private key, if issued.
	Certificate(ctx context.Context, name string) ([]byte, bool)
	// HTTPHandler answers ACME HTTP-01 challenges.
	HTTPHandler() http.Handler
	// SupportsWildcard reports whether DNS-01 (and so wildcards) is available.
	SupportsWildcard() bool
}

// Well-known ACME directories.
const (
	LetsEncrypt        = certmagic.LetsEncryptProductionCA
	LetsEncryptStaging = certmagic.LetsEncryptStagingCA
)

// Options configures the ACME manager.
type Options struct {
	// Storage holds the ACME account, certificates, and their keys. Control
	// plane nodes share it (EtcdStorage) so any of them can take over.
	Storage certmagic.Storage
	CA      string
	Email   string
	// DNSProvider enables DNS-01 for wildcard names and for the root domain
	// and the names under it, whose zone the provider holds. HTTP-01 is used
	// for other names, because custom domains are rarely hosted at the same
	// DNS provider.
	DNSProvider certmagic.DNSProvider
	// NewProvider makes the DNS provider for credentials Manage is given
	// for a name (ADR 0047). Nil leaves those names on HTTP-01.
	NewProvider func(DNS) (certmagic.DNSProvider, error)
	// OnObtained is called after a certificate is obtained or renewed.
	OnObtained func(name string)
	// OnFailed is called when obtaining or renewing a certificate failed;
	// certmagic retries with backoff.
	OnFailed func(name string, renewal bool, err error)
}

// DNS are a DNS provider's credentials for a name's certificate. They
// redact themselves when printed or logged.
type DNS struct {
	Provider string
	Token    string
}

// String implements fmt.Stringer without the token.
func (d DNS) String() string { return d.Provider + " (token redacted)" }

// LogValue implements slog.LogValuer without the token.
func (d DNS) LogValue() slog.Value { return slog.StringValue(d.String()) }

// Key names the credentials without holding the token.
func (d DNS) Key() string {
	h := sha256.Sum256([]byte(d.Provider + "\x00" + d.Token))
	return "dns:" + hex.EncodeToString(h[:])
}

func (o Options) onEvent(_ context.Context, event string, data map[string]any) error {
	name, _ := data["identifier"].(string)
	switch {
	case event == "cert_obtained" && o.OnObtained != nil:
		o.OnObtained(name)
	case event == "cert_failed" && o.OnFailed != nil:
		renewal, _ := data["renewal"].(bool)
		err, _ := data["error"].(error)
		o.OnFailed(name, renewal, err)
	}
	return nil
}

// ACME is the certmagic-backed Manager.
type ACME struct {
	storage     certmagic.Storage
	cache       *certmagic.Cache
	httpCfg     *certmagic.Config
	httpIssuer  *certmagic.ACMEIssuer
	dnsCfg      *certmagic.Config
	issuerKey   string
	newCfg      func(certmagic.DNSProvider) *certmagic.Config
	newProvider func(DNS) (certmagic.DNSProvider, error)

	mu sync.Mutex
	// managed maps each name to its obtain job, so a name that is dropped
	// stops being retried.
	managed map[string]managedName
	// root is the domain whose names use DNS-01. Renewals read it from
	// certmagic's goroutines, which must not wait for mu.
	root atomic.Pointer[string]
	// named holds the names with credentials of their own and a config per
	// credentials, replaced whole on each Manage; renewals read it too.
	named atomic.Pointer[namedDNS]
}

// namedDNS maps names to the key of their credentials, and keys to the
// config that solves DNS-01 with them.
type namedDNS struct {
	keys map[string]string
	cfgs map[string]*certmagic.Config
}

// Which credentials a certificate is obtained with: viaHTTP for HTTP-01,
// viaRoot for the cluster's DNS provider, else a DNS.key.
const (
	viaHTTP = ""
	viaRoot = "root"
)

// managedName is a name's obtain job and the challenge it uses.
type managedName struct {
	cancel context.CancelFunc
	via    string
}

var _ Manager = (*ACME)(nil)

// NewACME builds a manager. Nothing is requested until Manage is called.
func NewACME(opts Options) (*ACME, error) {
	if opts.Storage == nil || opts.CA == "" {
		return nil, errors.New("certs: Storage and CA are required")
	}
	storage := opts.Storage
	logger := zap.NewNop()

	a := &ACME{storage: storage, managed: map[string]managedName{}}
	a.cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(c certmagic.Certificate) (*certmagic.Config, error) {
			for _, n := range c.Names {
				if v := a.via(n); v != viaHTTP {
					return a.config(v), nil
				}
			}
			return a.httpCfg, nil
		},
		Logger: logger,
	})
	newCfg := func(dns certmagic.DNSProvider) (*certmagic.Config, *certmagic.ACMEIssuer) {
		cfg := certmagic.New(a.cache, certmagic.Config{Storage: storage, Logger: logger, OnEvent: opts.onEvent})
		tmpl := certmagic.ACMEIssuer{
			CA:     opts.CA,
			Email:  opts.Email,
			Agreed: true,
			// HAProxy terminates TLS, so TLS-ALPN cannot reach us.
			DisableTLSALPNChallenge: true,
			Logger:                  logger,
		}
		if dns != nil {
			tmpl.DisableHTTPChallenge = true
			tmpl.DNS01Solver = &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{DNSProvider: dns, Logger: logger}}
		}
		iss := certmagic.NewACMEIssuer(cfg, tmpl)
		cfg.Issuers = []certmagic.Issuer{iss}
		return cfg, iss
	}

	a.httpCfg, a.httpIssuer = newCfg(nil)
	if opts.DNSProvider != nil {
		a.dnsCfg, _ = newCfg(opts.DNSProvider)
	}
	a.newCfg = func(p certmagic.DNSProvider) *certmagic.Config { c, _ := newCfg(p); return c }
	a.newProvider = opts.NewProvider
	a.named.Store(&namedDNS{})
	a.issuerKey = a.httpIssuer.IssuerKey()
	return a, nil
}

// via says which credentials name's certificate is obtained with: its own
// (an app's custom domain), the cluster's DNS provider for a wildcard and
// for the root domain and the names under it, else HTTP-01.
func (a *ACME) via(name string) string {
	if k, ok := a.named.Load().keys[name]; ok {
		return k
	}
	if a.dnsCfg == nil {
		return viaHTTP
	}
	if strings.HasPrefix(name, "*.") {
		return viaRoot
	}
	if root := a.root.Load(); root != nil && *root != "" && (name == *root || strings.HasSuffix(name, "."+*root)) {
		return viaRoot
	}
	return viaHTTP
}

// config is the certmagic config for credentials via picked.
func (a *ACME) config(via string) *certmagic.Config {
	switch via {
	case viaHTTP:
		return a.httpCfg
	case viaRoot:
		return a.dnsCfg
	}
	if c := a.named.Load().cfgs[via]; c != nil {
		return c
	}
	return a.httpCfg
}

// setNamed makes dns the names with credentials of their own, keeping the
// configs of credentials still in use. A name whose provider cannot be
// made is left out (HTTP-01) and reported in the error.
func (a *ACME) setNamed(names []string, dns map[string]DNS) error {
	old := a.named.Load()
	next := &namedDNS{keys: map[string]string{}, cfgs: map[string]*certmagic.Config{}}
	var errs []error
	for _, n := range names {
		d, ok := dns[n]
		if !ok {
			continue
		}
		k := d.Key()
		if _, ok := next.cfgs[k]; !ok {
			if c := old.cfgs[k]; c != nil {
				next.cfgs[k] = c
			} else {
				if a.newProvider == nil {
					errs = append(errs, fmt.Errorf("%s: no DNS providers", n))
					continue
				}
				p, err := a.newProvider(d)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", n, err))
					continue
				}
				next.cfgs[k] = a.newCfg(p)
			}
		}
		next.keys[n] = k
	}
	a.named.Store(next)
	return errors.Join(errs...)
}

// Manage implements Manager.
func (a *ACME) Manage(ctx context.Context, names []string, root string, dns map[string]DNS) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	want := make(map[string]bool, len(names))
	for _, n := range names {
		if strings.HasPrefix(n, "*.") && a.dnsCfg == nil {
			return fmt.Errorf("wildcard certificate %s needs a DNS provider", n)
		}
		want[n] = true
	}
	a.root.Store(&root)
	// A name whose credentials fail keeps HTTP-01; the rest go on.
	namedErr := a.setNamed(names, dns)
	var drop []certmagic.SubjectIssuer
	for n, m := range a.managed {
		// A name whose challenge changed starts over with the new one.
		if !want[n] || m.via != a.via(n) {
			m.cancel()
			delete(a.managed, n)
			drop = append(drop, certmagic.SubjectIssuer{Subject: n})
		}
	}
	if len(drop) > 0 {
		// Stops renewal; the certificate stays in storage.
		a.cache.RemoveManaged(drop)
	}
	for _, n := range names {
		if _, ok := a.managed[n]; ok {
			continue
		}
		via := a.via(n)
		nctx, cancel := context.WithCancel(ctx)
		if err := a.config(via).ManageAsync(nctx, []string{n}); err != nil {
			cancel()
			return err
		}
		a.managed[n] = managedName{cancel: cancel, via: via}
	}
	return namedErr
}

func (a *ACME) managedNames() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.managed))
	for n := range a.managed {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// Certificate implements Manager.
func (a *ACME) Certificate(ctx context.Context, name string) ([]byte, bool) {
	return loadBundle(ctx, a.storage, a.issuerKey, name)
}

func loadBundle(ctx context.Context, s certmagic.Storage, issuerKey, name string) ([]byte, bool) {
	crt, err := s.Load(ctx, certmagic.StorageKeys.SiteCert(issuerKey, name))
	if err != nil {
		return nil, false
	}
	key, err := s.Load(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, name))
	if err != nil {
		return nil, false
	}
	out := append([]byte{}, crt...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(out, key...), true
}

// HTTPHandler implements Manager.
func (a *ACME) HTTPHandler() http.Handler {
	return a.httpIssuer.HTTPChallengeHandler(http.NotFoundHandler())
}

// SupportsWildcard implements Manager.
func (a *ACME) SupportsWildcard() bool { return a.dnsCfg != nil }

// Close stops renewing certificates. A control plane node that loses
// leadership closes its manager, so only the leader talks to the ACME CA.
func (a *ACME) Close() { a.cache.Stop() }
