// Package certs obtains and renews TLS certificates on the control plane
// with ACME (certmagic). Certificates are then distributed to every node's
// proxy as PEM bundles.
package certs

import (
	"context"
	"errors"
	"fmt"
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
	// With a DNS provider, root and the names under it use DNS-01.
	Manage(ctx context.Context, names []string, root string) error
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
	// OnObtained is called after a certificate is obtained or renewed.
	OnObtained func(name string)
	// OnFailed is called when obtaining or renewing a certificate failed;
	// certmagic retries with backoff.
	OnFailed func(name string, renewal bool, err error)
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
	storage    certmagic.Storage
	cache      *certmagic.Cache
	httpCfg    *certmagic.Config
	httpIssuer *certmagic.ACMEIssuer
	dnsCfg     *certmagic.Config
	issuerKey  string

	mu sync.Mutex
	// managed maps each name to its obtain job, so a name that is dropped
	// stops being retried.
	managed map[string]managedName
	// root is the domain whose names use DNS-01. Renewals read it from
	// certmagic's goroutines, which must not wait for mu.
	root atomic.Pointer[string]
}

// managedName is a name's obtain job and the challenge it uses.
type managedName struct {
	cancel context.CancelFunc
	dns    bool
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
			if slices.ContainsFunc(c.Names, a.usesDNS) {
				return a.dnsCfg, nil
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
	a.issuerKey = a.httpIssuer.IssuerKey()
	return a, nil
}

// usesDNS reports whether a name gets its certificate through DNS-01.
func (a *ACME) usesDNS(name string) bool {
	if a.dnsCfg == nil {
		return false
	}
	if strings.HasPrefix(name, "*.") {
		return true
	}
	root := a.root.Load()
	return root != nil && *root != "" && (name == *root || strings.HasSuffix(name, "."+*root))
}

// Manage implements Manager.
func (a *ACME) Manage(ctx context.Context, names []string, root string) error {
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
	var drop []certmagic.SubjectIssuer
	for n, m := range a.managed {
		// A name whose challenge changed starts over with the new one.
		if !want[n] || m.dns != a.usesDNS(n) {
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
		dns := a.usesDNS(n)
		cfg := a.httpCfg
		if dns {
			cfg = a.dnsCfg
		}
		nctx, cancel := context.WithCancel(ctx)
		if err := cfg.ManageAsync(nctx, []string{n}); err != nil {
			cancel()
			return err
		}
		a.managed[n] = managedName{cancel: cancel, dns: dns}
	}
	return nil
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
