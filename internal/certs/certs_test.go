package certs

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
)

func TestNewACMEValidates(t *testing.T) {
	t.Parallel()
	if _, err := NewACME(Options{CA: LetsEncryptStaging}); err == nil {
		t.Error("missing storage accepted")
	}
	if _, err := NewACME(Options{Storage: &certmagic.FileStorage{Path: t.TempDir()}}); err == nil {
		t.Error("missing CA accepted")
	}
}

func TestWildcardNeedsDNSProvider(t *testing.T) {
	t.Parallel()
	a, err := NewACME(Options{Storage: &certmagic.FileStorage{Path: t.TempDir()}, CA: LetsEncryptStaging})
	if err != nil {
		t.Fatal(err)
	}
	if a.SupportsWildcard() {
		t.Error("wildcard support without DNS provider")
	}
	if err := a.Manage(context.Background(), []string{"*.apps.example.org"}, ""); err == nil || !strings.Contains(err.Error(), "DNS provider") {
		t.Errorf("err = %v", err)
	}

	b, err := NewACME(Options{Storage: &certmagic.FileStorage{Path: t.TempDir()}, CA: LetsEncryptStaging, DNSProvider: nopDNS{}})
	if err != nil {
		t.Fatal(err)
	}
	if !b.SupportsWildcard() {
		t.Error("DNS provider configured but wildcards unsupported")
	}
}

type nopDNS struct{}

func (nopDNS) AppendRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}
func (nopDNS) DeleteRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

func TestCertificateFromStorage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	a, err := NewACME(Options{Storage: &certmagic.FileStorage{Path: dir}, CA: LetsEncryptStaging})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Certificate(ctx, "example.org"); ok {
		t.Error("certificate reported before issuance")
	}

	s := &certmagic.FileStorage{Path: dir}
	if err := s.Store(ctx, certmagic.StorageKeys.SiteCert(a.issuerKey, "example.org"), []byte("-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----")); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Certificate(ctx, "example.org"); ok {
		t.Error("certificate reported without its key")
	}
	if err := s.Store(ctx, certmagic.StorageKeys.SitePrivateKey(a.issuerKey, "example.org"), []byte("-----BEGIN PRIVATE KEY-----\nB\n-----END PRIVATE KEY-----\n")); err != nil {
		t.Fatal(err)
	}
	got, ok := a.Certificate(ctx, "example.org")
	if !ok || string(got) != "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nB\n-----END PRIVATE KEY-----\n" {
		t.Errorf("bundle = %q", got)
	}

	// Wildcards are stored under a safe name.
	_ = s.Store(ctx, certmagic.StorageKeys.SiteCert(a.issuerKey, "*.apps.example.org"), []byte("C\n"))
	_ = s.Store(ctx, certmagic.StorageKeys.SitePrivateKey(a.issuerKey, "*.apps.example.org"), []byte("K\n"))
	if got, ok := a.Certificate(ctx, "*.apps.example.org"); !ok || string(got) != "C\nK\n" {
		t.Errorf("wildcard bundle = %q, %v", got, ok)
	}
}

func TestHTTPHandlerOnlyServesChallenges(t *testing.T) {
	t.Parallel()
	a, err := NewACME(Options{Storage: &certmagic.FileStorage{Path: t.TempDir()}, CA: LetsEncryptStaging})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/", "/.well-known/acme-challenge/unknown-token", "/admin"} {
		rec := httptest.NewRecorder()
		a.HTTPHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.org"+p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, rec.Code)
		}
	}
}

func TestEvents(t *testing.T) {
	var obtained, failed string
	var failErr error
	o := Options{
		OnObtained: func(name string) { obtained = name },
		OnFailed:   func(name string, renewal bool, err error) { failed, failErr = name, err },
	}
	boom := errors.New("connection refused")
	_ = o.onEvent(context.Background(), "cert_failed", map[string]any{"identifier": "a.example.com", "renewal": false, "error": boom})
	_ = o.onEvent(context.Background(), "cert_obtained", map[string]any{"identifier": "b.example.com"})
	_ = o.onEvent(context.Background(), "cert_obtaining", map[string]any{"identifier": "c.example.com"})
	if failed != "a.example.com" || !errors.Is(failErr, boom) || obtained != "b.example.com" {
		t.Errorf("failed=%q err=%v obtained=%q", failed, failErr, obtained)
	}
	_ = Options{}.onEvent(context.Background(), "cert_failed", map[string]any{"identifier": "x"}) // no callbacks: no panic
}

// Names left out of Manage stop being requested and renewed.
func TestManageDropsNames(t *testing.T) {
	t.Parallel()
	// An unreachable CA: obtain jobs fail and retry until their name is dropped.
	// Cancelled jobs may still write lock files while they wind down, so the
	// storage is not a t.TempDir, whose cleanup fails on a non-empty tree.
	dir, err := os.MkdirTemp("", "armada-certs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	a, err := NewACME(Options{Storage: &certmagic.FileStorage{Path: dir}, CA: "https://127.0.0.1:1/directory", DNSProvider: nopDNS{}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx := context.Background()
	steps := []struct{ names, want []string }{
		{[]string{"a.example.com", "*.apps.example.com"}, []string{"*.apps.example.com", "a.example.com"}},
		{[]string{"a.example.com", "*.apps.example.com"}, []string{"*.apps.example.com", "a.example.com"}},
		{[]string{"*.apps2.example.com"}, []string{"*.apps2.example.com"}},
		{nil, []string{}},
	}
	for i, st := range steps {
		if err := a.Manage(ctx, st.names, ""); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if got := a.managedNames(); !slices.Equal(got, st.want) {
			t.Errorf("step %d: managed = %v, want %v", i, got, st.want)
		}
	}
}

// The root domain and the names under it use DNS-01, so they get a certificate
// when HTTP-01 cannot reach the node; other names keep HTTP-01.
func TestRootDomainUsesDNSChallenge(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "armada-certs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	a, err := NewACME(Options{Storage: &certmagic.FileStorage{Path: dir}, CA: "https://127.0.0.1:1/directory", DNSProvider: nopDNS{}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	names := []string{"example.org", "shop.example.org", "a.b.example.org", "notexample.org", "example.org.evil.net", "custom.net"}
	if err := a.Manage(context.Background(), names, "example.org"); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"example.org": true, "shop.example.org": true, "a.b.example.org": true}
	a.mu.Lock()
	for _, n := range names {
		if dns := a.managed[n].via == viaRoot; dns != want[n] {
			t.Errorf("%s: dns = %v, want %v", n, dns, want[n])
		}
	}
	a.mu.Unlock()

	// Without the root, its names go back to HTTP-01 and stay managed.
	if err := a.Manage(context.Background(), names, ""); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.managed) != len(names) {
		t.Errorf("managed = %d names, want %d", len(a.managed), len(names))
	}
	for _, n := range names {
		if a.managed[n].via != viaHTTP {
			t.Errorf("%s still uses DNS-01 with no root domain", n)
		}
	}
}

// With no DNS provider every plain name uses HTTP-01, whatever the root.
func TestNoProviderMeansHTTPChallenge(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "armada-certs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	a, err := NewACME(Options{Storage: &certmagic.FileStorage{Path: dir}, CA: "https://127.0.0.1:1/directory"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.Manage(context.Background(), []string{"example.org"}, "example.org"); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.managed["example.org"].via != viaHTTP {
		t.Error("example.org uses DNS-01 with no DNS provider")
	}
}

// Zones with credentials of their own (ADR 0047): the longest zone that holds
// a name wins, also over an equally long root domain; the root domain keeps
// the cluster's provider for what no longer zone holds; names in no zone and
// outside the root use HTTP-01; a wildcard counts as the name it covers.
func TestZonesPickTheirOwnCredentials(t *testing.T) {
	t.Parallel()
	dir := tempDir(t)
	a, err := NewACME(Options{Storage: &certmagic.FileStorage{Path: dir}, CA: "https://127.0.0.1:1/directory", DNSProvider: nopDNS{},
		Zones: []Zone{{Name: "shop.net", Provider: nopDNS{}}, {Name: "Example.ORG.", Provider: nopDNS{}}, {Name: "eu.shop.net", Provider: nopDNS{}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	want := map[string]string{
		"shop.net":             "shop.net",
		"www.shop.net":         "shop.net",
		"a.eu.shop.net":        "eu.shop.net",
		"*.eu.shop.net":        "eu.shop.net",
		"notshop.net":          viaHTTP,
		"shop.net.evil.com":    viaHTTP,
		"example.org":          "example.org",
		"apps.example.org":     viaRoot,
		"www.example.org":      "example.org",
		"web.apps.example.org": viaRoot,
		"*.apps.example.org":   viaRoot,
		"custom.com":           viaHTTP,
		"*.custom.com":         viaRoot,
	}
	names := slices.Sorted(maps.Keys(want))
	if err := a.Manage(context.Background(), names, "apps.example.org"); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	for _, n := range names {
		if got := a.managed[n].via; got != want[n] {
			t.Errorf("%s: via %q, want %q", n, got, want[n])
		}
	}
	a.mu.Unlock()

	// A root domain equal to a zone leaves its names with the zone.
	if err := a.Manage(context.Background(), []string{"x.example.org"}, "example.org"); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	if got := a.managed["x.example.org"].via; got != "example.org" {
		t.Errorf("x.example.org with root example.org: via %q", got)
	}
	a.mu.Unlock()

	// A zone without a provider is refused.
	if _, err := NewACME(Options{Storage: &certmagic.FileStorage{Path: dir}, CA: "https://127.0.0.1:1/directory", Zones: []Zone{{Name: "a.com"}}}); err == nil {
		t.Error("a zone without a provider was accepted")
	}
}

// Without a cluster DNS provider, a wildcard in a zone still gets DNS-01 and
// one outside every zone is refused.
func TestZoneWildcardWithoutRootProvider(t *testing.T) {
	t.Parallel()
	a, err := NewACME(Options{Storage: &certmagic.FileStorage{Path: tempDir(t)}, CA: "https://127.0.0.1:1/directory", Zones: []Zone{{Name: "shop.net", Provider: nopDNS{}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.Manage(context.Background(), []string{"*.shop.net"}, ""); err != nil {
		t.Errorf("wildcard in a zone: %v", err)
	}
	if err := a.Manage(context.Background(), []string{"*.other.net"}, ""); err == nil {
		t.Error("a wildcard outside every zone was accepted without a DNS provider")
	}
}

// tempDir is a directory removed after the test, whatever certmagic's
// background work leaves in it meanwhile.
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "armada-certs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
