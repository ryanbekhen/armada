package certs

import (
	"context"
	"errors"
	"fmt"
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
	if err := a.Manage(context.Background(), []string{"*.apps.example.org"}, "", nil); err == nil || !strings.Contains(err.Error(), "DNS provider") {
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
		if err := a.Manage(ctx, st.names, "", nil); err != nil {
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
	if err := a.Manage(context.Background(), names, "example.org", nil); err != nil {
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
	if err := a.Manage(context.Background(), names, "", nil); err != nil {
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
	if err := a.Manage(context.Background(), []string{"example.org"}, "example.org", nil); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.managed["example.org"].via != viaHTTP {
		t.Error("example.org uses DNS-01 with no DNS provider")
	}
}

// An app's custom domains with DNS credentials of their own (ADR 0047) use
// DNS-01 with them, before the root domain's provider; names sharing
// credentials share one config; changed credentials start the name over;
// a name whose provider cannot be made keeps HTTP-01 and the rest go on.
func TestNamesWithTheirOwnDNS(t *testing.T) {
	t.Parallel()
	var made []string
	a, err := NewACME(Options{Storage: &certmagic.FileStorage{Path: tempDir(t)}, CA: "https://127.0.0.1:1/directory", DNSProvider: nopDNS{},
		NewProvider: func(d DNS) (certmagic.DNSProvider, error) {
			if d.Provider != "cloudflare" {
				return nil, fmt.Errorf("unsupported DNS provider %q", d.Provider)
			}
			made = append(made, d.Token)
			return nopDNS{}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	shop := DNS{Provider: "cloudflare", Token: "tok-shop"}
	names := []string{"shop.net", "www.shop.net", "blog.apps.example.org", "web.apps.example.org", "other.net", "bad.net"}
	dns := map[string]DNS{"shop.net": shop, "www.shop.net": shop, "blog.apps.example.org": {Provider: "cloudflare", Token: "tok-blog"}, "bad.net": {Provider: "route66", Token: "x"}}
	err = a.Manage(context.Background(), names, "apps.example.org", dns)
	if err == nil || !strings.Contains(err.Error(), "bad.net") || strings.Contains(err.Error(), "tok-") {
		t.Errorf("Manage error = %v", err)
	}
	a.mu.Lock()
	via := func(n string) string { return a.managed[n].via }
	if via("shop.net") != shop.Key() || via("www.shop.net") != shop.Key() || via("blog.apps.example.org") == viaRoot ||
		via("web.apps.example.org") != viaRoot || via("other.net") != viaHTTP || via("bad.net") != viaHTTP {
		t.Errorf("via: %v", a.managed)
	}
	a.mu.Unlock()
	if len(made) != 2 {
		t.Errorf("providers made for %d credentials, want 2", len(made))
	}

	// New credentials for shop.net start it over with them; unchanged ones
	// keep their config.
	shop2 := DNS{Provider: "cloudflare", Token: "tok-shop-2"}
	if err := a.Manage(context.Background(), []string{"shop.net", "www.shop.net"}, "apps.example.org", map[string]DNS{"shop.net": shop2, "www.shop.net": shop}); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	if a.managed["shop.net"].via != shop2.Key() || a.managed["www.shop.net"].via != shop.Key() {
		t.Errorf("after the change: %v", a.managed)
	}
	a.mu.Unlock()
	if len(made) != 3 {
		t.Errorf("providers made = %d, want 3 (only the new token)", len(made))
	}
	if s := fmt.Sprint(shop) + fmt.Sprintf("%v %+v", shop, shop); strings.Contains(s, "tok-shop") {
		t.Errorf("credentials print their token: %s", s)
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
