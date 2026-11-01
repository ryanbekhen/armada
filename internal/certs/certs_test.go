package certs

import (
	"context"
	"errors"
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
	if err := a.Manage(context.Background(), []string{"*.apps.contoh.id"}); err == nil || !strings.Contains(err.Error(), "DNS provider") {
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
	if _, ok := a.Certificate(ctx, "contoh.id"); ok {
		t.Error("certificate reported before issuance")
	}

	s := &certmagic.FileStorage{Path: dir}
	if err := s.Store(ctx, certmagic.StorageKeys.SiteCert(a.issuerKey, "contoh.id"), []byte("-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----")); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Certificate(ctx, "contoh.id"); ok {
		t.Error("certificate reported without its key")
	}
	if err := s.Store(ctx, certmagic.StorageKeys.SitePrivateKey(a.issuerKey, "contoh.id"), []byte("-----BEGIN PRIVATE KEY-----\nB\n-----END PRIVATE KEY-----\n")); err != nil {
		t.Fatal(err)
	}
	got, ok := a.Certificate(ctx, "contoh.id")
	if !ok || string(got) != "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nB\n-----END PRIVATE KEY-----\n" {
		t.Errorf("bundle = %q", got)
	}

	// Wildcards are stored under a safe name.
	_ = s.Store(ctx, certmagic.StorageKeys.SiteCert(a.issuerKey, "*.apps.contoh.id"), []byte("C\n"))
	_ = s.Store(ctx, certmagic.StorageKeys.SitePrivateKey(a.issuerKey, "*.apps.contoh.id"), []byte("K\n"))
	if got, ok := a.Certificate(ctx, "*.apps.contoh.id"); !ok || string(got) != "C\nK\n" {
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
		a.HTTPHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://contoh.id"+p, nil))
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
		if err := a.Manage(ctx, st.names); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if got := a.managedNames(); !slices.Equal(got, st.want) {
			t.Errorf("step %d: managed = %v, want %v", i, got, st.want)
		}
	}
}
