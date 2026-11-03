package agent

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/proxy"
)

func applyProxyConfig(a *Agent, cfg *armadav1.ProxyConfig) {
	a.mu.Lock()
	a.proxyApplied = cfg
	close(a.proxyChanged)
	a.proxyChanged = make(chan struct{})
	a.mu.Unlock()
}

// A request for an app with no replica waits until the proxy
// configuration has one, then reaches it with its path, host, and
// forwarding headers, and without the wake header.
func TestWakeHoldsThenForwards(t *testing.T) {
	t.Parallel()
	got := make(chan *http.Request, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r
		_, _ = io.WriteString(w, "hello")
	}))
	defer backend.Close()

	a, _ := newAgent(t)
	sock := filepath.Join(t.TempDir(), "wake.sock")
	a.cfg.WakeSocket = sock
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.serveWake(ctx)
	waitFor(t, func() bool { _, err := os.Stat(sock); return err == nil })
	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode %v", fi.Mode().Perm())
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}

	go func() {
		time.Sleep(100 * time.Millisecond)
		applyProxyConfig(a, &armadav1.ProxyConfig{Backends: []*armadav1.ProxyBackend{
			{Name: "web", Wake: true, Servers: []*armadav1.ProxyServer{{Name: "web-1", Address: strings.TrimPrefix(backend.URL, "http://")}}},
		}})
	}()
	req, _ := http.NewRequest(http.MethodPost, "http://web.internal/api/x?q=1", strings.NewReader("body"))
	req.Header.Set(proxy.WakeHeader, "web")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(b) != "hello" {
		t.Fatalf("response %d %q", resp.StatusCode, b)
	}
	r := <-got
	if r.URL.RequestURI() != "/api/x?q=1" || r.Host != "web.internal" || r.Method != http.MethodPost || r.Header.Get(proxy.WakeHeader) != "" {
		t.Errorf("forwarded %s %s host=%s wake=%q", r.Method, r.URL.RequestURI(), r.Host, r.Header.Get(proxy.WakeHeader))
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "203.0.113.9" {
		t.Errorf("X-Forwarded-For %q", xff)
	}
}

func TestWakeRefuses(t *testing.T) {
	t.Parallel()
	a, _ := newAgent(t)
	h := a.wakeHandler()

	// No or invalid app name.
	for _, app := range []string{"", "Bad Name", "../x"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(proxy.WakeHeader, app)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("app %q: %d", app, rec.Code)
		}
	}
	// No replica in time: 503 with Retry-After.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	req.Header.Set(proxy.WakeHeader, "web")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("timeout: %d %v", rec.Code, rec.Header())
	}
	// Too many waiting.
	for range maxWaiting {
		a.wakes.slots <- struct{}{}
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(proxy.WakeHeader, "web")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "too many") {
		t.Errorf("full: %d %q", rec.Code, rec.Body.String())
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 200 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}
