package agent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/proxy"
	"github.com/ryanbekhen/armada/internal/spec"
)

const (
	// maxWaiting bounds the requests held on one node for apps that are
	// starting (ADR 0021).
	maxWaiting = 1000
	// wakeEvery is how often a waiting app is asked for again, in case a
	// wake was lost or the leader changed.
	wakeEvery = 5 * time.Second
)

// waker holds requests for apps scaled to zero until a replica serves.
type waker struct {
	slots chan struct{}
	next  atomic.Uint64 // round robin over an app's servers

	mu   sync.Mutex
	sent map[string]time.Time // app -> when a wake was last sent
}

func newWaker() *waker {
	return &waker{slots: make(chan struct{}, maxWaiting), sent: map[string]time.Time{}}
}

// serveWake listens on the wake socket until ctx ends. The socket is
// created with mode 0600 in the proxy's root-only run directory, so only
// the proxy reaches it; no network port is opened.
func (a *Agent) serveWake(ctx context.Context) {
	path := a.cfg.WakeSocket
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		a.log.Error("wake socket", "err", err)
		return
	}
	lis, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		a.log.Error("wake socket", "err", err)
		return
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = lis.Close()
		a.log.Error("wake socket", "err", err)
		return
	}
	srv := &http.Server{Handler: a.wakeHandler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
		a.log.Error("wake socket", "err", err)
	}
}

// wakeHandler holds a request until its app has a server in the applied
// proxy configuration, asking the leader to start one meanwhile, then
// forwards it there. After WakeTimeout it answers 503.
func (a *Agent) wakeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app := r.Header.Get(proxy.WakeHeader)
		if !spec.ValidAppID(app) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		select {
		case a.wakes.slots <- struct{}{}:
			defer func() { <-a.wakes.slots }()
		default:
			w.Header().Set("Retry-After", "5")
			http.Error(w, "too many requests are waiting for apps to start", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), proxy.WakeTimeout)
		defer cancel()
		addr, ok := a.awaitServer(ctx, app)
		if !ok {
			w.Header().Set("Retry-After", "5")
			http.Error(w, app+" is starting; try again shortly", http.StatusServiceUnavailable)
			return
		}
		r.Header.Del(proxy.WakeHeader)
		rp := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "http", Host: addr})
			pr.Out.Host = pr.In.Host
			// The proxy already set these for the client; keep them.
			for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Proto"} {
				if v := pr.In.Header.Values(h); len(v) > 0 {
					pr.Out.Header[h] = v
				}
			}
		}}
		rp.ServeHTTP(w, r)
	})
}

// awaitServer returns a server of app from the applied proxy
// configuration, asking the leader to start the app every wakeEvery until
// one appears or ctx ends.
func (a *Agent) awaitServer(ctx context.Context, app string) (string, bool) {
	t := time.NewTicker(wakeEvery)
	defer t.Stop()
	for {
		a.mu.Lock()
		cfg, changed := a.proxyApplied, a.proxyChanged
		a.mu.Unlock()
		for _, be := range cfg.GetBackends() {
			if be.GetName() == app && len(be.GetServers()) > 0 {
				srvs := be.GetServers()
				return srvs[a.wakes.next.Add(1)%uint64(len(srvs))].GetAddress(), true
			}
		}
		a.wake(app)
		select {
		case <-ctx.Done():
			return "", false
		case <-changed:
		case <-t.C:
		}
	}
}

// wake asks the leader to start app, at most once per wakeEvery.
func (a *Agent) wake(app string) {
	a.wakes.mu.Lock()
	if last, ok := a.wakes.sent[app]; ok && time.Since(last) < wakeEvery {
		a.wakes.mu.Unlock()
		return
	}
	a.wakes.sent[app] = time.Now()
	if len(a.wakes.sent) > maxWaiting {
		for k, v := range a.wakes.sent {
			if time.Since(v) >= wakeEvery {
				delete(a.wakes.sent, k)
			}
		}
	}
	a.wakes.mu.Unlock()

	a.streamMu.Lock()
	defer a.streamMu.Unlock()
	if a.stream == nil {
		return
	}
	if err := a.stream.Send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Wake{Wake: &armadav1.Wake{App: app}}}); err != nil {
		a.log.Warn("send wake failed", "app", app, "err", err)
	}
}
