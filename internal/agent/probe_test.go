package agent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
)

// checker is a scriptable CheckFunc keyed by probe path ("" = TCP).
type checker struct {
	mu    sync.Mutex
	fail  map[string]error
	calls map[string]int
	addrs []string
}

func newChecker() *checker {
	return &checker{fail: map[string]error{}, calls: map[string]int{}}
}

func (c *checker) check(_ context.Context, addr, path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls[path]++
	c.addrs = append(c.addrs, addr)
	return c.fail[path]
}

func (c *checker) set(path string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fail[path] = err
}

func (c *checker) count(path string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[path]
}

func probeAgent(t *testing.T, c *checker) (*Agent, *fake.Driver) {
	t.Helper()
	d := fake.New()
	return New(Config{NodeID: "n1", PrivateIP: "10.0.0.2", Driver: d, CPUMillis: 1000, MemoryBytes: 1 << 30, Check: c.check}), d
}

func fastProbe(path string) *armadav1.Probe {
	return &armadav1.Probe{Path: path, Port: 8080, PeriodMs: 5, TimeoutMs: 50, FailureThreshold: 2}
}

// eventually reconciles until cond holds for the replica state.
func eventually(t *testing.T, a *Agent, what string, cond func(*armadav1.ReplicaState) bool) *armadav1.ReplicaState {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last *armadav1.ReplicaState
	for time.Now().Before(deadline) {
		report, err := a.Reconcile(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if len(report.GetReplicas()) == 1 {
			last = report.Replicas[0]
			if cond(last) {
				return last
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s; last state %v", what, last)
	return nil
}

func TestReadinessGatesTraffic(t *testing.T) {
	t.Parallel()
	c := newChecker()
	c.set("/ready", errors.New("HTTP 503"))
	a, _ := probeAgent(t, c)
	s := replica("web-1", "nginx", 8080)
	s.Readiness = fastProbe("/ready")
	a.setDesired([]*armadav1.ReplicaSpec{s}, nil)

	st := eventually(t, a, "failing readiness", func(st *armadav1.ReplicaState) bool {
		return strings.Contains(st.Message, "readiness probe failed: HTTP 503")
	})
	if st.Ready || st.State != "running" {
		t.Errorf("unready replica reported ready: %v", st)
	}

	c.set("/ready", nil)
	st = eventually(t, a, "ready", func(st *armadav1.ReplicaState) bool { return st.Ready })
	if st.Message != "" {
		t.Errorf("message after ready = %q", st.Message)
	}
	// Losing readiness takes failureThreshold consecutive failures.
	c.set("/ready", errors.New("HTTP 500"))
	eventually(t, a, "not ready again", func(st *armadav1.ReplicaState) bool { return !st.Ready })
}

func TestImplicitReadiness(t *testing.T) {
	t.Parallel()
	c := newChecker()
	c.set("", errors.New("connection refused"))
	a, _ := probeAgent(t, c)
	// With a port but no readiness probe, the port must accept connections.
	a.setDesired([]*armadav1.ReplicaSpec{replica("web-1", "nginx", 8080)}, nil)
	time.Sleep(50 * time.Millisecond)
	if st := eventually(t, a, "probed", func(*armadav1.ReplicaState) bool { return c.count("") > 0 }); st.Ready {
		t.Error("ready before the port accepts connections")
	}
	c.set("", nil)
	eventually(t, a, "ready via TCP", func(st *armadav1.ReplicaState) bool { return st.Ready })

	// Without a port there is nothing to check.
	b, _ := probeAgent(t, newChecker())
	b.setDesired([]*armadav1.ReplicaSpec{replica("worker-1", "busybox", 0)}, nil)
	eventually(t, b, "ready without port", func(st *armadav1.ReplicaState) bool { return st.Ready })
}

func TestLivenessFailureRestartsContainer(t *testing.T) {
	t.Parallel()
	c := newChecker()
	a, d := probeAgent(t, c)
	s := replica("web-1", "nginx", 8080)
	s.Liveness = fastProbe("/live")
	a.setDesired([]*armadav1.ReplicaSpec{s}, nil)
	first := eventually(t, a, "ready", func(st *armadav1.ReplicaState) bool { return st.Ready })

	// Keep the new container unready until its message has been read: the
	// note stays, also next to readiness failures, until it is ready.
	c.set("", errors.New("connection refused"))
	c.set("/live", errors.New("HTTP 500"))
	st := eventually(t, a, "restart", func(st *armadav1.ReplicaState) bool { return st.ContainerId != first.ContainerId })
	c.set("/live", nil)
	if !strings.Contains(st.Message, "restarted: liveness probe failed: HTTP 500") {
		t.Errorf("message = %q", st.Message)
	}
	st = eventually(t, a, "readiness failure reported", func(st *armadav1.ReplicaState) bool {
		return strings.Contains(st.Message, "readiness probe failed")
	})
	if !strings.HasPrefix(st.Message, "restarted: liveness probe failed: HTTP 500; ") {
		t.Errorf("restart note lost behind a readiness failure: %q", st.Message)
	}
	c.set("", nil)
	if _, err := d.Inspect(t.Context(), first.ContainerId); !errors.Is(err, runtime.ErrNotFound) {
		t.Errorf("old container not removed: %v", err)
	}
	// The note clears once the new container is ready.
	eventually(t, a, "ready after restart", func(st *armadav1.ReplicaState) bool { return st.Ready && st.Message == "" })
}

func TestStartupProbeRunsFirst(t *testing.T) {
	t.Parallel()
	c := newChecker()
	c.set("/started", errors.New("connection refused"))
	a, _ := probeAgent(t, c)
	s := replica("web-1", "nginx", 8080)
	s.Startup = fastProbe("/started")
	s.Startup.FailureThreshold = 1000
	s.Readiness = fastProbe("/ready")
	a.setDesired([]*armadav1.ReplicaSpec{s}, nil)
	eventually(t, a, "startup probing", func(*armadav1.ReplicaState) bool { return c.count("/started") > 3 })
	if n := c.count("/ready"); n != 0 {
		t.Errorf("readiness probed %d times before startup succeeded", n)
	}
	c.set("/started", nil)
	eventually(t, a, "ready after startup", func(st *armadav1.ReplicaState) bool { return st.Ready })
}

func TestStartupFailureRestarts(t *testing.T) {
	t.Parallel()
	c := newChecker()
	c.set("/started", errors.New("timeout"))
	a, _ := probeAgent(t, c)
	s := replica("web-1", "nginx", 8080)
	s.Startup = fastProbe("/started")
	a.setDesired([]*armadav1.ReplicaSpec{s}, nil)
	eventually(t, a, "restart", func(st *armadav1.ReplicaState) bool {
		return strings.Contains(st.Message, "restarted: startup probe failed: timeout")
	})
}

func TestProbesStopWithReplica(t *testing.T) {
	t.Parallel()
	c := newChecker()
	a, _ := probeAgent(t, c)
	s := replica("web-1", "nginx", 8080)
	s.Readiness = fastProbe("/ready")
	a.setDesired([]*armadav1.ReplicaSpec{s}, nil)
	eventually(t, a, "ready", func(st *armadav1.ReplicaState) bool { return st.Ready })

	a.setDesired(nil, nil)
	if _, err := a.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	n := len(a.probes)
	a.mu.Unlock()
	if n != 0 {
		t.Errorf("%d probe workers left", n)
	}
	before := c.count("/ready")
	time.Sleep(50 * time.Millisecond)
	if after := c.count("/ready"); after > before+1 {
		t.Errorf("probes kept running after removal: %d -> %d", before, after)
	}
}

func TestProbeAddr(t *testing.T) {
	t.Parallel()
	s := replica("web-1", "nginx", 80)
	bridge := runtime.Container{IP: "172.17.0.5", HostIP: "10.0.0.2", HostPort: 32768}
	published := runtime.Container{HostIP: "10.0.0.2", HostPort: 32768}
	for name, tt := range map[string]struct {
		c    runtime.Container
		p    *armadav1.Probe
		want string
		err  string
	}{
		"bridge IP":          {bridge, &armadav1.Probe{Path: "/healthz", Port: 9090}, "172.17.0.5:9090", ""},
		"default port":       {bridge, &armadav1.Probe{Path: "/healthz"}, "172.17.0.5:80", ""},
		"published fallback": {published, &armadav1.Probe{Path: "/healthz", Port: 80}, "10.0.0.2:32768", ""},
		"unpublished port":   {published, &armadav1.Probe{Path: "/healthz", Port: 9090}, "", "no address"},
		"bad port":           {bridge, &armadav1.Probe{Path: "/healthz", Port: 70000}, "", "invalid probe port"},
		"injected host":      {bridge, &armadav1.Probe{Path: "@evil.example/x"}, "", "invalid probe path"},
		"scheme-relative":    {bridge, &armadav1.Probe{Path: "//evil.example/x"}, "172.17.0.5:80", ""},
		"CRLF":               {bridge, &armadav1.Probe{Path: "/x\r\nHost: evil"}, "", "invalid probe path"},
	} {
		got, err := probeAddr(s, tt.c, tt.p)
		if tt.err != "" {
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("%s: err = %v, want %q", name, err, tt.err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("%s: probeAddr = %q, %v; want %q", name, got, err, tt.want)
		}
	}
}

func TestDefaultCheck(t *testing.T) {
	t.Parallel()
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Store(true) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			if !strings.HasPrefix(r.UserAgent(), "armada-probe/") {
				w.WriteHeader(http.StatusBadRequest)
			}
		case "/redirect":
			http.Redirect(w, r, target.URL, http.StatusFound)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	ctx := t.Context()

	if err := DefaultCheck(ctx, addr, "/ok"); err != nil {
		t.Errorf("200: %v", err)
	}
	if err := DefaultCheck(ctx, addr, "/down"); err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Errorf("503: %v", err)
	}
	// A redirect is a success but is never followed.
	if err := DefaultCheck(ctx, addr, "/redirect"); err != nil || redirected.Load() {
		t.Errorf("redirect: err=%v followed=%v", err, redirected.Load())
	}
	if err := DefaultCheck(ctx, addr, ""); err != nil {
		t.Errorf("TCP: %v", err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().String()
	_ = l.Close()
	if err := DefaultCheck(ctx, closed, ""); err == nil {
		t.Error("TCP check of a closed port passed")
	}
}
