package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/version"
)

// CheckFunc runs one health check against addr ("ip:port"): an HTTP GET of
// path, or a TCP connect when path is empty.
type CheckFunc func(ctx context.Context, addr, path string) error

// Without a readiness probe, an app with a port is ready once the port
// accepts connections, so it never gets traffic before it listens.
var implicitReadiness = armadav1.Probe{PeriodMs: 1000, TimeoutMs: 1000, FailureThreshold: 3}

// probeClient never follows redirects or uses proxy settings from the
// environment: probes must reach the container and nothing else.
var probeClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
}

// DefaultCheck is the production CheckFunc.
func DefaultCheck(ctx context.Context, addr, path string) error {
	if path == "" {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		return c.Close()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "armada-probe/"+version.Get().Version)
	resp, err := probeClient.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// probeWorker runs the probes of one container.
type probeWorker struct {
	containerID string
	cancel      context.CancelFunc

	mu      sync.Mutex
	ready   bool
	message string
	// note (why the container was restarted) prefixes every message until
	// it has been reported while the container is ready (clearNote).
	note string
}

func (w *probeWorker) status() (bool, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ready, w.message
}

// set records a verdict and reports whether readiness changed.
func (w *probeWorker) set(ready bool, msg string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	changed := w.ready != ready
	switch {
	case w.note != "" && msg != "":
		msg = w.note + "; " + msg
	case w.note != "":
		msg = w.note
	}
	w.ready, w.message = ready, msg
	return changed
}

// clearNote drops the restart note once it has been reported for a ready
// container.
func (w *probeWorker) clearNote() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ready && w.note != "" {
		w.note, w.message = "", ""
	}
}

// startProbes launches the worker for container c of replica s. message is
// shown until the replica first becomes ready (e.g. why it was restarted).
func (a *Agent) startProbes(ctx context.Context, s *armadav1.ReplicaSpec, c runtime.Container, message string) *probeWorker {
	ctx, cancel := context.WithCancel(ctx)
	w := &probeWorker{containerID: c.ID, cancel: cancel, message: message, note: message}
	go a.runProbes(ctx, w, s, c)
	return w
}

func (a *Agent) runProbes(ctx context.Context, w *probeWorker, s *armadav1.ReplicaSpec, c runtime.Container) {
	check := func(p *armadav1.Probe) func(context.Context) error {
		addr, err := probeAddr(s, c, p)
		return func(ctx context.Context) error {
			if err != nil {
				return err
			}
			return a.cfg.Check(ctx, addr, p.GetPath())
		}
	}
	restart := func(reason string) {
		a.mu.Lock()
		a.restarts[w.containerID] = reason
		a.mu.Unlock()
		a.log.Warn("restarting replica", "replica", s.GetId(), "reason", reason)
		a.Trigger()
	}

	if p := s.GetStartup(); p != nil {
		started := false
		watch(ctx, check(p), p, func(err error, failures int) bool {
			if err == nil {
				started = true
				return true
			}
			if failures >= threshold(p) {
				restart("startup probe failed: " + err.Error())
				return true
			}
			return false
		})
		if !started {
			return
		}
	}

	readiness := s.GetReadiness()
	if readiness == nil && s.GetPort() > 0 {
		readiness = &implicitReadiness
	}
	if readiness == nil {
		if w.set(true, "") {
			a.Trigger()
		}
	}
	if p := s.GetLiveness(); p != nil {
		go watch(ctx, check(p), p, func(err error, failures int) bool {
			if err != nil && failures >= threshold(p) {
				restart("liveness probe failed: " + err.Error())
				return true
			}
			return false
		})
	}
	if readiness != nil {
		watch(ctx, check(readiness), readiness, func(err error, failures int) bool {
			var changed bool
			ready, _ := w.status()
			switch {
			case err == nil:
				changed = w.set(true, "")
			// The threshold guards against flapping out of service; a
			// replica that is not ready yet shows why at once.
			case !ready || failures >= threshold(readiness):
				changed = w.set(false, "readiness probe failed: "+err.Error())
			}
			if changed {
				a.Trigger()
			}
			return false
		})
	}
}

// watch runs check every period after the initial delay and passes each
// result with the count of consecutive failures to fn until fn returns true
// or ctx ends.
func watch(ctx context.Context, check func(context.Context) error, p *armadav1.Probe, fn func(err error, failures int) bool) {
	if !sleep(ctx, millis(p.GetInitialDelayMs(), 0)) {
		return
	}
	failures := 0
	for {
		cctx, cancel := context.WithTimeout(ctx, millis(p.GetTimeoutMs(), time.Second))
		err := check(cctx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			failures++
		} else {
			failures = 0
		}
		if fn(err, failures) {
			return
		}
		if !sleep(ctx, millis(p.GetPeriodMs(), 10*time.Second)) {
			return
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func millis(v int64, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return time.Duration(v) * time.Millisecond
}

func threshold(p *armadav1.Probe) int {
	if n := int(p.GetFailureThreshold()); n > 0 {
		return n
	}
	return 3
}

// probeAddr returns where to send probe p for container c. The probe config
// comes from the server and is re-validated: only the container itself may
// be probed, with a validated path.
func probeAddr(s *armadav1.ReplicaSpec, c runtime.Container, p *armadav1.Probe) (string, error) {
	if p.GetPath() != "" {
		if err := spec.ValidateProbePath(p.GetPath()); err != nil {
			return "", fmt.Errorf("invalid probe path: %w", err)
		}
	}
	port := int(p.GetPort())
	if port == 0 {
		port = int(s.GetPort())
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid probe port %d", port)
	}
	if c.IP != "" {
		return net.JoinHostPort(c.IP, strconv.Itoa(port)), nil
	}
	// Without a bridge IP only the published app port is reachable.
	if port == int(s.GetPort()) && c.HostPort != 0 {
		return net.JoinHostPort(c.HostIP, strconv.Itoa(c.HostPort)), nil
	}
	return "", fmt.Errorf("container has no address for port %d", port)
}
