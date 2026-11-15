package server

import (
	"context"
	"crypto/x509"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ryanbekhen/armada/internal/pki"
)

// streamRecheckEvery is how often a user's or service's open AdminService
// stream checks its access again by default.
const streamRecheckEvery = 5 * time.Second

type guardKey struct{}

// streamGuard keeps a user's or service's AdminService stream (an events
// or logs follow, an exec session) within the access the cluster gives it
// now, not only when it opened (ADR 0033): every Config.StreamRecheck it
// reads the principal's roles again, as a new call would, and runs the
// checks the handler asked for on the app or space it serves. Once the
// certificate is refused (the principal deleted, its certificate replaced
// or expired), the method is no longer reached, or a check fails, the
// stream's context is cancelled and the stream ends with that error.
type streamGuard struct {
	s      *Server
	pid    pki.Identity
	cert   *x509.Certificate
	method string
	cancel context.CancelFunc
	done   chan struct{}

	mu     sync.Mutex
	acc    access
	checks []func(access) error
	err    error
}

// guardStream starts a guard for a principal's stream and returns it with
// the context the handler gets; nil and ctx unchanged for other callers.
func (s *Server) guardStream(ctx context.Context, method string) (*streamGuard, context.Context) {
	acc, ok := ctx.Value(accessKey{}).(access)
	cert := peerCert(ctx)
	if !ok || acc.p == nil || cert == nil {
		return nil, ctx
	}
	ctx, cancel := context.WithCancel(ctx)
	g := &streamGuard{s: s, pid: acc.id, cert: cert, method: method, cancel: cancel, done: make(chan struct{}), acc: acc}
	go g.watch(ctx)
	return g, context.WithValue(ctx, guardKey{}, g)
}

func guardFrom(ctx context.Context) *streamGuard {
	g, _ := ctx.Value(guardKey{}).(*streamGuard)
	return g
}

// watch rechecks the stream's access until it ends, and ends it when the
// client certificate expires.
func (g *streamGuard) watch(ctx context.Context) {
	defer close(g.done)
	t := time.NewTicker(g.s.streamRecheck)
	defer t.Stop()
	expiry := time.NewTimer(time.Until(g.cert.NotAfter))
	defer expiry.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-expiry.C:
			g.end(status.Errorf(codes.Unauthenticated, "the certificate of %s expired", g.pid))
			return
		case <-t.C:
			if err := g.recheck(ctx); err != nil {
				return
			}
		}
	}
}

// recheck reads the principal's access again and runs the handler's
// checks with it, ending the stream on a refusal. A store that cannot be
// read leaves the stream as it is until the next check.
func (g *streamGuard) recheck(ctx context.Context) error {
	acc, err := g.s.methodAccess(ctx, g.pid, g.cert, g.method)
	if status.Code(err) == codes.Unavailable {
		return nil
	}
	if err == nil {
		g.mu.Lock()
		checks := g.checks
		g.mu.Unlock()
		for _, c := range checks {
			if err = c(acc); err != nil {
				break
			}
		}
	}
	if err != nil {
		g.end(err)
		return err
	}
	g.mu.Lock()
	g.acc = acc
	g.mu.Unlock()
	return nil
}

// require runs check with the stream's access now and on every recheck.
func (g *streamGuard) require(check func(access) error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := check(g.acc); err != nil {
		return err
	}
	g.checks = append(g.checks, check)
	return nil
}

func (g *streamGuard) current() access {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.acc
}

// end records why the stream ends, first reason only, and cancels it.
func (g *streamGuard) end(err error) {
	g.mu.Lock()
	if g.err == nil {
		g.err = err
	}
	g.mu.Unlock()
	g.cancel()
}

// ended is the error that ended the stream, or nil.
func (g *streamGuard) ended() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}

// stop ends the watcher once the handler returned.
func (g *streamGuard) stop() {
	g.cancel()
	<-g.done
}

// streamAccess is the caller's access as of the last check: a guarded
// stream's current one, else the one the call was authorized with.
func streamAccess(ctx context.Context) access {
	if g := guardFrom(ctx); g != nil {
		return g.current()
	}
	return accessFrom(ctx)
}

// requireAccess runs check now and, on a guarded stream, on every
// recheck, so the stream ends once the caller may no longer do what it
// opened the stream for.
func requireAccess(ctx context.Context, check func(access) error) error {
	if g := guardFrom(ctx); g != nil {
		return g.require(check)
	}
	return check(accessFrom(ctx))
}

// recheckAccess checks a guarded stream's access at once, before it
// reaches something new (a replica a logs follow picks up).
func recheckAccess(ctx context.Context) error {
	if g := guardFrom(ctx); g != nil {
		if err := g.recheck(ctx); err != nil {
			return err
		}
	}
	return nil
}
