package server

import (
	"context"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

// Event history (ADR 0018).
const (
	// eventDedup folds an event that happens again for the same object
	// within this window into the stored one, counting it.
	eventDedup = 10 * time.Minute
	// eventKeep bounds the stored events; the oldest go first. A larger
	// cluster keeps more (eventsPerObject per app and node, up to
	// maxEventKeep), so one busy hour does not wipe the day.
	eventKeep       = 2000
	eventsPerObject = 20
	maxEventKeep    = 50_000
	eventTrimEvery  = 100
	// maxEventMessage bounds messages, which may come from agents.
	maxEventMessage = 512
	eventWrite      = 5 * time.Second
	// defaultEventsSince is how far back `armada events` looks by default.
	defaultEventsSince = time.Hour
	eventSubBuffer     = 1024
)

// Event kinds.
const (
	eventReplica     = "replica"
	eventRollout     = "rollout"
	eventNode        = "node"
	eventApp         = "app"
	eventDomain      = "domain"
	eventCertificate = "certificate"
)

type eventKey struct{ kind, object, reason string }

type recentEvent struct {
	key string
	e   store.Event
}

// eventRecorder writes events, folds repeats, and feeds followers.
type eventRecorder struct {
	mu     sync.Mutex
	recent map[eventKey]recentEvent
	// active holds conditions reported once until they clear (a lost
	// node, an app that cannot be placed).
	active map[string]bool
	subs   map[chan store.Event]struct{}
	writes int
	total  *prometheus.CounterVec
}

func newEventRecorder() *eventRecorder {
	return &eventRecorder{
		recent: map[eventKey]recentEvent{},
		active: map[string]bool{},
		subs:   map[chan store.Event]struct{}{},
		total: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "armada_events_total", Help: "Events the leader recorded, by kind and reason.",
		}, []string{"kind", "reason"}),
	}
}

// record stores e. A failure is logged: events never hold up the work they
// describe. Servers built without a recorder (unit tests) record nothing.
func (s *Server) record(ctx context.Context, e store.Event) {
	if s.events == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), eventWrite)
	defer cancel()
	e.Message = cleanMessage(e.Message)
	now := s.now()
	r := s.events
	r.mu.Lock()
	k := eventKey{e.Kind, e.Object, e.Reason}
	replace := ""
	if prev, ok := r.recent[k]; ok && now.Sub(prev.e.Last) < eventDedup {
		e.Count, e.First, replace = prev.e.Count+1, prev.e.First, prev.key
	} else {
		e.Count, e.First = 1, now
	}
	e.Last = now
	key, err := s.store.PutEvent(ctx, e, replace)
	if err != nil {
		r.mu.Unlock()
		s.log.Warn("record event", "kind", e.Kind, "reason", e.Reason, "err", err)
		return
	}
	e.Key = key
	r.recent[k] = recentEvent{key: key, e: e}
	r.writes++
	trim := r.writes%eventTrimEvery == 0
	if trim {
		for k, v := range r.recent {
			if now.Sub(v.e.Last) >= eventDedup {
				delete(r.recent, k)
			}
		}
	}
	for ch := range r.subs {
		select {
		case ch <- e:
		default:
			// A follower that cannot keep up is dropped rather than
			// slowing the reconciler.
			delete(r.subs, ch)
			close(ch)
		}
	}
	r.mu.Unlock()
	r.total.WithLabelValues(e.Kind, e.Reason).Inc()
	if trim {
		if err := s.store.TrimEvents(ctx, s.eventKeep()); err != nil {
			s.log.Warn("trim events", "err", err)
		}
	}
}

// condition records e when the condition named key starts, and nothing
// while it lasts; clear (on) false ends it.
func (s *Server) condition(ctx context.Context, key string, on bool, e store.Event) {
	r := s.events
	if r == nil {
		return
	}
	r.mu.Lock()
	was := r.active[key]
	if on {
		r.active[key] = true
	} else {
		delete(r.active, key)
	}
	r.mu.Unlock()
	if on && !was {
		s.record(ctx, e)
	}
}

func (r *eventRecorder) subscribe() chan store.Event {
	ch := make(chan store.Event, eventSubBuffer)
	r.mu.Lock()
	r.subs[ch] = struct{}{}
	r.mu.Unlock()
	return ch
}

func (r *eventRecorder) unsubscribe(ch chan store.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.subs[ch]; ok {
		delete(r.subs, ch)
		close(ch)
	}
}

// cleanMessage bounds a message and replaces control characters, so text
// from an agent cannot forge lines or terminal sequences.
func cleanMessage(m string) string {
	if len(m) > maxEventMessage {
		m = m[:maxEventMessage]
		for !utf8.ValidString(m) {
			m = m[:len(m)-1]
		}
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return ' '
		}
		return r
	}, m)
}

// replicaEvent records what an agent's report changed about a replica. The
// message comes from the agent and is cleaned by record.
func (s *Server) replicaEvent(ctx context.Context, prev store.Replica, next store.ReplicaStatus) {
	e := store.Event{Kind: eventReplica, Object: prev.ID, App: prev.App, Node: prev.NodeID, Message: next.Message}
	running := next.State == store.ReplicaRunning
	switch {
	case prev.ContainerID != "" && next.ContainerID != "" && next.ContainerID != prev.ContainerID:
		// The agent recreated the container: it crashed, or a liveness
		// probe failed.
		e.Reason = "Restarted"
	case next.State != prev.State && (next.State == store.ReplicaExited || next.State == store.ReplicaFailed):
		e.Reason = "Crashed"
		if next.State == store.ReplicaFailed {
			e.Reason = "Failed"
		}
	case running && prev.State != store.ReplicaRunning:
		e.Reason = "Started"
	case running && next.Ready && !prev.Ready:
		e.Reason, e.Message = "Ready", ""
	case running && !next.Ready && prev.Ready:
		e.Reason = "NotReady"
	default:
		return
	}
	s.record(ctx, e)
}

// CertificateEvent records that a certificate was obtained (err nil) or
// that obtaining it failed.
func (s *Server) CertificateEvent(name string, err error) {
	// Obtained or renewed: the next read gets the new one.
	s.forgetCertificate(name)
	e := store.Event{Kind: eventCertificate, Object: name, Reason: "Obtained"}
	if err != nil {
		e.Reason, e.Message = "Failed", err.Error()
	}
	s.record(context.Background(), e)
}

// Events streams events, newest last (ADR 0018).
func (s *Server) Events(req *armadav1.EventsRequest, stream armadav1.AdminService_EventsServer) error {
	ctx := stream.Context()
	since := defaultEventsSince
	if req.GetSinceSeconds() != 0 {
		since = time.Duration(req.GetSinceSeconds()) * time.Second
	}
	if since <= 0 || since > store.EventTTL {
		return status.Errorf(codes.InvalidArgument, "since must be between 1s and %s", store.EventTTL)
	}
	acc := accessFrom(ctx)
	if req.GetApp() != "" {
		if err := acc.app(req.GetApp()); err != nil {
			return err
		}
	}
	if req.GetNode() != "" && !acc.admin() {
		return status.Error(codes.PermissionDenied, "only administrators may list a node's events")
	}
	match := func(e store.Event) bool {
		// Others see only events of their projects' apps; events of the
		// cluster (nodes, servers) have no app.
		return (req.GetApp() == "" || e.App == req.GetApp()) && (req.GetNode() == "" || e.Node == req.GetNode()) &&
			(acc.admin() || (e.App != "" && acc.sees(e.App)))
	}
	var sub chan store.Event
	if req.GetFollow() {
		// Before listing, so nothing falls between the two.
		sub = s.events.subscribe()
		defer s.events.unsubscribe(sub)
	}
	evs, err := s.store.ListEvents(ctx, s.now().Add(-since))
	if err != nil {
		return storeErr(err)
	}
	sent := map[string]bool{}
	for _, e := range evs {
		if !match(e) {
			continue
		}
		sent[e.Key] = true
		if err := stream.Send(eventInfo(e)); err != nil {
			return err
		}
	}
	if sub == nil {
		return nil
	}
	for {
		select {
		case e, ok := <-sub:
			if !ok {
				return status.Error(codes.ResourceExhausted, "fell behind the event stream; run the command again")
			}
			if !match(e) || sent[e.Key] {
				continue
			}
			if err := stream.Send(eventInfo(e)); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func eventInfo(e store.Event) *armadav1.EventInfo {
	return &armadav1.EventInfo{
		Kind: e.Kind, Object: e.Object, App: e.App, Node: e.Node, Reason: e.Reason, Message: e.Message,
		Count: int32(min(e.Count, 1<<31-1)), //nolint:gosec // bounded above
		First: timestamppb.New(e.First), Last: timestamppb.New(e.Last),
	}
}

// eventKeep is how many events to keep for a cluster of the size the last
// reconcile pass saw.
func (s *Server) eventKeep() int {
	return min(max(eventKeep, eventsPerObject*int(s.clusterSize.Load())), maxEventKeep)
}
