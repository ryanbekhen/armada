package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/store/storetest"
)

func TestCleanMessage(t *testing.T) {
	t.Parallel()
	if got := cleanMessage("line\n2\x1b[31mred\r\t\x00"); got != "line 2 [31mred   " {
		t.Errorf("control characters: %q", got)
	}
	long := strings.Repeat("é", 400) // 800 bytes
	got := cleanMessage(long)
	if len(got) > maxEventMessage || !strings.HasPrefix(long, got) || len(got) < maxEventMessage-1 {
		t.Errorf("truncated to %d bytes", len(got))
	}
	if got := cleanMessage("bad \xff byte"); got != "bad   byte" {
		t.Errorf("invalid UTF-8: %q", got)
	}
}

func newEventServer(t *testing.T) (*Server, store.Store) {
	t.Helper()
	st := storetest.Open(t)
	now := time.Now()
	s := &Server{store: st, log: slog.New(slog.DiscardHandler), events: newEventRecorder(), now: func() time.Time { return now }}
	return s, st
}

func listEvents(t *testing.T, st store.Store) []store.Event {
	t.Helper()
	evs, err := st.ListEvents(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// Repeats are counted in one stored event; conditions are recorded once
// until they clear.
func TestEventDedupAndConditions(t *testing.T) {
	t.Parallel()
	s, st := newEventServer(t)
	ctx := context.Background()
	start := s.now()
	crash := store.Event{Kind: eventReplica, Object: "web-1", App: "web", Reason: "Crashed", Message: "exit 1"}
	for range 3 {
		s.record(ctx, crash)
	}
	if evs := listEvents(t, st); len(evs) != 1 || evs[0].Count != 3 {
		t.Fatalf("repeats: %+v", evs)
	}
	// Past the window, it is a new event.
	s.now = func() time.Time { return start.Add(eventDedup) }
	s.record(ctx, crash)
	if evs := listEvents(t, st); len(evs) != 2 || evs[1].Count != 1 {
		t.Fatalf("after the window: %+v", evs)
	}

	lost := store.Event{Kind: eventNode, Object: "n2", Node: "n2", Reason: "Lost"}
	for range 3 {
		s.condition(ctx, "lost:n2", true, lost)
	}
	s.condition(ctx, "lost:n2", false, lost)
	s.now = func() time.Time { return start.Add(2 * eventDedup) }
	s.condition(ctx, "lost:n2", true, lost)
	n := 0
	for _, e := range listEvents(t, st) {
		if e.Reason == "Lost" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("lost recorded %d times, want 2 (once per start)", n)
	}
	if got := testutilCount(s, eventReplica, "Crashed"); got != 4 {
		t.Errorf("armada_events_total = %v", got)
	}
}

func testutilCount(s *Server, kind, reason string) float64 {
	var m dto.Metric
	_ = s.events.total.WithLabelValues(kind, reason).Write(&m)
	return m.GetCounter().GetValue()
}

func TestReplicaEvent(t *testing.T) {
	t.Parallel()
	rep := store.Replica{ID: "web-1", App: "web", NodeID: "n1"}
	at := func(state string, ready bool) store.Replica { r := rep; r.State, r.Ready = state, ready; return r }
	tests := []struct {
		prev   store.Replica
		next   store.ReplicaStatus
		reason string
	}{
		{at(store.ReplicaStarting, false), store.ReplicaStatus{State: store.ReplicaRunning}, "Started"},
		{at(store.ReplicaRunning, false), store.ReplicaStatus{State: store.ReplicaRunning, Ready: true}, "Ready"},
		{at(store.ReplicaRunning, true), store.ReplicaStatus{State: store.ReplicaRunning, Message: "probe failed"}, "NotReady"},
		{at(store.ReplicaRunning, true), store.ReplicaStatus{State: store.ReplicaExited, Message: "exit code 137"}, "Crashed"},
		{at(store.ReplicaPulling, false), store.ReplicaStatus{State: store.ReplicaFailed, Message: "pull failed"}, "Failed"},
		{at(store.ReplicaRunning, true), store.ReplicaStatus{State: store.ReplicaRunning, Ready: true}, ""},
		{at(store.ReplicaExited, false), store.ReplicaStatus{State: store.ReplicaExited}, ""},
		{func() store.Replica { r := at(store.ReplicaRunning, true); r.ContainerID = "c1"; return r }(),
			store.ReplicaStatus{State: store.ReplicaRunning, ContainerID: "c2", Message: "restarted: exit code 137"}, "Restarted"},
	}
	for _, tt := range tests {
		s, st := newEventServer(t)
		s.replicaEvent(context.Background(), tt.prev, tt.next)
		evs := listEvents(t, st)
		switch {
		case tt.reason == "" && len(evs) != 0:
			t.Errorf("%s -> %s: unexpected %+v", tt.prev.State, tt.next.State, evs)
		case tt.reason != "" && (len(evs) != 1 || evs[0].Reason != tt.reason || evs[0].App != "web" || evs[0].Node != "n1"):
			t.Errorf("%s -> %s: %+v, want %s", tt.prev.State, tt.next.State, evs, tt.reason)
		}
	}
}

func collect(t *testing.T, stream armadav1.AdminService_EventsClient) []*armadav1.EventInfo {
	t.Helper()
	var out []*armadav1.EventInfo
	for {
		e, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
}

func hasEvent(evs []*armadav1.EventInfo, kind, reason string) *armadav1.EventInfo {
	for _, e := range evs {
		if e.GetKind() == kind && e.GetReason() == reason {
			return e
		}
	}
	return nil
}

func TestEventsRPC(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	c.addNode("n1", "10.0.0.11")
	c.addNode("n2", "10.0.0.12")
	c.deploy(webSpec("nginx:1", 1))
	c.eventually("running", func() bool { return len(c.running("web")) == 1 })

	events := func(req *armadav1.EventsRequest) []*armadav1.EventInfo {
		stream, err := c.admin.Events(c.ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		return collect(t, stream)
	}
	all := events(&armadav1.EventsRequest{})
	for _, want := range [][2]string{{eventRollout, "Started"}, {eventReplica, "Scheduled"}, {eventReplica, "Started"}, {eventNode, "Connected"}} {
		if hasEvent(all, want[0], want[1]) == nil {
			t.Errorf("no %s %s event in %v", want[0], want[1], all)
		}
	}

	// A crash is recorded with the agent's message.
	node := c.running("web")[0].GetNodeId()
	cs, _ := c.nodes[node].d.List(c.ctx, nil)
	for _, ct := range cs {
		c.nodes[node].d.SetState(ct.ID, "exited", 137)
	}
	c.eventually("restart event", func() bool {
		e := hasEvent(events(&armadav1.EventsRequest{App: "web"}), eventReplica, "Restarted")
		return e != nil && strings.Contains(e.GetMessage(), "137")
	})

	// Filters: by app, by node.
	for _, e := range events(&armadav1.EventsRequest{App: "web"}) {
		if e.GetApp() != "web" {
			t.Errorf("app filter let through %v", e)
		}
	}
	for _, e := range events(&armadav1.EventsRequest{Node: node}) {
		if e.GetNode() != node {
			t.Errorf("node filter let through %v", e)
		}
	}

	// Follow: new events arrive after the history.
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	stream, err := c.admin.Events(ctx, &armadav1.EventsRequest{Node: "n2", Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.admin.CordonNode(c.ctx, &armadav1.CordonNodeRequest{Node: "n2", Cordoned: true}); err != nil {
		t.Fatal(err)
	}
	for {
		e, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if e.GetReason() == "Cordoned" {
			if !strings.Contains(e.GetMessage(), "user:ryan") {
				t.Errorf("cordon message %q", e.GetMessage())
			}
			break
		}
	}

	// The error of a stream arrives with its first receive.
	bad, err := c.admin.Events(c.ctx, &armadav1.EventsRequest{SinceSeconds: 25 * 3600})
	if err == nil {
		_, err = bad.Recv()
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("since 25h: %v", err)
	}

	// Only admins read events.
	agent := armadav1.NewAdminServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: "n1"}))
	s, err := agent.Events(c.ctx, &armadav1.EventsRequest{})
	if err == nil {
		_, err = s.Recv()
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("node reading events: %v", err)
	}
}

// A follower that does not read is dropped instead of blocking recording.
func TestEventSlowFollower(t *testing.T) {
	t.Parallel()
	s, _ := newEventServer(t)
	ch := s.events.subscribe()
	for i := range eventSubBuffer + 1 {
		s.record(context.Background(), store.Event{Kind: eventNode, Object: "n" + string(rune('a'+i%26)) + strings.Repeat("x", i/26), Reason: "Connected"})
	}
	n := 0
	for range ch {
		n++
	}
	if n != eventSubBuffer {
		t.Errorf("follower got %d events before being dropped", n)
	}
}

// A space created again under a deleted space's name, by someone else,
// shows none of the earlier space's events; cluster-admins still see them.
func TestRecreatedSpaceHidesEarlierEvents(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	ctx := c.ctx
	c.addNode("n1", "10.0.0.11")
	owner := c.newUser("olivia", &armadav1.RoleAssignment{Role: "space-creator"})
	other := c.newUser("mallory", &armadav1.RoleAssignment{Role: "space-creator"})
	if _, err := owner.CreateSpace(ctx, &armadav1.CreateSpaceRequest{Name: "team"}); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte("name: api\nimage: example/private-api:7\n"), Space: "team"}); err != nil {
		t.Fatal(err)
	}
	c.eventually("api.team running", func() bool { return len(c.running("api.team")) == 1 })
	if _, err := owner.RemoveApp(ctx, &armadav1.RemoveAppRequest{App: "api.team"}); err != nil {
		t.Fatal(err)
	}
	c.eventually("api.team gone", func() bool {
		_, err := c.admin.GetAppSpec(ctx, &armadav1.GetAppSpecRequest{App: "api.team"})
		return err != nil
	})
	if _, err := owner.DeleteSpace(ctx, &armadav1.DeleteSpaceRequest{Name: "team"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond) // the space's creation time has milliseconds
	if _, err := other.CreateSpace(ctx, &armadav1.CreateSpaceRequest{Name: "team"}); err != nil {
		t.Fatal(err)
	}
	st, err := other.Events(ctx, &armadav1.EventsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range collect(t, st) {
		if e.GetApp() == "api.team" {
			t.Errorf("mallory sees the earlier space's event %s %s", e.GetReason(), e.GetMessage())
		}
	}
	st, err = c.admin.Events(ctx, &armadav1.EventsRequest{App: "api.team"})
	if err != nil {
		t.Fatal(err)
	}
	if len(collect(t, st)) == 0 {
		t.Error("cluster-admin lost the earlier space's events")
	}
}
