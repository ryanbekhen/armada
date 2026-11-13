package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/alert"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/store"
)

// hookSink records the webhook notices it gets as "type reason object".
type hookSink struct {
	mu     sync.Mutex
	got    []string
	status int
}

func (h *hookSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var n alert.Notice
	_ = json.NewDecoder(r.Body).Decode(&n)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.status != 0 {
		w.WriteHeader(h.status)
		return
	}
	h.got = append(h.got, n.Kind+" "+n.Reason+" "+n.Object+" "+n.Space)
}

func (h *hookSink) notices() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.got)
}

func TestAlerts(t *testing.T) {
	t.Parallel()
	keys, err := secrets.NewKeyring(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sink := &hookSink{}
	srv := httptest.NewServer(sink)
	defer srv.Close()
	c := newCluster(t, func(cfg *Config) { cfg.Secrets = keys })
	ctx := c.ctx
	hook := srv.URL + "/hook?key=s3cret"

	for name, req := range map[string]*armadav1.AlertChannelRequest{
		"no type":     {Channel: &armadav1.AlertChannel{Name: "a"}},
		"no secret":   {Channel: &armadav1.AlertChannel{Name: "a", Type: "slack"}},
		"public http": {Channel: &armadav1.AlertChannel{Name: "a", Type: "webhook"}, SetSecret: true, Secret: []byte("http://example.com/x")},
		"bad name":    {Channel: &armadav1.AlertChannel{Name: "A!", Type: "webhook"}, SetSecret: true, Secret: []byte(hook)},
	} {
		if _, err := c.admin.CreateAlertChannel(ctx, req); status.Code(err) != codes.InvalidArgument && status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s: %v", name, err)
		}
	}
	ch, err := c.admin.CreateAlertChannel(ctx, &armadav1.AlertChannelRequest{
		Channel: &armadav1.AlertChannel{Name: "ops", Type: "webhook"}, SetSecret: true, Secret: []byte(hook + "\n")})
	if err != nil || !ch.SecretSet {
		t.Fatalf("create: %v %v", ch, err)
	}
	if _, err := c.admin.CreateAlertChannel(ctx, &armadav1.AlertChannelRequest{
		Channel: &armadav1.AlertChannel{Name: "ops", Type: "webhook"}, SetSecret: true, Secret: []byte(hook)}); status.Code(err) != codes.AlreadyExists {
		t.Errorf("twice: %v", err)
	}
	if _, err := c.admin.TestAlertChannel(ctx, &armadav1.TestAlertChannelRequest{Name: "ops"}); err != nil {
		t.Fatal(err)
	}

	// A warning is sent once; a repeat within the dedup window and a
	// normal event are not.
	lost := store.Event{Kind: eventNode, Object: "n9", Node: "n9", Reason: "Lost", Message: "gone"}
	c.srv.condition(ctx, "lost:n9", true, lost)
	c.srv.condition(ctx, "lost:n9", true, lost)
	c.srv.record(ctx, store.Event{Kind: eventApp, Object: "web.shop", App: "web.shop", Reason: "OutOfMemory"})
	c.srv.record(ctx, store.Event{Kind: eventApp, Object: "web.shop", App: "web.shop", Reason: "OutOfMemory"})
	c.srv.record(ctx, store.Event{Kind: eventApp, Object: "web", App: "web", Reason: "Deployed"})
	c.srv.condition(ctx, "lost:n9", false, lost)
	want := []string{"test   ", "event Lost node n9 ", "event OutOfMemory app web.shop shop", "resolved Lost node n9 "}
	c.eventually("notices", func() bool { return slices.Equal(sink.notices(), want) })

	// Filters: only Deployed of space shop.
	if _, err := c.admin.UpdateAlertChannel(ctx, &armadav1.AlertChannelRequest{
		Channel: &armadav1.AlertChannel{Name: "ops", Spaces: []string{"shop"}, Reasons: []string{"Deployed"}}, SetSpaces: true, SetReasons: true}); err != nil {
		t.Fatal(err)
	}
	c.srv.record(ctx, store.Event{Kind: eventApp, Object: "api", App: "api", Reason: "Deployed"})
	c.srv.record(ctx, store.Event{Kind: eventApp, Object: "api.shop", App: "api.shop", Reason: "Deployed"})
	c.eventually("filtered", func() bool { n := sink.notices(); return len(n) == 5 && n[4] == "event Deployed app api.shop shop" })

	// A failing channel says why, without its secret.
	sink.mu.Lock()
	sink.status = http.StatusUnauthorized
	sink.mu.Unlock()
	if _, err := c.admin.TestAlertChannel(ctx, &armadav1.TestAlertChannelRequest{Name: "ops"}); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("failing test: %v", err)
	}
	list, err := c.admin.ListAlertChannels(ctx, &armadav1.ListAlertChannelsRequest{})
	if err != nil || len(list.Channels) != 1 || list.Channels[0].Sent != 4 || strings.Contains(list.String(), "s3cret") {
		t.Errorf("list: %v %v", list, err)
	}
	audit, _ := c.store.ListAudit(ctx, 100)
	for _, a := range audit {
		if strings.Contains(a.Detail+a.Target, "s3cret") {
			t.Errorf("secret in the audit log: %v", a)
		}
	}
	if _, err := c.admin.DeleteAlertChannel(ctx, &armadav1.DeleteAlertChannelRequest{Name: "ops"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.admin.TestAlertChannel(ctx, &armadav1.TestAlertChannelRequest{Name: "ops"}); status.Code(err) != codes.NotFound {
		t.Errorf("deleted: %v", err)
	}
}

func TestAlertRateLimit(t *testing.T) {
	t.Parallel()
	w := &alertWorker{tokens: alertBurst, refilled: time.Now()}
	now := w.refilled
	for range alertBurst {
		if !w.take(now) {
			t.Fatal("burst refused")
		}
	}
	for range 2 {
		if w.take(now) {
			t.Error("over the burst")
		}
	}
	if w.release() != 2 || w.release() != 0 {
		t.Error("held count")
	}
	if !w.take(now.Add(4 * time.Second)) {
		t.Error("not refilled after 4s (20 a minute)")
	}
}
