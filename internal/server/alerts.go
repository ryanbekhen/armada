package server

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/alert"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// Alerts (ADR 0045).
const (
	metaAlerts = "alerts"
	// alertQueue bounds the notices waiting per channel; more are dropped
	// and counted.
	alertQueue = 256
	// alertBurst notices may go at once per channel, then alertBurst per
	// minute; the rest are summed up in one notice.
	alertBurst = 20
	// alertTries is how often a notice is tried, alertRetry the first wait.
	alertTries = 3
	alertRetry = 2 * time.Second
)

// alertRec is a stored channel: alert.Channel without the secret, which is
// sealed.
type alertRec struct {
	alert.Channel
	Sealed  *secrets.Sealed `json:"secret,omitempty"`
	Version int             `json:"version,omitempty"`
}

type alertConfig struct {
	Channels []alertRec `json:"channels"`
}

func (s *Server) alertConfig(ctx context.Context) (alertConfig, error) {
	var ac alertConfig
	v, err := s.store.GetMeta(ctx, metaAlerts)
	if errors.Is(err, store.ErrNotFound) || (err == nil && v == "") {
		return ac, nil
	}
	if err != nil {
		return ac, err
	}
	if err := json.Unmarshal([]byte(v), &ac); err != nil {
		return ac, fmt.Errorf("alert channels: %w", err)
	}
	return ac, nil
}

func (s *Server) saveAlertConfig(ctx context.Context, ac alertConfig) error {
	b, err := json.Marshal(ac)
	if err != nil {
		return err
	}
	return s.store.SetMeta(ctx, metaAlerts, string(b))
}

func alertSecretName(channel string) string { return "alert-" + channel }

// alerter delivers notices: one worker and queue per channel, so a slow
// channel holds up no other, and nothing waits on a channel when an event
// is recorded.
type alerter struct {
	mu      sync.Mutex
	workers map[string]*alertWorker
	cluster string
	ctx     context.Context
	http    *http.Client
	sent    *prometheus.CounterVec
	failed  *prometheus.CounterVec
	dropped *prometheus.CounterVec
}

func newAlerter() *alerter {
	return &alerter{
		workers: map[string]*alertWorker{},
		sent: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "armada_alerts_sent_total", Help: "Notices sent to alert channels, by channel.",
		}, []string{"channel"}),
		failed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "armada_alerts_failed_total", Help: "Notices that could not be sent after every try, by channel.",
		}, []string{"channel"}),
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "armada_alerts_dropped_total", Help: "Notices dropped because a channel's queue was full, by channel.",
		}, []string{"channel"}),
	}
}

type alertWorker struct {
	ch     alert.Channel
	send   *alert.Sender
	queue  chan alert.Notice
	cancel context.CancelFunc

	mu                    sync.Mutex
	lastSent, lastErrorAt time.Time
	lastError             string
	sentN, failedN, drops int64
	// Rate limit: tokens refill alertBurst per minute.
	tokens   float64
	refilled time.Time
	held     int
}

// start begins delivering with the leader term's context.
func (a *alerter) start(ctx context.Context, hc *http.Client) {
	a.mu.Lock()
	a.ctx, a.http = ctx, hc
	a.mu.Unlock()
}

// set replaces the channels; workers of unchanged channels keep their
// queue and counts.
func (a *alerter) set(chs []alert.Channel, cluster string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cluster = cluster
	if a.ctx == nil {
		return
	}
	keep := map[string]bool{}
	for _, c := range chs {
		keep[c.Name] = true
		if w := a.workers[c.Name]; w != nil && sameChannel(w.ch, c) {
			continue
		}
		ctx, cancel := context.WithCancel(a.ctx)
		w := &alertWorker{ch: c, send: alert.NewSender(c, a.http, nil), queue: make(chan alert.Notice, alertQueue),
			cancel: cancel, tokens: alertBurst, refilled: time.Now()}
		if old := a.workers[c.Name]; old != nil {
			// A changed channel keeps its counts, rate, and waiting notices.
			old.cancel()
			old.mu.Lock()
			w.lastSent, w.lastErrorAt, w.lastError = old.lastSent, old.lastErrorAt, old.lastError
			w.sentN, w.failedN, w.drops, w.tokens, w.refilled, w.held = old.sentN, old.failedN, old.drops, old.tokens, old.refilled, old.held
			old.mu.Unlock()
		moved:
			for {
				select {
				case n := <-old.queue:
					w.queue <- n
				default:
					break moved
				}
			}
		}
		a.workers[c.Name] = w
		go a.run(ctx, w)
	}
	for name, w := range a.workers {
		if !keep[name] {
			w.cancel()
			delete(a.workers, name)
		}
	}
}

func sameChannel(a, b alert.Channel) bool {
	return a.Type == b.Type && a.ChatID == b.ChatID && a.SMTPHost == b.SMTPHost && a.SMTPUser == b.SMTPUser &&
		a.From == b.From && slices.Equal(a.To, b.To) && slices.Equal(a.Spaces, b.Spaces) &&
		slices.Equal(a.Reasons, b.Reasons) && string(a.Secret) == string(b.Secret)
}

// notify queues n for every channel that wants it; it never blocks.
func (a *alerter) notify(n alert.Notice) {
	a.mu.Lock()
	defer a.mu.Unlock()
	n.Cluster = a.cluster
	for name, w := range a.workers {
		if !w.ch.Wants(n.Reason, n.Space) {
			continue
		}
		select {
		case w.queue <- n:
		default:
			w.mu.Lock()
			w.drops++
			w.mu.Unlock()
			a.dropped.WithLabelValues(name).Inc()
		}
	}
}

func (a *alerter) run(ctx context.Context, w *alertWorker) {
	for {
		select {
		case <-ctx.Done():
			return
		case n := <-w.queue:
			if !w.take(time.Now()) {
				continue // summed up in the next notice that goes
			}
			if held := w.release(); held > 0 {
				a.deliver(ctx, w, alert.Notice{Kind: alert.KindSummary, Cluster: n.Cluster, Time: time.Now(),
					Message: fmt.Sprintf("%d more notices were held back (more than %d a minute)", held, alertBurst)})
			}
			a.deliver(ctx, w, n)
		}
	}
}

// take spends a token, or counts the notice as held back.
func (w *alertWorker) take(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.tokens = min(alertBurst, w.tokens+now.Sub(w.refilled).Minutes()*alertBurst)
	w.refilled = now
	if w.tokens < 1 {
		w.held++
		return false
	}
	w.tokens--
	return true
}

func (w *alertWorker) release() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	h := w.held
	w.held = 0
	return h
}

// deliver tries n a few times with backoff and records how it went.
func (a *alerter) deliver(ctx context.Context, w *alertWorker, n alert.Notice) {
	wait := alertRetry
	var err error
	for try := range alertTries {
		if try > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			wait *= 5
		}
		if err = w.send.Send(ctx, n); err == nil {
			break
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err != nil {
		w.failedN++
		w.lastError, w.lastErrorAt = err.Error(), time.Now()
		a.failed.WithLabelValues(w.ch.Name).Inc()
		return
	}
	w.sentN++
	w.lastSent = time.Now()
	a.sent.WithLabelValues(w.ch.Name).Inc()
}

// stats fills a channel's delivery fields.
func (a *alerter) stats(name string, out *armadav1.AlertChannel) {
	a.mu.Lock()
	w := a.workers[name]
	a.mu.Unlock()
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	out.LastSent, out.LastError, out.LastErrorAt = optionalTime(w.lastSent), w.lastError, optionalTime(w.lastErrorAt)
	out.Sent, out.Failed, out.Dropped = w.sentN, w.failedN, w.drops
}

func (a *alerter) sender(name string) *alert.Sender {
	a.mu.Lock()
	defer a.mu.Unlock()
	if w := a.workers[name]; w != nil {
		return w.send
	}
	return nil
}

// noticeOf turns an event into a notice.
func noticeOf(e store.Event, kind string) alert.Notice {
	n := alert.Notice{Kind: kind, Reason: e.Reason, Object: e.Kind + " " + e.Object, App: e.App, Node: e.Node,
		Message: e.Message, Count: e.Count, Time: cmp.Or(e.Last, time.Now())}
	if e.App != "" {
		if space, name, ok := spec.SplitAppID(e.App); ok {
			n.Space, n.App = space, name
		}
	}
	if kind == alert.KindResolved {
		n.Message, n.Count = "", 0
	}
	return n
}

// loadAlerts opens every channel's secret and hands the channels to the
// alerter.
func (s *Server) loadAlerts(ctx context.Context) error {
	ac, err := s.alertConfig(ctx)
	if err != nil {
		return err
	}
	var chs []alert.Channel
	for _, r := range ac.Channels {
		c := r.Channel
		if r.Sealed != nil {
			if s.keys == nil {
				s.log.Warn("alert channel: no master key to open its secret", "channel", c.Name)
				continue
			}
			v, err := s.keys.Open(*r.Sealed, tokenScope, alertSecretName(c.Name), r.Version)
			if err != nil {
				s.log.Warn("alert channel: open its secret", "channel", c.Name, "err", err)
				continue
			}
			c.Secret = v.Bytes()
		}
		chs = append(chs, c)
	}
	s.alerts.set(chs, cmp.Or(s.rootDomain(ctx), s.name))
	return nil
}

// alertMu serialises channel changes (the leader alone serves them).
var alertMu sync.Mutex

func channelProto(r alertRec) *armadav1.AlertChannel {
	c := r.Channel
	return &armadav1.AlertChannel{Name: c.Name, Type: c.Type, ChatId: c.ChatID, SmtpHost: c.SMTPHost, SmtpUser: c.SMTPUser,
		From: c.From, To: c.To, Spaces: c.Spaces, Reasons: c.Reasons, SecretSet: r.Sealed != nil}
}

// applyChannel copies the fields req names onto c.
func applyChannel(c *alert.Channel, req *armadav1.AlertChannelRequest, create bool) {
	p := req.GetChannel()
	if create || req.GetSetChatId() {
		c.ChatID = strings.TrimSpace(p.GetChatId())
	}
	if create || req.GetSetSmtp() {
		c.SMTPHost, c.SMTPUser = strings.TrimSpace(p.GetSmtpHost()), strings.TrimSpace(p.GetSmtpUser())
	}
	if create || req.GetSetFrom() {
		c.From = strings.TrimSpace(p.GetFrom())
	}
	if create || req.GetSetTo() {
		c.To = trimAll(p.GetTo())
	}
	if create || req.GetSetSpaces() {
		c.Spaces = trimAll(p.GetSpaces())
	}
	if create || req.GetSetReasons() {
		c.Reasons = trimAll(p.GetReasons())
	}
}

func trimAll(in []string) []string {
	var out []string
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// CreateAlertChannel adds a channel (cluster-admin only).
func (s *Server) CreateAlertChannel(ctx context.Context, req *armadav1.AlertChannelRequest) (*armadav1.AlertChannel, error) {
	return s.changeAlertChannel(ctx, req, true)
}

// UpdateAlertChannel changes the fields the request names.
func (s *Server) UpdateAlertChannel(ctx context.Context, req *armadav1.AlertChannelRequest) (*armadav1.AlertChannel, error) {
	return s.changeAlertChannel(ctx, req, false)
}

func (s *Server) changeAlertChannel(ctx context.Context, req *armadav1.AlertChannelRequest, create bool) (*armadav1.AlertChannel, error) {
	name := req.GetChannel().GetName()
	if err := alert.CheckName(name); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	alertMu.Lock()
	defer alertMu.Unlock()
	ac, err := s.alertConfig(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	i := slices.IndexFunc(ac.Channels, func(r alertRec) bool { return r.Name == name })
	switch {
	case create && i >= 0:
		return nil, status.Errorf(codes.AlreadyExists, "alert channel %s exists; change it with armada alert channel update", name)
	case create && len(ac.Channels) >= alert.MaxChannels:
		return nil, status.Errorf(codes.ResourceExhausted, "at most %d alert channels", alert.MaxChannels)
	case !create && i < 0:
		return nil, status.Errorf(codes.NotFound, "alert channel %s not found", name)
	}
	var r alertRec
	if create {
		r.Name, r.Type = name, strings.TrimSpace(req.GetChannel().GetType())
	} else {
		r = ac.Channels[i]
		if t := req.GetChannel().GetType(); t != "" && t != r.Type {
			return nil, status.Error(codes.InvalidArgument, "the type of a channel cannot change; delete it and create it again")
		}
	}
	applyChannel(&r.Channel, req, create)
	if err := r.Check(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if req.GetSetSecret() || create {
		secret := []byte(strings.TrimSpace(string(req.GetSecret())))
		if err := r.CheckSecret(secret); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		r.Sealed = nil
		if len(secret) > 0 {
			if s.keys == nil {
				return nil, status.Error(codes.FailedPrecondition, "this server has no master key to encrypt the secret with")
			}
			sealed, err := s.keys.Seal(tokenScope, alertSecretName(name), r.Version+1, secrets.NewValue(secret))
			if err != nil {
				return nil, status.Error(codes.Internal, "seal the channel's secret")
			}
			r.Version++
			r.Sealed = &sealed
		}
	} else if r.Sealed == nil && r.NeedsSecret() {
		return nil, status.Errorf(codes.FailedPrecondition, "%s needs its secret: --%s -", r.Type, alert.SecretFlag(r.Type))
	}
	if create {
		ac.Channels = append(ac.Channels, r)
	} else {
		ac.Channels[i] = r
	}
	if err := s.saveAlertConfig(ctx, ac); err != nil {
		return nil, storeErr(err)
	}
	verb := map[bool]string{true: "alert.create", false: "alert.update"}[create]
	what := fmt.Sprintf("%s spaces=%s reasons=%s", r.Type, strings.Join(r.Spaces, ","), strings.Join(r.Reasons, ","))
	if req.GetSetSecret() {
		what += " secret"
	}
	if err := s.store.RecordAudit(ctx, actor(ctx), verb, "alert/"+name, what); err != nil {
		return nil, storeErr(err)
	}
	if err := s.loadAlerts(ctx); err != nil {
		s.log.Warn("alert channels: reload", "err", err)
	}
	out := channelProto(r)
	s.alerts.stats(name, out)
	return out, nil
}

// ListAlertChannels lists the channels with how delivery went since the
// leader started.
func (s *Server) ListAlertChannels(ctx context.Context, _ *armadav1.ListAlertChannelsRequest) (*armadav1.ListAlertChannelsResponse, error) {
	ac, err := s.alertConfig(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	resp := &armadav1.ListAlertChannelsResponse{}
	for _, r := range ac.Channels {
		c := channelProto(r)
		s.alerts.stats(r.Name, c)
		resp.Channels = append(resp.Channels, c)
	}
	slices.SortFunc(resp.Channels, func(a, b *armadav1.AlertChannel) int { return strings.Compare(a.Name, b.Name) })
	return resp, nil
}

// DeleteAlertChannel removes a channel.
func (s *Server) DeleteAlertChannel(ctx context.Context, req *armadav1.DeleteAlertChannelRequest) (*armadav1.DeleteAlertChannelResponse, error) {
	alertMu.Lock()
	defer alertMu.Unlock()
	ac, err := s.alertConfig(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	i := slices.IndexFunc(ac.Channels, func(r alertRec) bool { return r.Name == req.GetName() })
	if i < 0 {
		return nil, status.Errorf(codes.NotFound, "alert channel %s not found", req.GetName())
	}
	ac.Channels = slices.Delete(ac.Channels, i, i+1)
	if err := s.saveAlertConfig(ctx, ac); err != nil {
		return nil, storeErr(err)
	}
	if err := s.store.RecordAudit(ctx, actor(ctx), "alert.delete", "alert/"+req.GetName(), ""); err != nil {
		return nil, storeErr(err)
	}
	if err := s.loadAlerts(ctx); err != nil {
		s.log.Warn("alert channels: reload", "err", err)
	}
	return &armadav1.DeleteAlertChannelResponse{}, nil
}

// TestAlertChannel sends a test notice now and says how it went.
func (s *Server) TestAlertChannel(ctx context.Context, req *armadav1.TestAlertChannelRequest) (*armadav1.TestAlertChannelResponse, error) {
	snd := s.alerts.sender(req.GetName())
	if snd == nil {
		return nil, status.Errorf(codes.NotFound, "alert channel %s not found", req.GetName())
	}
	n := alert.Notice{Kind: alert.KindTest, Cluster: cmp.Or(s.rootDomain(ctx), s.name), Time: time.Now(),
		Message: "Armada can reach this channel. Notices about events that need a person will come here."}
	if err := snd.Send(ctx, n); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "the test notice was not sent: %v", err)
	}
	return &armadav1.TestAlertChannelResponse{}, nil
}
