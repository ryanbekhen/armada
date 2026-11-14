package server

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/logexport"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/store"
)

// Log history (ADR 0043).
const (
	metaLogs = "logs"
	// defaultSearchLimit and maxSearchLimit bound the entries a search
	// returns.
	defaultSearchLimit = 500
	maxSearchLimit     = 5000
	// searchWait is how long the leader waits for the nodes' answers.
	searchWait = 45 * time.Second
	// maxSearches and maxSearchesPerCaller bound the searches the leader
	// runs at once; maxSearchNodeBytes bounds what it keeps of one node's
	// answer.
	maxSearches          = 4
	maxSearchesPerCaller = 2
	maxSearchNodeBytes   = 32 << 20
	// searchSkew is how far in the future a node's entry may be stamped.
	searchSkew = time.Minute
	// Bounds of the cluster's log settings.
	minLogRetention = time.Hour
	maxLogRetention = 90 * 24 * time.Hour
	minLogMaxBytes  = 64 << 20
	maxLogMaxBytes  = 1 << 40
)

// The log endpoint's token is sealed like the DNS token (ADR 0044).
const logTokenName = "log-token"

// logSettings is the meta record of the cluster's log settings: history
// (ADR 0043) and where logs are sent (ADR 0044).
type logSettings struct {
	RetentionSeconds int64 `json:"retentionSeconds,omitempty"`
	MaxBytes         int64 `json:"maxBytes,omitempty"`
	// Export is loki or otlp; empty sends nothing.
	Export       string          `json:"export,omitempty"`
	Endpoint     string          `json:"endpoint,omitempty"`
	User         string          `json:"user,omitempty"`
	Tenant       string          `json:"tenant,omitempty"`
	Token        *secrets.Sealed `json:"token,omitempty"`
	TokenVersion int             `json:"tokenVersion,omitempty"`
	// SetAt is when the export was last set, in unix nanoseconds.
	SetAt int64 `json:"setAt,omitempty"`
}

func (s *Server) logSettings(ctx context.Context) (logSettings, error) {
	var ls logSettings
	v, err := s.store.GetMeta(ctx, metaLogs)
	if errors.Is(err, store.ErrNotFound) || (err == nil && v == "") {
		return ls, nil
	}
	if err != nil {
		return ls, err
	}
	if err := json.Unmarshal([]byte(v), &ls); err != nil {
		return ls, fmt.Errorf("log settings: %w", err)
	}
	return ls, nil
}

// CheckLogRetention validates a log retention; 0 means the default.
func CheckLogRetention(d time.Duration) error {
	if d != 0 && (d < minLogRetention || d > maxLogRetention) {
		return fmt.Errorf("log retention must be between %s and %s (0 for the default, 7 days)", minLogRetention, "90 days")
	}
	return nil
}

// CheckLogMaxBytes validates the log history size per node; 0 means the
// default.
func CheckLogMaxBytes(n int64) error {
	if n != 0 && (n < minLogMaxBytes || n > maxLogMaxBytes) {
		return fmt.Errorf("log history size must be between 64Mi and 1Ti per node (0 for the default)")
	}
	return nil
}

// setLogSettings stores the log settings the request names; they reach the
// agents with the next assignments, without a restart.
func (s *Server) setLogSettings(ctx context.Context, req *armadav1.SetClusterConfigRequest) error {
	if !req.GetSetLogRetention() && !req.GetSetLogMaxBytes() && !req.GetSetLogExport() && !req.GetSetLogToken() {
		return nil
	}
	ls, err := s.logSettings(ctx)
	if err != nil {
		return storeErr(err)
	}
	c := req.GetConfig()
	if req.GetSetLogRetention() {
		if err := CheckLogRetention(time.Duration(c.GetLogRetentionSeconds()) * time.Second); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		ls.RetentionSeconds = c.GetLogRetentionSeconds()
	}
	if req.GetSetLogMaxBytes() {
		if err := CheckLogMaxBytes(c.GetLogMaxBytes()); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		ls.MaxBytes = c.GetLogMaxBytes()
	}
	if err := s.setLogExport(req, &ls); err != nil {
		return err
	}
	b, err := json.Marshal(ls)
	if err != nil {
		return err
	}
	if err := s.store.SetMeta(ctx, metaLogs, string(b)); err != nil {
		return storeErr(err)
	}
	what := fmt.Sprintf("retention=%ds max_bytes=%d export=%s", ls.RetentionSeconds, ls.MaxBytes, cmp.Or(ls.Export, "none"))
	if ls.Export != "" {
		what += " endpoint=" + ls.Endpoint
	}
	if req.GetSetLogToken() {
		what += " token"
	}
	if err := s.store.RecordAudit(ctx, actor(ctx), "cluster.logs", "cluster", what); err != nil {
		return storeErr(err)
	}
	s.log.Info("log settings changed", "retention_seconds", ls.RetentionSeconds, "max_bytes", ls.MaxBytes, "export", cmp.Or(ls.Export, "none"), "by", actor(ctx))
	return nil
}

// setLogExport applies the request's log export and token to ls (ADR 0044).
func (s *Server) setLogExport(req *armadav1.SetClusterConfigRequest, ls *logSettings) error {
	c := req.GetConfig()
	if req.GetSetLogExport() {
		format := strings.TrimSpace(c.GetLogExport())
		if format == "none" {
			format = ""
		}
		ls.Export, ls.Endpoint, ls.User, ls.Tenant = format, strings.TrimSpace(c.GetLogEndpoint()), strings.TrimSpace(c.GetLogExportUser()), strings.TrimSpace(c.GetLogExportTenant())
		ls.SetAt = s.now().UnixNano()
		if format == "" {
			*ls = logSettings{RetentionSeconds: ls.RetentionSeconds, MaxBytes: ls.MaxBytes}
		}
	}
	if req.GetSetLogToken() {
		token := []byte(strings.TrimSpace(string(req.GetLogToken())))
		if err := logexport.CheckToken(token); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		if len(token) == 0 {
			ls.Token = nil
		} else {
			if s.keys == nil {
				return status.Error(codes.FailedPrecondition, "this server has no master key to encrypt the token with")
			}
			sealed, err := s.keys.Seal(tokenScope, logTokenName, ls.TokenVersion+1, secrets.NewValue(token))
			if err != nil {
				return status.Error(codes.Internal, "seal the log token")
			}
			ls.TokenVersion++
			ls.Token = &sealed
		}
	}
	if ls.Export == "" {
		if ls.Token != nil {
			return status.Error(codes.FailedPrecondition, "a log token needs a log export: --log-export loki|otlp --log-endpoint URL")
		}
		return nil
	}
	check := logexport.Config{Format: ls.Export, Endpoint: ls.Endpoint, User: ls.User, Tenant: ls.Tenant}
	if ls.Token != nil {
		check.Token = []byte("x") // stands for the sealed token
	}
	if err := check.Check(); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}

// logSettingsProto is what assignments carry: the token opened, since the
// agents send it (never logged; assignments are not).
func (s *Server) logSettingsProto(ls logSettings) *armadav1.LogSettings {
	p := &armadav1.LogSettings{RetentionSeconds: ls.RetentionSeconds, MaxBytes: ls.MaxBytes}
	if ls.Export == "" {
		return p
	}
	e := &armadav1.LogExport{Format: ls.Export, Endpoint: ls.Endpoint, User: ls.User, Tenant: ls.Tenant, SetAt: ls.SetAt}
	if ls.Token != nil {
		if s.keys == nil {
			s.log.Warn("log export: no master key to open the token with; logs are not sent")
			return p
		}
		v, err := s.keys.Open(*ls.Token, tokenScope, logTokenName, ls.TokenVersion)
		if err != nil {
			s.log.Warn("log export: open the token", "err", err)
			return p
		}
		e.Token = v.Bytes()
	}
	p.Export = e
	return p
}

// searchSessions are the connected agents whose runtime keeps a log
// history.
func (s *Server) searchSessions() []*session {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*session
	for _, sess := range s.sessions {
		if sess.logHistory {
			out = append(out, sess)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].nodeID < out[j].nodeID })
	return out
}

// searchLogs asks every node that keeps a log history for app's entries in
// the request's window and sends the newest limit of them, oldest first.
func (s *Server) searchLogs(ctx context.Context, app string, req *armadav1.LogsRequest, stream armadav1.AdminService_LogsServer) error {
	limit := int32(defaultSearchLimit)
	if l := req.GetLimit(); l > 0 {
		limit = min(l, maxSearchLimit)
	}
	if req.GetUntil() != nil && req.GetUntil().AsTime().Before(req.GetSince().AsTime()) {
		return status.Error(codes.InvalidArgument, "--until is before --since")
	}
	release, err := s.searches.take(actor(ctx))
	if err != nil {
		return err
	}
	defer release()
	q := &armadav1.LogQuery{App: app, Replica: req.GetReplica(), Container: req.GetContainer(),
		Since: req.GetSince(), Until: req.GetUntil(), Grep: req.GetGrep(), Limit: limit}
	ctx, cancel := context.WithTimeout(ctx, searchWait)
	defer cancel()

	var (
		mu      sync.Mutex
		entries []*armadav1.LogEntry
		notices []string
		wg      sync.WaitGroup
	)
	note := func(node, msg string) {
		mu.Lock()
		notices = append(notices, "node "+node+": "+msg)
		mu.Unlock()
	}
	sessions := s.searchSessions()
	if len(sessions) == 0 {
		return status.Error(codes.FailedPrecondition, "no connected node keeps a log history (upgrade the nodes)")
	}
	for _, sess := range sessions {
		wg.Go(func() {
			got, msg := s.searchNode(ctx, sess, q)
			if msg != "" {
				note(sess.nodeID, msg)
			}
			mu.Lock()
			entries = append(entries, got...)
			mu.Unlock()
		})
	}
	wg.Wait()
	slices.SortStableFunc(entries, func(a, b *armadav1.LogEntry) int { return a.GetTime().AsTime().Compare(b.GetTime().AsTime()) })
	if len(entries) > int(limit) {
		entries = entries[len(entries)-int(limit):]
	}
	for _, e := range entries {
		if err := stream.Send(e); err != nil {
			return err
		}
	}
	slices.Sort(notices)
	for _, n := range notices {
		if err := stream.Send(&armadav1.LogEntry{Stream: armadav1.Stream_STREAM_STDERR, Data: []byte("[armada] " + n + "\n")}); err != nil {
			return err
		}
	}
	return nil
}

// searchNode runs one node's part of a search and returns its entries and
// a notice, if any.
func (s *Server) searchNode(ctx context.Context, sess *session, q *armadav1.LogQuery) ([]*armadav1.LogEntry, string) {
	id, p := s.logs.register(sess.nodeID)
	defer s.logs.cancel(id, p)
	if !sess.offer(&armadav1.ServerMessage{Msg: &armadav1.ServerMessage_LogRequest{LogRequest: &armadav1.LogRequest{RequestId: id, Query: q}}}) {
		return nil, "did not accept the search"
	}
	defer sess.offer(&armadav1.ServerMessage{Msg: &armadav1.ServerMessage_LogCancel{LogCancel: &armadav1.LogCancel{RequestId: id}}})
	select {
	case <-p.attached:
	case <-time.After(attachTimeout):
		return nil, "did not answer"
	case <-ctx.Done():
		return nil, "did not answer in time"
	}
	var (
		out   []*armadav1.LogEntry
		bytes int
		full  string
	)
	for {
		select {
		case m, open := <-p.ch:
			if !open {
				return out, full
			}
			if m.GetError() != "" {
				return out, m.GetError()
			}
			// A node's answer is trusted only for the query it was
			// asked: the app's replicas, inside the window.
			if len(m.GetData()) == 0 || m.GetTime() == nil || len(out) >= maxSearchLimit || !searchMatch(q, m, time.Now()) {
				continue
			}
			if bytes+len(m.GetData()) > maxSearchNodeBytes {
				full = "stopped at " + strconv.Itoa(maxSearchNodeBytes>>20) + " MiB of output; narrow the search"
				continue
			}
			bytes += len(m.GetData())
			out = append(out, &armadav1.LogEntry{Replica: m.GetReplica(), Stream: m.GetStream(), Data: m.GetData(), Time: m.GetTime()})
		case <-ctx.Done():
			return out, "did not finish in time"
		}
	}
}

// searchMatch reports whether a node's entry answers q: a replica of the
// queried app (the asked one, if any) and a time inside the window, not
// later than a minute from now.
func searchMatch(q *armadav1.LogQuery, m *armadav1.LogPush, now time.Time) bool {
	r := m.GetReplica()
	if !strings.HasPrefix(r, q.GetApp()+"-") || (q.GetReplica() != "" && r != q.GetReplica()) {
		return false
	}
	t := m.GetTime().AsTime()
	if t.Before(q.GetSince().AsTime()) || t.After(now.Add(searchSkew)) {
		return false
	}
	return q.GetUntil() == nil || !t.After(q.GetUntil().AsTime())
}

// searchSlots bounds the history searches the leader runs at once, in
// total and per caller.
type searchSlots struct {
	mu     sync.Mutex
	total  int
	caller map[string]int
}

func (s *searchSlots) take(who string) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.caller == nil {
		s.caller = map[string]int{}
	}
	if s.total >= maxSearches || s.caller[who] >= maxSearchesPerCaller {
		return nil, status.Error(codes.ResourceExhausted, "too many log searches are running; try again shortly")
	}
	s.total++
	s.caller[who]++
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.total--
		if s.caller[who]--; s.caller[who] <= 0 {
			delete(s.caller, who)
		}
	}, nil
}
