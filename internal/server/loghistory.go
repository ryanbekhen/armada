package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
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
	// Bounds of the cluster's log settings.
	minLogRetention = time.Hour
	maxLogRetention = 90 * 24 * time.Hour
	minLogMaxBytes  = 64 << 20
	maxLogMaxBytes  = 1 << 40
)

// logSettings is the meta record of the cluster's log history settings.
type logSettings struct {
	RetentionSeconds int64 `json:"retentionSeconds,omitempty"`
	MaxBytes         int64 `json:"maxBytes,omitempty"`
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
	if !req.GetSetLogRetention() && !req.GetSetLogMaxBytes() {
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
	b, err := json.Marshal(ls)
	if err != nil {
		return err
	}
	if err := s.store.SetMeta(ctx, metaLogs, string(b)); err != nil {
		return storeErr(err)
	}
	what := fmt.Sprintf("retention=%ds max_bytes=%d", ls.RetentionSeconds, ls.MaxBytes)
	if err := s.store.RecordAudit(ctx, actor(ctx), "cluster.logs", "cluster", what); err != nil {
		return storeErr(err)
	}
	s.log.Info("log settings changed", "retention_seconds", ls.RetentionSeconds, "max_bytes", ls.MaxBytes, "by", actor(ctx))
	return nil
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
	var out []*armadav1.LogEntry
	for {
		select {
		case m, open := <-p.ch:
			if !open {
				return out, ""
			}
			if m.GetError() != "" {
				return out, m.GetError()
			}
			if len(m.GetData()) == 0 || m.GetTime() == nil || len(out) >= maxSearchLimit {
				continue
			}
			out = append(out, &armadav1.LogEntry{Replica: m.GetReplica(), Stream: m.GetStream(), Data: m.GetData(), Time: m.GetTime()})
		case <-ctx.Done():
			return out, "did not finish in time"
		}
	}
}

// logSettingsProto is what assignments carry.
func (ls logSettings) proto() *armadav1.LogSettings {
	return &armadav1.LogSettings{RetentionSeconds: ls.RetentionSeconds, MaxBytes: ls.MaxBytes}
}
