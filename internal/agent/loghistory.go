package agent

import (
	"context"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// Log history (ADR 0043).
const (
	// logPruneEvery is how often the node's log history is bounded.
	logPruneEvery = time.Minute
	// maxSearchBytes and searchTimeout bound one search on this node.
	maxSearchBytes = 1 << 30
	searchTimeout  = 30 * time.Second
	// maxSearchLimit bounds the entries one search returns.
	maxSearchLimit = 5000
	// maxSearches bounds the searches the node runs at once: each may
	// hold its matching entries in memory.
	maxSearches = 2
)

// logSettings holds the latest Assignment.logs.
type logSettings struct {
	v atomic.Pointer[armadav1.LogSettings]
}

func (a *Agent) logHistoryOn() bool {
	_, ok := a.cfg.Driver.(runtime.LogSearcher)
	return ok
}

func (a *Agent) setLogSettings(s *armadav1.LogSettings) {
	if s == nil {
		s = &armadav1.LogSettings{}
	}
	a.logs.v.Store(s)
}

// pruneLogs bounds the node's log history with the cluster's settings.
func (a *Agent) pruneLogs(ctx context.Context) {
	p, ok := a.cfg.Driver.(runtime.LogPruner)
	if !ok {
		return
	}
	s := a.logs.v.Load()
	if s == nil {
		return // no assignment yet
	}
	if err := p.PruneLogs(ctx, time.Duration(s.GetRetentionSeconds())*time.Second, s.GetMaxBytes()); err != nil {
		a.log.Warn("log history: prune", "err", err)
	}
}

// serveSearch answers a search of this node's log history; finish closes
// the push stream with an optional notice.
func (a *Agent) serveSearch(ctx context.Context, req *armadav1.LogRequest, push armadav1.AgentService_PushLogsClient, finish func(string)) {
	select {
	case a.searches <- struct{}{}:
		defer func() { <-a.searches }()
	default:
		finish("busy with other log searches; try again shortly")
		return
	}
	ls, ok := a.cfg.Driver.(runtime.LogSearcher)
	if !ok {
		finish("this node keeps no log history")
		return
	}
	q := req.GetQuery()
	ctx, cancel := context.WithTimeout(ctx, searchTimeout)
	defer cancel()
	recs, notice, err := ls.SearchLogs(ctx, runtime.LogQuery{
		App: q.GetApp(), Replica: q.GetReplica(), Container: q.GetContainer(),
		Since: q.GetSince().AsTime(), Until: untilOf(q), Grep: q.GetGrep(),
		Limit: int(min(max(q.GetLimit(), 1), maxSearchLimit)), MaxBytes: maxSearchBytes,
	})
	if err != nil {
		finish(err.Error())
		return
	}
	for _, r := range recs {
		stream := armadav1.Stream_STREAM_STDOUT
		if r.Stream == runtime.Stderr {
			stream = armadav1.Stream_STREAM_STDERR
		}
		if err := push.Send(&armadav1.LogPush{RequestId: req.GetRequestId(), Stream: stream, Data: r.Data,
			Time: timestamppb.New(r.Time), Replica: r.Replica}); err != nil {
			return
		}
	}
	finish(notice)
}

func untilOf(q *armadav1.LogQuery) time.Time {
	if q.GetUntil() == nil {
		return time.Time{}
	}
	return q.GetUntil().AsTime()
}
