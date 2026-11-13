package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync/atomic"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/logexport"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/spec"
)

// Sending logs elsewhere (ADR 0044).
const (
	// logExportEvery is how often new output is sent.
	logExportEvery = 2 * time.Second
	// exportTailBytes bounds the output read per round; a round with more
	// to send goes again at once.
	exportTailBytes = 8 << 20
	// exportBatchRecords and exportBatchBytes bound one request.
	exportBatchRecords = 2000
	exportBatchBytes   = 1 << 20
	// exportBackoffMax is the longest wait after failures.
	exportBackoffMax = time.Minute
)

// exportStatus is what usage reports say about sending logs.
type exportStatus struct {
	v atomic.Pointer[armadav1.LogExportStatus]
}

func (a *Agent) exportsLogs() bool {
	_, ok := a.cfg.Driver.(runtime.LogTailer)
	return ok
}

// exportConfig reads the cluster's log export from the latest assignment.
func (a *Agent) exportConfig() (logexport.Config, string, bool) {
	e := a.logs.v.Load().GetExport()
	if e.GetFormat() == "" {
		return logexport.Config{}, "", false
	}
	c := logexport.Config{Format: e.GetFormat(), Endpoint: e.GetEndpoint(), User: e.GetUser(), Tenant: e.GetTenant(), Token: e.GetToken()}
	return c, exportTarget(c, e.GetSetAt()), true
}

// exportTarget names where logs go: setting the export again starts over,
// a new token does not.
func exportTarget(c logexport.Config, setAt int64) string {
	h := sha256.Sum256([]byte(c.Format + "\x00" + c.Endpoint + "\x00" + c.User + "\x00" + c.Tenant + "\x00" + strconv.FormatInt(setAt, 10)))
	return hex.EncodeToString(h[:16])
}

func sameExport(a, b logexport.Config) bool {
	return a.Format == b.Format && a.Endpoint == b.Endpoint && a.User == b.User && a.Tenant == b.Tenant && bytes.Equal(a.Token, b.Token)
}

// logExportLoop sends the node's app output to the cluster's log endpoint,
// at least once: what was read is marked sent only after the endpoint took
// all of it.
func (a *Agent) logExportLoop(ctx context.Context) {
	lt, ok := a.cfg.Driver.(runtime.LogTailer)
	if !ok {
		return
	}
	var (
		client  *logexport.Client
		current logexport.Config
		wait    = a.cfg.LogExport
		fails   int
		lastErr string
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = a.cfg.LogExport
		cfg, target, on := a.exportConfig()
		if !on {
			client, current, fails, lastErr = nil, logexport.Config{}, 0, ""
			a.export.v.Store(nil)
			continue
		}
		if client == nil || !sameExport(cfg, current) {
			c, err := logexport.NewClient(cfg, a.cfg.LogExportClient)
			if err != nil {
				a.exportFailed(err.Error(), &lastErr)
				continue
			}
			client, current, fails = c, cfg, 0
		}
		more, err := a.exportOnce(ctx, lt, client, target)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fails++
			wait = min(a.cfg.LogExport<<min(fails, 6), exportBackoffMax)
			a.exportFailed(err.Error(), &lastErr)
			continue
		}
		if fails > 0 || lastErr != "" {
			a.log.Info("log export: sending again")
		}
		fails, lastErr = 0, ""
		a.export.v.Store(&armadav1.LogExportStatus{})
		if more {
			wait = 0
		}
	}
}

func (a *Agent) exportFailed(msg string, last *string) {
	if msg != *last {
		a.log.Warn("log export failed", "err", msg)
		*last = msg
	}
	a.export.v.Store(&armadav1.LogExportStatus{Failing: true, Error: msg})
}

// exportOnce sends one round of new output and reports whether more may be
// waiting.
func (a *Agent) exportOnce(ctx context.Context, lt runtime.LogTailer, client *logexport.Client, target string) (bool, error) {
	tail, err := lt.TailLogs(ctx, target, exportTailBytes)
	if err != nil {
		return false, err
	}
	recs := make([]logexport.Record, 0, len(tail.Records))
	size := 0
	for _, r := range tail.Records {
		space, name, ok := spec.SplitAppID(r.App)
		if !ok {
			continue
		}
		container := r.Container
		if container == "" {
			container = "app"
		}
		recs = append(recs, logexport.Record{Time: r.Time, Stderr: r.Stream == runtime.Stderr, Line: string(r.Data),
			App: name, Space: space, Revision: r.Revision, Replica: r.Replica, Container: container, Node: a.cfg.NodeID})
		size += len(r.Data)
	}
	for _, b := range logexport.Batches(recs, exportBatchRecords, exportBatchBytes) {
		if err := client.Push(ctx, b); err != nil {
			return false, err
		}
	}
	if err := tail.Commit(); err != nil {
		return false, err
	}
	return size >= exportTailBytes/2, nil
}
