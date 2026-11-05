package agent

import (
	"context"
	"maps"
	"slices"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/proxy"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// defaultUsageInterval is how often the agent samples what its replicas
// use (ADR 0016).
const defaultUsageInterval = 10 * time.Second

// usageSample is a container's cumulative CPU time when it was sampled.
type usageSample struct {
	container string
	cpu       time.Duration
	egress    int64
	at        time.Time
}

// usageLoop samples the node's replicas and sends what they use to the
// server, if the runtime can measure containers, together with the
// requests in progress at the node's proxy (ADR 0020).
func (a *Agent) usageLoop(ctx context.Context) {
	sr, ok := a.cfg.Driver.(runtime.StatsReader)
	if !ok || !runtime.CanStats(a.cfg.Driver) {
		a.log.Info("the container runtime cannot sample containers; armada top shows no usage for this node")
		sr = nil
	}
	lr, _ := a.cfg.Proxy.(proxy.LoadReader)
	vols := a.mountsVolumes()
	if sr == nil && lr == nil && !vols {
		return
	}
	t := time.NewTicker(a.cfg.UsageInterval)
	defer t.Stop()
	prev := map[string]usageSample{}
	totals := map[string]int64{}
	var measured time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		report, sampled := &armadav1.UsageReport{}, false
		if sr != nil {
			var r *armadav1.UsageReport
			if r, prev = a.sampleUsage(ctx, sr, prev); r != nil {
				report.Replicas, sampled = r.Replicas, true
			}
		}
		if lr != nil {
			totals = a.sampleLoad(ctx, lr, report, totals)
		}
		if vols && time.Since(measured) >= a.cfg.VolumeInterval {
			report.Volumes, report.VolumesMeasured, measured = a.measureVolumes(ctx), true, time.Now()
		}
		if sampled || report.LoadMeasured || report.VolumesMeasured {
			a.sendUsage(report)
		}
	}
}

// sampleUsage measures every running replica container. CPU is a rate, so
// a replica is reported from the second sample of the same container on.
func (a *Agent) sampleUsage(ctx context.Context, sr runtime.StatsReader, prev map[string]usageSample) (*armadav1.UsageReport, map[string]usageSample) {
	cs, err := a.cfg.Driver.List(ctx, map[string]string{runtime.LabelManaged: "true"})
	if err != nil {
		a.log.Debug("list containers for usage", "err", err)
		return nil, prev
	}
	next := make(map[string]usageSample, len(cs))
	report := &armadav1.UsageReport{}
	for _, c := range cs {
		id := c.Labels[runtime.LabelReplica]
		if id == "" || c.Labels[runtime.LabelSystem] != "" || c.State != runtime.StateRunning {
			continue
		}
		st, err := sr.Stats(ctx, c.ID)
		if err != nil {
			a.log.Debug("sample container", "replica", id, "err", err)
			continue
		}
		now := time.Now()
		next[id] = usageSample{container: c.ID, cpu: st.CPU, egress: st.EgressBytes, at: now}
		p, ok := prev[id]
		elapsed := now.Sub(p.at)
		if !ok || p.container != c.ID || st.CPU < p.cpu || elapsed <= 0 {
			continue
		}
		report.Replicas = append(report.Replicas, &armadav1.ReplicaUsage{
			Id:          id,
			CpuMillis:   int64(float64(st.CPU-p.cpu) / float64(elapsed) * 1000),
			MemoryBytes: st.MemoryBytes,
			EgressBytes: max(0, st.EgressBytes-p.egress),
		})
	}
	return report, next
}

// sampleLoad adds the requests in progress per replica at the node's
// proxy, and the requests sent to it since the previous sample (a counter
// that went backwards, after a proxy reload, starts over). A proxy that
// cannot be read leaves the report unmeasured. It returns the totals for
// the next sample.
func (a *Agent) sampleLoad(ctx context.Context, lr proxy.LoadReader, report *armadav1.UsageReport, prev map[string]int64) map[string]int64 {
	load, err := lr.Load(ctx)
	if err != nil {
		a.log.Debug("read proxy load", "err", err)
		return prev
	}
	report.LoadMeasured = true
	next := make(map[string]int64, len(load))
	for _, id := range slices.Sorted(maps.Keys(load)) {
		l := load[id]
		next[id] = l.Total
		var requests int64
		if p, ok := prev[id]; ok {
			requests = l.Total - p
			if requests < 0 {
				requests = l.Total
			}
		}
		report.Load = append(report.Load, &armadav1.ReplicaLoad{Id: id, InFlight: l.InFlight, Requests: requests})
	}
	return next
}

func (a *Agent) sendUsage(r *armadav1.UsageReport) {
	a.streamMu.Lock()
	defer a.streamMu.Unlock()
	if a.stream == nil {
		return
	}
	if err := a.stream.Send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Usage{Usage: r}}); err != nil {
		a.log.Warn("send usage failed", "err", err)
	}
}
