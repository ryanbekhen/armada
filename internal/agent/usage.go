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
	oomKills  int64
	at        time.Time
	noNetwork bool
}

// usageLoop samples the node's replicas and sends what they use to the
// server, if the runtime can measure containers, together with the
// requests in progress at the node's proxy (ADR 0020).
func (a *Agent) usageLoop(ctx context.Context) {
	sr, ok := a.cfg.Driver.(runtime.StatsReader)
	if !ok || !runtime.CanStats(a.cfg.Driver) {
		a.log.Info("the container runtime cannot sample containers; armada app top shows no usage for this node")
		sr = nil
	}
	lr, _ := a.cfg.Proxy.(proxy.LoadReader)
	vols := a.mountsVolumes()
	if sr == nil && lr == nil && !vols && a.cfg.Conntrack == nil && !runtime.CanExec(a.cfg.Driver) && !a.sandboxesOn() {
		return
	}
	warned := false
	a.sampleConntrack(&armadav1.UsageReport{}, &warned)
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
		a.sampleConntrack(report, &warned)
		report.Queues = a.queues.fresh(time.Now(), 2*a.cfg.QueueInterval)
		report.Sandboxes = a.sandboxReport(time.Now())
		if sampled || report.LoadMeasured || report.VolumesMeasured || report.ConntrackMax > 0 || len(report.Queues) > 0 || len(report.Sandboxes) > 0 {
			a.sendUsage(report)
		}
	}
}

// sampleConntrack keeps the node's connection tracking limit raised and adds
// the table's use to report (ADR 0025). It repeats because the kernel module
// may load after the agent starts. A node that cannot raise it, such as an
// agent not running as root, still works: the operator sees the limit in the
// metrics and armadad doctor.
func (a *Agent) sampleConntrack(report *armadav1.UsageReport, warned *bool) {
	if a.cfg.Conntrack == nil {
		return
	}
	previous, err := a.cfg.Conntrack.Raise()
	switch {
	case err != nil && !*warned:
		a.log.Warn("connection tracking limit not raised", "err", err)
		*warned = true
	case previous > 0:
		a.log.Info("raised the connection tracking limit", "previous", previous)
	}
	if entries, limit, ok := a.cfg.Conntrack.Read(); ok {
		report.ConntrackEntries, report.ConntrackMax = entries, limit
	}
}

// sampleUsage measures every running replica container. CPU is a rate, so
// a replica is reported from the second sample of the same container on.
// restartLostNetwork asks for a container whose network interface stayed gone
// over two samples to be recreated: no probe of a replica with a port can
// succeed, and nothing else brings the interface back.
func (a *Agent) restartLostNetwork(replica, container string) {
	const reason = "its network interface is gone"
	a.mu.Lock()
	a.restarts[container] = reason
	a.mu.Unlock()
	a.log.Warn("restarting replica", "replica", replica, "reason", reason)
	a.Trigger()
}

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
		next[id] = usageSample{container: c.ID, cpu: st.CPU, egress: st.EgressBytes, oomKills: st.OOMKills, at: now, noNetwork: st.NetworkLost}
		p, ok := prev[id]
		if ok && p.container == c.ID && p.noNetwork && st.NetworkLost {
			a.restartLostNetwork(id, c.ID)
		}
		elapsed := now.Sub(p.at)
		if !ok || p.container != c.ID || st.CPU < p.cpu || elapsed <= 0 {
			continue
		}
		report.Replicas = append(report.Replicas, &armadav1.ReplicaUsage{
			Id:          id,
			CpuMillis:   int64(float64(st.CPU-p.cpu) / float64(elapsed) * 1000),
			MemoryBytes: st.MemoryBytes,
			EgressBytes: max(0, st.EgressBytes-p.egress),
			OomKills:    max(0, st.OOMKills-p.oomKills),
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
		// The proxy routes to every replica in the cluster; idle ones
		// count as zero, so only busy ones are sent.
		if l.InFlight > 0 || requests > 0 {
			report.Load = append(report.Load, &armadav1.ReplicaLoad{Id: id, InFlight: l.InFlight, Requests: requests})
		}
	}
	if len(report.Load) > proxy.MaxLoadEntries {
		// Too many to send: unmeasured, which holds autoscaling and scale
		// to zero instead of misleading them.
		a.log.Warn("proxy load not reported: too many busy replicas", "replicas", len(report.Load))
		report.Load, report.LoadMeasured = nil, false
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
