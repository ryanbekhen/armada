package agent

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/queuelen"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/spec"
)

// Network sandboxes for job queue triggers (ADR 0040).
const (
	// maxSandboxes bounds the sandboxes one node keeps.
	maxSandboxes = 64
	// sandboxTick is how often the agent checks for sandboxes to make,
	// remove, or read.
	sandboxTick = time.Second
	// maxSandboxReads bounds the readings that run at once.
	maxSandboxReads = 8
)

// sandboxes is what the agent knows of its network sandboxes: the ones the
// leader asks for, and each one's address and latest reading.
type sandboxes struct {
	mu sync.Mutex
	// want is nil until the first assignment: an agent that restarts while
	// the server is down removes nothing.
	want map[string]*armadav1.QueueSandbox
	have map[string]*sandboxState
	kick chan struct{}
}

type sandboxState struct {
	ip       string
	probe    *armadav1.QueueProbe // the probe the reading was taken with
	measured bool
	length   int64
	at       time.Time // of the reading
	reading  int64
	next     time.Time // the next reading is due
	busy     bool      // a reading runs
	failed   string    // the last failure, logged once
}

// sandboxesOn reports whether the node reads job queues from network
// sandboxes: only in its subnet of a cluster network, where the firewall
// gives a sandbox exactly what the job's containers would get, and never
// from the host's own network.
func (a *Agent) sandboxesOn() bool {
	return a.cfg.Unpublished && a.cfg.Network != nil && runtime.CanSandbox(a.cfg.Driver)
}

// setSandboxes takes the sandboxes of an assignment. Entries are checked
// again: the job must be a valid ID and the queue a type the agent reads.
func (a *Agent) setSandboxes(list []*armadav1.QueueSandbox) {
	want := map[string]*armadav1.QueueSandbox{}
	for _, s := range list {
		p := s.GetProbe()
		switch {
		case len(want) == maxSandboxes:
		case !spec.ValidAppID(s.GetJob()) || runtime.CheckSandboxID(s.GetJob()) != nil:
		case p.GetType() != spec.ScaleRedis && p.GetType() != spec.ScaleRabbitMQ:
		default:
			want[s.GetJob()] = s
		}
	}
	a.sb.mu.Lock()
	a.sb.want = want
	a.sb.mu.Unlock()
	select {
	case a.sb.kick <- struct{}{}:
	default:
	}
}

// sandboxLoop keeps the sandboxes the leader asks for, removes the others,
// and reads each one's queue every polling interval.
func (a *Agent) sandboxLoop(ctx context.Context) {
	if !a.sandboxesOn() {
		return
	}
	t := time.NewTicker(sandboxTick)
	defer t.Stop()
	for {
		a.syncSandboxes(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.sb.kick:
		}
	}
}

// syncSandboxes makes the node's sandboxes match the assignment and starts
// the readings that are due.
func (a *Agent) syncSandboxes(ctx context.Context) {
	sb, ok := a.cfg.Driver.(runtime.NetworkSandboxer)
	if !ok {
		return
	}
	a.sb.mu.Lock()
	want := a.sb.want
	a.sb.mu.Unlock()
	if want == nil {
		return
	}
	existing, err := sb.ListSandboxes(ctx)
	if err != nil {
		a.log.Warn("list network sandboxes", "err", err)
		return
	}
	changed := false
	listed := map[string]string{}
	for _, s := range existing {
		if _, ok := want[s.ID]; ok {
			listed[s.ID] = s.IP
			continue
		}
		if err := sb.RemoveSandbox(ctx, s.ID); err != nil {
			a.log.Warn("remove network sandbox", "job", s.ID, "err", err)
			continue
		}
		a.log.Info("removed network sandbox", "job", s.ID)
		a.forgetLocal(s.IP)
		changed = true
	}
	a.sb.mu.Lock()
	for id := range a.sb.have {
		if _, ok := want[id]; !ok {
			delete(a.sb.have, id)
		}
	}
	a.sb.mu.Unlock()
	for _, id := range slices.Sorted(maps.Keys(want)) {
		ip, ok := listed[id]
		if !ok || ip == "" {
			s, err := sb.EnsureSandbox(ctx, id)
			if err != nil {
				a.log.Warn("make network sandbox", "job", id, "err", err)
				continue
			}
			ip = s.IP
			if !ok {
				a.log.Info("made network sandbox", "job", id, "ip", ip)
			}
			changed = true
		}
		a.sb.mu.Lock()
		st := a.sb.have[id]
		if st == nil {
			st = &sandboxState{}
			a.sb.have[id] = st
		}
		if st.ip != ip {
			// A new sandbox reads anew, once the firewall knows it.
			st.ip, st.next = ip, time.Time{}
		}
		a.sb.mu.Unlock()
		if addr, err := netip.ParseAddr(ip); err == nil {
			a.setLocal(addr, id)
		}
	}
	if changed && a.cfg.Network != nil {
		// The firewall and the internal DNS know a sandbox before anything
		// is dialled from it.
		a.applyNetworkNow(ctx)
	}
	a.readSandboxes(ctx, want)
}

// readSandboxes starts the readings that are due, at most maxSandboxReads at
// a time, and waits for them.
func (a *Agent) readSandboxes(ctx context.Context, want map[string]*armadav1.QueueSandbox) {
	now := time.Now()
	type job struct {
		id    string
		probe *armadav1.QueueProbe
		every time.Duration
	}
	var due []job
	a.sb.mu.Lock()
	for id, w := range want {
		st := a.sb.have[id]
		if st == nil || st.ip == "" || st.busy {
			continue
		}
		if st.probe != nil && !sameProbe(st.probe, w.GetProbe()) {
			// Another queue or broker: the last length says nothing of it.
			st.measured, st.next = false, time.Time{}
		}
		if now.Before(st.next) {
			continue
		}
		st.busy = true
		due = append(due, job{id: id, probe: w.GetProbe(), every: a.sandboxInterval(w)})
	}
	a.sb.mu.Unlock()
	slices.SortFunc(due, func(x, y job) int { return cmp.Compare(x.id, y.id) })
	limit := make(chan struct{}, maxSandboxReads)
	var wg sync.WaitGroup
	for _, j := range due {
		limit <- struct{}{}
		wg.Go(func() {
			defer func() { <-limit }()
			n, err := a.readSandbox(ctx, j.id, j.probe)
			a.sb.mu.Lock()
			defer a.sb.mu.Unlock()
			st := a.sb.have[j.id]
			if st == nil {
				return
			}
			st.busy, st.next, st.probe = false, time.Now().Add(j.every), j.probe
			if err != nil {
				// Only the kind of failure: never the URL or what the broker sent.
				if msg := err.Error(); msg != st.failed {
					a.log.Warn("job queue not read", "job", j.id, "type", j.probe.GetType(), "err", err)
					st.failed = msg
				}
				return
			}
			if st.failed != "" {
				a.log.Info("job queue read again", "job", j.id)
				st.failed = ""
			}
			st.measured, st.length, st.at = true, n, time.Now()
			st.reading++
		})
	}
	wg.Wait()
}

func sameProbe(x, y *armadav1.QueueProbe) bool {
	return x.GetType() == y.GetType() && x.GetName() == y.GetName() && x.GetUrlRef() == y.GetUrlRef()
}

// sandboxInterval is how often a sandbox's queue is read: the trigger's
// polling interval, within its bounds, unless the agent sets its own.
func (a *Agent) sandboxInterval(w *armadav1.QueueSandbox) time.Duration {
	if a.cfg.SandboxInterval > 0 {
		return a.cfg.SandboxInterval
	}
	d := time.Duration(w.GetIntervalSeconds()) * time.Second
	return min(max(d, spec.MinPollingInterval), spec.MaxPollingInterval)
}

// readSandbox reads the job's queue from its sandbox.
func (a *Agent) readSandbox(ctx context.Context, id string, p *armadav1.QueueProbe) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, queueTimeout)
	defer cancel()
	sb, _ := a.cfg.Driver.(runtime.NetworkSandboxer)
	dial := a.namespaceDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		return sb.DialSandbox(ctx, id, network, address)
	})
	switch p.GetType() {
	case spec.ScaleRedis:
		return queuelen.RedisListLength(ctx, dial, p.GetUrl(), p.GetName())
	case spec.ScaleRabbitMQ:
		return queuelen.RabbitMQQueueLength(ctx, dial, p.GetUrl(), p.GetName())
	}
	return 0, errors.New("unknown queue type")
}

// sandboxReport is every sandbox with its address and, when one is recent,
// its latest reading, for a usage report.
func (a *Agent) sandboxReport(now time.Time) []*armadav1.SandboxQueue {
	a.sb.mu.Lock()
	defer a.sb.mu.Unlock()
	var out []*armadav1.SandboxQueue
	for id, st := range a.sb.have {
		w := a.sb.want[id]
		if st.ip == "" || w == nil {
			continue
		}
		q := &armadav1.SandboxQueue{Job: id, Ip: st.ip}
		// A reading counts for two intervals; then the leader goes without.
		if age := now.Sub(st.at); st.measured && age <= 2*a.sandboxInterval(w)+sandboxTick {
			q.Measured, q.Length, q.AgeMillis, q.Reading = true, st.length, max(0, age.Milliseconds()), st.reading
		}
		out = append(out, q)
	}
	slices.SortFunc(out, func(x, y *armadav1.SandboxQueue) int { return cmp.Compare(x.GetJob(), y.GetJob()) })
	return out
}

// setLocal and forgetLocal keep a sandbox's address among the node's own
// for the firewall and the internal DNS, until listLocal finds it next.
func (a *Agent) setLocal(ip netip.Addr, app string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.local == nil {
		a.local = map[netip.Addr]string{}
	}
	a.local[ip] = app
}

func (a *Agent) forgetLocal(ip string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.local, addr)
}

// localSandboxes adds the node's sandboxes to local, as addresses of their
// jobs.
func (a *Agent) localSandboxes(ctx context.Context, local map[netip.Addr]string) {
	if !a.sandboxesOn() {
		return
	}
	sb, _ := a.cfg.Driver.(runtime.NetworkSandboxer)
	list, err := sb.ListSandboxes(ctx)
	if err != nil {
		return
	}
	for _, s := range list {
		if ip, err := netip.ParseAddr(s.IP); err == nil && spec.ValidAppID(s.ID) {
			local[ip] = s.ID
		}
	}
}
