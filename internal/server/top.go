package server

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/proxy"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

const (
	// usageMaxAge is how long a node's usage sample counts: a few of its
	// agent's 10-second intervals (ADR 0016).
	usageMaxAge = 35 * time.Second
	// maxUsageReplicas bounds the replicas in one usage report; a node with
	// more is reported as unmeasured.
	maxUsageReplicas = 1024
	maxReplicaIDLen  = 128
	// maxInFlight bounds one node's count of requests in progress for a
	// replica.
	maxInFlight = 1_000_000
	// maxConntrack bounds a node's reported connection tracking numbers.
	maxConntrack = 1 << 32
	// maxQueueLength bounds a reported queue length (ADR 0034).
	maxQueueLength = 1 << 40
	// maxReportRequests and maxReportEgress bound what one report adds to a
	// project's counters for one replica.
	maxReportRequests = 1 << 30
	maxReportEgress   = 1 << 40
)

// usageStore keeps the latest usage sample from each node, in memory only:
// it is cheap to lose, and a new leader has samples again after one agent
// interval.
type usageStore struct {
	mu    sync.Mutex
	nodes map[string]nodeUsage
	// active is when a proxy last reported a request for a replica (ADR
	// 0021), kept across reports so none is missed between evaluations.
	active map[string]time.Time
	// volumes is each node's latest volume measurement (ADR 0023).
	volumes map[string]volumeUsage
	// owners says which project and node each replica belongs to, from the
	// reconciler's latest pass, so a report costs no store access.
	owners map[string]replicaOwner
	// totals counts requests and egress per project since since. Replicas
	// come and go, so the sums are kept here, not derived when read.
	totals map[string]projectTotals
	since  time.Time
}

type replicaOwner struct{ project, app, node string }

type projectTotals struct{ requests, egress int64 }

// maxActive bounds usageStore.active.
const maxActive = 8192

type nodeUsage struct {
	at       time.Time
	replicas map[string]replicaUsage
	// load is the requests in progress at the node's proxy per replica,
	// for any replica, if loadMeasured (ADR 0020).
	load         map[string]int64
	loadMeasured bool
	// conntrackEntries and conntrackMax are the node's connection tracking
	// table; conntrackMax is 0 when unknown (ADR 0025).
	conntrackEntries int64
	conntrackMax     int64
	// queues is the length each queue rule read, by the replica it was
	// read from and the rule's type (ADR 0034).
	queues map[queueKey]int64
}

// queueKey names a queue reading: the replica it came from and the rule.
type queueKey struct{ replica, typ string }

type replicaUsage struct {
	cpu int64 // millicores
	mem int64 // bytes
}

func newUsageStore() *usageStore {
	return &usageStore{
		nodes: map[string]nodeUsage{}, active: map[string]time.Time{}, volumes: map[string]volumeUsage{},
		owners: map[string]replicaOwner{}, totals: map[string]projectTotals{},
	}
}

// set replaces nodeID's sample. Reports are self-reported and untrusted:
// values are bounded, and a report with too many replicas is dropped. Which
// replicas belong to the node is only checked when the sample is read, so
// a report costs no store access.
func (u *usageStore) set(nodeID string, r *armadav1.UsageReport, at time.Time) {
	if len(r.GetReplicas()) > maxUsageReplicas {
		u.forget(nodeID)
		return
	}
	// Load covers every replica the node's proxy routes to, across the
	// cluster: too much of it makes the load unmeasured, not the node.
	measured := r.GetLoadMeasured() && len(r.GetLoad()) <= proxy.MaxLoadEntries
	reps := make(map[string]replicaUsage, len(r.GetReplicas()))
	for _, ru := range r.GetReplicas() {
		if id := ru.GetId(); id != "" && len(id) <= maxReplicaIDLen {
			reps[id] = replicaUsage{
				cpu: max(0, min(ru.GetCpuMillis(), maxNodeCPUMillis)),
				mem: max(0, min(ru.GetMemoryBytes(), maxNodeMemory)),
			}
		}
	}
	var load map[string]int64
	var busy []string
	if measured {
		load = make(map[string]int64, len(r.GetLoad()))
		for _, l := range r.GetLoad() {
			if id := l.GetId(); id != "" && len(id) <= maxReplicaIDLen {
				load[id] = max(0, min(l.GetInFlight(), maxInFlight))
				if l.GetInFlight() > 0 || l.GetRequests() > 0 {
					busy = append(busy, id)
				}
			}
		}
	}
	var queues map[queueKey]int64
	if q := r.GetQueues(); len(q) > 0 && len(q) <= maxUsageReplicas {
		queues = make(map[queueKey]int64, len(q))
		for _, l := range q {
			if id, typ := l.GetId(), l.GetType(); id != "" && len(id) <= maxReplicaIDLen && len(typ) <= 16 {
				if typ == "" {
					typ = spec.ScaleQueue
				}
				queues[queueKey{id, typ}] = max(0, min(l.GetLength(), maxQueueLength))
			}
		}
	}
	u.mu.Lock()
	u.count(nodeID, r)
	for _, id := range busy {
		u.active[id] = at
	}
	if len(u.active) > maxActive {
		for id, t := range u.active {
			if at.Sub(t) > spec.MaxIdleAfter || len(u.active) > maxActive {
				delete(u.active, id)
			}
		}
	}
	u.nodes[nodeID] = nodeUsage{
		at: at, replicas: reps, load: load, loadMeasured: measured,
		conntrackEntries: max(0, min(r.GetConntrackEntries(), maxConntrack)),
		conntrackMax:     max(0, min(r.GetConntrackMax(), maxConntrack)),
		queues:           queues,
	}
	u.mu.Unlock()
}

// count adds a report to the project counters; u.mu is held. Egress counts
// only from a replica's own node. Requests count from every node's proxy,
// like the load of ADR 0020.
func (u *usageStore) count(nodeID string, r *armadav1.UsageReport) {
	for _, ru := range r.GetReplicas() {
		if o, ok := u.owners[ru.GetId()]; ok && o.node == nodeID {
			t := u.totals[o.project]
			t.egress = saturatingAdd(t.egress, max(0, min(ru.GetEgressBytes(), maxReportEgress)))
			u.totals[o.project] = t
		}
	}
	if !r.GetLoadMeasured() {
		return
	}
	for _, l := range r.GetLoad() {
		if o, ok := u.owners[l.GetId()]; ok {
			t := u.totals[o.project]
			t.requests = saturatingAdd(t.requests, max(0, min(l.GetRequests(), maxReportRequests)))
			u.totals[o.project] = t
		}
	}
}

// Bounds on what a report says about processes killed at the memory limit.
const (
	maxOOMEvents = 8
	maxOOMReport = 1 << 20
)

// outOfMemory returns an event for each replica of nodeID whose processes the
// kernel killed at the memory limit since the previous report. The container
// lives on when that was not its main process, so nothing else would show it.
func (u *usageStore) outOfMemory(nodeID string, r *armadav1.UsageReport) []store.Event {
	var out []store.Event
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, ru := range r.GetReplicas() {
		if ru.GetOomKills() <= 0 || len(out) == maxOOMEvents {
			continue
		}
		if o, ok := u.owners[ru.GetId()]; ok && o.node == nodeID {
			out = append(out, store.Event{
				Kind: eventReplica, Reason: "OutOfMemory", Object: ru.GetId(), App: o.app, Node: nodeID,
				Message: fmt.Sprintf("processes killed at the memory limit: %d", min(ru.GetOomKills(), maxOOMReport)),
			})
		}
	}
	return out
}

func saturatingAdd(a, b int64) int64 {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// setOwners replaces what reports are counted against. Counting starts with
// the first call.
func (u *usageStore) setOwners(reps []store.Replica, now time.Time) {
	owners := make(map[string]replicaOwner, len(reps))
	for _, r := range reps {
		if p, _, ok := spec.SplitAppID(r.App); ok {
			owners[r.ID] = replicaOwner{project: p, app: r.App, node: r.NodeID}
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.owners = owners
	if u.since.IsZero() {
		u.since = now
	}
}

// projectTotals returns a project's counters and when counting began.
func (u *usageStore) projectTotals(project string) (projectTotals, time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.totals[project], u.since
}

// forgetProject drops a removed project's counters.
func (u *usageStore) forgetProject(project string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.totals, project)
}

func (u *usageStore) forget(nodeID string) {
	u.mu.Lock()
	delete(u.nodes, nodeID)
	delete(u.volumes, nodeID)
	u.mu.Unlock()
}

// node returns nodeID's sample if it is recent.
func (u *usageStore) node(nodeID string, now time.Time) (nodeUsage, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	n, ok := u.nodes[nodeID]
	if !ok || now.Sub(n.at) > usageMaxAge {
		return nodeUsage{}, false
	}
	return n, true
}

// lastActive returns when a proxy last reported a request for any of ids.
func (u *usageStore) lastActive(ids []string) time.Time {
	u.mu.Lock()
	defer u.mu.Unlock()
	var last time.Time
	for _, id := range ids {
		if t := u.active[id]; t.After(last) {
			last = t
		}
	}
	return last
}

// load sums the requests in progress per replica over every node whose
// proxy was read recently. ok is false if no node's proxy was.
func (u *usageStore) load(now time.Time) (map[string]int64, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	out, ok := map[string]int64{}, false
	for _, n := range u.nodes {
		if !n.loadMeasured || now.Sub(n.at) > usageMaxAge {
			continue
		}
		ok = true
		for id, v := range n.load {
			out[id] += v
		}
	}
	return out, ok
}

// Top reports what replicas use from the latest samples of their nodes
// (ADR 0016). A replica's usage only counts when it comes from the node the
// replica is assigned to.
func (s *Server) Top(ctx context.Context, req *armadav1.TopRequest) (*armadav1.TopResponse, error) {
	acc := accessFrom(ctx)
	filter := store.ReplicaFilter{}
	if req.GetApp() != "" {
		if err := acc.app(req.GetApp()); err != nil {
			return nil, err
		}
		if _, err := s.store.GetApp(ctx, req.GetApp()); err != nil {
			return nil, storeErr(err)
		}
		filter.App = req.GetApp()
	}
	reps, err := s.store.ListReplicas(ctx, filter)
	if err != nil {
		return nil, storeErr(err)
	}
	// Finished job attempts keep a stopped container for their logs only.
	reps = slices.DeleteFunc(reps, func(r store.Replica) bool { return r.Done || !acc.sees(r.App) })
	now := s.now()
	revs := &revisionCache{store: s.store, m: map[string]store.Revision{}}
	revs.preload(ctx, nil, reps)
	reserved := revs.reserved(ctx)

	resp := &armadav1.TopResponse{}
	for _, r := range reps {
		rt := &armadav1.ReplicaTop{Id: r.ID, App: r.App, NodeId: r.NodeID, State: r.State}
		if rev, err := revs.get(ctx, r.Revision); err == nil {
			res := reservation(rev)
			rt.CpuReservedMillis, rt.MemoryLimitBytes = res.cpu, res.mem
			if rev.Spec.NanoCPUs() > 0 {
				rt.CpuLimitMillis = res.cpu
			}
		}
		if n, ok := s.usage.node(r.NodeID, now); ok {
			if ru, ok := n.replicas[r.ID]; ok {
				rt.Measured, rt.CpuMillis, rt.MemoryBytes = true, ru.cpu, ru.mem
				rt.SampledAt = timestamppb.New(n.at)
			}
		}
		resp.Replicas = append(resp.Replicas, rt)
	}
	if req.GetApp() != "" {
		return resp, nil
	}
	if err := s.topProjects(ctx, acc, resp, now); err != nil {
		return nil, storeErr(err)
	}

	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	alloc, err := s.allocatable(ctx, nodes)
	if err != nil {
		return nil, storeErr(err)
	}
	for _, n := range alloc {
		nt := &armadav1.NodeTop{Id: n.ID, CpuAllocatableMillis: n.CPUMillis, MemoryAllocatableBytes: n.MemoryBytes}
		sample, measured := s.usage.node(n.ID, now)
		nt.Measured = measured
		nt.ConntrackEntries, nt.ConntrackMax = sample.conntrackEntries, sample.conntrackMax
		for _, r := range reps {
			if r.NodeID != n.ID {
				continue
			}
			nt.Replicas++
			res := reserved(r)
			nt.CpuReservedMillis += res.cpu
			nt.MemoryReservedBytes += res.mem
			if ru, ok := sample.replicas[r.ID]; ok {
				nt.CpuMillis += ru.cpu
				nt.MemoryBytes += ru.mem
			}
		}
		resp.Nodes = append(resp.Nodes, nt)
	}
	if !acc.admin() {
		resp.Nodes = nil
	}
	return resp, nil
}

// topProjects adds up what the replicas in resp use per project, for the
// projects the caller may manage (ADR 0026).
func (s *Server) topProjects(ctx context.Context, acc access, resp *armadav1.TopResponse, now time.Time) error {
	ps, err := s.store.ListProjects(ctx)
	if err != nil {
		return err
	}
	vols, err := s.store.ListVolumes(ctx, "")
	if err != nil {
		return err
	}
	byName := make(map[string]*armadav1.ProjectTop, len(ps))
	for _, p := range ps {
		if acc.project(p.Name) != nil {
			continue
		}
		totals, since := s.usage.projectTotals(p.Name)
		pt := &armadav1.ProjectTop{Name: p.Name, Requests: totals.requests, EgressBytes: totals.egress}
		byName[p.Name] = pt
		resp.Projects = append(resp.Projects, pt)
		if !since.IsZero() {
			resp.CountedSince = timestamppb.New(since)
		}
	}
	for _, r := range resp.GetReplicas() {
		p, _, _ := spec.SplitAppID(r.GetApp())
		pt := byName[p]
		if pt == nil {
			continue
		}
		pt.Replicas++
		pt.CpuReservedMillis += r.GetCpuReservedMillis()
		pt.MemoryReservedBytes += r.GetMemoryLimitBytes()
		if r.GetMeasured() {
			pt.Measured++
			pt.CpuMillis += r.GetCpuMillis()
			pt.MemoryBytes += r.GetMemoryBytes()
		}
	}
	for _, v := range vols {
		p, _, _ := spec.SplitAppID(v.App)
		if pt := byName[p]; pt != nil {
			if b, ok := s.usage.volume(v.Node, v.App, v.Name, now); ok {
				pt.VolumeBytes += b
			}
		}
	}
	return nil
}
