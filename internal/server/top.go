package server

import (
	"context"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

const (
	// usageMaxAge is how long a node's usage sample counts: a few of its
	// agent's 10-second intervals (ADR 0018).
	usageMaxAge = 35 * time.Second
	// maxUsageReplicas bounds the replicas in one usage report; a node with
	// more is reported as unmeasured.
	maxUsageReplicas = 1024
	maxReplicaIDLen  = 128
)

// usageStore keeps the latest usage sample from each node, in memory only:
// it is cheap to lose, and a new leader has samples again after one agent
// interval.
type usageStore struct {
	mu    sync.Mutex
	nodes map[string]nodeUsage
}

type nodeUsage struct {
	at       time.Time
	replicas map[string]replicaUsage
}

type replicaUsage struct {
	cpu int64 // millicores
	mem int64 // bytes
}

func newUsageStore() *usageStore { return &usageStore{nodes: map[string]nodeUsage{}} }

// set replaces nodeID's sample. Reports are self-reported and untrusted:
// values are bounded, and a report with too many replicas is dropped. Which
// replicas belong to the node is only checked when the sample is read, so
// a report costs no store access.
func (u *usageStore) set(nodeID string, r *armadav1.UsageReport, at time.Time) {
	if len(r.GetReplicas()) > maxUsageReplicas {
		u.forget(nodeID)
		return
	}
	reps := make(map[string]replicaUsage, len(r.GetReplicas()))
	for _, ru := range r.GetReplicas() {
		if id := ru.GetId(); id != "" && len(id) <= maxReplicaIDLen {
			reps[id] = replicaUsage{
				cpu: max(0, min(ru.GetCpuMillis(), maxNodeCPUMillis)),
				mem: max(0, min(ru.GetMemoryBytes(), maxNodeMemory)),
			}
		}
	}
	u.mu.Lock()
	u.nodes[nodeID] = nodeUsage{at: at, replicas: reps}
	u.mu.Unlock()
}

func (u *usageStore) forget(nodeID string) {
	u.mu.Lock()
	delete(u.nodes, nodeID)
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

// Top reports what replicas use from the latest samples of their nodes
// (ADR 0018). A replica's usage only counts when it comes from the node the
// replica is assigned to.
func (s *Server) Top(ctx context.Context, req *armadav1.TopRequest) (*armadav1.TopResponse, error) {
	filter := store.ReplicaFilter{}
	if req.GetApp() != "" {
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
	reps = slices.DeleteFunc(reps, func(r store.Replica) bool { return r.Done })
	now := s.now()
	revs := &revisionCache{store: s.store, m: map[string]store.Revision{}}
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
	return resp, nil
}
