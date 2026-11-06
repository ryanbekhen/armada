package server

import (
	"context"
	"fmt"

	"github.com/ryanbekhen/armada/internal/store"
)

// What Armada keeps for itself before a node's capacity is shared out to
// replicas: the agent, containerd, and HAProxy on every node, and the
// control plane (with etcd) on server machines.
const (
	systemCPUMillis   = 100
	systemMemoryBytes = 128 << 20
	serverCPUMillis   = 100
)

// maxSubnetReplicas is how many replicas a node with its own container subnet
// takes. A /24 has 253 addresses for containers; the rest leave room for a
// container whose replica is gone but whose address is not free yet.
const maxSubnetReplicas = 250

// resources is what a replica reserves on its node, or what a node has.
type resources struct {
	cpu int64 // millicores
	mem int64 // bytes
}

func (r resources) String() string {
	return fmt.Sprintf("%s of CPU and %s of memory", humanCPU(r.cpu), humanMemory(r.mem))
}

// allocatable returns copies of nodes with the capacity left for replicas:
// what each reports minus what Armada keeps. A node too small to keep
// anything for replicas gets a capacity of 1 rather than 0, which means
// unknown and would skip the check.
func (s *Server) allocatable(ctx context.Context, nodes []store.Node) ([]store.Node, error) {
	servers, err := s.store.ListServers(ctx)
	if err != nil {
		return nil, err
	}
	isServer := map[string]bool{}
	for _, sv := range servers {
		isServer[sv.PrivateIP] = true
	}
	out := make([]store.Node, len(nodes))
	for i, n := range nodes {
		cpu := int64(systemCPUMillis)
		if isServer[n.PrivateIP] {
			cpu += serverCPUMillis
		}
		if n.CPUMillis > 0 {
			n.CPUMillis = max(1, n.CPUMillis-cpu)
		}
		if n.MemoryBytes > 0 {
			n.MemoryBytes = max(1, n.MemoryBytes-systemMemoryBytes)
		}
		out[i] = n
	}
	return out, nil
}

// replicasFull reports whether n's container subnet has no address to spare
// for another replica. A finished job attempt holds none: its address is freed
// when it stops.
func replicasFull(n store.Node, replicas []store.Replica) bool {
	if n.Subnet == "" {
		return false
	}
	used := 0
	for _, r := range replicas {
		if r.NodeID == n.ID && !r.Done {
			used++
		}
	}
	return used >= maxSubnetReplicas
}

func humanCPU(m int64) string {
	if m%1000 == 0 {
		return fmt.Sprintf("%d", m/1000)
	}
	return fmt.Sprintf("%dm", m)
}
