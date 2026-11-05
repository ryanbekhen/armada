package server

import (
	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
)

// quotaFrom converts a quota from the API; nil is no quota. Callers check
// it with spec.CheckQuota.
func quotaFrom(q *armadav1.Quota) spec.Quota {
	if q == nil {
		return spec.Quota{}
	}
	return spec.Quota{CPUMillis: q.GetCpuMillis(), MemoryBytes: q.GetMemoryBytes(), Replicas: int(q.GetReplicas()),
		Volumes: int(q.GetVolumes()), Domains: int(q.GetDomains()), Secrets: int(q.GetSecrets()), Jobs: int(q.GetJobs()),
		EgressBits: q.GetEgressBits(), RequestRate: int(q.GetRequestRate()), Connections: int(q.GetConnections())}
}

// quotaProto converts a quota or a usage for the API. Counts are bounded
// by spec.CheckQuota (quotas) and by the store's limits (usage).
func quotaProto(q spec.Quota) *armadav1.Quota {
	return &armadav1.Quota{CpuMillis: q.CPUMillis, MemoryBytes: q.MemoryBytes,
		Replicas: int32(q.Replicas), Volumes: int32(q.Volumes), Domains: int32(q.Domains), //nolint:gosec // bounded, see above
		Secrets: int32(q.Secrets), Jobs: int32(q.Jobs), EgressBits: q.EgressBits, //nolint:gosec // bounded, see above
		RequestRate: int32(q.RequestRate), Connections: int32(q.Connections)} //nolint:gosec // bounded, see above
}
