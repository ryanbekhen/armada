package cli

import (
	"strconv"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
)

// parseQuotaFlag parses --quota for the API: "none" is an empty quota,
// which removes one.
func parseQuotaFlag(s string) (*armadav1.Quota, error) {
	q, err := spec.ParseQuota(s)
	if err != nil {
		return nil, err
	}
	return &armadav1.Quota{CpuMillis: q.CPUMillis, MemoryBytes: q.MemoryBytes, Replicas: int32(q.Replicas), //nolint:gosec // bounded by ParseQuota
		Volumes: int32(q.Volumes), Domains: int32(q.Domains), Secrets: int32(q.Secrets), Jobs: int32(q.Jobs), //nolint:gosec // bounded by ParseQuota
		EgressBits: q.EgressBits, RequestRate: int32(q.RequestRate), Connections: int32(q.Connections)}, nil //nolint:gosec // bounded by ParseQuota
}

func quotaOf(q *armadav1.Quota) spec.Quota {
	return spec.Quota{CPUMillis: q.GetCpuMillis(), MemoryBytes: q.GetMemoryBytes(), Replicas: int(q.GetReplicas()),
		Volumes: int(q.GetVolumes()), Domains: int(q.GetDomains()), Secrets: int(q.GetSecrets()), Jobs: int(q.GetJobs()),
		EgressBits: q.GetEgressBits(), RequestRate: int(q.GetRequestRate()), Connections: int(q.GetConnections())}
}

// quotaHelp describes --quota.
const quotaHelp = "quota KEY=VALUE,... with cpu, memory, replicas, volumes, domains, secrets, jobs, egress (bits per second per replica, such as 100M), requests and connections (per app at each node; none removes it)"

// quotaRows lists every resource with what is used and its limit ("-" for
// unlimited).
func quotaRows(used, quota spec.Quota) [][3]string {
	limit := func(n int64, s string) string {
		if n == 0 {
			return "-"
		}
		return s
	}
	count := func(n int) string { return strconv.Itoa(n) }
	return [][3]string{
		{"cpu", spec.FormatCPUMillis(used.CPUMillis), limit(quota.CPUMillis, spec.FormatCPUMillis(quota.CPUMillis))},
		{"memory", spec.FormatMemory(used.MemoryBytes), limit(quota.MemoryBytes, spec.FormatMemory(quota.MemoryBytes))},
		{"replicas", count(used.Replicas), limit(int64(quota.Replicas), count(quota.Replicas))},
		{"volumes", count(used.Volumes), limit(int64(quota.Volumes), count(quota.Volumes))},
		{"domains", count(used.Domains), limit(int64(quota.Domains), count(quota.Domains))},
		{"secrets", count(used.Secrets), limit(int64(quota.Secrets), count(quota.Secrets))},
		{"job attempts", count(used.Jobs), limit(int64(quota.Jobs), count(quota.Jobs))},
		{"egress per replica", "-", limit(quota.EgressBits, spec.FormatBitRate(quota.EgressBits)+"bit/s")},
		{"requests per app", "-", limit(int64(quota.RequestRate), count(quota.RequestRate)+"/s per node")},
		{"connections per app", "-", limit(int64(quota.Connections), count(quota.Connections)+" per node")},
	}
}
