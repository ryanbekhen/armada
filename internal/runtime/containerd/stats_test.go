package containerd

import (
	"testing"
	"time"

	cgroupstats "github.com/containerd/cgroups/v3/cgroup2/stats"
)

func TestStatsFromCgroup(t *testing.T) {
	t.Parallel()
	s := statsFromCgroup(&cgroupstats.Metrics{
		CPU:    &cgroupstats.CPUStat{UsageUsec: 2_500_000},
		Memory: &cgroupstats.MemoryStat{Usage: 100 << 20, InactiveFile: 30 << 20},
	})
	if s.CPU != 2500*time.Millisecond || s.MemoryBytes != 70<<20 {
		t.Errorf("stats = %+v", s)
	}
	// Reclaimable cache larger than the usage, and missing groups.
	if s := statsFromCgroup(&cgroupstats.Metrics{Memory: &cgroupstats.MemoryStat{Usage: 1, InactiveFile: 2}}); s.MemoryBytes != 0 || s.CPU != 0 {
		t.Errorf("stats = %+v", s)
	}
}
