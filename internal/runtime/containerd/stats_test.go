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

func TestEgressFromNetDev(t *testing.T) {
	t.Parallel()
	const header = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
`
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{header + "    lo:    100       1    0    0    0     0          0         0      900       1    0    0    0     0       0          0\n" +
			"  eth0: 12345      10    0    0    0     0          0         0    67890      11    0    0    0     0       0          0\n", 67890},
		{header + "    lo:    100       1    0    0    0     0          0         0      900       1    0    0    0     0       0          0\n", 0},
		{header + "  eth0: 1 2 3\n", 0},
		{header + "  eth0: 1 2 3 4 5 6 7 8 nope 10\n", 0},
		{header + "  eth0: 1 2 3 4 5 6 7 8 -9 10\n", 0},
		{"", 0},
	} {
		if got := egressFromNetDev(tc.in); got != tc.want {
			t.Errorf("%q: got %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestHasInterface(t *testing.T) {
	t.Parallel()
	header := "Inter-|   Receive\n face |bytes\n"
	if !hasInterface(header + "    lo: 0 0\n  eth0: 1 2\n") {
		t.Error("eth0 not found")
	}
	if hasInterface(header + "    lo: 0 0\n") {
		t.Error("found eth0 with only loopback")
	}
}
