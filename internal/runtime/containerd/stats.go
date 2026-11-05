package containerd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	cgroupstats "github.com/containerd/cgroups/v3/cgroup2/stats"
	"github.com/containerd/typeurl/v2"

	"github.com/ryanbekhen/armada/internal/runtime"
)

var _ runtime.StatsReader = (*Driver)(nil)

// Stats samples a container's cgroup (v2, which Armada requires) through
// its task's metrics. Memory is the cgroup's usage without inactive page
// cache, which the kernel reclaims before it kills anything.
func (d *Driver) Stats(ctx context.Context, id string) (runtime.Stats, error) {
	ctx = d.ctx(ctx)
	c, err := d.client.LoadContainer(ctx, id)
	if err != nil {
		return runtime.Stats{}, notFound(err)
	}
	t, err := c.Task(ctx, nil)
	if err != nil {
		return runtime.Stats{}, notFound(err)
	}
	m, err := t.Metrics(ctx)
	if err != nil {
		return runtime.Stats{}, notFound(err)
	}
	v, err := typeurl.UnmarshalAny(m.GetData())
	if err != nil {
		return runtime.Stats{}, fmt.Errorf("task metrics: %w", err)
	}
	cg, ok := v.(*cgroupstats.Metrics)
	if !ok {
		return runtime.Stats{}, fmt.Errorf("task metrics: unexpected type %T (cgroup v2 is required)", v)
	}
	st := statsFromCgroup(cg)
	// The counters are the network namespace's, which outlives what the
	// container does inside it; without them the rest of the sample stands.
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/dev", t.Pid())); err == nil {
		st.EgressBytes = egressFromNetDev(string(b))
	}
	return st, nil
}

// egressFromNetDev returns the bytes eth0 sent, from /proc/PID/net/dev: two
// header lines, then "name: " and 8 receive counters before the transmitted
// bytes.
func egressFromNetDev(netDev string) int64 {
	for line := range strings.Lines(netDev) {
		name, counters, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) != "eth0" {
			continue
		}
		f := strings.Fields(counters)
		if len(f) < 9 {
			return 0
		}
		n, err := strconv.ParseInt(f[8], 10, 64)
		if err != nil || n < 0 {
			return 0
		}
		return n
	}
	return 0
}

func statsFromCgroup(m *cgroupstats.Metrics) runtime.Stats {
	var s runtime.Stats
	if cpu := m.GetCPU(); cpu != nil {
		s.CPU = time.Duration(min(cpu.GetUsageUsec(), uint64(1<<63-1)/1000)) * time.Microsecond
	}
	if mem := m.GetMemory(); mem != nil {
		used := mem.GetUsage()
		if inactive := mem.GetInactiveFile(); inactive < used {
			used -= inactive
		} else {
			used = 0
		}
		s.MemoryBytes = int64(min(used, 1<<62))
	}
	return s
}
