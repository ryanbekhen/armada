package containerd

import (
	"context"
	"fmt"
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
	return statsFromCgroup(cg), nil
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
