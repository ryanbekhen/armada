package remote

import (
	"context"
	"errors"
	"time"

	driverv1 "github.com/ryanbekhen/armada/api/armada/driver/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

var _ runtime.StatsReader = (*Driver)(nil)

// CanStats reports whether the driver samples what containers use.
func (d *Driver) CanStats() bool { return d.has(driverv1.Capability_CAPABILITY_STATS) }

// Stats samples what an app container uses through the driver.
func (d *Driver) Stats(ctx context.Context, id string) (runtime.Stats, error) {
	if !d.CanStats() {
		return runtime.Stats{}, errors.New("the node's runtime driver does not sample containers")
	}
	r, err := d.client.Stats(ctx, &driverv1.StatsRequest{Id: id})
	if err != nil {
		return runtime.Stats{}, wrap(err)
	}
	// Self-reported by the driver: negative values mean nothing.
	return runtime.Stats{
		CPU:         time.Duration(max(0, min(r.GetCpuUsec(), maxCPUUsec))) * time.Microsecond,
		MemoryBytes: max(0, r.GetMemoryBytes()),
	}, nil
}

// maxCPUUsec keeps the conversion to a time.Duration from overflowing.
const maxCPUUsec = int64(1<<63-1) / int64(time.Microsecond)
