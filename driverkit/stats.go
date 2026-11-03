package driverkit

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	driverv1 "github.com/ryanbekhen/armada/api/armada/driver/v1"
)

// StatsReader samples what app containers use, for `armada top`
// (ADR 0018). Implementing it declares CAPABILITY_STATS.
type StatsReader interface {
	// Stats returns what container id uses now. The agent samples its
	// containers every few seconds, so it should be cheap: a single reading,
	// not a stream.
	Stats(ctx context.Context, id string) (Stats, error)
}

// Stats is what a container uses.
type Stats struct {
	// CPU is the CPU time the container used since it started; the agent
	// derives the rate from two samples.
	CPU time.Duration
	// MemoryBytes is the memory in use, without page cache the kernel can
	// reclaim.
	MemoryBytes int64
}

func (s *server) Stats(ctx context.Context, req *driverv1.StatsRequest) (*driverv1.StatsResponse, error) {
	sr, ok := s.d.(StatsReader)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "driver does not sample containers")
	}
	if err := checkID(req.GetId()); err != nil {
		return nil, err
	}
	st, err := sr.Stats(ctx, req.GetId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &driverv1.StatsResponse{CpuUsec: max(0, st.CPU.Microseconds()), MemoryBytes: max(0, st.MemoryBytes)}, nil
}
