package cli

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// restartingAdmin is down for its first few calls of GetClusterConfig, as
// the leader is while it restarts its control plane.
type restartingAdmin struct {
	armadav1.AdminServiceClient
	down  int32
	calls atomic.Int32
}

func (f *restartingAdmin) GetClusterConfig(context.Context, *armadav1.GetClusterConfigRequest, ...grpc.CallOption) (*armadav1.ClusterConfig, error) {
	if f.calls.Add(1) <= f.down {
		return nil, status.Error(codes.Unavailable, "connection refused")
	}
	return &armadav1.ClusterConfig{}, nil
}

func TestWaitForAPI(t *testing.T) {
	t.Parallel()
	f := &restartingAdmin{down: 2}
	if err := waitForAPI(context.Background(), f, time.Millisecond, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if n := f.calls.Load(); n != 3 {
		t.Errorf("asked %d times, want 3 (two refused, then an answer)", n)
	}

	never := &restartingAdmin{down: 1 << 30}
	err := waitForAPI(context.Background(), never, time.Millisecond, 700*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "settings are saved") {
		t.Errorf("no answer = %v", err)
	}
}
