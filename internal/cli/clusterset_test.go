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

// cluster status shows a network switch and the nodes it waits for.
func TestPrintClusterStatusSwitch(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	err := printClusterStatus(&b, &armadav1.ClusterStatusResponse{Nodes: 3, NodesReady: 3, NetworkSwitch: &armadav1.NetworkSwitchProgress{
		From: "plain", To: "wireguard", Step: "prepare", SinceUnix: 1_700_000_000, WaitingTotal: 4,
		Waiting: []*armadav1.NodeSwitchWait{
			{Node: "n1", Unreached: []string{"n2", "n3"}},
			{Node: "n2", Unsupported: true},
			{Node: "n3", Error: "no WireGuard\x1b[2J"},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"switching from plain to wireguard, bringing it up beside plain", "a path to n2, n3", "an upgrade", "no WireGuard", "and 1 more"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing:\n%s", want, out)
		}
	}
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("control character printed:\n%q", out)
	}
}
