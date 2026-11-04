package cli

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/agent"
)

// TestMain runs the tests as on Linux, also on a macOS development
// machine, and never mounts a RAM disk there; macOS behaviour is tested
// through the functions that take the system as an argument. The cluster
// network is recorded instead of set up on the host.
func TestMain(m *testing.M) {
	goos = "linux"
	prepareSecretsDisk = func(string) error { return nil }
	newClusterNet = func(ac *agentConfig, _ *slog.Logger) (agent.Network, error) {
		if ac.Network == "" {
			return nil, nil
		}
		return testNets.get(ac.NodeID), nil
	}
	os.Exit(m.Run())
}

// fakeNets holds the cluster network each test node last applied.
type fakeNets struct {
	mu   sync.Mutex
	nets map[string]*fakeNet
}

var testNets = &fakeNets{nets: map[string]*fakeNet{}}

func (f *fakeNets) get(node string) *fakeNet {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nets[node] == nil {
		f.nets[node] = &fakeNet{}
	}
	return f.nets[node]
}

type fakeNet struct {
	mu   sync.Mutex
	last *armadav1.NetworkConfig
}

func (n *fakeNet) Apply(_ context.Context, cfg *armadav1.NetworkConfig) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.last = proto.CloneOf(cfg)
	return nil
}

func (n *fakeNet) applied() *armadav1.NetworkConfig {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.last
}
