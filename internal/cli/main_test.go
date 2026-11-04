package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/netip"
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
	newClusterNet = func(_ string, ac *agentConfig, _ *slog.Logger) (agent.Network, string, error) {
		if ac.Network == "" {
			return nil, "", nil
		}
		return testNets.get(ac.NodeID), testKey(ac.NodeID), nil
	}
	os.Exit(m.Run())
}

// testKey is a node's stand-in public key.
func testKey(node string) string {
	sum := sha256.Sum256([]byte(node))
	return base64.StdEncoding.EncodeToString(sum[:])
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

func (n *fakeNet) Apply(_ context.Context, cfg *armadav1.NetworkConfig, _ map[netip.Addr]string) error {
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
