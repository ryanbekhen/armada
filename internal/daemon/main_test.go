package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/agent"
	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/clientconfig/sshtest"
	"github.com/ryanbekhen/armada/internal/release"
)

// TestMain records the cluster network instead of setting it up on the host.
func TestMain(m *testing.M) {
	// Started by the client's SSH dialer, this binary acts as ssh.
	sshtest.Main()
	clientconfig.SSHProgram = os.Args[0]
	// No look for the latest release from tests.
	_ = os.Setenv(release.DisableEnv, "1")
	newClusterNet = func(_ string, ac *agentConfig, _ *slog.Logger) (agent.Network, string, error) {
		if ac.Network == "" {
			return nil, "", nil
		}
		return testNets.get(ac.NodeID), testKey(ac.NodeID), nil
	}
	// A mesh node's tunnel is recorded, not set up on the host.
	upMesh = func(dataDir string, ac *agentConfig, cfg *armadav1.NetworkConfig, _ *slog.Logger) error {
		if ac.Network == "mesh" {
			meshUps.Store(dataDir, cfg)
		}
		return nil
	}
	// No machine's interfaces decide what a test node announces.
	detectEndpoint = func() (netip.Addr, error) { return netip.Addr{}, errors.New("no public address in tests") }
	restartService = func(context.Context) (string, error) { return "", nil }
	// `armadad user renew` records the name in a stand-in for the state.
	recordUser = func(_ context.Context, dataDir, name string) error {
		recordedUsers.Store(dataDir+"/"+name, true)
		return nil
	}
	os.Exit(m.Run())
}

// meshUps holds the peer list each data dir's mesh tunnel came up with
// (nil: from the node's own list).
var meshUps sync.Map

// recordedUsers holds dataDir/name of every user `armadad user renew`
// recorded.
var recordedUsers sync.Map

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
