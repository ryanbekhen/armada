package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ryanbekhen/armada/internal/agent"
	"github.com/ryanbekhen/armada/internal/fsutil"
)

// Data directory layout. Every file holding key material is mode 0600 and
// the directory itself is 0700.
const (
	defaultPort    = 7443
	fileCACert     = "ca.crt"
	fileCAKey      = "ca.key"
	fileServerCert = "server.crt"
	fileServerKey  = "server.key"
	fileNodeCert   = "node.crt"
	fileNodeKey    = "node.key"
	fileAgent      = "agent.json"
	// fileNetworkKey is the node's WireGuard key (ADR 0025).
	fileNetworkKey = "network.key"
	dirEtcd        = "etcd"
	fileEtcdKey    = "etcd/member.key"
	// fileEtcdInitial holds the etcd members of the cluster a server joins,
	// until its member first starts.
	fileEtcdInitial = "etcd/initial-cluster"
	fileMasterKey   = "master.key"
	metaCluster     = "cluster"
	metaMasterKey   = "master_key_id"
)

// proxyStartWait is how long the agent waits to confirm HAProxy stays up
// after starting it. Tests shorten it.
var proxyStartWait = 2 * time.Second

// checkTmpfs verifies the agent's secrets directory; tests replace it.
var checkTmpfs = agent.CheckTmpfs

// renewCheck is how often the agent checks whether its certificate needs
// renewal; tests shorten it.
var renewCheck = time.Hour

// probeCheck runs the agent's health checks; tests replace it because fake
// containers have nothing listening.
var probeCheck = agent.DefaultCheck

// agentConfig is what a node's agent needs besides its certificate.
type agentConfig struct {
	NodeID    string `json:"nodeId"`
	PrivateIP string `json:"privateIp"`
	// Servers are the control plane API addresses; the agent keeps them up
	// to date from its assignments.
	Servers []string `json:"servers"`
	// Runtime is the node's container runtime, "embedded" (checkRuntime).
	Runtime string `json:"runtime,omitempty"`
	// ContainerSubnet is the embedded runtime's bridge subnet.
	ContainerSubnet string `json:"containerSubnet,omitempty"`
	// Network is the cluster network's mode (ADR 0025), "plain"; empty in
	// clusters without one.
	Network string `json:"network,omitempty"`
}

func saveAgentConfig(dataDir string, c agentConfig) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dataDir, fileAgent), append(b, '\n'), 0o600)
}

func loadAgentConfig(dataDir string) (*agentConfig, error) {
	b, err := fsutil.ReadPrivateFile(filepath.Join(dataDir, fileAgent))
	if err != nil {
		return nil, err
	}
	var c agentConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", fileAgent, err)
	}
	if len(c.Servers) == 0 {
		return nil, fmt.Errorf("%s lists no control plane address", fileAgent)
	}
	return &c, nil
}

func readPrivate(dataDir string, names ...string) ([][]byte, error) {
	out := make([][]byte, 0, len(names))
	for _, n := range names {
		b, err := fsutil.ReadPrivateFile(filepath.Join(dataDir, n))
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// nextStep tells the operator how to start role ("server" or "agent") after
// init or join: the systemd unit from install.sh when the default data
// directory is used, the foreground command otherwise.
func nextStep(role, dataDir string) string {
	if dataDir == defaultDataDir {
		return fmt.Sprintf("Next: sudo systemctl enable --now armada-%s\n", role)
	}
	return fmt.Sprintf("Next: armadad %s --data-dir %s\n", role, dataDir)
}

// lockDataDir refuses a second agent on a data directory. Two agents with one
// node's identity take turns on the server's connection and start and remove
// each other's containers. The kernel releases the lock when the process ends.
func lockDataDir(dir string) (unlock func(), err error) {
	f, err := os.Open(dir) // #nosec G304 -- the operator's data directory
	if err != nil {
		return nil, fmt.Errorf("open data directory: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("another agent is using %s: `armadad server` already runs this node's agent, so do not also start `armadad agent` here", dir)
		}
		return nil, fmt.Errorf("lock data directory: %w", err)
	}
	return func() { _ = f.Close() }, nil
}
