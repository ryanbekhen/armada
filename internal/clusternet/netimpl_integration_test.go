//go:build integration && linux

package clusternet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// netImpl is the cluster network one node of the integration tests runs:
// this package's Net, or, with ARMADA_NET_IMPL=rust, armada-node's (ADR
// 0054), which ARMADA_NODE_BIN names. Each method runs on a thread in the
// node's network namespace (switchNode.in), which armada-node inherits.
type netImpl interface {
	Apply(ctx context.Context, cfg *armadav1.NetworkConfig, local map[netip.Addr]string) error
	Up(cfg *armadav1.NetworkConfig) error
	SwitchStatus() *armadav1.NetworkSwitchStatus
}

// newNetImpl returns the node's cluster network in the implementation
// ARMADA_NET_IMPL picks.
func newNetImpl(t *testing.T, cfg Config) netImpl {
	t.Helper()
	if os.Getenv("ARMADA_NET_IMPL") != "rust" {
		n, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	return newRustNet(t, cfg)
}

func newRustNet(t *testing.T, cfg Config) *rustNet {
	t.Helper()
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		t.Fatal("ARMADA_NET_IMPL=rust needs ARMADA_NODE_BIN (make node)")
	}
	return &rustNet{t: t, bin: bin, cfg: cfg, state: json.RawMessage("null")}
}

// rustNet runs armada-node net apply and net up, keeping between passes
// the state Go's Net keeps in memory.
type rustNet struct {
	t     *testing.T
	bin   string
	cfg   Config
	state json.RawMessage
	sw    *armadav1.NetworkSwitchStatus
	// done is what the last pass changed.
	done []string
}

// rustAnswer is what armada-node net apply and net up print.
type rustAnswer struct {
	Error          string          `json:"error"`
	NeedsUserspace bool            `json:"needsUserspace"`
	State          json.RawMessage `json:"state"`
	Switch         *struct {
		To        string   `json:"to"`
		Step      string   `json:"step"`
		Ready     bool     `json:"ready"`
		Unreached []string `json:"unreached"`
		Error     string   `json:"error"`
	} `json:"switch"`
	Done []string `json:"done"`
	Log  []string `json:"log"`
}

// errNeedsUserspace: armada-node leaves the userspace WireGuard device to
// the Go agent.
var errNeedsUserspace = errors.New("armada-node: the pass needs the userspace WireGuard device")

func (r *rustNet) run(op string, cfg *armadav1.NetworkConfig, local map[netip.Addr]string) error {
	config := json.RawMessage("null")
	if cfg != nil {
		b, err := protojson.Marshal(cfg)
		if err != nil {
			return err
		}
		config = b
	}
	key, endpoint := "", ""
	if !r.cfg.Key.IsZero() {
		key = r.cfg.Key.k.String()
	}
	if r.cfg.Endpoint.IsValid() {
		endpoint = r.cfg.Endpoint.String()
	}
	in, err := json.Marshal(map[string]any{"Config": config, "Node": r.cfg.Node, "PrivateIP": r.cfg.PrivateIP.String(),
		"Endpoint": endpoint, "MeshCache": r.cfg.MeshCache, "UplinkMTU": r.cfg.UplinkMTU, "Key": key, "Local": local,
		"State": r.state})
	if err != nil {
		return err
	}
	// Run on this (locked) thread, so the program starts in its network
	// namespace.
	cmd := exec.Command(r.bin, "net", op)
	cmd.Stdin = bytes.NewReader(in)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, runErr := cmd.Output()
	var a rustAnswer
	if err := json.Unmarshal(out, &a); err != nil {
		return fmt.Errorf("armada-node net %s: %w: %s", op, runErr, strings.TrimSpace(stderr.String()))
	}
	r.state, r.done = a.State, a.Done
	r.sw = nil
	if a.Switch != nil {
		r.sw = &armadav1.NetworkSwitchStatus{To: a.Switch.To, Step: a.Switch.Step, Ready: a.Switch.Ready, Unreached: a.Switch.Unreached, Error: a.Switch.Error}
	}
	for _, l := range a.Log {
		r.t.Logf("armada-node %s: %s", r.cfg.Node, l)
	}
	switch {
	case a.NeedsUserspace:
		return errNeedsUserspace
	case a.Error != "":
		return errors.New(a.Error)
	}
	return nil
}

func (r *rustNet) Apply(_ context.Context, cfg *armadav1.NetworkConfig, local map[netip.Addr]string) error {
	return r.run("apply", cfg, local)
}

func (r *rustNet) Up(cfg *armadav1.NetworkConfig) error {
	return r.run("up", cfg, nil)
}

func (r *rustNet) SwitchStatus() *armadav1.NetworkSwitchStatus {
	return r.sw
}

// removeNet takes the cluster network off the node in the implementation
// ARMADA_NET_IMPL picks (Remove, or armada-node net remove), on a thread in
// the node's namespace.
func removeNet() error {
	if os.Getenv("ARMADA_NET_IMPL") != "rust" {
		return Remove()
	}
	return removeRust(os.Getenv("ARMADA_NODE_BIN"))
}

func removeRust(bin string) error {
	out, err := exec.Command(bin, "net", "remove").CombinedOutput()
	if err != nil {
		return fmt.Errorf("armada-node net remove: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
