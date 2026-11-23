//go:build integration && linux

package clusternet

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// netImpl is the cluster network one node of the integration tests runs:
// this package's Net in Go, or, with ARMADA_NET_IMPL=rust, the same Net
// running armada-node (ADR 0054), which ARMADA_NODE_BIN names, as a node
// with agent.json netAgent "rust" does, but with no fallback to Go, so
// armada-node's own errors fail the test. Each method runs on a thread in
// the node's network namespace (switchNode.in), which armada-node
// inherits.
type netImpl interface {
	Apply(ctx context.Context, cfg *armadav1.NetworkConfig, local map[netip.Addr]string) error
	Up(cfg *armadav1.NetworkConfig) error
	SwitchStatus() *armadav1.NetworkSwitchStatus
	UnreachablePeers() []string
}

// rustImpl reports whether the tests run armada-node.
func rustImpl() bool { return os.Getenv("ARMADA_NET_IMPL") == "rust" }

// newNetImpl returns the node's cluster network in the implementation
// ARMADA_NET_IMPL picks.
func newNetImpl(t *testing.T, cfg Config) netImpl {
	t.Helper()
	if !rustImpl() {
		n, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	return newRustNet(t, cfg)
}

// rustNet is a Net that runs armada-node for everything it can, with no
// fallback to Go.
type rustNet struct {
	*Net
}

func newRustNet(t *testing.T, cfg Config) *rustNet {
	t.Helper()
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		t.Fatal("ARMADA_NET_IMPL=rust needs ARMADA_NODE_BIN (make node)")
	}
	cfg.Program = func() string { return bin }
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n.prog.noFallback = true
	return &rustNet{Net: n}
}

// done is what armada-node's last pass changed.
func (r *rustNet) done() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.prog.done
}

// netOf is the Net of an implementation.
func netOf(n netImpl) *Net {
	switch x := n.(type) {
	case *Net:
		return x
	case *rustNet:
		return x.Net
	}
	return nil
}

// age moves back when n first configured each WireGuard peer, so
// UnreachablePeers counts every peer without a recent handshake.
func age(n netImpl, by time.Duration) {
	net := netOf(n)
	if net == nil {
		return
	}
	net.mu.Lock()
	defer net.mu.Unlock()
	for k, s := range net.wgSince {
		s.since = s.since.Add(-by)
		net.wgSince[k] = s
	}
}

// removeNet takes the cluster network off the node in the implementation
// ARMADA_NET_IMPL picks (Remove, or armada-node net remove), on a thread in
// the node's namespace.
func removeNet() error {
	if !rustImpl() {
		return Remove()
	}
	return removeRust(os.Getenv("ARMADA_NODE_BIN"))
}

func removeRust(bin string) error {
	_, err := runProgram(context.Background(), bin, nil, "net", "remove")
	return err
}

// diagnoseImpl is doctor's checks in the implementation ARMADA_NET_IMPL
// picks, armada-node's with no fallback to Go.
func diagnoseImpl(t *testing.T, mode string, ip, endpoint netip.Addr, sites Sites) []Check {
	t.Helper()
	if !rustImpl() {
		return Diagnose(mode, ip, endpoint, sites)
	}
	out, ok := diagnoseVia(os.Getenv("ARMADA_NODE_BIN"), mode, ip, endpoint, sites)
	if !ok {
		t.Fatal("armada-node net diagnose failed")
	}
	return out
}
