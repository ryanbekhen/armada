//go:build integration && linux

package containerd

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/ryanbekhen/armada/internal/runtime/conformance"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// TestIntegrationConformance runs the conformance suite against the
// embedded runtime of an initialized node. Run it as root on
// the node, with the runtime running and the armada binary that stores
// container output:
//
//	sudo ARMADA_BIN=/usr/local/bin/armadad ARMADA_HOST_IP=10.0.0.5 \
//	  go test -tags integration -run Conformance ./internal/runtime/containerd/
//
// On a node of a cluster network, set ARMADA_SUBNET to the node's
// container subnet (containerSubnet in agent.json).
func TestIntegrationConformance(t *testing.T) {
	bin := os.Getenv("ARMADA_BIN")
	if bin == "" || os.Geteuid() != 0 {
		t.Skip("needs root and ARMADA_BIN")
	}
	d, err := New(nodeConfig(t, bin))
	if err != nil {
		t.Fatal(err)
	}
	conformance.Run(t, d, conformance.Options{HostIP: os.Getenv("ARMADA_HOST_IP")})
	// The isolation firewall filters IPv4 only (T13).
	if off, err := embedded.IPv6Off(embedded.BridgeName); err != nil || !off {
		t.Errorf("IPv6 on %s: off = %v, err = %v", embedded.BridgeName, off, err)
	}
}

// TestIntegrationSandboxAdopt checks that a network sandbox outlives the
// driver that made it, as it outlives an agent that restarts (ADR 0040): a
// new driver lists it with the same address and removes it. It also makes
// one from a file left unpinned, as an agent killed while making it leaves.
//
//	sudo ARMADA_BIN=/usr/local/bin/armadad \
//	  go test -tags integration -run SandboxAdopt ./internal/runtime/containerd/
func TestIntegrationSandboxAdopt(t *testing.T) {
	bin := os.Getenv("ARMADA_BIN")
	if bin == "" || os.Geteuid() != 0 {
		t.Skip("needs root and ARMADA_BIN")
	}
	ctx := context.Background()
	cfg := nodeConfig(t, bin)
	first, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("conformance-adopt-%d", os.Getpid())
	t.Cleanup(func() { _ = first.RemoveSandbox(ctx, id) })
	s, err := first.EnsureSandbox(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	second, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	list, err := second.ListSandboxes(ctx)
	if err != nil || !slices.Contains(list, s) {
		t.Fatalf("after a restart: %+v, %v; want %+v", list, err, s)
	}
	if again, err := second.EnsureSandbox(ctx, id); err != nil || again != s {
		t.Errorf("adopted = %+v, %v; want %+v", again, err, s)
	}
	if err := second.RemoveSandbox(ctx, id); err != nil {
		t.Fatal(err)
	}

	half := id + "-half"
	if err := os.MkdirAll(cfg.Paths.Sandboxes(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.Paths.Sandboxes(), half), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.RemoveSandbox(ctx, half) })
	if s, err := second.EnsureSandbox(ctx, half); err != nil || s.IP == "" {
		t.Errorf("from an unpinned file: %+v, %v", s, err)
	}
}

// nodeConfig is the driver configuration of this node.
func nodeConfig(t *testing.T, bin string) Config {
	cfg := Config{Paths: embedded.Paths{DataDir: "/var/lib/armada", RunDir: "/run/armada"}, Self: bin}
	if s := os.Getenv("ARMADA_SUBNET"); s != "" {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("ARMADA_SUBNET: %v", err)
		}
		cfg.Subnet = p
	}
	return cfg
}

// TestIntegrationConformanceSupervisor runs the conformance suite against
// the runtime without containerd (ADR 0046): the agent's own image store
// and armada-shim, on an initialized node:
//
//	sudo ARMADA_BIN=/usr/local/bin/armadad ARMADA_SHIM_BIN=/root/armada-shim \
//	  ARMADA_HOST_IP=10.0.0.5 go test -tags integration -run ConformanceSupervisor ./internal/runtime/containerd/
//
// With ARMADA_RUNTIME_AGENT=rust and ARMADA_NODE_BIN naming armada-node,
// the same cases run with armada-node doing the store's work (ADR 0054:
// images in its store, root filesystems, bundles, shim requests,
// statistics, dials, and starting runc exec).
func TestIntegrationConformanceSupervisor(t *testing.T) {
	bin, shim := os.Getenv("ARMADA_BIN"), os.Getenv("ARMADA_SHIM_BIN")
	if bin == "" || shim == "" || os.Geteuid() != 0 {
		t.Skip("needs root, ARMADA_BIN, and ARMADA_SHIM_BIN")
	}
	// The agent's service runs with umask 0077; image content must not
	// take it (a container's non-root users could not read its files).
	old := unix.Umask(0o077)
	t.Cleanup(func() { unix.Umask(old) })
	cfg := nodeConfig(t, bin)
	cfg.Supervisor, cfg.ShimBin = true, shim
	if os.Getenv("ARMADA_RUNTIME_AGENT") == "rust" {
		if cfg.NodeBin = os.Getenv("ARMADA_NODE_BIN"); cfg.NodeBin == "" {
			t.Fatal("ARMADA_RUNTIME_AGENT=rust needs ARMADA_NODE_BIN")
		}
	}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if (d.native != nil) != (cfg.NodeBin != "") {
		t.Fatalf("armada-node runs containers: %v, want %v", d.native != nil, cfg.NodeBin != "")
	}
	conformance.Run(t, d, conformance.Options{HostIP: os.Getenv("ARMADA_HOST_IP")})
	if d.native != nil {
		// Samples of containers and dials from them and from sandboxes
		// (ADR 0054 step 4, fifth part), and every exec, command probe,
		// and system exec (sixth part) went through armada-node, with Go
		// standing in nowhere.
		for _, op := range []string{"stats", "dial", "exec"} {
			if n := d.native.StoodIn(op); n > 0 {
				t.Errorf("Go did %q %d times instead of armada-node", op, n)
			}
		}
		if d.native.Ran("exec") == 0 {
			t.Error("no exec went through armada-node")
		}
	}
}
