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
