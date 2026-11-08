//go:build integration && linux

package containerd

import (
	"net/netip"
	"os"
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
