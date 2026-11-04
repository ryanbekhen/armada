//go:build integration && linux

package containerd

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/conformance"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// TestIntegrationConformance runs the conformance suite against the
// embedded runtime of an initialized node. Run it as root on
// the node, with the runtime running and the armada binary that stores
// container output:
//
//	sudo ARMADA_BIN=/usr/local/bin/armada ARMADA_HOST_IP=10.0.0.5 \
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

// TestIntegrationConformanceSandbox runs the same suite with every app
// container in gVisor (`isolation: sandbox`, ADR 0029): logs, exec,
// stats, volumes, and the security defaults must work there too, and each
// container must have a kernel of its own.
func TestIntegrationConformanceSandbox(t *testing.T) {
	bin := os.Getenv("ARMADA_BIN")
	if bin == "" || os.Geteuid() != 0 {
		t.Skip("needs root and ARMADA_BIN")
	}
	d, err := New(nodeConfig(t, bin))
	if err != nil {
		t.Fatal(err)
	}
	if !d.CanSandbox() {
		t.Fatal("the runtime has no runsc")
	}
	conformance.Run(t, sandboxed{d}, conformance.Options{HostIP: os.Getenv("ARMADA_HOST_IP"), Sandbox: true})
}

// TestIntegrationSandboxLimits checks what the suite cannot see from
// inside a sandbox: the memory and PID limits bound the whole sandbox in
// its cgroup on the host.
func TestIntegrationSandboxLimits(t *testing.T) {
	bin := os.Getenv("ARMADA_BIN")
	if bin == "" || os.Geteuid() != 0 {
		t.Skip("needs root and ARMADA_BIN")
	}
	d, err := New(nodeConfig(t, bin))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := d.Pull(ctx, "busybox:1.37", nil); err != nil {
		t.Fatal(err)
	}
	id, err := d.Run(ctx, runtime.ContainerSpec{
		Name: "sandbox-limits", Image: "busybox:1.37", Cmd: []string{"sleep", "60"},
		MemoryBytes: 96 << 20, PidsLimit: 150, Sandbox: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Remove(context.WithoutCancel(ctx), id) }()
	dir := filepath.Join("/sys/fs/cgroup", cgroupParent, id)
	for file, want := range map[string]string{"memory.max": strconv.Itoa(96 << 20), "pids.max": "150"} {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Errorf("%s: %v", file, err)
		} else if got := strings.TrimSpace(string(b)); got != want {
			t.Errorf("%s = %s, want %s", file, got, want)
		}
	}
	procs, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil || len(strings.Fields(string(procs))) == 0 {
		t.Errorf("no sandbox process in %s: %q %v", dir, procs, err)
	}
	c, err := d.client.LoadContainer(d.ctx(ctx), id)
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := c.Labels(d.ctx(ctx)); l[labelIsolation] != "sandbox" {
		t.Errorf("isolation label %q", l[labelIsolation])
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

// sandboxed runs every app container of d in gVisor.
type sandboxed struct{ *Driver }

func (s sandboxed) Run(ctx context.Context, spec runtime.ContainerSpec) (string, error) {
	spec.Sandbox = true
	return s.Driver.Run(ctx, spec)
}
