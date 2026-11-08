package daemon

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
)

func TestRuntimeReset(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ac := agentConfig{NodeID: "n1", PrivateIP: "10.0.0.2", Servers: []string{"10.0.0.2:7443"}, Runtime: runtimeEmbedded, ContainerSubnet: "10.121.0.0/24"}
	if err := saveAgentConfig(dir, ac); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	d := fake.New()
	for _, n := range []string{"armada-a", "armada-b"} {
		if _, err := d.Run(ctx, runtime.ContainerSpec{Name: n, Image: "x", Labels: map[string]string{runtime.LabelManaged: "true"}}); err != nil {
			t.Fatal(err)
		}
	}
	// Not Armada's: reset leaves containers without its labels alone.
	if _, err := d.Run(ctx, runtime.ContainerSpec{Name: "someone-else", Image: "x"}); err != nil {
		t.Fatal(err)
	}
	orig := newDriver
	newDriver = func(string, *agentConfig) (runtime.Driver, error) { return d, nil }
	t.Cleanup(func() { newDriver = orig })

	var out, errOut strings.Builder
	if code := Execute(ctx, []string{"runtime", "reset", "--data-dir", dir}, &out, &errOut); code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	if cs, _ := d.List(ctx, nil); len(cs) != 1 || cs[0].Name != "someone-else" || !strings.Contains(out.String(), "Removed 2") {
		t.Errorf("left %v; output %q", cs, out.String())
	}
	// A node of a cluster network also takes the tunnel off the host.
	removed := 0
	origRemove := removeClusterNet
	removeClusterNet = func() error { removed++; return nil }
	t.Cleanup(func() { removeClusterNet = origRemove })
	if removed != 0 || strings.Contains(out.String(), "cluster network") {
		t.Error("cluster network removed on a node without one")
	}
	ac.Network = "plain"
	if err := saveAgentConfig(dir, ac); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := Execute(ctx, []string{"runtime", "reset", "--data-dir", dir}, &out, &errOut); code != 0 || removed != 1 || !strings.Contains(out.String(), "armada-net") {
		t.Errorf("cluster network: code %d, removed %d, %q", code, removed, out.String())
	}

	ac.Runtime = "Not A Name"
	if err := saveAgentConfig(dir, ac); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := Execute(ctx, []string{"runtime", "reset", "--data-dir", dir}, &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "names container runtime") {
		t.Errorf("unknown runtime: code %d, %q", code, errOut.String())
	}
}

func TestRuntimeCommandFreshAndUnknownNodes(t *testing.T) {
	dir := t.TempDir()
	var out, errOut strings.Builder
	if code := Execute(context.Background(), []string{"runtime", "--data-dir", dir}, &out, &errOut); code != 0 || !strings.Contains(errOut.String(), "not initialized") {
		t.Errorf("fresh node: code %d, %q", code, errOut.String())
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := saveAgentConfig(dir, agentConfig{NodeID: "n1", PrivateIP: "10.0.0.2", Servers: []string{"10.0.0.2:7443"}, Runtime: "docker"}); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := Execute(context.Background(), []string{"runtime", "--data-dir", dir}, &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "names container runtime") {
		t.Errorf("unknown runtime: code %d, %q", code, errOut.String())
	}
}

func TestNextStep(t *testing.T) {
	if got := nextStep("server", defaultDataDir); !strings.Contains(got, "systemctl enable --now armada-server") {
		t.Errorf("default data dir: %q", got)
	}
	if got := nextStep("agent", "/srv/armada"); got != "Next: armadad agent --data-dir /srv/armada\n" {
		t.Errorf("custom data dir: %q", got)
	}
}

// The agent takes the subnet the control plane gives it (ADR 0025) only
// when it is a usable /24 that does not hold the node's own address.
func TestUseNodeSubnet(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr("10.0.0.5")
	for _, c := range []struct {
		subnet, want string
		ok           bool
	}{
		{"", "10.121.0.0/24", true}, // no cluster network: keep the setting
		{"10.120.3.0/24", "10.120.3.0/24", true},
		{"10.120.3.0/25", "", false},
		{"10.120.3.1/24", "", false}, // not canonical
		{"10.0.0.0/24", "", false},   // holds the private IP
		{"8.8.8.0/24", "", false},
		{"not-a-subnet", "", false},
	} {
		ac := agentConfig{Runtime: runtimeEmbedded, ContainerSubnet: "10.121.0.0/24"}
		_, err := runtimeFlags{}.useNodeSubnet(&ac, c.subnet, "plain", ip)
		if (err == nil) != c.ok || (c.ok && ac.ContainerSubnet != c.want) {
			t.Errorf("useNodeSubnet(%q) = %q, %v", c.subnet, ac.ContainerSubnet, err)
		}
	}
	// A mode this binary does not know is refused.
	ac := agentConfig{Runtime: runtimeEmbedded}
	if _, err := (runtimeFlags{}).useNodeSubnet(&ac, "10.120.3.0/24", "carrier-pigeon", ip); err == nil {
		t.Error("unknown mode accepted")
	}
}
