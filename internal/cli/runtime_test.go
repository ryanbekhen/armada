package cli

import (
	"context"
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
		if _, err := d.Run(ctx, runtime.ContainerSpec{Name: n, Image: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	orig := newDriver
	newDriver = func(string, *agentConfig) (runtime.Driver, error) { return d, nil }
	t.Cleanup(func() { newDriver = orig })

	var out, errOut strings.Builder
	if code := Execute(ctx, []string{"runtime", "reset", "--data-dir", dir}, &out, &errOut); code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	if cs, _ := d.List(ctx, nil); len(cs) != 0 || !strings.Contains(out.String(), "Removed 2") {
		t.Errorf("left %d containers; output %q", len(cs), out.String())
	}

	ac.Runtime = "other"
	if err := saveAgentConfig(dir, ac); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := Execute(ctx, []string{"runtime", "reset", "--data-dir", dir}, &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "supports \"embedded\"") {
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
	if err := saveAgentConfig(dir, agentConfig{NodeID: "n1", PrivateIP: "10.0.0.2", Servers: []string{"10.0.0.2:7443"}, Runtime: "other"}); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := Execute(context.Background(), []string{"runtime", "--data-dir", dir}, &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "supports \"embedded\"") {
		t.Errorf("unknown runtime: code %d, %q", code, errOut.String())
	}
}

func TestNextStep(t *testing.T) {
	if got := nextStep("server", defaultDataDir); !strings.Contains(got, "systemctl enable --now armada-server") {
		t.Errorf("default data dir: %q", got)
	}
	if got := nextStep("agent", "/srv/armada"); got != "Next: armada agent --data-dir /srv/armada\n" {
		t.Errorf("custom data dir: %q", got)
	}
}
