package daemon

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
)

func TestRuntimeMigrate(t *testing.T) {
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
	orig := newDriver
	newDriver = func(string, *agentConfig) (runtime.Driver, error) { return d, nil }
	t.Cleanup(func() { newDriver = orig })

	var stopped []string
	m := runtimeMigrator{
		dataDir: dir,
		lock:    func(string) (func(), error) { return func() {}, nil },
		systemctl: func(_ context.Context, args ...string) error {
			stopped = append(stopped, strings.Join(args, " "))
			return nil
		},
	}
	run := func(to string) (string, error) {
		var out strings.Builder
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetContext(ctx)
		err := m.run(cmd, to)
		return out.String(), err
	}

	if _, err := run("docker"); err == nil {
		t.Error("--to docker accepted")
	}
	out, err := run(runtimeSupervisor)
	if err != nil {
		t.Fatal(err)
	}
	if cs, _ := d.List(ctx, nil); len(cs) != 0 || !strings.Contains(out, "Removed 2") {
		t.Errorf("left %v; output %q", cs, out)
	}
	got, err := loadAgentConfig(dir)
	if err != nil || got.Runtime != runtimeSupervisor || got.NodeID != "n1" || got.ContainerSubnet != ac.ContainerSubnet {
		t.Fatalf("agent.json %+v, %v", got, err)
	}
	if len(stopped) != 1 || stopped[0] != "stop armada-runtime" {
		t.Errorf("systemctl %q", stopped)
	}
	if out, err := run(runtimeSupervisor); err != nil || !strings.Contains(out, "already") {
		t.Errorf("again: %q, %v", out, err)
	}

	// Back to containerd: nothing to stop, the unit starts it with the service.
	stopped = nil
	if _, err := run(runtimeEmbedded); err != nil {
		t.Fatal(err)
	}
	if got, _ := loadAgentConfig(dir); got.Runtime != runtimeEmbedded || len(stopped) != 0 {
		t.Errorf("runtime %q, systemctl %q", got.Runtime, stopped)
	}

	// A running agent holds the data directory: nothing changes.
	m.lock = func(string) (func(), error) { return nil, errors.New("another agent is using it") }
	if _, err := run(runtimeSupervisor); err == nil || !strings.Contains(err.Error(), "systemctl stop") {
		t.Errorf("while the agent runs: %v", err)
	}
	if got, _ := loadAgentConfig(dir); got.Runtime != runtimeEmbedded {
		t.Errorf("runtime changed to %q while the agent ran", got.Runtime)
	}
}
