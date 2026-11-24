package daemon

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// runtimeMigrator holds what `armadad runtime migrate` does to the
// machine; tests replace the parts.
type runtimeMigrator struct {
	dataDir string
	// lock takes the data directory, which a running agent holds.
	lock func(dir string) (func(), error)
	// systemctl stops containerd once its containers are gone.
	systemctl func(ctx context.Context, args ...string) error
}

func newRuntimeMigrateCommand() *cobra.Command {
	var dataDir, to string
	cmd := &cobra.Command{
		Use:   "migrate --to embedded|supervisor",
		Short: "Move this node to another container runtime (ADR 0046)",
		Long: "migrate moves this node between the embedded containerd and the supervisor,\n" +
			"which runs containers without containerd (ADR 0046). It removes every\n" +
			"container Armada runs here from the current runtime and records the new one;\n" +
			"the agent then starts its replicas on the new runtime, pulling their images\n" +
			"again. First drain the node (armada node drain NODE) and stop its service\n" +
			"(systemctl stop armada-server, or armada-agent); afterwards start the service\n" +
			"and resume the node (armada node resume NODE).\n\n" +
			"Moving to the supervisor stops containerd and leaves its data in\n" +
			"<data-dir>/containerd, which can be removed once the node runs.\n\n" +
			"The cluster's leader moves containerd nodes to the supervisor by itself, one\n" +
			"at a time (ADR 0054; armada cluster status shows it). Run this for a node it\n" +
			"does not move: a cluster's only node, a node holding volumes, or any node\n" +
			"while the move is turned off (armada cluster update --runtime-move=false).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m := runtimeMigrator{dataDir: dataDir, lock: lockDataDir, systemctl: systemctl}
			return m.run(cmd, to)
		},
	}
	f := cmd.Flags()
	f.StringVar(&dataDir, "data-dir", defaultDataDir, "Armada data directory")
	f.StringVar(&to, "to", "", "runtime to move to: embedded or supervisor")
	_ = cmd.MarkFlagRequired("to")
	return cmd
}

func (m runtimeMigrator) run(cmd *cobra.Command, to string) error {
	if to != runtimeEmbedded && to != runtimeSupervisor {
		return fmt.Errorf("invalid --to %q: use %s or %s", to, runtimeEmbedded, runtimeSupervisor)
	}
	ac, err := loadAgentConfig(m.dataDir)
	if err != nil {
		return err
	}
	if err := ac.checkRuntime(); err != nil {
		return err
	}
	from := ac.Runtime
	if from == "" {
		from = runtimeEmbedded
	}
	out := cmd.OutOrStdout()
	if from == to {
		_, _ = fmt.Fprintf(out, "This node already runs containers on %s.\n", to)
		return nil
	}
	unlock, err := m.lock(m.dataDir)
	if err != nil {
		return fmt.Errorf("%w\nstop the node's service first: systemctl stop armada-server (or armada-agent)", err)
	}
	defer unlock()

	ctx := cmd.Context()
	rt, err := newDriver(m.dataDir, ac)
	if err != nil {
		return err
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = rt.Ping(pctx)
	cancel()
	if err != nil {
		return fmt.Errorf("the current runtime (%s): %w (%s)", from, err, runtimeHint(from))
	}
	if err := migrateRuntime(ctx, m.dataDir, ac, rt, to, out, cmd.ErrOrStderr(), m.systemctl); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "This node now runs containers on %s. Start its service (systemctl start armada-server, or armada-agent), then resume it (armada node resume NODE).\n", to)
	return nil
}

// migrateRuntime moves the node from the runtime agent.json records (ac)
// to to: it removes every container and network sandbox Armada runs on rt,
// the current runtime, records to in agent.json, and stops containerd when
// leaving it. Nothing is recorded while a container is left. The caller
// holds the data directory: `armadad runtime migrate`, or the running agent
// when the leader moves its node (ADR 0054, moveRunningNode).
func migrateRuntime(ctx context.Context, dataDir string, ac *agentConfig, rt runtime.Driver, to string, out, errOut io.Writer, systemctl func(ctx context.Context, args ...string) error) error {
	from := cmp.Or(ac.Runtime, runtimeEmbedded)
	errs, err := removeContainers(ctx, rt, out)
	if err != nil {
		return err
	}
	if len(errs) > 0 {
		return fmt.Errorf("the node still runs on %s; containers that could not be removed: %w", from, errors.Join(errs...))
	}
	// Only the runtime changes, in agent.json as it is now: ac may be older
	// than what the agent saved since it started (its control plane list).
	if _, err := updateAgentConfig(dataDir, func(c *agentConfig) error {
		c.Runtime = to
		return nil
	}); err != nil {
		return err
	}
	ac.Runtime = to
	if to == runtimeSupervisor {
		// The unit now only installs the runtime pack and exits.
		if err := systemctl(ctx, "stop", "armada-runtime"); err != nil {
			_, _ = fmt.Fprintf(errOut, "Could not stop containerd (%v); it stops at the next restart.\n", err)
		}
	}
	return nil
}
