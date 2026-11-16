package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
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
		Short: "Move this node to another container runtime (ADR 0046, experimental)",
		Long: "migrate moves this node between the embedded containerd and the supervisor,\n" +
			"which runs containers without containerd (ADR 0046). It removes every\n" +
			"container Armada runs here from the current runtime and records the new one;\n" +
			"the agent then starts its replicas on the new runtime, pulling their images\n" +
			"again. First drain the node (armada node drain NODE) and stop its service\n" +
			"(systemctl stop armada-server, or armada-agent); afterwards start the service\n" +
			"and resume the node (armada node resume NODE).\n\n" +
			"Moving to the supervisor stops containerd and leaves its data in\n" +
			"<data-dir>/containerd, which can be removed once the node runs.",
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
	errs, err := removeContainers(ctx, rt, out)
	if err != nil {
		return err
	}
	if len(errs) > 0 {
		return fmt.Errorf("the node still runs on %s; containers that could not be removed: %w", from, errors.Join(errs...))
	}
	ac.Runtime = to
	if err := saveAgentConfig(m.dataDir, *ac); err != nil {
		return err
	}
	if to == runtimeSupervisor {
		// The unit now only installs the runtime pack and exits.
		if err := m.systemctl(ctx, "stop", "armada-runtime"); err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Could not stop containerd (%v); it stops at the next restart.\n", err)
		}
	}
	_, _ = fmt.Fprintf(out, "This node now runs containers on %s. Start its service (systemctl start armada-server, or armada-agent), then resume it (armada node resume NODE).\n", to)
	return nil
}
