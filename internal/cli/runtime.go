package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/ryanbekhen/armada/driverkit"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/containerd"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
	"github.com/ryanbekhen/armada/internal/runtime/remote"
)

// runtimeEmbedded is the built-in container runtime (ADR 0011); any other
// name in agent.json is an external driver (ADR 0015).
const runtimeEmbedded = "embedded"

// runDir holds the node's runtime state on tmpfs; tests replace it.
var runDir = "/run/armada"

func runtimePaths(dataDir string) embedded.Paths {
	return embedded.Paths{DataDir: dataDir, RunDir: runDir}
}

// checkRuntime refuses an agent.json naming neither the embedded runtime
// nor a valid driver name.
func (c agentConfig) checkRuntime() error {
	if c.Runtime == runtimeEmbedded {
		return nil
	}
	if err := driverkit.CheckName(c.Runtime); err != nil {
		return fmt.Errorf("%s names container runtime %q: %w", fileAgent, c.Runtime, err)
	}
	return nil
}

// external reports whether the node runs containers through an external
// driver.
func (c agentConfig) external() bool { return c.Runtime != runtimeEmbedded }

// runtimeFlags are shared by the commands that set up a node.
type runtimeFlags struct {
	runtime string
	subnet  string
	flags   *pflag.FlagSet
}

func (r *runtimeFlags) register(f *pflag.FlagSet) {
	r.flags = f
	f.StringVar(&r.runtime, "runtime", runtimeEmbedded, "container runtime: embedded, or the name of an installed driver (listening on "+driverkit.SocketDir+"/NAME.sock)")
	f.StringVar(&r.subnet, "container-subnet", embedded.DefaultSubnet.String(), "private IPv4 subnet for this node's containers (embedded runtime)")
}

// apply validates the flags and records them in c.
func (r runtimeFlags) apply(c *agentConfig, privateIP netip.Addr) error {
	if r.runtime != "" && r.runtime != runtimeEmbedded {
		if err := driverkit.CheckName(r.runtime); err != nil {
			return fmt.Errorf("invalid --runtime: %w", err)
		}
		if r.flags != nil && r.flags.Changed("container-subnet") {
			return errors.New("--container-subnet applies to the embedded runtime; a driver chooses its own container network")
		}
		c.Runtime, c.ContainerSubnet = r.runtime, ""
		return nil
	}
	p, err := netip.ParsePrefix(r.subnet)
	if err != nil {
		return fmt.Errorf("invalid --container-subnet: %w", err)
	}
	b, err := containerd.BridgeOf(p)
	if err != nil {
		return err
	}
	if b.Subnet.Contains(privateIP) {
		return fmt.Errorf("--container-subnet %s contains the private IP %s; pick a subnet the network does not use", b.Subnet, privateIP)
	}
	c.Runtime, c.ContainerSubnet = runtimeEmbedded, b.Subnet.String()
	return nil
}

// newDriver connects to the node's container runtime; tests replace it.
var newDriver = func(dataDir string, ac *agentConfig) (runtime.Driver, error) {
	if err := ac.checkRuntime(); err != nil {
		return nil, err
	}
	if ac.external() {
		d, err := remote.New(remote.Config{Name: ac.Runtime})
		if err != nil {
			return nil, err
		}
		return d, nil
	}
	var subnet netip.Prefix
	if ac.ContainerSubnet != "" {
		p, err := netip.ParsePrefix(ac.ContainerSubnet)
		if err != nil {
			return nil, fmt.Errorf("%s: container subnet: %w", fileAgent, err)
		}
		subnet = p
	}
	return containerd.New(containerd.Config{Paths: runtimePaths(dataDir), Subnet: subnet})
}

// runtimeHint says how to start the node's runtime.
func runtimeHint(ac *agentConfig) string {
	if ac.external() {
		return "systemctl status armada-driver-" + ac.Runtime
	}
	return "systemctl start armada-runtime"
}

// runtimeWait bounds how long the agent waits for the runtime at start.
var runtimeWait = 2 * time.Minute

// waitRuntime waits until the runtime answers: at boot the embedded
// containerd may still be starting.
func waitRuntime(ctx context.Context, rt runtime.Driver, log *slog.Logger) error {
	deadline := time.Now().Add(runtimeWait)
	logged := false
	for {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := rt.Ping(pctx)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("container runtime: %w", err)
		}
		if !logged {
			log.Info("waiting for the container runtime", "err", err)
			logged = true
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func newRuntimeCommand() *cobra.Command {
	var dataDir, binDir string
	cmd := &cobra.Command{
		Use:   "runtime",
		Short: "Run the embedded container runtime (started by systemd)",
		Long: "runtime extracts the bundled containerd, runc, CNI plugins, and tini into the\n" +
			"data directory, verifies them, and replaces itself with containerd. It does\n" +
			"nothing on nodes that are not initialized yet.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ac, err := loadAgentConfig(dataDir)
			if errors.Is(err, fs.ErrNotExist) {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s is not initialized; nothing to run\n", dataDir)
				return nil
			}
			if err != nil {
				return err
			}
			if err := ac.checkRuntime(); err != nil {
				return err
			}
			if ac.external() {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "this node runs containers through driver %q; the embedded runtime does not run\n", ac.Runtime)
				return nil
			}
			return embedded.Exec(runtimePaths(dataDir), embedded.Bundled(), binDir)
		},
	}
	f := cmd.Flags()
	f.StringVar(&dataDir, "data-dir", defaultDataDir, "Armada data directory")
	f.StringVar(&binDir, "bin-dir", "", "use runtime binaries from this directory (builds without the bundle)")
	cmd.AddCommand(newRuntimeResetCommand())
	return cmd
}

func newRuntimeResetCommand() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Remove every container Armada runs on this node",
		Long: "reset stops and removes all of Armada's containers on this node (those with\n" +
			"Armada's labels; with an external driver, other containers are left alone).\n" +
			"Use it after `armada node remove`, with the agent (or server) stopped first,\n" +
			"or it starts its replicas again.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ac, err := loadAgentConfig(dataDir)
			if err != nil {
				return err
			}
			if err := ac.checkRuntime(); err != nil {
				return err
			}
			rt, err := newDriver(dataDir, ac)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = rt.Ping(pctx)
			cancel()
			if err != nil {
				return fmt.Errorf("container runtime: %w (%s)", err, runtimeHint(ac))
			}
			all, err := rt.List(ctx, nil)
			if err != nil {
				return err
			}
			// Only Armada's containers: an external driver's engine may run
			// others.
			var cs []runtime.Container
			for _, c := range all {
				if c.Labels[runtime.LabelManaged] == "true" || c.Labels[runtime.LabelSystem] != "" {
					cs = append(cs, c)
				}
			}
			var errs []error
			for _, c := range cs {
				_ = rt.Stop(ctx, c.ID, 10*time.Second)
				if err := rt.Remove(ctx, c.ID); err != nil && !errors.Is(err, runtime.ErrNotFound) {
					errs = append(errs, fmt.Errorf("%s: %w", c.Name, err))
				}
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed %d container(s).\n", len(cs)-len(errs))
			return errors.Join(errs...)
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir, "Armada data directory")
	return cmd
}

// newRuntimeLogCommand is the logging binary containerd's shim runs for
// every container: output arrives on fds 3 (stdout) and 4 (stderr), and
// closing fd 5 tells the shim the logger is ready.
func newRuntimeLogCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "runtime-log DIR",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			dir := args[0]
			if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
				return fmt.Errorf("log directory %q must be absolute and clean", dir)
			}
			stdout, stderr, ready := os.NewFile(3, "stdout"), os.NewFile(4, "stderr"), os.NewFile(5, "ready")
			if stdout == nil || stderr == nil || ready == nil {
				return errors.New("must be run by the containerd shim")
			}
			_ = ready.Close()
			return embedded.WriteLogs(dir, os.Getenv("CONTAINER_ID"), stdout, stderr)
		},
	}
}
