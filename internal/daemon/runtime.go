package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/ryanbekhen/armada/internal/clusternet"
	"github.com/ryanbekhen/armada/internal/dnsserver"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/containerd"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
	"github.com/ryanbekhen/armada/internal/store"
)

// Container runtimes recorded in agent.json: the embedded containerd
// (ADR 0011), or containers supervised by armada-shim without containerd
// (ADR 0046, experimental).
const (
	runtimeEmbedded   = "embedded"
	runtimeSupervisor = "supervisor"
	// defaultRuntime is what init and join record when --runtime is not
	// given (ADR 0046). An agent.json without a runtime was written before
	// the supervisor existed and stays on containerd.
	defaultRuntime = runtimeSupervisor
)

// runDir holds the node's runtime state on tmpfs; tests replace it.
var runDir = "/run/armada"

// packProgram returns a function that finds name in the node's runtime
// pack: its path while it is a regular file there, else "" (no pack yet, or
// one from before the program).
func packProgram(dataDir, name string) func() string {
	return func() string {
		p := filepath.Join(runtimePaths(dataDir).Bin(), name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
		return ""
	}
}

func runtimePaths(dataDir string) embedded.Paths {
	return embedded.Paths{DataDir: dataDir, RunDir: runDir}
}

// checkRuntime refuses an agent.json naming another container runtime.
func (c agentConfig) checkRuntime() error {
	switch c.Runtime {
	case runtimeEmbedded, runtimeSupervisor, "":
		return nil
	}
	return fmt.Errorf("%s names container runtime %q, which this Armada does not know (%s or %s); remove the node and join it again", fileAgent, c.Runtime, runtimeEmbedded, runtimeSupervisor)
}

// runtimeFlags are shared by the commands that set up a node.
type runtimeFlags struct {
	subnet  string
	runtime string
	flags   *pflag.FlagSet
}

func (r *runtimeFlags) register(f *pflag.FlagSet) {
	r.flags = f
	f.StringVar(&r.subnet, "container-subnet", embedded.DefaultSubnet.String(), "private IPv4 subnet for this node's containers (clusters without a cluster network; others give each node a subnet)")
	f.StringVar(&r.runtime, "runtime", defaultRuntime, "container runtime: supervisor (no containerd daemon, ADR 0046), or embedded (containerd)")
}

// apply validates the flags and records them in c.
func (r runtimeFlags) apply(c *agentConfig, privateIP netip.Addr) error {
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
	switch r.runtime {
	case "":
		c.Runtime = defaultRuntime
	case runtimeEmbedded, runtimeSupervisor:
		c.Runtime = r.runtime
	default:
		return fmt.Errorf("invalid --runtime %q: use %s or %s", r.runtime, runtimeSupervisor, runtimeEmbedded)
	}
	c.ContainerSubnet = b.Subnet.String()
	return nil
}

// useNodeSubnet records the cluster network the node joined (ADR 0025) and
// makes the subnet the cluster gave the node the embedded runtime's bridge
// subnet. It returns a note for the operator when it overrides
// --container-subnet. Nodes of clusters without a network keep their
// setting.
func (r runtimeFlags) useNodeSubnet(c *agentConfig, subnet, mode string, privateIP netip.Addr) (string, error) {
	if subnet == "" {
		return "", nil
	}
	if mode != store.NetworkPlain && mode != store.NetworkWireGuard && mode != store.NetworkMesh {
		return "", fmt.Errorf("the control plane uses cluster network mode %q, which this Armada does not know; upgrade it", mode)
	}
	c.Network = mode
	p, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", fmt.Errorf("the control plane gave this node an invalid subnet %q", subnet)
	}
	b, err := containerd.BridgeOf(p)
	if err != nil || b.Subnet != p || p.Bits() != store.NodeSubnetBits {
		return "", fmt.Errorf("the control plane gave this node an unusable subnet %s", subnet)
	}
	if b.Subnet.Contains(privateIP) {
		return "", fmt.Errorf("the node subnet %s contains this machine's private IP %s", b.Subnet, privateIP)
	}
	note := ""
	if r.flags != nil && r.flags.Changed("container-subnet") && r.subnet != b.Subnet.String() {
		note = fmt.Sprintf("--container-subnet %s is not used: the cluster network gives this node %s.\n", r.subnet, b.Subnet)
	}
	c.ContainerSubnet = b.Subnet.String()
	return note, nil
}

// newDriver connects to the node's container runtime; tests replace it.
var newDriver = func(dataDir string, ac *agentConfig) (runtime.Driver, error) {
	if err := ac.checkRuntime(); err != nil {
		return nil, err
	}
	var subnet netip.Prefix
	if ac.ContainerSubnet != "" {
		p, err := netip.ParsePrefix(ac.ContainerSubnet)
		if err != nil {
			return nil, fmt.Errorf("%s: container subnet: %w", fileAgent, err)
		}
		subnet = p
	}
	mtu := 0
	if ac.Network != "" {
		// Containers reach other nodes through the tunnel, which takes
		// its overhead from each packet (ADR 0025).
		ip, err := netip.ParseAddr(ac.PrivateIP)
		if err != nil {
			return nil, fmt.Errorf("%s: private IP: %w", fileAgent, err)
		}
		if mtu, err = clusternet.ContainerMTU(ac.Network, ip, ac.uplinkEndpoint(), ac.MTU); err != nil {
			return nil, fmt.Errorf("cluster network: %w", err)
		}
	}
	cfg := containerd.Config{Paths: runtimePaths(dataDir), Subnet: subnet, MTU: mtu}
	if ac.Runtime == runtimeSupervisor {
		// No daemon to start: the agent installs the runtime pack itself,
		// so an upgrade brings the new armada-shim and runc with it.
		if err := installPack(cfg.Paths); err != nil {
			return nil, err
		}
		cfg.Supervisor = true
	}
	return containerd.New(cfg)
}

// installPack extracts and verifies the embedded runtime pack, and makes
// the directories the runtime writes to. Builds without a pack use what an
// earlier `armadad runtime --bin-dir` installed.
func installPack(p embedded.Paths) error {
	if err := embedded.CheckHost(); err != nil {
		return err
	}
	if pack := embedded.Bundled(); len(pack) > 0 {
		if _, _, err := embedded.Install(p.Bundle(), pack); err != nil {
			return fmt.Errorf("runtime pack: %w", err)
		}
	}
	for _, d := range []string{p.Logs(), p.Containers(), p.CNI()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// runtimeHint says how to start or check the node's runtime.
func runtimeHint(rt string) string {
	if rt == runtimeSupervisor {
		return "the runtime pack is installed by armada-server or armada-agent; check sudo armadad doctor"
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
			if ac.Runtime == runtimeSupervisor {
				// No containerd here (ADR 0046): install the pack for the
				// agent and exit.
				if binDir != "" {
					if err := embedded.UseBinDir(runtimePaths(dataDir).Bundle(), binDir); err != nil {
						return err
					}
				}
				if err := installPack(runtimePaths(dataDir)); err != nil {
					return err
				}
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "this node runs containers without containerd (runtime: supervisor); the runtime pack is installed, nothing to run")
				return nil
			}
			return embedded.Exec(runtimePaths(dataDir), embedded.Bundled(), binDir)
		},
	}
	f := cmd.Flags()
	f.StringVar(&dataDir, "data-dir", defaultDataDir, "Armada data directory")
	f.StringVar(&binDir, "bin-dir", "", "use runtime binaries from this directory (builds without the bundle)")
	cmd.AddCommand(newRuntimeResetCommand(), newRuntimeMigrateCommand())
	return cmd
}

// removeClusterNet takes the cluster network off the node, through
// armada-node when bin names it; tests replace it.
var removeClusterNet = clusternet.RemoveWith

// stopDNS stops the node's armada-dns (ADR 0053); tests replace it.
var stopDNS = dnsserver.StopUnits

func newRuntimeResetCommand() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Remove every container Armada runs on this node",
		Long: "reset stops and removes all of Armada's containers on this node (those with\n" +
			"Armada's labels), the network sandboxes job queues are read from,\n" +
			"the node's resolver (armada-dns), and the cluster network's interface\n" +
			"and firewall rules.\n" +
			"Use it after `armada node delete`, with the agent (or server) stopped first,\n" +
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
				return fmt.Errorf("container runtime: %w (%s)", err, runtimeHint(ac.Runtime))
			}
			errs, err := removeContainers(ctx, rt, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			if err := stopDNS(ctx); err != nil {
				errs = append(errs, fmt.Errorf("armada-dns: %w", err))
			}
			if ac.Network != "" {
				bin := ""
				if find := ac.netProgram(dataDir); find != nil {
					bin = find()
				}
				if err := removeClusterNet(bin); err != nil {
					errs = append(errs, fmt.Errorf("cluster network: %w", err))
				} else {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed the cluster network interface %s and its firewall rules.\n", clusternet.Interface)
				}
			}
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

// removeContainers stops and removes every container Armada runs on rt
// (those with Armada's labels) and the network sandboxes job queues are
// read from (ADR 0040), saying how many on w. It returns what failed, or
// an error when the containers cannot be listed.
func removeContainers(ctx context.Context, rt runtime.Driver, w io.Writer) ([]error, error) {
	all, err := rt.List(ctx, nil)
	if err != nil {
		return nil, err
	}
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
	_, _ = fmt.Fprintf(w, "Removed %d container(s).\n", len(cs)-len(errs))
	if sb, ok := rt.(runtime.NetworkSandboxer); ok {
		sandboxes, err := sb.ListSandboxes(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("network sandboxes: %w", err))
		}
		removed := 0
		for _, s := range sandboxes {
			if err := sb.RemoveSandbox(ctx, s.ID); err != nil {
				errs = append(errs, fmt.Errorf("network sandbox %s: %w", s.ID, err))
				continue
			}
			removed++
		}
		if removed > 0 {
			_, _ = fmt.Fprintf(w, "Removed %d network sandbox(es).\n", removed)
		}
	}
	return errs, nil
}
