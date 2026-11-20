package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/store"
)

// detectEndpoint finds the machine's public IPv4 address; tests replace it.
var detectEndpoint = netutil.DetectEndpoint

// announcedEndpoint is the endpoint the agent announces (ADR 0050): the
// one agent.json records (mesh nodes, `armadad endpoint set`), else, on a
// node of a cluster network, the only public IPv4 address on its
// interfaces, found again at every start. Other sites' nodes reach it there.
func announcedEndpoint(ac *agentConfig, log *slog.Logger) string {
	if ac.Endpoint != "" || ac.Network == "" {
		return ac.Endpoint
	}
	ep, err := detectEndpoint()
	if err != nil {
		log.Info("no endpoint to announce; nodes of other sites cannot reach this one until `armadad endpoint set` names one", "reason", err)
		return ""
	}
	return ep.String()
}

// restartService restarts the machine's active Armada service; tests
// replace it.
var restartService = func(ctx context.Context) (string, error) {
	for _, unit := range []string{"armada-server", "armada-agent"} {
		if unitActive(ctx, unit) {
			return unit, systemctl(ctx, "restart", unit)
		}
	}
	return "", nil
}

func newEndpointCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "endpoint",
		Short: "Show or set the public address other sites' nodes reach this machine at",
		Long: "A machine's endpoint is the public IPv4 address WireGuard packets from nodes in\n" +
			"other sites, or from every node in a mesh cluster, are sent to (ADR 0049, ADR\n" +
			"0050). Without one set, a node announces the only public IPv4 address on its\n" +
			"interfaces. Set it behind one-to-one NAT (the public address is on no\n" +
			"interface), on a machine with several, or when its address changed for good.",
	}
	var dataDir string
	show := &cobra.Command{
		Use:   "show",
		Short: "Show the endpoint this machine announces",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ac, err := loadAgentConfig(dataDir)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			switch ep := announcedEndpoint(ac, slog.New(slog.DiscardHandler)); {
			case ac.Endpoint != "":
				_, err = fmt.Fprintf(out, "%s (set)\n", ac.Endpoint)
			case ep != "":
				_, err = fmt.Fprintf(out, "%s (found on this machine's interfaces)\n", ep)
			case ac.Network == "":
				_, err = fmt.Fprintln(out, "none: this cluster has no cluster network")
			default:
				_, err = fmt.Fprintln(out, "none: no single public IPv4 address on this machine's interfaces; set one with `armadad endpoint set IP`")
			}
			return err
		},
	}
	var noRestart bool
	set := &cobra.Command{
		Use:   "set IP",
		Short: "Set the endpoint and restart this machine's Armada service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ep, err := netutil.CheckEndpoint(args[0])
			if err != nil {
				return err
			}
			ac, err := loadAgentConfig(dataDir)
			if err != nil {
				return err
			}
			if ac.Network == "" {
				return errors.New("this cluster has no cluster network: its nodes reach each other only over the private network")
			}
			if ac.Network == store.NetworkMesh && ac.Endpoint == "" {
				return errors.New("agent.json records no endpoint for this mesh node; it is not a node of this Armada's mesh")
			}
			ac.Endpoint = ep.String()
			if err := saveAgentConfig(dataDir, *ac); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Endpoint set to %s.\n", ep)
			if noRestart {
				_, err = fmt.Fprintln(out, "Restart armada-server or armada-agent to announce it.")
				return err
			}
			unit, err := restartService(cmd.Context())
			switch {
			case err != nil:
				return fmt.Errorf("restart %s: %w", unit, err)
			case unit == "":
				_, err = fmt.Fprintln(out, "No Armada service runs; it announces the endpoint when it starts.")
			default:
				_, err = fmt.Fprintf(out, "Restarted %s: it announces the endpoint, and the other nodes follow within seconds.\n", unit)
			}
			return err
		},
	}
	set.Flags().BoolVar(&noRestart, "no-restart", false, "only record the endpoint; restart the service yourself")
	cmd.PersistentFlags().StringVar(&dataDir, "data-dir", defaultDataDir, "data directory")
	cmd.AddCommand(show, set)
	return cmd
}
