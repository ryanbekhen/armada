package cli

import (
	"errors"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

const dnsZoneLong = "DNS zones with credentials of their own (ADR 0047). Every certificate for a name\n" +
	"in a zone (the zone itself or a name under it) is obtained through DNS-01 with\n" +
	"that zone's provider and token, so a custom domain whose DNS lives in another\n" +
	"account gets certificates without HTTP-01 reaching the nodes. The longest zone\n" +
	"that holds a name wins, also over the root domain's --dns-provider; names in no\n" +
	"zone keep using it under the root domain, and HTTP-01 elsewhere.\n\n" +
	"Tokens are read from a file or stdin (--token -), stored encrypted, and never\n" +
	"shown. Give each token access to its zone's DNS records only. A change applies\n" +
	"within seconds: the leader restarts its control plane while apps keep serving,\n" +
	"and the command waits until it answers again."

func newDNSZoneCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "DNS zones whose certificates use credentials of their own",
		Long:  dnsZoneLong,
	}
	cmd.AddCommand(newDNSZoneSetCommand(g, true), newDNSZoneSetCommand(g, false), newDNSZoneListCommand(g), newDNSZoneDeleteCommand(g))
	return cmd
}

func newDNSZoneSetCommand(g *globals, create bool) *cobra.Command {
	var provider, token string
	use, short := "update ZONE --token FILE", "Replace a DNS zone's provider and token"
	if create {
		use, short = "create ZONE --token FILE", "Add a DNS zone with its provider's token"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long:  dnsZoneLong,
		Example: "  printf '%s' \"$TOKEN\" | armada cluster dns create shop.example --token -\n" +
			"  armada cluster dns update shop.example --token token.txt",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("token") {
				return errors.New("--token is required: a file holding the provider's API token, or - for stdin")
			}
			// Never from an argument: shell history keeps those.
			v, err := readTokenArg(cmd, "--token", token)
			if err != nil {
				return err
			}
			if len(v) == 0 {
				return errors.New("--token: the token is empty; remove a zone with armada cluster dns delete")
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.SetDNSZone(cmd.Context(), &armadav1.SetDNSZoneRequest{
				Zone: args[0], Provider: provider, Token: v, MustCreate: create, MustExist: !create,
			}); err != nil {
				return RPCError(err)
			}
			if err := waitForAPI(cmd.Context(), client, settingsSettle, settingsWait); err != nil {
				return err
			}
			verb := "Updated"
			if create {
				verb = "Created"
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s DNS zone %s; its names get certificates through DNS-01 with its token.\n", verb, args[0])
			return err
		},
	}
	cmd.Flags().StringVar(&provider, "provider", "cloudflare", "the zone's DNS provider: cloudflare")
	cmd.Flags().StringVar(&token, "token", "", "file holding the provider's API token, or - for stdin")
	return cmd
}

func newDNSZoneListCommand(g *globals) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List DNS zones with credentials of their own",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.check(); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			cc, err := client.GetClusterConfig(cmd.Context(), &armadav1.GetClusterConfigRequest{})
			if err != nil {
				return RPCError(err)
			}
			if o.json() {
				return printJSON(cmd.OutOrStdout(), &armadav1.ClusterConfig{DnsZones: cc.DnsZones})
			}
			return printDNSZones(cmd.OutOrStdout(), cc.DnsZones)
		},
	}
	o = addOutput(cmd, false)
	return cmd
}

func newDNSZoneDeleteCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:     "delete ZONE",
		Aliases: []string{"rm"},
		Short:   "Remove a DNS zone's credentials",
		Long: "Remove a DNS zone's credentials. Certificates already issued stay valid; their\n" +
			"renewals use the root domain's provider for names under it, else HTTP-01.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.DeleteDNSZone(cmd.Context(), &armadav1.DeleteDNSZoneRequest{Zone: args[0]}); err != nil {
				return RPCError(err)
			}
			if err := waitForAPI(cmd.Context(), client, settingsSettle, settingsWait); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Deleted DNS zone %s.\n", args[0])
			return err
		},
	}
}

func printDNSZones(w io.Writer, zones []*armadav1.DNSZone) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ZONE\tPROVIDER\tTOKEN")
	for _, z := range zones {
		fmt.Fprintf(tw, "%s\t%s\tset\n", z.Zone, z.Provider)
	}
	return tw.Flush()
}
