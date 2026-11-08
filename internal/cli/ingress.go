package cli

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

func newClusterCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "cluster", Short: "Show or change cluster settings"}
	show := &cobra.Command{
		Use:   "show",
		Short: "Show cluster settings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			cc, err := client.GetClusterConfig(cmd.Context(), &armadav1.GetClusterConfigRequest{})
			if err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "root domain:     %s\nacme email:      %s\ntrusted proxies: %s\n", dash(cc.RootDomain), dash(cc.AcmeEmail), dash(strings.Join(cc.TrustedProxies, ",")))
			return err
		},
	}
	var (
		root    string
		trusted []string
	)
	set := &cobra.Command{
		Use:   "set",
		Short: "Change cluster settings",
		Long: "Change cluster settings.\n\nWith --root-domain, every app with external ingress is reachable at\n" +
			"https://<app>.<root-domain>. Point a wildcard DNS record (*.<root-domain>)\nat your nodes first.\n\n" +
			"With --trusted-proxies, requests from these prefixes keep the client address\n" +
			"headers they carry (X-Forwarded-For, CF-Connecting-IP, and the like). Every\n" +
			"other request loses them, so a client cannot claim another address.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			setRoot, setTrusted := cmd.Flags().Changed("root-domain"), cmd.Flags().Changed("trusted-proxies")
			if !setRoot && !setTrusted {
				return errors.New("nothing to change; pass --root-domain or --trusted-proxies")
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			cc, err := client.SetClusterConfig(cmd.Context(), &armadav1.SetClusterConfigRequest{
				Config:            &armadav1.ClusterConfig{RootDomain: root, TrustedProxies: trusted},
				SetRootDomain:     setRoot,
				SetTrustedProxies: setTrusted,
			})
			if err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "root domain:     %s\ntrusted proxies: %s\n", dash(cc.RootDomain), dash(strings.Join(cc.TrustedProxies, ",")))
			return err
		},
	}
	set.Flags().StringVar(&root, "root-domain", "", "root domain for app URLs (empty to clear)")
	set.Flags().StringSliceVar(&trusted, "trusted-proxies", nil, "address prefixes of proxies in front of the nodes, comma separated (empty to clear)")
	cmd.AddCommand(show, set)
	return cmd
}

func newDomainCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "domain", Aliases: []string{"domains"}, Short: "Manage custom domains"}
	var app string
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List custom domains and the DNS records that prove ownership",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id := app
			if id != "" {
				var err error
				if id, err = g.app(id); err != nil {
					return err
				}
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.ListDomains(cmd.Context(), &armadav1.ListDomainsRequest{App: id})
			if err != nil {
				return RPCError(err)
			}
			if g.project != "" {
				resp.Domains = slices.DeleteFunc(resp.Domains, func(d *armadav1.Domain) bool {
					return !slices.ContainsFunc(d.Apps, g.listed)
				})
			}
			return printDomains(cmd, resp.Domains)
		},
	}
	list.Flags().StringVar(&app, "app", "", "only domains used by this app")
	verify := &cobra.Command{
		Use:   "verify DOMAIN",
		Short: "Check a domain's TXT record now",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			d, err := client.VerifyDomain(cmd.Context(), &armadav1.VerifyDomainRequest{Name: args[0]})
			if err != nil {
				return RPCError(err)
			}
			return printDomains(cmd, []*armadav1.Domain{d})
		},
	}
	cmd.AddCommand(list, verify)
	return cmd
}

func printDomains(cmd *cobra.Command, ds []*armadav1.Domain) error {
	out := cmd.OutOrStdout()
	if len(ds) == 0 {
		_, err := fmt.Fprintln(out, "No custom domains.")
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "DOMAIN\tAPPS\tVERIFIED\tTLS")
	var pending []*armadav1.Domain
	for _, d := range ds {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", d.Name, dash(strings.Join(d.Apps, ",")), yesNo(d.Verified), yesNo(d.TlsReady))
		if !d.Verified {
			pending = append(pending, d)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(pending) > 0 {
		_, _ = fmt.Fprintln(out, "\nTo verify ownership, create these DNS records (checked every minute):")
		for _, d := range pending {
			_, _ = fmt.Fprintf(out, "  TXT  %s  %q\n", d.TxtName, d.TxtValue)
			if d.Message != "" {
				_, _ = fmt.Fprintf(out, "       last check: %s\n", d.Message)
			}
		}
	}
	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
