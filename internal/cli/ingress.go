package cli

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/fsutil"
)

func newClusterCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "cluster", Short: "The cluster's status, settings, and events"}
	var so *outputFlag
	show := &cobra.Command{
		Use:   "show",
		Short: "Show cluster settings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := so.check(); err != nil {
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
			if so.json() {
				return printJSON(cmd.OutOrStdout(), cc)
			}
			return printClusterConfig(cmd.OutOrStdout(), cc)
		},
	}
	so = addOutput(show, false)
	var (
		root, email, acmeCA, dnsProvider, dnsToken string
		trusted                                    []string
		tlsOn                                      bool
		metricsPort                                int
		lostTimeout                                time.Duration
	)
	set := &cobra.Command{
		Use:   "set",
		Short: "Change cluster settings, for every server at once",
		Long: "Change cluster settings. They are kept in the cluster's state, so every server\n" +
			"uses them, also after another one takes over as leader (ADR 0031).\n\n" +
			"With --root-domain, every app with external ingress is reachable at\n" +
			"https://<app>.<root-domain>. Point a wildcard DNS record (*.<root-domain>)\nat your nodes first.\n\n" +
			"With --trusted-proxies, requests from these prefixes keep the client address\n" +
			"headers they carry (X-Forwarded-For, CF-Connecting-IP, and the like). Every\n" +
			"other request loses them, so a client cannot claim another address.\n\n" +
			"Certificates, the DNS provider and its token, the metrics port, and the\n" +
			"node-lost timeout apply within seconds: the leader restarts its control plane\n" +
			"with them while apps keep serving; the command waits until it answers again.\n" +
			"The token is read from a file or stdin (--dns-token -), stored encrypted, and\n" +
			"never shown.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ch := cmd.Flags().Changed
			req := &armadav1.SetClusterConfigRequest{
				Config: &armadav1.ClusterConfig{RootDomain: root, TrustedProxies: trusted, Tls: tlsOn, AcmeEmail: email, AcmeCa: acmeCA,
					DnsProvider: dnsProvider, MetricsPort: int32(metricsPort), NodeLostTimeoutSeconds: int64(lostTimeout / time.Second)}, //nolint:gosec // the server bounds the port
				SetRootDomain: ch("root-domain"), SetTrustedProxies: ch("trusted-proxies"), SetTls: ch("tls"),
				SetAcmeEmail: ch("acme-email"), SetAcmeCa: ch("acme-ca"), SetDnsProvider: ch("dns-provider"),
				SetMetricsPort: ch("metrics-port"), SetNodeLostTimeout: ch("node-lost-timeout"), SetDnsToken: ch("dns-token"),
			}
			if !slices.ContainsFunc([]string{"root-domain", "trusted-proxies", "tls", "acme-email", "acme-ca", "dns-provider", "dns-token", "metrics-port", "node-lost-timeout"}, ch) {
				return errors.New("nothing to change; see armada cluster set --help")
			}
			if ch("dns-token") {
				// Never from an argument: shell history keeps those.
				v, err := readTokenArg(cmd, dnsToken)
				if err != nil {
					return err
				}
				req.DnsToken = v
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			cc, err := client.SetClusterConfig(cmd.Context(), req)
			if err != nil {
				return RPCError(err)
			}
			if slices.ContainsFunc(restartingSettings, ch) {
				// The leader restarts its control plane with them right
				// after answering; the next command would find no API.
				if err := waitForAPI(cmd.Context(), client, settingsSettle, settingsWait); err != nil {
					return err
				}
			}
			return printClusterConfig(cmd.OutOrStdout(), cc)
		},
	}
	f := set.Flags()
	f.StringVar(&root, "root-domain", "", "root domain for app URLs (empty to clear)")
	f.StringSliceVar(&trusted, "trusted-proxies", nil, "address prefixes of proxies in front of the nodes, comma separated (empty to clear)")
	f.BoolVar(&tlsOn, "tls", true, "obtain and renew certificates with ACME")
	f.StringVar(&email, "acme-email", "", "contact email for the ACME account")
	f.StringVar(&acmeCA, "acme-ca", "", "ACME directory: letsencrypt, letsencrypt-staging, or an https:// URL")
	f.StringVar(&dnsProvider, "dns-provider", "", "DNS provider for the root domain and the names under it, including a wildcard: cloudflare, or none")
	f.StringVar(&dnsToken, "dns-token", "", "file holding the DNS provider's API token, or - for stdin; an empty file removes it")
	f.IntVar(&metricsPort, "metrics-port", 0, "port of the Prometheus metrics endpoint on each server's private address; 0 turns it off")
	f.DurationVar(&lostTimeout, "node-lost-timeout", 0, "how long a node may be unreachable before its replicas move to other nodes")
	cmd.AddCommand(newClusterStatusCommand(g), show, set, newEventsCommand(g, eventsOfCluster))
	return cmd
}

// restartingSettings are the flags of cluster set whose change makes the
// leader restart its control plane (ADR 0031).
var restartingSettings = []string{"tls", "acme-email", "acme-ca", "dns-provider", "dns-token", "metrics-port", "node-lost-timeout"}

// settingsSettle is how long cluster set waits before asking whether the
// API is back: the leader restarts 300 ms after answering. settingsWait
// bounds the whole wait.
var settingsSettle, settingsWait = time.Second, time.Minute

// waitForAPI waits until the control plane answers again after a change of
// its settings, so that the next command does not fail while it restarts.
func waitForAPI(ctx context.Context, client armadav1.AdminServiceClient, settle, limit time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	t := time.NewTimer(settle)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("the settings are saved, but the control plane did not answer within %s after applying them; see armada cluster status", limit)
		case <-t.C:
		}
		cctx, ccancel := context.WithTimeout(ctx, 3*time.Second)
		_, err := client.GetClusterConfig(cctx, &armadav1.GetClusterConfigRequest{}, grpc.WaitForReady(true))
		ccancel()
		if err == nil {
			return nil
		}
		t.Reset(500 * time.Millisecond)
	}
}

func newClusterStatusCommand(g *globals) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Summarize the cluster: nodes, apps, and what needs attention",
		Long: "Summarize the cluster in one line, then list the apps that are not ready\n" +
			"(at most 20) and the nodes that are not ready, if any.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.check(); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.ClusterStatus(cmd.Context(), &armadav1.ClusterStatusRequest{})
			if err != nil {
				return RPCError(err)
			}
			if o.json() {
				return printJSON(cmd.OutOrStdout(), resp)
			}
			return printClusterStatus(cmd.OutOrStdout(), resp)
		},
	}
	o = addOutput(cmd, false)
	return cmd
}

func printClusterStatus(out io.Writer, r *armadav1.ClusterStatusResponse) error {
	_, _ = fmt.Fprintf(out, "nodes %d/%d ready · apps %d · ready %d · rolling out %d · failing %d · jobs %d\n",
		r.NodesReady, r.Nodes, r.Apps, r.AppsReady, r.AppsProgressing, r.AppsFailing, r.Jobs)
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if len(r.Attention) > 0 {
		_, _ = fmt.Fprintln(tw, "\nNAME\tREADY\tSTATE\tMESSAGE")
		for _, a := range r.Attention {
			_, _ = fmt.Fprintf(tw, "%s\t%d/%d\t%s\t%s\n", a.Name, a.Ready, a.Desired, a.State, dash(printable(a.Message)))
		}
		if more := int(r.AttentionTotal) - len(r.Attention); more > 0 {
			_, _ = fmt.Fprintf(tw, "and %d more\n", more)
		}
	}
	if len(r.NodesNotReady) > 0 {
		_, _ = fmt.Fprintln(tw, "\nNODE NOT READY")
		for _, n := range r.NodesNotReady {
			_, _ = fmt.Fprintln(tw, n)
		}
	}
	return tw.Flush()
}

// readTokenArg reads --dns-token: a file (mode 0600) or "-" for stdin.
func readTokenArg(cmd *cobra.Command, arg string) ([]byte, error) {
	var b []byte
	var err error
	if arg == "-" {
		b, err = io.ReadAll(io.LimitReader(cmd.InOrStdin(), 64<<10))
	} else {
		b, err = fsutil.ReadPrivateFile(arg)
	}
	if err != nil {
		return nil, fmt.Errorf("--dns-token: %w", err)
	}
	return bytes.TrimSpace(b), nil
}

func printClusterConfig(w io.Writer, cc *armadav1.ClusterConfig) error {
	metrics := "off"
	if cc.MetricsPort > 0 {
		metrics = fmt.Sprintf("port %d on each server's private address", cc.MetricsPort)
	}
	token := "not set"
	if cc.DnsTokenSet {
		token = "set"
	}
	certs := "off"
	if cc.Tls {
		certs = "on, " + dash(cc.AcmeCa)
	}
	_, err := fmt.Fprintf(w, "root domain:       %s\ntrusted proxies:   %s\ncertificates:      %s\nacme email:        %s\ndns provider:      %s (token %s)\nmetrics:           %s\nnode lost timeout: %s\n",
		dash(cc.RootDomain), dash(strings.Join(cc.TrustedProxies, ",")), certs, dash(cc.AcmeEmail),
		cmp.Or(cc.DnsProvider, "none"), token, metrics, time.Duration(cc.NodeLostTimeoutSeconds)*time.Second)
	return err
}

func newDomainCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "domain", Aliases: []string{"domains"}, Short: "List and verify custom domains"}
	var (
		app    string
		lo, vo *outputFlag
	)
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List custom domains and the DNS records that prove ownership",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := lo.check(); err != nil {
				return err
			}
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
			if !g.allSpaces {
				resp.Domains = slices.DeleteFunc(resp.Domains, func(d *armadav1.Domain) bool {
					return !slices.ContainsFunc(d.Apps, g.listed)
				})
			}
			if lo.json() {
				return printJSON(cmd.OutOrStdout(), resp)
			}
			return printDomains(cmd, resp.Domains)
		},
	}
	list.Flags().StringVar(&app, "app", "", "only domains used by this app")
	lo = addOutput(list, false)
	verify := &cobra.Command{
		Use:   "verify DOMAIN",
		Short: "Check a domain's TXT record now",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := vo.check(); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			d, err := client.VerifyDomain(cmd.Context(), &armadav1.VerifyDomainRequest{Name: args[0]})
			if err != nil {
				return RPCError(err)
			}
			if vo.json() {
				return printJSON(cmd.OutOrStdout(), d)
			}
			return printDomains(cmd, []*armadav1.Domain{d})
		},
	}
	vo = addOutput(verify, false)
	cmd.AddCommand(list, verify)
	return cmd
}

func printDomains(cmd *cobra.Command, ds []*armadav1.Domain) error {
	out := cmd.OutOrStdout()
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
	// What needs doing goes to stderr, so the table stays a table.
	if len(pending) > 0 {
		w := cmd.ErrOrStderr()
		_, _ = fmt.Fprintln(w, "\nTo verify ownership, create these DNS records (checked every minute):")
		for _, d := range pending {
			_, _ = fmt.Fprintf(w, "  TXT  %s  %q\n", d.TxtName, d.TxtValue)
			if d.Message != "" {
				_, _ = fmt.Fprintf(w, "       last check: %s\n", printable(d.Message))
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
