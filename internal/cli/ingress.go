package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/libdns/cloudflare"
	"github.com/spf13/cobra"
	clientv3 "go.etcd.io/etcd/client/v3"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/certs"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/proxy"
	"github.com/ryanbekhen/armada/internal/proxy/haproxy"
	"github.com/ryanbekhen/armada/internal/runtime"
)

const (
	defaultACMEPort = 7480
	dirHAProxy      = "haproxy"
)

// tlsFlags configure certificate management on the server.
type tlsFlags struct {
	enabled      bool
	ca           string
	email        string
	listen       string
	dnsProvider  string
	dnsTokenFile string
}

func (f *tlsFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.enabled, "tls", true, "obtain and renew TLS certificates with ACME")
	fl.StringVar(&f.ca, "acme-ca", "letsencrypt", "ACME directory: letsencrypt, letsencrypt-staging, or an https:// URL")
	fl.StringVar(&f.email, "acme-email", "", "contact email for the ACME account")
	fl.StringVar(&f.listen, "acme-listen", "", "private ip:port for HTTP-01 challenges forwarded by HAProxy (default: <server ip>:7480)")
	fl.StringVar(&f.dnsProvider, "dns-provider", "", "DNS provider for certificates of the root domain and the names under it, including a wildcard: cloudflare")
	fl.StringVar(&f.dnsTokenFile, "dns-token-file", "", "file (mode 0600) holding the DNS provider API token")
}

// acmeDirectory resolves --acme-ca.
func acmeDirectory(v string) (string, error) {
	switch v {
	case "letsencrypt":
		return certs.LetsEncrypt, nil
	case "letsencrypt-staging":
		return certs.LetsEncryptStaging, nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("--acme-ca must be letsencrypt, letsencrypt-staging, or an https:// URL")
	}
	return v, nil
}

// certOptions validates the TLS flags and returns the certificate manager
// options (without storage) and the ACME responder address, or ok=false
// when TLS is disabled. serverListen is the gRPC listen address; its IP is
// the default for the responder. onResult hears of every certificate
// obtained (err nil) or failed attempt.
func (f *tlsFlags) certOptions(serverListen string, log *slog.Logger, onResult func(name string, err error)) (opts certs.Options, listen string, ok bool, err error) {
	if !f.enabled {
		if f.dnsProvider != "" || f.dnsTokenFile != "" {
			return opts, "", false, errors.New("--dns-provider needs --tls")
		}
		return opts, "", false, nil
	}
	ca, err := acmeDirectory(f.ca)
	if err != nil {
		return opts, "", false, err
	}
	listen = f.listen
	if listen == "" {
		ap, err := netip.ParseAddrPort(serverListen)
		if err != nil {
			return opts, "", false, err
		}
		listen = net.JoinHostPort(ap.Addr().String(), strconv.Itoa(defaultACMEPort))
	}
	// Checked here as well as by the server, which only starts once this
	// node leads: a bad flag should fail at startup.
	if err := netutil.CheckPrivateListen(listen); err != nil {
		return opts, "", false, fmt.Errorf("ACME responder: %w", err)
	}
	if ap, _ := netip.ParseAddrPort(listen); ap.Port() == 0 {
		return opts, "", false, errors.New("ACME responder needs a fixed port")
	}
	opts = certs.Options{
		CA:    ca,
		Email: f.email,
		OnObtained: func(name string) {
			log.Info("certificate obtained", "name", name)
			onResult(name, nil)
		},
		OnFailed: func(name string, renewal bool, err error) {
			log.Warn("certificate request failed; retrying with backoff", "name", name, "renewal", renewal, "err", err)
			if err == nil {
				err = errors.New("certificate request failed")
			}
			onResult(name, err)
		},
	}
	switch f.dnsProvider {
	case "":
		if f.dnsTokenFile != "" {
			return opts, "", false, errors.New("--dns-token-file needs --dns-provider")
		}
	case "cloudflare":
		if f.dnsTokenFile == "" {
			return opts, "", false, errors.New("--dns-provider cloudflare needs --dns-token-file")
		}
		// Read from a private file, never a flag value, so the token stays
		// out of shell history and process listings.
		b, err := fsutil.ReadPrivateFile(f.dnsTokenFile)
		if err != nil {
			return opts, "", false, fmt.Errorf("DNS token: %w", err)
		}
		token := strings.TrimSpace(string(b))
		if token == "" {
			return opts, "", false, errors.New("DNS token file is empty")
		}
		opts.DNSProvider = &cloudflare.Provider{APIToken: token}
	default:
		return opts, "", false, fmt.Errorf("unsupported --dns-provider %q (want cloudflare)", f.dnsProvider)
	}
	return opts, listen, true, nil
}

// acmePrefix is where certificates and the ACME account live in etcd.
const acmePrefix = "/armada-acme/"

// newCertManager builds a certificate manager on the shared etcd storage.
// The returned function stops it.
func newCertManager(c *clientv3.Client, opts certs.Options) (*certs.ACME, func(), error) {
	storage, err := certs.NewEtcdStorage(c, acmePrefix)
	if err != nil {
		return nil, nil, err
	}
	opts.Storage = storage
	m, err := certs.NewACME(opts)
	if err != nil {
		return nil, nil, err
	}
	return m, func() { m.Close(); _ = storage.Close() }, nil
}

// newProxy builds the node's proxy driver.
func checkProxyKind(kind string) error {
	if kind != "none" && kind != "haproxy" {
		return fmt.Errorf("unsupported --proxy %q (want haproxy or none)", kind)
	}
	return nil
}

// newProxy starts the node's HAProxy. subnet is the node's container subnet
// when its replicas have their own addresses in it (ADR 0025), else empty.
func newProxy(kind, dataDir, privateIP, internalIP, subnet string, rt runtime.Driver, log *slog.Logger) (proxy.Driver, error) {
	if err := checkProxyKind(kind); err != nil || kind == "none" {
		return nil, err
	}
	sys, ok := rt.(runtime.SystemRunner)
	if !ok || !runtime.CanRunSystem(rt) {
		return nil, errors.New("this node's container runtime cannot run system containers such as HAProxy; run the node with --proxy none")
	}
	dir := filepath.Join(dataDir, dirHAProxy)
	return haproxy.New(haproxy.Config{
		Dir:        dir,
		PrivateIP:  privateIP,
		InternalIP: internalIP,
		Subnet:     subnet,
		Engine:     &haproxy.ContainerEngine{Runtime: rt, System: sys, Dir: dir, StartWait: proxyStartWait},
		Logger:     log,
	})
}

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
				return rpcErr(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "root domain: %s\nacme email:  %s\n", dash(cc.RootDomain), dash(cc.AcmeEmail))
			return err
		},
	}
	var root string
	set := &cobra.Command{
		Use:   "set",
		Short: "Change cluster settings",
		Long: "Change cluster settings.\n\nWith --root-domain, every app with external ingress is reachable at\n" +
			"https://<app>.<root-domain>. Point a wildcard DNS record (*.<root-domain>)\nat your nodes first.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !cmd.Flags().Changed("root-domain") {
				return errors.New("nothing to change; pass --root-domain")
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			cc, err := client.SetClusterConfig(cmd.Context(), &armadav1.SetClusterConfigRequest{Config: &armadav1.ClusterConfig{RootDomain: root}})
			if err != nil {
				return rpcErr(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "root domain: %s\n", dash(cc.RootDomain))
			return err
		},
	}
	set.Flags().StringVar(&root, "root-domain", "", "root domain for app URLs (empty to clear)")
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
				return rpcErr(err)
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
				return rpcErr(err)
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
