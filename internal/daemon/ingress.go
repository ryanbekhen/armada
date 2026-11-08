package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/libdns/cloudflare"
	"github.com/spf13/cobra"
	clientv3 "go.etcd.io/etcd/client/v3"

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
