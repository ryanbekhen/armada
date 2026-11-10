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

// certSettings are the certificate settings a term uses: the cluster's
// (ADR 0031) over this server's flags.
type certSettings struct {
	enabled     bool
	ca          string
	email       string
	dnsProvider string
	token       string
}

// certOptions returns the certificate manager options (without storage) and
// the ACME responder address, or ok=false when TLS is disabled. listenFlag
// is --acme-listen; serverListen is the gRPC listen address, whose IP is the
// responder's default. onResult hears of every certificate obtained (err
// nil) or failed attempt.
func certOptions(cs certSettings, listenFlag, serverListen string, log *slog.Logger, onResult func(name string, err error)) (opts certs.Options, listen string, ok bool, err error) {
	if !cs.enabled {
		return opts, "", false, nil
	}
	ca, err := acmeDirectory(cs.ca)
	if err != nil {
		return opts, "", false, err
	}
	listen, err = acmeListen(listenFlag, serverListen)
	if err != nil {
		return opts, "", false, err
	}
	opts = certs.Options{
		CA:    ca,
		Email: cs.email,
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
	switch cs.dnsProvider {
	case "":
	case "cloudflare":
		if cs.token == "" {
			return opts, "", false, errors.New("DNS provider cloudflare needs a token (armada cluster set --dns-token - < FILE)")
		}
		opts.DNSProvider = &cloudflare.Provider{APIToken: cs.token}
	default:
		return opts, "", false, fmt.Errorf("unsupported DNS provider %q (want cloudflare)", cs.dnsProvider)
	}
	return opts, listen, true, nil
}

// acmeListen resolves --acme-listen: by default the server's IP and port
// 7480. Checked at startup as well as by the server, which only starts once
// this node leads: a bad flag should fail at once.
func acmeListen(flag, serverListen string) (string, error) {
	listen := flag
	if listen == "" {
		ap, err := netip.ParseAddrPort(serverListen)
		if err != nil {
			return "", err
		}
		listen = net.JoinHostPort(ap.Addr().String(), strconv.Itoa(defaultACMEPort))
	}
	if err := netutil.CheckPrivateListen(listen); err != nil {
		return "", fmt.Errorf("ACME responder: %w", err)
	}
	if ap, _ := netip.ParseAddrPort(listen); ap.Port() == 0 {
		return "", errors.New("ACME responder needs a fixed port")
	}
	return listen, nil
}

// readTokenFile reads --dns-token-file: a private file, never a flag value,
// so the token stays out of shell history and process listings.
func readTokenFile(path string) (string, error) {
	b, err := fsutil.ReadPrivateFile(path)
	if err != nil {
		return "", fmt.Errorf("DNS token: %w", err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", errors.New("DNS token file is empty")
	}
	return token, nil
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
