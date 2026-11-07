// Package etcd runs the embedded etcd member that holds the control plane's
// state, and connects clients to it.
//
// Every connection, client or peer, is mutual TLS with certificates from the
// cluster CA, and only the etcd member identity (pki.EtcdMember), which only
// control plane nodes hold, is accepted: node, admin, and server
// certificates, although signed by the same CA, cannot reach etcd. Listeners
// bind private addresses only.
package etcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"
	"go.etcd.io/etcd/server/v3/storage/wal"
	"go.uber.org/zap"

	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/pki"
)

// Default ports, on the member's address.
const (
	DefaultClientPort = 2379
	DefaultPeerPort   = 2380
)

// Files below the member directory.
const (
	dirData    = "data"
	fileCert   = "member.crt"
	fileKey    = "member.key"
	fileCA     = "ca.crt"
	certRenew  = 30 * 24 * time.Hour
	readyLimit = time.Minute

	clusterToken = "armada"
)

// Config describes one member.
type Config struct {
	// Dir holds the member's data and certificate (created 0700).
	Dir string
	// Name is the control plane node's name, which names the member.
	Name string
	// Addr is the private address the member listens on.
	Addr       netip.Addr
	ClientPort int
	PeerPort   int
	// CA issues the member certificate.
	CA *pki.CA
	// Logger receives the member's warnings and errors.
	Logger *slog.Logger
	// InitialCluster lists the members ("name=peerURL,...", this one
	// included) of the existing cluster this member joins. It is used only
	// on the first start; empty starts a new single-member cluster.
	InitialCluster string
	// UnsafeNoFsync skips fsync on writes. Only tests set it: a crash can
	// lose or corrupt data.
	UnsafeNoFsync bool
}

// Member is a running embedded etcd member.
type Member struct {
	etcd   *embed.Etcd
	client *clientv3.Client
	cfg    Config

	closing   *atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

// Start starts the member (a new single-member cluster on first start) and
// returns once it serves requests.
func Start(ctx context.Context, cfg Config) (*Member, error) {
	if cfg.Name == "" || cfg.CA == nil {
		return nil, errors.New("etcd: Name and CA are required")
	}
	if !cfg.Addr.IsValid() || !netutil.IsPrivate(cfg.Addr) {
		return nil, fmt.Errorf("etcd: listen address %s must be private", cfg.Addr)
	}
	cfg = withDefaults(cfg)
	if err := fsutil.MkdirPrivate(cfg.Dir); err != nil {
		return nil, err
	}
	if err := ensureCert(cfg); err != nil {
		return nil, err
	}

	clientURL := memberURL(cfg.Addr, cfg.ClientPort)
	peerURL := memberURL(cfg.Addr, cfg.PeerPort)
	certFile, keyFile, caFile := filepath.Join(cfg.Dir, fileCert), filepath.Join(cfg.Dir, fileKey), filepath.Join(cfg.Dir, fileCA)
	allowed := []string{pki.EtcdMember.String()}
	// A member without a write-ahead log has never started: a first start
	// that failed half-way leaves a data directory behind, which etcd would
	// otherwise take for a member of a new cluster of its own.
	data := filepath.Join(cfg.Dir, dirData)
	fresh := !wal.Exist(filepath.Join(data, "member", "wal"))
	if fresh {
		if err := os.RemoveAll(data); err != nil {
			return nil, err
		}
	}

	ec := embed.NewConfig()
	ec.Name = cfg.Name
	ec.Dir = filepath.Join(cfg.Dir, dirData)
	ec.ListenClientUrls = []url.URL{clientURL}
	ec.AdvertiseClientUrls = []url.URL{clientURL}
	ec.ListenPeerUrls = []url.URL{peerURL}
	ec.AdvertisePeerUrls = []url.URL{peerURL}
	ec.InitialCluster = cfg.Name + "=" + peerURL.String()
	ec.InitialClusterToken = clusterToken
	ec.ClusterState = embed.ClusterStateFlagNew
	if cfg.InitialCluster != "" && fresh {
		ec.InitialCluster = cfg.InitialCluster
		ec.ClusterState = embed.ClusterStateFlagExisting
	}
	ec.EnableGRPCGateway = false // gRPC only: no HTTP/JSON surface
	ec.ListenMetricsUrls = nil
	ec.TlsMinVersion = "TLS1.3"
	ec.UnsafeNoFsync = cfg.UnsafeNoFsync
	ec.AutoCompactionMode = "periodic"
	ec.AutoCompactionRetention = "1h"
	closing := new(atomic.Bool)
	ec.ZapLoggerBuilder = embed.NewZapLoggerBuilder(newZapLogger(cfg.Logger, closing))
	ec.ClientTLSInfo.CertFile, ec.ClientTLSInfo.KeyFile, ec.ClientTLSInfo.TrustedCAFile = certFile, keyFile, caFile
	ec.ClientTLSInfo.ClientCertAuth = true
	ec.ClientTLSInfo.AllowedCNs = allowed
	ec.PeerTLSInfo.CertFile, ec.PeerTLSInfo.KeyFile, ec.PeerTLSInfo.TrustedCAFile = certFile, keyFile, caFile
	ec.PeerTLSInfo.ClientCertAuth = true
	ec.PeerTLSInfo.AllowedCNs = allowed

	e, err := embed.StartEtcd(ec)
	if err != nil {
		return nil, fmt.Errorf("start etcd: %w", err)
	}
	select {
	case <-e.Server.ReadyNotify():
	case err := <-e.Err():
		closing.Store(true)
		e.Close()
		return nil, fmt.Errorf("etcd: %w", err)
	case <-time.After(readyLimit):
		closing.Store(true)
		e.Close()
		return nil, errors.New("etcd did not become ready within a minute")
	case <-ctx.Done():
		closing.Store(true)
		e.Close()
		return nil, ctx.Err()
	}

	m := &Member{etcd: e, cfg: cfg, closing: closing}
	if m.client, err = m.newClient(); err != nil {
		closing.Store(true)
		e.Close()
		return nil, err
	}
	if err := m.updatePeerURL(ctx, peerURL); err != nil {
		_ = m.Close()
		return nil, err
	}
	go func() {
		if err, ok := <-e.Err(); ok && err != nil {
			cfg.Logger.Error("etcd stopped", "err", err)
		}
	}()
	return m, nil
}

func withDefaults(cfg Config) Config {
	if cfg.ClientPort == 0 {
		cfg.ClientPort = DefaultClientPort
	}
	if cfg.PeerPort == 0 {
		cfg.PeerPort = DefaultPeerPort
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return cfg
}

// Client is a client of this member, authenticated as the control plane.
func (m *Member) Client() *clientv3.Client { return m.client }

// ID is the member's ID in the cluster.
func (m *Member) ID() uint64 { return uint64(m.etcd.Server.MemberID()) }

// IsLearner reports whether the member is a learner (not yet voting).
func (m *Member) IsLearner() bool { return m.etcd.Server.IsLearner() }

// updatePeerURL records the member's peer URL in the cluster if it changed
// since the member was created, which happens when the listen address
// changes: a single control plane node that moves to another private IP.
func (m *Member) updatePeerURL(ctx context.Context, peerURL url.URL) error {
	if m.IsLearner() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := m.client.MemberList(ctx)
	if err != nil {
		return fmt.Errorf("etcd member list: %w", err)
	}
	for _, mem := range resp.Members {
		if mem.ID != m.ID() {
			continue
		}
		if len(mem.PeerURLs) == 1 && mem.PeerURLs[0] == peerURL.String() {
			return nil
		}
		if _, err := m.client.MemberUpdate(ctx, mem.ID, []string{peerURL.String()}); err != nil {
			return fmt.Errorf("etcd: update peer URL to %s: %w", peerURL.String(), err)
		}
		m.cfg.Logger.Info("etcd peer URL updated", "component", "etcd", "url", peerURL.String())
	}
	return nil
}

// Close stops the client and the member. It is safe to call more than once.
func (m *Member) Close() error {
	m.closeOnce.Do(func() {
		m.closing.Store(true)
		m.closeErr = m.client.Close()
		m.etcd.Close()
	})
	return m.closeErr
}

func (m *Member) newClient() (*clientv3.Client, error) {
	tlsCfg, err := clientTLS(m.cfg.Dir)
	if err != nil {
		return nil, err
	}
	u := memberURL(m.cfg.Addr, m.cfg.ClientPort)
	return clientv3.New(clientv3.Config{
		Endpoints:   []string{u.String()},
		TLS:         tlsCfg,
		DialTimeout: 5 * time.Second,
		Logger:      zap.NewNop(),
	})
}

func clientTLS(dir string) (*tls.Config, error) {
	files, err := readAll(dir, fileCA, fileCert, fileKey)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(files[0]) {
		return nil, errors.New("etcd: invalid CA certificate")
	}
	if _, err := tls.X509KeyPair(files[1], files[2]); err != nil {
		return nil, err
	}
	// Read on every handshake, like etcd's own listeners, so a renewed
	// member certificate (RenewCert) is used without a restart.
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		files, err := readAll(dir, fileCert, fileKey)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair(files[0], files[1])
		return &cert, err
	}}, nil
}

// RenewCert signs the member certificate again, for the same key, once
// pki.RenewDue says so at now. etcd and the member's clients read the files on
// every handshake, so the new certificate is used without a restart. It
// reports whether it renewed.
func (m *Member) RenewCert(now time.Time) (bool, error) {
	certPath := filepath.Join(m.cfg.Dir, fileCert)
	b, err := fsutil.ReadPrivateFile(certPath)
	if err != nil {
		return false, err
	}
	c, err := pki.ParseCertPEM(b)
	if err != nil {
		return false, err
	}
	if !pki.RenewDue(c, now) {
		return false, nil
	}
	certPEM, err := m.cfg.CA.Reissue(c, 0)
	if err != nil {
		return false, fmt.Errorf("etcd member certificate: %w", err)
	}
	return true, fsutil.WriteFileAtomic(certPath, certPEM, 0o600)
}

func readAll(dir string, names ...string) ([][]byte, error) {
	out := make([][]byte, 0, len(names))
	for _, n := range names {
		b, err := fsutil.ReadPrivateFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// hostAddrs returns the private addresses of this machine's interfaces;
// tests replace it.
var hostAddrs = func() []netip.Addr {
	ifaddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range ifaddrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && netutil.IsPrivate(p.Addr()) {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// certAddrs are the addresses the member certificate names: the listen
// address and every other private address of the machine. etcd checks that
// a peer connects from an address its certificate names, and a machine
// with several addresses connects from whichever its routing picks.
func certAddrs(cfg Config) []netip.Addr {
	addrs := append([]netip.Addr{cfg.Addr}, hostAddrs()...)
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(addrs)
}

// ensureCert issues the member certificate (pki.EtcdMember, client and
// server usage, the machine's private addresses as SANs) if it is missing,
// does not match the identity or addresses, or expires within certRenew.
func ensureCert(cfg Config) error {
	certPath := filepath.Join(cfg.Dir, fileCert)
	if b, err := fsutil.ReadPrivateFile(certPath); err == nil {
		if c, err := pki.ParseCertPEM(b); err == nil && certFits(c, cfg) {
			return writeCA(cfg)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var ips []net.IP
	for _, a := range certAddrs(cfg) {
		ips = append(ips, a.AsSlice())
	}
	certPEM, keyPEM, err := cfg.CA.Issue(pki.IssueRequest{
		Identity: pki.EtcdMember,
		IPs:      ips,
		Server:   true,
		Client:   true,
	})
	if err != nil {
		return fmt.Errorf("etcd member certificate: %w", err)
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(cfg.Dir, fileKey), keyPEM, 0o600); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(certPath, certPEM, 0o600); err != nil {
		return err
	}
	return writeCA(cfg)
}

func certFits(c *x509.Certificate, cfg Config) bool {
	if c.Subject.CommonName != pki.EtcdMember.String() || time.Until(c.NotAfter) < certRenew {
		return false
	}
	roots := x509.NewCertPool()
	roots.AddCert(cfg.CA.Cert)
	if _, err := c.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return false
	}
	have := map[netip.Addr]bool{}
	for _, ip := range c.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok {
			have[a.Unmap()] = true
		}
	}
	for _, a := range certAddrs(cfg) {
		if !have[a] {
			return false
		}
	}
	return true
}

func writeCA(cfg Config) error {
	return fsutil.WriteFileAtomic(filepath.Join(cfg.Dir, fileCA), cfg.CA.CertPEM, 0o600)
}

func memberURL(addr netip.Addr, port int) url.URL {
	return url.URL{Scheme: "https", Host: netip.AddrPortFrom(addr, uint16(port)).String()} //nolint:gosec // port validated by the caller's flags
}
