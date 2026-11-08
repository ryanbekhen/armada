package daemon

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

// etcdPrefix is where the control plane's records live in etcd.
const etcdPrefix = "/armada/"

// etcdAddrOverride, if valid, replaces the address the embedded etcd member
// listens on, which is otherwise the server's private IP (other control
// plane nodes must reach it). Tests set loopback.
var etcdAddrOverride netip.Addr

// etcdPorts returns the member's client and peer ports; tests replace it so
// clusters in parallel tests do not collide.
var etcdPorts = func(string) (client, peer int) { return etcd.DefaultClientPort, etcd.DefaultPeerPort }

// etcdNoFsync turns off fsync in the member; only tests set it.
var etcdNoFsync = false

// etcdConfig describes this control plane node's etcd member. Its name is
// the identity of the server certificate.
func etcdConfig(dataDir string, log *slog.Logger) (etcd.Config, error) {
	pem, err := readPrivate(dataDir, fileCACert, fileCAKey, fileServerCert)
	if err != nil {
		return etcd.Config{}, err
	}
	ca, err := pki.LoadCA(pem[0], pem[1])
	if err != nil {
		return etcd.Config{}, err
	}
	cert, err := pki.ParseCertPEM(pem[2])
	if err != nil {
		return etcd.Config{}, err
	}
	id, err := pki.IdentityFromCert(cert)
	if err != nil || id.Kind != pki.KindServer {
		return etcd.Config{}, fmt.Errorf("%s is not a server certificate", fileServerCert)
	}
	cfg := memberConfig(dataDir)
	cfg.Name, cfg.CA, cfg.Logger = id.Name, ca, log
	return cfg, nil
}

// memberConfig is where dataDir's member lives and listens: the private IP
// of the server certificate, if there is one yet (a restore takes it from
// the backup's certificate).
func memberConfig(dataDir string) etcd.Config {
	client, peer := etcdPorts(dataDir)
	cfg := etcd.Config{Dir: filepath.Join(dataDir, dirEtcd), Addr: etcdAddrOverride, ClientPort: client, PeerPort: peer, UnsafeNoFsync: etcdNoFsync}
	if !cfg.Addr.IsValid() {
		if b, err := fsutil.ReadPrivateFile(filepath.Join(dataDir, fileServerCert)); err == nil {
			cfg.Addr, _ = serverIP(b)
		}
	}
	if b, err := fsutil.ReadPrivateFile(filepath.Join(dataDir, fileEtcdInitial)); err == nil {
		cfg.InitialCluster = strings.TrimSpace(string(b))
	}
	return cfg
}

// serverIP returns the private IP a server certificate was issued for.
func serverIP(certPEM []byte) (netip.Addr, error) {
	c, err := pki.ParseCertPEM(certPEM)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range c.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok {
			return a.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s has no IP address", fileServerCert)
}

// openState starts this node's etcd member and opens the cluster state.
// Closing the member stops it.
func openState(ctx context.Context, dataDir string, log *slog.Logger) (*store.Etcd, *etcd.Member, error) {
	if _, err := os.Stat(filepath.Join(dataDir, fileServerCert)); errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("%s is not initialized; run `armadad init`", dataDir)
	}
	cfg, err := etcdConfig(dataDir, log)
	if err != nil {
		return nil, nil, err
	}
	m, err := startMember(ctx, cfg, dataDir, log)
	if err != nil {
		return nil, nil, err
	}
	st, err := store.NewEtcd(ctx, m.Client(), etcdPrefix)
	if err != nil {
		_ = m.Close()
		return nil, nil, err
	}
	return st, m, nil
}

// startMember starts the member and, on a server that joined, waits until
// the leader promoted it to a voting member: a learner cannot serve the
// store.
func startMember(ctx context.Context, cfg etcd.Config, dataDir string, log *slog.Logger) (*etcd.Member, error) {
	m, err := etcd.Start(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if m.IsLearner() {
		if log != nil {
			log.Info("waiting for the leader to promote this server to a voting etcd member")
		}
		if err := m.WaitVoter(ctx); err != nil {
			_ = m.Close()
			return nil, err
		}
	}
	// Joined: later starts use the member's own data.
	if err := os.Remove(filepath.Join(dataDir, fileEtcdInitial)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		_ = m.Close()
		return nil, err
	}
	return m, nil
}

// stateClient connects to the etcd member of a running server in dataDir,
// or starts the member if no server is running. The returned function
// releases it.
func stateClient(ctx context.Context, dataDir string) (*clientv3.Client, func() error, error) {
	cfg, err := etcdConfig(dataDir, nil)
	if err != nil {
		return nil, nil, err
	}
	if c, err := etcd.Dial(ctx, cfg); err == nil {
		return c, c.Close, nil
	}
	m, err := startMember(ctx, cfg, dataDir, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("the server's state is not reachable (is it starting?): %w", err)
	}
	return m.Client(), m.Close, nil
}
