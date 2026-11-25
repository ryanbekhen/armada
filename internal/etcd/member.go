package etcd

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"go.etcd.io/etcd/server/v3/embed"
	"go.etcd.io/etcd/server/v3/storage/wal"
	"go.yaml.in/yaml/v3"

	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/pki"
)

// FileConfig is the configuration file `armadad etcd` writes beside the
// member for the pinned etcd of the runtime pack (ADR 0055).
const FileConfig = "etcd.yaml"

// Settings every member runs with, embedded or from the pack.
const (
	// maxTxnOps bounds the operations of one transaction (etcd's default
	// is 128). Armada deletes what it can by range, but a transaction may
	// still touch a few hundred keys (a node's replicas, a large app's
	// records).
	maxTxnOps = 4096

	tlsMinVersion        = "TLS1.3"
	compactionMode       = "periodic"
	compactionRetention  = "1h"
	clusterStateNew      = embed.ClusterStateFlagNew
	clusterStateExisting = embed.ClusterStateFlagExisting
)

// memberSpec is everything etcd is told about the member. Both the
// embedded member (embedConfig) and the configuration file of
// armada-etcd.service (fileConfig) are made from it, so either runs the
// same member on the same files.
type memberSpec struct {
	Name    string
	DataDir string
	// ClientURL and PeerURL are listened on and advertised.
	ClientURL, PeerURL url.URL
	// InitialCluster and ClusterState only matter on a first start.
	InitialCluster string
	ClusterState   string
	Token          string
	// CertFile, KeyFile, and CAFile serve and check both listeners; only
	// AllowedCN may connect to either.
	CertFile, KeyFile, CAFile string
	AllowedCN                 string
	UnsafeNoFsync             bool
}

// prepare checks cfg, makes the member's directory, issues its certificate
// when needed (ensureCert), and removes a data directory that never
// started, and returns the member's description. Start and WriteConfigFile
// both begin with it.
func prepare(cfg Config) (Config, memberSpec, error) {
	if cfg.Name == "" || cfg.CA == nil {
		return cfg, memberSpec{}, errors.New("etcd: Name and CA are required")
	}
	if !cfg.Addr.IsValid() || !netutil.IsPrivate(cfg.Addr) {
		return cfg, memberSpec{}, fmt.Errorf("etcd: listen address %s must be private", cfg.Addr)
	}
	cfg = withDefaults(cfg)
	dir, err := filepath.Abs(cfg.Dir)
	if err != nil {
		return cfg, memberSpec{}, err
	}
	cfg.Dir = dir
	if err := fsutil.MkdirPrivate(cfg.Dir); err != nil {
		return cfg, memberSpec{}, err
	}
	if err := ensureCert(cfg); err != nil {
		return cfg, memberSpec{}, err
	}
	// A member without a write-ahead log has never started: a first start
	// that failed half-way leaves a data directory behind, which etcd would
	// otherwise take for a member of a new cluster of its own.
	data := filepath.Join(cfg.Dir, dirData)
	fresh := !wal.Exist(filepath.Join(data, "member", "wal"))
	if fresh {
		if err := os.RemoveAll(data); err != nil {
			return cfg, memberSpec{}, err
		}
	}
	s := memberSpec{
		Name:          cfg.Name,
		DataDir:       data,
		ClientURL:     memberURL(cfg.Addr, cfg.ClientPort),
		PeerURL:       memberURL(cfg.Addr, cfg.PeerPort),
		ClusterState:  clusterStateNew,
		Token:         clusterToken,
		CertFile:      filepath.Join(cfg.Dir, fileCert),
		KeyFile:       filepath.Join(cfg.Dir, fileKey),
		CAFile:        filepath.Join(cfg.Dir, fileCA),
		AllowedCN:     pki.EtcdMember.String(),
		UnsafeNoFsync: cfg.UnsafeNoFsync,
	}
	s.InitialCluster = cfg.Name + "=" + s.PeerURL.String()
	if cfg.InitialCluster != "" && fresh {
		s.InitialCluster = cfg.InitialCluster
		s.ClusterState = clusterStateExisting
	}
	return cfg, s, nil
}

// embedConfig is the embedded member's configuration; the caller sets its
// logger.
func embedConfig(s memberSpec) *embed.Config {
	ec := embed.NewConfig()
	ec.Name = s.Name
	ec.Dir = s.DataDir
	ec.ListenClientUrls = []url.URL{s.ClientURL}
	ec.AdvertiseClientUrls = []url.URL{s.ClientURL}
	ec.ListenPeerUrls = []url.URL{s.PeerURL}
	ec.AdvertisePeerUrls = []url.URL{s.PeerURL}
	ec.InitialCluster = s.InitialCluster
	ec.InitialClusterToken = s.Token
	ec.ClusterState = s.ClusterState
	ec.EnableGRPCGateway = false // gRPC only: no HTTP/JSON surface
	ec.ListenMetricsUrls = nil
	ec.TlsMinVersion = tlsMinVersion
	ec.UnsafeNoFsync = s.UnsafeNoFsync
	ec.MaxTxnOps = maxTxnOps
	ec.AutoCompactionMode = compactionMode
	ec.AutoCompactionRetention = compactionRetention
	ec.ClientTLSInfo.CertFile, ec.ClientTLSInfo.KeyFile, ec.ClientTLSInfo.TrustedCAFile = s.CertFile, s.KeyFile, s.CAFile
	ec.ClientTLSInfo.ClientCertAuth = true
	ec.ClientTLSInfo.AllowedCNs = []string{s.AllowedCN}
	ec.PeerTLSInfo.CertFile, ec.PeerTLSInfo.KeyFile, ec.PeerTLSInfo.TrustedCAFile = s.CertFile, s.KeyFile, s.CAFile
	ec.PeerTLSInfo.ClientCertAuth = true
	ec.PeerTLSInfo.AllowedCNs = []string{s.AllowedCN}
	return ec
}

// etcdFile is etcd's configuration file (the keys of embed.Config's
// configYAML, as `etcd --config-file` reads them).
type etcdFile struct {
	Name                    string       `yaml:"name"`
	DataDir                 string       `yaml:"data-dir"`
	ListenClientURLs        string       `yaml:"listen-client-urls"`
	AdvertiseClientURLs     string       `yaml:"advertise-client-urls"`
	ListenPeerURLs          string       `yaml:"listen-peer-urls"`
	AdvertisePeerURLs       string       `yaml:"initial-advertise-peer-urls"`
	InitialCluster          string       `yaml:"initial-cluster"`
	InitialClusterToken     string       `yaml:"initial-cluster-token"`
	InitialClusterState     string       `yaml:"initial-cluster-state"`
	EnableGRPCGateway       bool         `yaml:"enable-grpc-gateway"`
	TLSMinVersion           string       `yaml:"tls-min-version"`
	MaxTxnOps               uint         `yaml:"max-txn-ops"`
	AutoCompactionMode      string       `yaml:"auto-compaction-mode"`
	AutoCompactionRetention string       `yaml:"auto-compaction-retention"`
	UnsafeNoFsync           bool         `yaml:"unsafe-no-fsync,omitempty"`
	Logger                  string       `yaml:"logger"`
	LogLevel                string       `yaml:"log-level"`
	LogOutputs              []string     `yaml:"log-outputs"`
	ClientSecurity          etcdSecurity `yaml:"client-transport-security"`
	PeerSecurity            etcdSecurity `yaml:"peer-transport-security"`
}

type etcdSecurity struct {
	CertFile      string   `yaml:"cert-file"`
	KeyFile       string   `yaml:"key-file"`
	TrustedCAFile string   `yaml:"trusted-ca-file"`
	CertAuth      bool     `yaml:"client-cert-auth"`
	AllowedCN     []string `yaml:"allowed-cn"`
}

// fileConfig is the configuration file's content for s. etcd logs
// warnings and errors to its standard error (the unit's journal), as the
// embedded member's are kept.
func fileConfig(s memberSpec) ([]byte, error) {
	sec := etcdSecurity{CertFile: s.CertFile, KeyFile: s.KeyFile, TrustedCAFile: s.CAFile, CertAuth: true, AllowedCN: []string{s.AllowedCN}}
	b, err := yaml.Marshal(etcdFile{
		Name:                    s.Name,
		DataDir:                 s.DataDir,
		ListenClientURLs:        s.ClientURL.String(),
		AdvertiseClientURLs:     s.ClientURL.String(),
		ListenPeerURLs:          s.PeerURL.String(),
		AdvertisePeerURLs:       s.PeerURL.String(),
		InitialCluster:          s.InitialCluster,
		InitialClusterToken:     s.Token,
		InitialClusterState:     s.ClusterState,
		EnableGRPCGateway:       false,
		TLSMinVersion:           tlsMinVersion,
		MaxTxnOps:               maxTxnOps,
		AutoCompactionMode:      compactionMode,
		AutoCompactionRetention: compactionRetention,
		UnsafeNoFsync:           s.UnsafeNoFsync,
		Logger:                  "zap",
		LogLevel:                "warn",
		LogOutputs:              []string{"stderr"},
		ClientSecurity:          sec,
		PeerSecurity:            sec,
	})
	if err != nil {
		return nil, err
	}
	return append([]byte("# Written by armadad etcd at every start; changes are overwritten.\n"), b...), nil
}

// WriteConfigFile prepares the member described by cfg as Start does
// (certificate, a data directory that never started removed) and writes
// the configuration file of the pinned etcd (0600, FileConfig in cfg.Dir).
// It returns the file's path.
func WriteConfigFile(cfg Config) (string, error) {
	cfg, s, err := prepare(cfg)
	if err != nil {
		return "", err
	}
	b, err := fileConfig(s)
	if err != nil {
		return "", err
	}
	path := filepath.Join(cfg.Dir, FileConfig)
	if err := fsutil.WriteFileAtomic(path, b, 0o600); err != nil {
		return "", err
	}
	return path, nil
}
