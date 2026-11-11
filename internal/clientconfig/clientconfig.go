// Package clientconfig loads and stores the CLI's credentials
// (~/.armada/config) and dials the control plane with them.
package clientconfig

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	grpcbackoff "google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"

	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/pki"
)

// EnvPath overrides the default config location.
const EnvPath = "ARMADA_CONFIG"

// Config holds the control plane addresses and the admin's mTLS
// credentials. The file contains a private key and must be mode 0600.
type Config struct {
	// Servers are the API addresses of the control plane nodes. Only the
	// leader answers; clients use the first that does.
	Servers []string `json:"servers"`
	CA      string   `json:"ca"`
	Cert    string   `json:"cert"`
	Key     string   `json:"key"`
	// Project is the project commands work in when they name none
	// (`armada project use`, ADR 0032); empty means the default project.
	Project string `json:"project,omitempty"`
}

// DefaultPath returns $ARMADA_CONFIG, else ~/.armada/config when it exists,
// else SystemPath when it exists, else ~/.armada/config.
func DefaultPath() string {
	if p := os.Getenv(EnvPath); p != "" {
		return p
	}
	own := filepath.Join(".armada", "config")
	if home, err := os.UserHomeDir(); err == nil {
		own = filepath.Join(home, ".armada", "config")
	}
	if _, err := os.Stat(own); err == nil {
		return own
	}
	if _, err := os.Stat(systemPath); err == nil {
		return systemPath
	}
	return own
}

// Load reads a config, refusing files readable by group or others.
func Load(path string) (*Config, error) {
	b, err := readConfig(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no client config at %s; run `armadad init` on the server or set %s", path, EnvPath)
	}
	if errors.Is(err, os.ErrPermission) && path == systemPath {
		return nil, fmt.Errorf("%s: %w: %s", path, os.ErrPermission, groupAdvice())
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(c.Servers) == 0 || c.CA == "" || c.Cert == "" || c.Key == "" {
		return nil, fmt.Errorf("%s is incomplete", path)
	}
	return &c, nil
}

// Save writes the config with mode 0600, creating its directory with 0700.
// An existing file is rewritten in place (see SaveFile).
func (c *Config) Save(path string) error {
	if _, err := os.Stat(path); err == nil {
		return c.SaveFile(path)
	}
	if err := fsutil.MkdirPrivate(filepath.Dir(path)); err != nil {
		return err
	}
	return c.SaveFile(path)
}

// SaveFile writes the config with mode 0600 into an existing directory,
// whatever its mode: a tool's config (ADR 0026) lives where the tool keeps
// its files. A config root shared with Group stays shared.
func (c *Config) SaveFile(path string) error {
	b, err := c.encode()
	if err != nil {
		return err
	}
	old, statErr := os.Stat(path)
	if err := fsutil.WriteFileAtomic(path, b, 0o600); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("%w (a shared config is changed as root: run the command with sudo)", err)
		}
		return err
	}
	if statErr == nil {
		return keepShared(path, old)
	}
	return nil
}

func (c *Config) encode() ([]byte, error) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Dial opens an mTLS connection to the control plane: the config's servers
// first, then those of the machine's ServersPath it lacks.
func (c *Config) Dial(opts ...grpc.DialOption) (*Conn, error) {
	tlsCfg, err := pki.ClientTLS([]byte(c.CA), []byte(c.Cert), []byte(c.Key))
	if err != nil {
		return nil, err
	}
	return Dial(withMachineServers(c.Servers), tlsCfg, opts...)
}

// Conn is a gRPC connection to whichever control plane node serves. Only
// the leader listens, so the connection tries the addresses in order and
// moves on when one refuses or goes away.
type Conn struct {
	*grpc.ClientConn
	r *manual.Resolver
}

// SetServers replaces the control plane addresses. An existing connection
// to an address still in the list is kept.
func (c *Conn) SetServers(addrs []string) { c.r.UpdateState(state(addrs)) }

func state(addrs []string) resolver.State {
	st := resolver.State{}
	for _, a := range addrs {
		st.Addresses = append(st.Addresses, resolver.Address{Addr: a, ServerName: pki.ServerName})
	}
	return st
}

// Dial opens a gRPC connection to the control plane at addrs with the given
// client TLS config. It is shared by the CLI and the agent.
func Dial(addrs []string, tlsCfg *tls.Config, opts ...grpc.DialOption) (*Conn, error) {
	if len(addrs) == 0 {
		return nil, errors.New("no control plane address")
	}
	r := manual.NewBuilderWithScheme("armada")
	r.InitialState(state(addrs))
	backoff := grpcbackoff.DefaultConfig
	// Fail over within seconds: an election takes about as long as the
	// leader lease, and agents should not wait minutes after it.
	backoff.MaxDelay = 5 * time.Second
	conn, err := grpc.NewClient(r.Scheme()+":///control-plane", append([]grpc.DialOption{
		grpc.WithResolvers(r),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff, MinConnectTimeout: 5 * time.Second}),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}),
	}, opts...)...,
	)
	if err != nil {
		return nil, err
	}
	return &Conn{ClientConn: conn, r: r}, nil
}

// CheckServers validates control plane addresses received from a server.
func CheckServers(addrs []string) ([]string, error) {
	if len(addrs) == 0 {
		return nil, errors.New("server returned no control plane address")
	}
	for _, a := range addrs {
		if err := netutil.CheckPrivateListen(a); err != nil {
			return nil, fmt.Errorf("server address: %w", err)
		}
	}
	return addrs, nil
}
