package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/pki"
)

// Node credential files in the data directory.
const (
	FileCACert   = "ca.crt"
	FileNodeCert = "node.crt"
	FileNodeKey  = "node.key"
	pendingExt   = ".new"
)

// Credentials is the node's certificate and key, renewed in place.
type Credentials struct {
	dir  string
	node string
	ca   []byte
	pool *x509.CertPool

	mu   sync.Mutex
	pair *tls.Certificate
	leaf *x509.Certificate
}

// LoadCredentials reads the node's CA, certificate, and key from dir. A
// renewal interrupted after writing both new files is completed first.
func LoadCredentials(dir, node string) (*Credentials, error) {
	if err := promotePending(dir); err != nil {
		return nil, err
	}
	ca, err := fsutil.ReadPrivateFile(filepath.Join(dir, FileCACert))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid CA certificate")
	}
	certPEM, err := fsutil.ReadPrivateFile(filepath.Join(dir, FileNodeCert))
	if err != nil {
		return nil, err
	}
	keyPEM, err := fsutil.ReadPrivateFile(filepath.Join(dir, FileNodeKey))
	if err != nil {
		return nil, err
	}
	c := &Credentials{dir: dir, node: node, ca: ca, pool: pool}
	if err := c.set(certPEM, keyPEM); err != nil {
		return nil, err
	}
	return c, nil
}

// promotePending moves node.crt.new/node.key.new into place if both exist
// and match; otherwise it discards them.
func promotePending(dir string) error {
	crt, key := filepath.Join(dir, FileNodeCert+pendingExt), filepath.Join(dir, FileNodeKey+pendingExt)
	certPEM, errC := fsutil.ReadPrivateFile(crt)
	keyPEM, errK := fsutil.ReadPrivateFile(key)
	if errors.Is(errC, fs.ErrNotExist) && errors.Is(errK, fs.ErrNotExist) {
		return nil
	}
	if errC == nil && errK == nil {
		if _, err := tls.X509KeyPair(certPEM, keyPEM); err == nil {
			if err := os.Rename(key, filepath.Join(dir, FileNodeKey)); err != nil {
				return err
			}
			return os.Rename(crt, filepath.Join(dir, FileNodeCert))
		}
	}
	_ = os.Remove(crt)
	_ = os.Remove(key)
	return nil
}

// set validates and installs a certificate/key pair for this node.
func (c *Credentials) set(certPEM, keyPEM []byte) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: c.pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("node certificate: %w", err)
	}
	id, err := pki.IdentityFromCert(leaf)
	if err != nil {
		return err
	}
	if id != (pki.Identity{Kind: pki.KindNode, Name: c.node}) {
		return fmt.Errorf("node certificate is for %s, not node:%s", id, c.node)
	}
	c.mu.Lock()
	c.pair, c.leaf = &pair, leaf
	c.mu.Unlock()
	return nil
}

// Leaf returns the current certificate.
func (c *Credentials) Leaf() *x509.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.leaf
}

// TLSConfig returns a client config that always presents the current
// certificate.
func (c *Credentials) TLSConfig() (*tls.Config, error) {
	return pki.RotatingClientTLS(c.ca, func() (*tls.Certificate, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.pair, nil
	})
}

// Renew obtains a certificate for a new key and stores both. The new files
// are written next to the old ones and renamed into place, so a crash
// leaves a usable pair.
func (c *Credentials) Renew(ctx context.Context, client armadav1.AgentServiceClient) error {
	keyPEM, csr, err := pki.NewNodeCSR(c.node)
	if err != nil {
		return err
	}
	resp, err := client.RenewCertificate(ctx, &armadav1.RenewCertificateRequest{Csr: csr})
	if err != nil {
		return err
	}
	certPEM := resp.GetCert()
	// Check before touching the files: the server must have certified our
	// new key under our identity.
	probe := &Credentials{node: c.node, pool: c.pool}
	if err := probe.set(certPEM, keyPEM); err != nil {
		return fmt.Errorf("renewed certificate: %w", err)
	}
	crt, key := filepath.Join(c.dir, FileNodeCert+pendingExt), filepath.Join(c.dir, FileNodeKey+pendingExt)
	if err := fsutil.WriteFileAtomic(key, keyPEM, 0o600); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(crt, certPEM, 0o600); err != nil {
		return err
	}
	if err := promotePending(c.dir); err != nil {
		return err
	}
	return c.set(certPEM, keyPEM)
}

// ServerConn is the agent's connection to the server. Its Client keeps
// working across Redial, which replaces the connection so the next
// handshake uses a renewed certificate.
type ServerConn struct {
	dial func() (*grpc.ClientConn, error)

	mu   sync.Mutex
	conn *grpc.ClientConn
}

// NewServerConn dials with dial.
func NewServerConn(dial func() (*grpc.ClientConn, error)) (*ServerConn, error) {
	conn, err := dial()
	if err != nil {
		return nil, err
	}
	return &ServerConn{dial: dial, conn: conn}, nil
}

// Redial opens a new connection and closes the old one, ending its streams.
func (s *ServerConn) Redial() error {
	conn, err := s.dial()
	if err != nil {
		return err
	}
	s.mu.Lock()
	old := s.conn
	s.conn = conn
	s.mu.Unlock()
	return old.Close()
}

// Close closes the connection.
func (s *ServerConn) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.Close()
}

func (s *ServerConn) client() armadav1.AgentServiceClient {
	s.mu.Lock()
	defer s.mu.Unlock()
	return armadav1.NewAgentServiceClient(s.conn)
}

// Client returns a client that always uses the current connection.
func (s *ServerConn) Client() armadav1.AgentServiceClient { return switchingClient{s} }

type switchingClient struct{ s *ServerConn }

func (c switchingClient) Connect(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[armadav1.AgentMessage, armadav1.ServerMessage], error) {
	return c.s.client().Connect(ctx, opts...)
}

func (c switchingClient) PushLogs(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[armadav1.LogPush, armadav1.PushLogsResponse], error) {
	return c.s.client().PushLogs(ctx, opts...)
}

func (c switchingClient) ExecSession(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[armadav1.ExecSessionOutput, armadav1.ExecInput], error) {
	return c.s.client().ExecSession(ctx, opts...)
}

func (c switchingClient) VolumeSession(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[armadav1.VolumeData, armadav1.VolumeData], error) {
	return c.s.client().VolumeSession(ctx, opts...)
}

func (c switchingClient) RenewCertificate(ctx context.Context, in *armadav1.RenewCertificateRequest, opts ...grpc.CallOption) (*armadav1.RenewCertificateResponse, error) {
	return c.s.client().RenewCertificate(ctx, in, opts...)
}

// RenewLoop renews the node certificate when it enters the last third of
// its lifetime (checked every interval) and then redials.
func RenewLoop(ctx context.Context, creds *Credentials, conn *ServerConn, interval time.Duration, log interface {
	Info(string, ...any)
	Warn(string, ...any)
},
) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if pki.NeedsRenewal(creds.Leaf(), time.Now()) {
			if err := creds.Renew(ctx, conn.Client()); err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Warn("node certificate renewal failed; retrying", "err", err, "expires", creds.Leaf().NotAfter)
			} else {
				log.Info("node certificate renewed", "expires", creds.Leaf().NotAfter)
				if err := conn.Redial(); err != nil {
					log.Warn("reconnect after renewal failed", "err", err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
