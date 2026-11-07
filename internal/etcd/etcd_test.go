package etcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"

	"github.com/ryanbekhen/armada/internal/pki"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startMember(t *testing.T, ca *pki.CA) (*Member, Config) {
	t.Helper()
	cfg := Config{
		Dir: filepath.Join(t.TempDir(), "etcd"), Name: "cp-1", Addr: netip.MustParseAddr("127.0.0.1"),
		ClientPort: freePort(t), PeerPort: freePort(t), CA: ca,
	}
	m, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m, cfg
}

func TestMemberServesAndPersists(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("test")
	m, cfg := startMember(t, ca)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := m.Client().Put(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{fileCert, fileKey, fileCA} {
		fi, err := os.Stat(filepath.Join(cfg.Dir, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, fi, err)
		}
	}
	if fi, _ := os.Stat(cfg.Dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %o", fi.Mode().Perm())
	}
	// Restart on the same data: the value is still there.
	_ = m.Close()
	m2, err := Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	resp, err := m2.Client().Get(ctx, "k")
	if err != nil || len(resp.Kvs) != 1 || string(resp.Kvs[0].Value) != "v" {
		t.Errorf("after restart: %v %v", resp, err)
	}
}

func TestRejectsOtherIdentities(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("test")
	other, _ := pki.NewCA("other")
	_, cfg := startMember(t, ca)
	u := memberURL(cfg.Addr, cfg.ClientPort)
	endpoint := u.String()

	issue := func(c *pki.CA, id pki.Identity) []tls.Certificate {
		certPEM, keyPEM, err := c.Issue(pki.IssueRequest{Identity: id, Client: true, IPs: []net.IP{net.ParseIP("127.0.0.1")}})
		if err != nil {
			t.Fatal(err)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return []tls.Certificate{cert}
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	cases := map[string][]tls.Certificate{
		"node certificate":      issue(ca, pki.Identity{Kind: pki.KindNode, Name: "n1"}),
		"admin certificate":     issue(ca, pki.Identity{Kind: pki.KindAdmin, Name: "ryan"}),
		"server certificate":    issue(ca, pki.Identity{Kind: pki.KindServer, Name: "cp-1"}),
		"member, other CA":      issue(other, pki.EtcdMember),
		"no client certificate": nil,
	}
	for name, certs := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, err := clientv3.New(clientv3.Config{
				Endpoints: []string{endpoint}, DialTimeout: 2 * time.Second,
				TLS: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: certs},
			})
			if err == nil {
				defer c.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_, err = c.Get(ctx, "k")
			}
			if err == nil {
				t.Error("etcd accepted the client")
			}
		})
	}
}

func TestStartRefusesPublicAddress(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("test")
	for _, a := range []string{"0.0.0.0", "8.8.8.8", "::"} {
		if _, err := Start(context.Background(), Config{Dir: t.TempDir(), Name: "x", Addr: netip.MustParseAddr(a), CA: ca}); err == nil {
			t.Errorf("started on %s", a)
		}
	}
}

func TestCertReissuedWhenAddressChanges(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("test")
	cfg := Config{Dir: t.TempDir(), Name: "cp-1", Addr: netip.MustParseAddr("10.0.0.2"), CA: ca}
	if err := ensureCert(cfg); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(filepath.Join(cfg.Dir, fileCert))
	if err := ensureCert(cfg); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(filepath.Join(cfg.Dir, fileCert)); string(again) != string(first) {
		t.Error("valid certificate reissued")
	}
	cfg.Addr = netip.MustParseAddr("10.0.0.3")
	if err := ensureCert(cfg); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(filepath.Join(cfg.Dir, fileCert)); string(again) == string(first) {
		t.Error("certificate kept after the address changed")
	}
}

func TestSnapshotRestore(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("test")
	m, cfg := startMember(t, ca)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := m.Client().Put(ctx, "/armada/k", "v"); err != nil {
		t.Fatal(err)
	}
	c, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	snap := filepath.Join(t.TempDir(), "snap.db")
	f, _ := os.Create(snap)
	if err := Snapshot(ctx, c, f); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	// A corrupted snapshot fails the checksum and leaves nothing behind.
	b, _ := os.ReadFile(snap)
	bad := filepath.Join(t.TempDir(), "bad.db")
	flipped := append([]byte(nil), b...)
	flipped[len(flipped)/2] ^= 0xff
	_ = os.WriteFile(bad, flipped, 0o600)
	badCfg := cfg
	badCfg.Dir = filepath.Join(t.TempDir(), "etcd")
	if err := Restore(bad, badCfg); err == nil {
		t.Error("corrupted snapshot restored")
	}
	if _, err := os.Stat(filepath.Join(badCfg.Dir, dirData)); err == nil {
		t.Error("data left behind after a failed restore")
	}

	rcfg := cfg
	rcfg.Dir = filepath.Join(t.TempDir(), "etcd")
	rcfg.ClientPort, rcfg.PeerPort = freePort(t), freePort(t)
	if err := Restore(snap, rcfg); err != nil {
		t.Fatal(err)
	}
	if err := Restore(snap, rcfg); err == nil {
		t.Error("restored over existing data")
	}
	r, err := Start(ctx, rcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	resp, err := r.Client().Get(ctx, "/armada/k")
	if err != nil || len(resp.Kvs) != 1 || string(resp.Kvs[0].Value) != "v" {
		t.Errorf("restored: %v %v", resp, err)
	}
}

func TestDialFailsWithoutMember(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("test")
	cfg := Config{Dir: t.TempDir(), Name: "cp-1", Addr: netip.MustParseAddr("127.0.0.1"), ClientPort: freePort(t), CA: ca}
	if err := ensureCert(cfg); err != nil {
		t.Fatal(err)
	}
	if c, err := Dial(context.Background(), cfg); err == nil {
		_ = c.Close()
		t.Error("dial succeeded without a member")
	}
}

func TestLogsGoToSlog(t *testing.T) {
	t.Parallel()
	var buf syncBuffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	closing := new(atomic.Bool)
	lg := newZapLogger(log, closing)
	lg.Info("chatty")
	lg.Warn("slow apply", zap.String("took", "2s"))
	lg.Warn("simple token is not cryptographically signed")
	closing.Store(true)
	lg.Error("use of closed network connection")
	out := buf.String()
	if strings.Contains(out, "chatty") || strings.Contains(out, "closed network") || strings.Contains(out, "simple token") {
		t.Errorf("unexpected log lines:\n%s", out)
	}
	if !strings.Contains(out, "slow apply") || !strings.Contains(out, "component=etcd") || !strings.Contains(out, "took=2s") {
		t.Errorf("warning not forwarded:\n%s", out)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// The member certificate names every private address of the machine, so a
// peer connecting from a secondary address passes etcd's SAN check; a new
// address gets a new certificate. Not parallel: it replaces hostAddrs.
func TestCertNamesHostAddresses(t *testing.T) {
	orig := hostAddrs
	t.Cleanup(func() { hostAddrs = orig })
	host := []netip.Addr{netip.MustParseAddr("192.168.65.20"), netip.MustParseAddr("192.168.65.6")}
	hostAddrs = func() []netip.Addr { return host }

	ca, _ := pki.NewCA("test")
	cfg := Config{Dir: t.TempDir(), Name: "cp-1", Addr: netip.MustParseAddr("192.168.65.6"), CA: ca}
	if err := ensureCert(cfg); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(cfg.Dir, fileCert))
	c, _ := pki.ParseCertPEM(b)
	var got []string
	for _, ip := range c.IPAddresses {
		got = append(got, ip.String())
	}
	if strings.Join(got, ",") != "192.168.65.6,192.168.65.20" {
		t.Errorf("SANs = %v", got)
	}
	host = append(host, netip.MustParseAddr("10.1.0.5"))
	if err := ensureCert(cfg); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(filepath.Join(cfg.Dir, fileCert)); string(again) == string(b) {
		t.Error("certificate kept after the machine gained an address")
	}
}

func TestRenewCertKeepsKeyAndClientsPickItUp(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("test")
	cfg := withDefaults(Config{Dir: t.TempDir(), Name: "cp-1", Addr: netip.MustParseAddr("10.0.0.2"), CA: ca})
	if err := ensureCert(cfg); err != nil {
		t.Fatal(err)
	}
	m := &Member{cfg: cfg}
	if ok, err := m.RenewCert(time.Now()); err != nil || ok {
		t.Fatalf("fresh certificate renewed: %v %v", ok, err)
	}
	tlsCfg, err := clientTLS(cfg.Dir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := tlsCfg.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Make it due: a certificate for the same key, with an hour left.
	certPath := filepath.Join(cfg.Dir, fileCert)
	b, _ := os.ReadFile(certPath)
	old, _ := pki.ParseCertPEM(b)
	short, err := ca.Reissue(old, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, short, 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := m.RenewCert(time.Now().Add(50 * time.Minute)); err != nil || !ok {
		t.Fatalf("due certificate not renewed: %v %v", ok, err)
	}
	b, _ = os.ReadFile(certPath)
	renewed, _ := pki.ParseCertPEM(b)
	if time.Until(renewed.NotAfter) < 300*24*time.Hour || renewed.Subject.CommonName != pki.EtcdMember.String() || len(renewed.IPAddresses) != len(old.IPAddresses) {
		t.Errorf("renewed %s %v until %v", renewed.Subject.CommonName, renewed.IPAddresses, renewed.NotAfter)
	}
	after, err := tlsCfg.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("client cannot load the renewed pair: %v", err)
	}
	if string(after.Certificate[0]) == string(before.Certificate[0]) || string(after.Certificate[0]) != string(renewed.Raw) {
		t.Error("client still presents the old certificate")
	}
}
