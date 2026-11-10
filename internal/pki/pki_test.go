package pki

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func mustCA(t *testing.T) *CA {
	t.Helper()
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestParseIdentity(t *testing.T) {
	t.Parallel()

	ok := map[string]Identity{
		"admin:ryan":    {KindAdmin, "ryan"},
		"user:ryan":     {KindUser, "ryan"},
		"service:ci":    {KindService, "ci"},
		"node:node-1":   {KindNode, "node-1"},
		"server:armada": {KindServer, "armada"},
	}
	for cn, want := range ok {
		got, err := ParseIdentity(cn)
		if err != nil || got != want {
			t.Errorf("ParseIdentity(%q) = %v, %v", cn, got, err)
		}
		if got.String() != cn {
			t.Errorf("String() = %q", got.String())
		}
	}
	for _, cn := range []string{"", "ryan", "root:ryan", "admin:", "node:a b", "node:-x", "admin:" + strings.Repeat("a", 64), "node:a:b"} {
		if _, err := ParseIdentity(cn); err == nil {
			t.Errorf("ParseIdentity(%q) accepted", cn)
		}
	}
}

func TestCARoundTrip(t *testing.T) {
	t.Parallel()

	ca := mustCA(t)
	if !ca.Cert.IsCA || !ca.Cert.MaxPathLenZero {
		t.Error("CA constraints missing")
	}
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCA(ca.CertPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(loaded.Cert) != Fingerprint(ca.Cert) {
		t.Error("fingerprint changed after reload")
	}

	other := mustCA(t)
	otherKey, _ := other.KeyPEM()
	if _, err := LoadCA(ca.CertPEM, otherKey); err == nil {
		t.Error("LoadCA accepted mismatched key")
	}
	leaf, leafKey, _ := ca.Issue(IssueRequest{Identity: Identity{KindAdmin, "x"}, Client: true})
	if _, err := LoadCA(leaf, leafKey); err == nil {
		t.Error("LoadCA accepted a leaf certificate")
	}
	if _, err := LoadCA([]byte("junk"), keyPEM); err == nil {
		t.Error("LoadCA accepted junk cert")
	}
	if _, err := LoadCA(ca.CertPEM, []byte("junk")); err == nil {
		t.Error("LoadCA accepted junk key")
	}
}

func TestIssue(t *testing.T) {
	t.Parallel()

	ca := mustCA(t)
	certPEM, keyPEM, err := ca.Issue(IssueRequest{
		Identity: Identity{KindServer, "armada"},
		DNSNames: []string{ServerName},
		IPs:      []net.IP{net.ParseIP("10.0.0.1")},
		Server:   true,
		Client:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKeyPEM(keyPEM); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: ServerName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("verify: %v", err)
	}
	id, err := IdentityFromCert(cert)
	if err != nil || id != (Identity{KindServer, "armada"}) {
		t.Errorf("identity = %v, %v", id, err)
	}
	if cert.IsCA {
		t.Error("leaf must not be a CA")
	}
	if time.Until(cert.NotAfter) > LeafValidity {
		t.Error("leaf validity too long")
	}

	if _, _, err := ca.Issue(IssueRequest{Identity: Identity{"root", "x"}, Client: true}); err == nil {
		t.Error("Issue accepted invalid identity")
	}
	if _, _, err := ca.Issue(IssueRequest{Identity: Identity{KindNode, "x"}}); err == nil {
		t.Error("Issue accepted certificate without usage")
	}
	long, _, err := ca.Issue(IssueRequest{Identity: Identity{KindNode, "x"}, Client: true, Validity: 100 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	lc, _ := ParseCertPEM(long)
	if lc.NotAfter.After(ca.Cert.NotAfter) {
		t.Error("leaf outlives CA")
	}
}

func TestParsePEMErrors(t *testing.T) {
	t.Parallel()

	if _, err := ParseCertPEM([]byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")); err == nil {
		t.Error("ParseCertPEM accepted a key block")
	}
	if _, err := ParseKeyPEM([]byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")); err == nil {
		t.Error("ParseKeyPEM accepted garbage DER")
	}
	ca := mustCA(t)
	if _, err := ParseKeyPEM(ca.CertPEM); err == nil {
		t.Error("ParseKeyPEM accepted a certificate")
	}
}

// handshake runs a TLS handshake over an in-memory pipe and returns the
// server-side view of the client identity.
func handshake(t *testing.T, server, client *tls.Config) (Identity, error) {
	t.Helper()
	sc, cc := net.Pipe()
	defer sc.Close()
	defer cc.Close()

	type result struct {
		id  Identity
		err error
	}
	done := make(chan result, 1)
	go func() {
		s := tls.Server(sc, server)
		if err := s.Handshake(); err != nil {
			done <- result{err: err}
			return
		}
		peers := s.ConnectionState().PeerCertificates
		id, err := IdentityFromCert(peers[0])
		done <- result{id, err}
	}()
	c := tls.Client(cc, client)
	cerr := c.Handshake()
	if cerr != nil {
		_ = cc.Close()
	} else {
		// In TLS 1.3 the server verifies the client certificate after the
		// client finishes, then writes an alert or session tickets. net.Pipe
		// is synchronous, so keep reading until the server side is done.
		go func() { _, _ = io.Copy(io.Discard, c) }()
	}
	r := <-done
	_ = sc.Close()
	if cerr != nil {
		return Identity{}, cerr
	}
	return r.id, r.err
}

func TestMutualTLS(t *testing.T) {
	t.Parallel()

	ca := mustCA(t)
	srvCert, srvKey, _ := ca.Issue(IssueRequest{Identity: Identity{KindServer, "armada"}, DNSNames: []string{ServerName}, Server: true})
	adminCert, adminKey, _ := ca.Issue(IssueRequest{Identity: Identity{KindAdmin, "ryan"}, Client: true})

	serverCfg, err := ServerTLS(ca.CertPEM, srvCert, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := ClientTLS(ca.CertPEM, adminCert, adminKey)
	if err != nil {
		t.Fatal(err)
	}
	if serverCfg.MinVersion != tls.VersionTLS13 || clientCfg.MinVersion != tls.VersionTLS13 {
		t.Error("TLS 1.3 not enforced")
	}

	id, err := handshake(t, serverCfg, clientCfg)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if id != (Identity{KindAdmin, "ryan"}) {
		t.Errorf("identity = %v", id)
	}

	t.Run("client from another CA is rejected", func(t *testing.T) {
		t.Parallel()
		evil := mustCA(t)
		c, k, _ := evil.Issue(IssueRequest{Identity: Identity{KindAdmin, "ryan"}, Client: true})
		cfg, _ := ClientTLS(ca.CertPEM, c, k)
		if _, err := handshake(t, serverCfg, cfg); err == nil {
			t.Error("handshake succeeded with foreign client cert")
		}
	})

	t.Run("server from another CA is rejected", func(t *testing.T) {
		t.Parallel()
		evil := mustCA(t)
		c, k, _ := evil.Issue(IssueRequest{Identity: Identity{KindServer, "armada"}, DNSNames: []string{ServerName}, Server: true})
		cfg, _ := ServerTLS(ca.CertPEM, c, k)
		if _, err := handshake(t, cfg, clientCfg); err == nil {
			t.Error("client accepted foreign server cert")
		}
	})

	t.Run("server cert without ServerName SAN is rejected", func(t *testing.T) {
		t.Parallel()
		c, k, _ := ca.Issue(IssueRequest{Identity: Identity{KindServer, "armada"}, DNSNames: []string{"other"}, Server: true})
		cfg, _ := ServerTLS(ca.CertPEM, c, k)
		if _, err := handshake(t, cfg, clientCfg); err == nil {
			t.Error("client accepted server cert with wrong SAN")
		}
	})

	t.Run("client-only cert cannot act as server", func(t *testing.T) {
		t.Parallel()
		c, k, _ := ca.Issue(IssueRequest{Identity: Identity{KindServer, "armada"}, DNSNames: []string{ServerName}, Client: true})
		cfg, _ := ServerTLS(ca.CertPEM, c, k)
		if _, err := handshake(t, cfg, clientCfg); err == nil {
			t.Error("client accepted cert without server auth usage")
		}
	})

	t.Run("missing client cert is rejected", func(t *testing.T) {
		t.Parallel()
		cfg := clientCfg.Clone()
		cfg.Certificates = nil
		if _, err := handshake(t, serverCfg, cfg); err == nil {
			t.Error("handshake succeeded without client cert")
		}
	})
}

func TestTLSConfigErrors(t *testing.T) {
	t.Parallel()

	ca := mustCA(t)
	c, k, _ := ca.Issue(IssueRequest{Identity: Identity{KindAdmin, "a"}, Client: true})
	if _, err := ServerTLS([]byte("junk"), c, k); err == nil {
		t.Error("ServerTLS accepted junk CA")
	}
	if _, err := ClientTLS(ca.CertPEM, c, []byte("junk")); err == nil {
		t.Error("ClientTLS accepted junk key")
	}
}
