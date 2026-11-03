package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestJoinToken(t *testing.T) {
	t.Parallel()
	tok, err := NewJoinToken()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseJoinToken(" " + tok.Reveal() + "\n")
	if err != nil || got != tok {
		t.Fatalf("round trip = %v, %v", got, err)
	}
	for _, s := range []string{fmt.Sprint(tok), fmt.Sprintf("%v %+v %#v %s", tok, tok, tok, tok)} {
		if strings.Contains(s, tok.Secret) {
			t.Errorf("token prints its secret: %s", s)
		}
	}
	if !TokenSecretMatches(tok.Secret, tok.SecretHash()) {
		t.Error("secret does not match its hash")
	}
	other, _ := NewJoinToken()
	if TokenSecretMatches(other.Secret, tok.SecretHash()) || TokenSecretMatches("", tok.SecretHash()) {
		t.Error("wrong secret matches")
	}
	if tok.SecretHash() == tok.Secret || strings.Contains(tok.SecretHash(), tok.Secret) {
		t.Error("hash reveals the secret")
	}
	for _, bad := range []string{"", tok.ID, tok.ID + ".", "." + tok.Secret, tok.ID + "." + tok.Secret[:63],
		tok.ID + "." + tok.Secret + "0", strings.ToUpper(tok.Reveal()), tok.ID + ":" + tok.Secret, tok.Reveal() + ".x"} {
		if _, err := ParseJoinToken(bad); err == nil {
			t.Errorf("ParseJoinToken(%q) accepted", bad)
		}
	}
}

func FuzzParseJoinToken(f *testing.F) {
	f.Add("0123456789ab." + strings.Repeat("a", 64))
	f.Add("x.y")
	f.Fuzz(func(t *testing.T, s string) {
		tok, err := ParseJoinToken(s)
		if err != nil {
			return
		}
		if again, err := ParseJoinToken(tok.Reveal()); err != nil || again != tok {
			t.Fatalf("re-parse of %q failed", s)
		}
	})
}

func TestCAHash(t *testing.T) {
	t.Parallel()
	ca, _ := NewCA("c")
	h, err := ParseCAHash(CAHash(ca.Cert))
	if err != nil || h != Fingerprint(ca.Cert) {
		t.Fatalf("ParseCAHash = %q, %v", h, err)
	}
	for _, bad := range []string{"", Fingerprint(ca.Cert), "sha1:" + Fingerprint(ca.Cert), "sha256:" + Fingerprint(ca.Cert)[:10]} {
		if _, err := ParseCAHash(bad); err == nil {
			t.Errorf("ParseCAHash(%q) accepted", bad)
		}
	}
}

func TestSignNodeCSR(t *testing.T) {
	t.Parallel()
	ca, _ := NewCA("c")
	keyPEM, csr, err := NewNodeCSR("node-2")
	if err != nil {
		t.Fatal(err)
	}
	nc, err := ca.SignNodeCSR(csr, "node-2", 0)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := ParseCertPEM(nc.PEM)
	id, _ := IdentityFromCert(cert)
	if id != (Identity{Kind: KindNode, Name: "node-2"}) || cert.IsCA || SerialString(cert) != nc.Serial {
		t.Errorf("cert identity %v, CA %v", id, cert.IsCA)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("usages = %v", cert.ExtKeyUsage)
	}
	if life := time.Until(cert.NotAfter); life > NodeValidity || life < NodeValidity-time.Minute {
		t.Errorf("lifetime = %v", life)
	}
	// The certificate works against the server's mTLS config.
	if _, err := ClientTLS(ca.CertPEM, nc.PEM, keyPEM); err != nil {
		t.Errorf("issued cert does not pair with its key: %v", err)
	}
	if c, _ := ca.SignNodeCSR(csr, "node-2", 400*24*time.Hour); time.Until(c.NotAfter) > NodeValidity {
		t.Error("validity not capped")
	}

	// The CSR's name is ignored: the CA decides the identity.
	_, csrOther, _ := NewNodeCSR("admin-ish")
	if nc, err := ca.SignNodeCSR(csrOther, "node-3", 0); err != nil {
		t.Error(err)
	} else if c, _ := ParseCertPEM(nc.PEM); c.Subject.CommonName != "node:node-3" {
		t.Errorf("CN = %q", c.Subject.CommonName)
	}

	tampered := append([]byte(nil), csr...)
	tampered[len(tampered)-5] ^= 0xff
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "node:x"}}, rsaKey)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384CSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "node:x"}}, p384)
	for name, tc := range map[string]struct {
		csr  []byte
		node string
	}{
		"garbage":       {[]byte("not a csr"), "node-2"},
		"bad signature": {tampered, "node-2"},
		"rsa key":       {rsaCSR, "node-2"},
		"p384 key":      {p384CSR, "node-2"},
		"bad node name": {csr, "../x"},
		"empty name":    {csr, ""},
	} {
		if _, err := ca.SignNodeCSR(tc.csr, tc.node, 0); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

func TestNeedsRenewal(t *testing.T) {
	t.Parallel()
	now := time.Now()
	// Like SignNodeCSR: issued age ago, valid for life, NotBefore backdated.
	cert := func(age, life time.Duration) *x509.Certificate {
		issued := now.Add(-age)
		return &x509.Certificate{NotBefore: issued.Add(-clockSkew), NotAfter: issued.Add(life)}
	}
	for name, tc := range map[string]struct {
		c    *x509.Certificate
		want bool
	}{
		"fresh":                       {cert(time.Hour, NodeValidity), false},
		"two thirds":                  {cert(19*24*time.Hour, NodeValidity), false},
		"last third":                  {cert(21*24*time.Hour, NodeValidity), true},
		"expired":                     {cert(31*24*time.Hour, NodeValidity), true},
		"legacy 1 year":               {cert(time.Hour, LeafValidity), true},
		"short (tests)":               {cert(10*time.Second, 30*time.Second), false},
		"short and late":              {cert(25*time.Second, 30*time.Second), true},
		"legacy 1 year (no backdate)": {&x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(LeafValidity)}, true},
	} {
		if got := NeedsRenewal(tc.c, now); got != tc.want {
			t.Errorf("%s: NeedsRenewal = %v", name, got)
		}
	}
}

// joinListener serves TLS with cfg and completes handshakes in the
// background.
func joinListener(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}()
		}
	}()
	return l.Addr().String()
}

func serverCert(t *testing.T, ca *CA) (certPEM, keyPEM []byte) {
	t.Helper()
	certPEM, keyPEM, err := ca.Issue(IssueRequest{Identity: Identity{Kind: KindServer, Name: "s"}, DNSNames: []string{ServerName}, Server: true})
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM
}

func TestFetchPinnedCA(t *testing.T) {
	t.Parallel()
	ca, _ := NewCA("real")
	certPEM, keyPEM := serverCert(t, ca)
	cfg, err := JoinServerTLS(ca.CertPEM, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Error("join listener asks for client certificates")
	}
	addr := joinListener(t, cfg)
	ctx := context.Background()

	got, err := FetchPinnedCA(ctx, addr, Fingerprint(ca.Cert))
	if err != nil || !got.Equal(ca.Cert) {
		t.Fatalf("FetchPinnedCA = %v", err)
	}
	// The pinned config then verifies the server normally.
	conn, err := tls.Dial("tcp", addr, JoinClientTLS(got))
	if err != nil {
		t.Fatalf("dial with pinned CA: %v", err)
	}
	_ = conn.Close()

	other, _ := NewCA("other")
	if _, err := FetchPinnedCA(ctx, addr, Fingerprint(other.Cert)); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("wrong pin = %v", err)
	}

	// A man in the middle with its own CA, even one that also sends the
	// real CA certificate along, is rejected.
	mitmCert, mitmKey := serverCert(t, other)
	mitm, _ := tls.X509KeyPair(mitmCert, mitmKey)
	mitm.Certificate = append(mitm.Certificate, ca.Cert.Raw)
	mitmAddr := joinListener(t, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{mitm}})
	if _, err := FetchPinnedCA(ctx, mitmAddr, Fingerprint(ca.Cert)); err == nil || !strings.Contains(err.Error(), "not valid for the pinned CA") {
		t.Errorf("MITM = %v", err)
	}

	// A server that does not send its CA.
	plain, _ := tls.X509KeyPair(certPEM, keyPEM)
	bareAddr := joinListener(t, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{plain}})
	if _, err := FetchPinnedCA(ctx, bareAddr, Fingerprint(ca.Cert)); err == nil {
		t.Error("server without CA in chain accepted")
	}

	// A pinned "CA" that is just the leaf.
	leaf, _ := ParseCertPEM(certPEM)
	selfish, _ := tls.X509KeyPair(certPEM, keyPEM)
	selfish.Certificate = append(selfish.Certificate, leaf.Raw)
	leafAddr := joinListener(t, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{selfish}})
	if _, err := FetchPinnedCA(ctx, leafAddr, Fingerprint(leaf)); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Errorf("leaf as CA = %v", err)
	}

	// Nothing listening.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	_ = l.Close()
	if _, err := FetchPinnedCA(ctx, dead, Fingerprint(ca.Cert)); err == nil {
		t.Error("dead address accepted")
	}
}

func TestSignMetricsCSR(t *testing.T) {
	t.Parallel()
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	// The CA decides the identity: a CSR asking for admin still gets a
	// metrics certificate.
	_, csr, err := NewCSR(Identity{Kind: KindAdmin, Name: "root"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.SignMetricsCSR(csr, "prometheus")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertPEM(c.PEM)
	if err != nil {
		t.Fatal(err)
	}
	id, err := IdentityFromCert(cert)
	if err != nil || id != (Identity{Kind: KindMetrics, Name: "prometheus"}) {
		t.Errorf("identity %v, %v", id, err)
	}
	if life := time.Until(cert.NotAfter); life < LeafValidity-time.Hour || life > LeafValidity {
		t.Errorf("lifetime %s", life)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("usages %v", cert.ExtKeyUsage)
	}
	if _, err := ca.SignMetricsCSR(csr, "../bad"); err == nil {
		t.Error("invalid name accepted")
	}
}
