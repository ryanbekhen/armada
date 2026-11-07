package pki

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestRenewDue(t *testing.T) {
	t.Parallel()
	ca, _ := NewCA("c")
	certPEM, _, err := ca.Issue(IssueRequest{Identity: Identity{Kind: KindServer, Name: "s"}, Server: true, Validity: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := ParseCertPEM(certPEM)
	now := time.Now()
	if RenewDue(c, now) || RenewDue(c, now.Add(19*24*time.Hour)) {
		t.Error("due with more than a third left")
	}
	if !RenewDue(c, now.Add(21*24*time.Hour)) || !RenewDue(c, now.Add(40*24*time.Hour)) {
		t.Error("not due in the last third or after expiry")
	}
}

func TestReissueKeepsKeyNamesAndUsages(t *testing.T) {
	t.Parallel()
	ca, _ := NewCA("c")
	certPEM, keyPEM, _ := ca.Issue(IssueRequest{Identity: Identity{Kind: KindServer, Name: "cp-1"}, DNSNames: []string{ServerName}, IPs: []net.IP{net.ParseIP("10.0.0.2")}, Server: true, Validity: time.Hour})
	old, _ := ParseCertPEM(certPEM)
	newPEM, err := ca.Reissue(old, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := ParseCertPEM(newPEM)
	if _, err := tls.X509KeyPair(newPEM, keyPEM); err != nil {
		t.Errorf("new certificate does not match the old key: %v", err)
	}
	if c.Subject.CommonName != "server:cp-1" || len(c.DNSNames) != 1 || c.DNSNames[0] != ServerName || !c.IPAddresses[0].Equal(net.ParseIP("10.0.0.2")) {
		t.Errorf("names changed: %s %v %v", c.Subject.CommonName, c.DNSNames, c.IPAddresses)
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("usages changed: %v", c.ExtKeyUsage)
	}
	if c.SerialNumber.Cmp(old.SerialNumber) == 0 || time.Until(c.NotAfter) < 300*24*time.Hour {
		t.Errorf("serial %v, expires %v", c.SerialNumber, c.NotAfter)
	}
	if err := c.CheckSignatureFrom(ca.Cert); err != nil {
		t.Error(err)
	}
}

func TestReissueRefusesOtherCA(t *testing.T) {
	t.Parallel()
	ca, _ := NewCA("c")
	other, _ := NewCA("other")
	certPEM, _, _ := other.Issue(IssueRequest{Identity: Identity{Kind: KindAdmin, Name: "eve"}, Client: true})
	c, _ := ParseCertPEM(certPEM)
	if _, err := ca.Reissue(c, 0); err == nil {
		t.Error("reissued a certificate of another CA")
	}
}

func TestSignAdminCSR(t *testing.T) {
	t.Parallel()
	ca, _ := NewCA("c")
	_, csr, _ := NewCSR(Identity{Kind: KindServer, Name: "asks-for-more"})
	got, err := ca.SignAdminCSR(csr, "root")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := ParseCertPEM(got.PEM)
	if id, _ := IdentityFromCert(c); id.String() != "admin:root" || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("identity %v, usages %v", id, c.ExtKeyUsage)
	}
}

func TestServerCertSwapsOnNextHandshake(t *testing.T) {
	t.Parallel()
	ca, _ := NewCA("c")
	certPEM, keyPEM, _ := ca.Issue(IssueRequest{Identity: Identity{Kind: KindServer, Name: "cp-1"}, DNSNames: []string{ServerName}, Server: true})
	sc, err := NewServerCert(ca.CertPEM, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	// Refused: not for ServerName, a client certificate, another CA.
	wrongName, wrongKey, _ := ca.Issue(IssueRequest{Identity: Identity{Kind: KindServer, Name: "cp-1"}, Server: true})
	client, clientKey, _ := ca.Issue(IssueRequest{Identity: Identity{Kind: KindAdmin, Name: "a"}, DNSNames: []string{ServerName}, Client: true})
	other, _ := NewCA("other")
	foreign, foreignKey, _ := other.Issue(IssueRequest{Identity: Identity{Kind: KindServer, Name: "cp-1"}, DNSNames: []string{ServerName}, Server: true})
	for name, pair := range map[string][2][]byte{"no server name": {wrongName, wrongKey}, "client usage": {client, clientKey}, "other CA": {foreign, foreignKey}} {
		if err := sc.Set(pair[0], pair[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	l, err := tls.Listen("tcp", "127.0.0.1:0", sc.TLS())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()
	adminPEM, adminKey, _ := ca.Issue(IssueRequest{Identity: Identity{Kind: KindAdmin, Name: "a"}, Client: true})
	cfg, err := ClientTLS(ca.CertPEM, adminPEM, adminKey)
	if err != nil {
		t.Fatal(err)
	}
	served := func() []byte {
		conn, err := tls.Dial("tcp", l.Addr().String(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].Raw
	}
	first := served()
	newPEM, err := ca.Reissue(sc.Leaf(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.Set(newPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	second := served()
	want, _ := ParseCertPEM(newPEM)
	if bytes.Equal(first, second) || !bytes.Equal(second, want.Raw) {
		t.Error("the next handshake did not use the renewed certificate")
	}
	// The join config sends the CA along for pinning.
	jc := sc.JoinTLS()
	got, _ := jc.GetCertificate(nil)
	if len(got.Certificate) != 2 || !bytes.Equal(got.Certificate[1], ca.Cert.Raw) || !bytes.Equal(got.Certificate[0], want.Raw) {
		t.Error("join certificate is not the renewed leaf and the CA")
	}
}
