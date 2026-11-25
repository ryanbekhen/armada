package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/fsutil"
)

// The parity tests of the Rust port (ADR 0055): armada-pki-parity, built
// with `cargo build -p armada-pki --features parity`, issues, signs, reads,
// and refuses what this package does, and each side accepts what the other
// issued.

func pkiBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("ARMADA_PKI_BIN")
	if bin == "" {
		t.Skip("ARMADA_PKI_BIN is not set (cargo build -p armada-pki --features parity)")
	}
	return bin
}

type rustAnswer map[string]any

func (a rustAnswer) str(k string) string { s, _ := a[k].(string); return s }

func (a rustAnswer) err() string { return a.str("error") }

func rust(t *testing.T, cmd string, req any) rustAnswer {
	t.Helper()
	in, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	c := exec.Command(pkiBin(t), cmd)
	c.Stdin = bytes.NewReader(in)
	c.Stderr = os.Stderr
	out, err := c.Output()
	if err != nil {
		t.Fatalf("armada-pki-parity %s: %v", cmd, err)
	}
	var a rustAnswer
	if err := json.Unmarshal(out, &a); err != nil {
		t.Fatalf("armada-pki-parity %s answered %q: %v", cmd, out, err)
	}
	return a
}

// rustOK is rust for a call that must succeed.
func rustOK(t *testing.T, cmd string, req any) rustAnswer {
	t.Helper()
	a := rust(t, cmd, req)
	if e := a.err(); e != "" {
		t.Fatalf("armada-pki-parity %s: %s", cmd, e)
	}
	return a
}

func caKeyPEM(t *testing.T, ca *CA) string {
	t.Helper()
	k, err := ca.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	return string(k)
}

// shape is everything of a certificate that does not depend on its key,
// serial, or the moment it was issued.
type shape struct {
	Version, SigAlg, PubAlg       string
	RawSubject, RawIssuer         []byte
	KeyUsage                      x509.KeyUsage
	ExtKeyUsage                   []x509.ExtKeyUsage
	BasicConstraintsValid, IsCA   bool
	MaxPathLen                    int
	MaxPathLenZero                bool
	DNSNames                      []string
	IPs                           []string
	AuthorityKeyID                []byte
	Life                          time.Duration
	Extensions                    []string
	SubjectKeyIDFromKey, Curve256 bool
}

func shapeOf(t *testing.T, c *x509.Certificate) shape {
	t.Helper()
	s := shape{
		Version: fmt.Sprint(c.Version), SigAlg: c.SignatureAlgorithm.String(), PubAlg: c.PublicKeyAlgorithm.String(),
		RawSubject: c.RawSubject, RawIssuer: c.RawIssuer, KeyUsage: c.KeyUsage, ExtKeyUsage: c.ExtKeyUsage,
		BasicConstraintsValid: c.BasicConstraintsValid, IsCA: c.IsCA, MaxPathLen: c.MaxPathLen, MaxPathLenZero: c.MaxPathLenZero,
		DNSNames: c.DNSNames, AuthorityKeyID: c.AuthorityKeyId, Life: c.NotAfter.Sub(c.NotBefore),
	}
	for _, ip := range c.IPAddresses {
		s.IPs = append(s.IPs, ip.String())
	}
	// Every extension in order, with its criticality and value; the
	// subject key identifier (the CA's) depends on the key, so it is
	// checked against the key instead.
	for _, e := range c.Extensions {
		v := base64.StdEncoding.EncodeToString(e.Value)
		if e.Id.Equal([]int{2, 5, 29, 14}) {
			v = "ski"
		}
		s.Extensions = append(s.Extensions, fmt.Sprintf("%v %v %s", e.Id, e.Critical, v))
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	s.Curve256 = ok && pub.Curve == elliptic.P256()
	if len(c.SubjectKeyId) > 0 && ok {
		point, _ := pub.Bytes()
		h := sha256.Sum256(point)
		s.SubjectKeyIDFromKey = bytes.Equal(c.SubjectKeyId, h[:20])
	}
	if c.SerialNumber.Sign() < 0 || c.SerialNumber.BitLen() > 128 {
		t.Errorf("serial %v outside [0, 2^128)", c.SerialNumber)
	}
	return s
}

func mustParse(t *testing.T, pemText string) *x509.Certificate {
	t.Helper()
	c, err := ParseCertPEM([]byte(pemText))
	if err != nil {
		t.Fatalf("parse %q: %v", pemText, err)
	}
	return c
}

func sameShape(t *testing.T, what string, goCert, rustCert *x509.Certificate) {
	t.Helper()
	g, r := shapeOf(t, goCert), shapeOf(t, rustCert)
	// Lifetimes are whole seconds apart from the moment of issue.
	if d := g.Life - r.Life; d < -2*time.Second || d > 2*time.Second {
		t.Errorf("%s: lifetime Go %v, Rust %v", what, g.Life, r.Life)
	}
	g.Life, r.Life = 0, 0
	gj, _ := json.MarshalIndent(g, "", " ")
	rj, _ := json.MarshalIndent(r, "", " ")
	if !bytes.Equal(gj, rj) {
		t.Errorf("%s: certificates differ\nGo:   %s\nRust: %s", what, gj, rj)
	}
}

// keyMatchesGo checks a key Rust wrote reads in Go and encodes back to the
// same bytes: Go's PKCS#8 for P-256.
func keyMatchesGo(t *testing.T, keyPEM string) {
	t.Helper()
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("not a PRIVATE KEY block: %q", keyPEM)
	}
	k, err := ParseKeyPEM([]byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	again, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, block.Bytes) {
		t.Errorf("Rust's PKCS#8 differs from Go's encoding of the same key")
	}
	if goPEM, _ := encodeKey(k); string(goPEM) != keyPEM {
		t.Errorf("Rust's key PEM differs from Go's:\n%s\n%s", goPEM, keyPEM)
	}
}

func TestArmadaPKIIssuesWhatGoIssues(t *testing.T) {
	pkiBin(t)
	ca, err := NewCA("lab_1")
	if err != nil {
		t.Fatal(err)
	}
	caKey := caKeyPEM(t, ca)
	for name, req := range map[string]IssueRequest{
		"server":  {Identity: Identity{Kind: KindServer, Name: "cp-1"}, DNSNames: []string{ServerName}, IPs: []net.IP{net.ParseIP("10.0.0.2")}, Server: true},
		"etcd":    {Identity: EtcdMember, IPs: []net.IP{net.ParseIP("10.0.0.2"), net.ParseIP("192.168.1.9"), net.ParseIP("fd00::7")}, Server: true, Client: true},
		"user":    {Identity: Identity{Kind: KindUser, Name: "ada_l"}, Client: true},
		"admin":   {Identity: Identity{Kind: KindAdmin, Name: "root"}, Client: true},
		"service": {Identity: Identity{Kind: KindService, Name: "ci"}, Client: true, Validity: ServiceValidity},
		"metrics": {Identity: Identity{Kind: KindMetrics, Name: "prom"}, Client: true},
		"node":    {Identity: Identity{Kind: KindNode, Name: "web-1"}, Client: true, Validity: NodeValidity},
		"short":   {Identity: Identity{Kind: KindServer, Name: "s"}, DNSNames: []string{ServerName, "other.example"}, Server: true, Validity: time.Hour},
		"capped":  {Identity: Identity{Kind: KindUser, Name: "u"}, Client: true, Validity: 20 * 365 * 24 * time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			goPEM, _, err := ca.Issue(req)
			if err != nil {
				t.Fatal(err)
			}
			var ips []string
			for _, ip := range req.IPs {
				ips = append(ips, ip.String())
			}
			a := rustOK(t, "issue", map[string]any{
				"caCert": string(ca.CertPEM), "caKey": caKey, "kind": req.Identity.Kind, "name": req.Identity.Name,
				"dns": req.DNSNames, "ips": ips, "server": req.Server, "client": req.Client,
				"validitySeconds": int64(req.Validity / time.Second),
			})
			rc := mustParse(t, a.str("cert"))
			sameShape(t, name, mustParse(t, string(goPEM)), rc)
			keyMatchesGo(t, a.str("key"))
			if _, err := tls.X509KeyPair([]byte(a.str("cert")), []byte(a.str("key"))); err != nil {
				t.Errorf("certificate and key do not pair: %v", err)
			}
			if err := rc.CheckSignatureFrom(ca.Cert); err != nil {
				t.Error(err)
			}
			if id, err := IdentityFromCert(rc); err != nil || id != req.Identity {
				t.Errorf("identity %v, %v", id, err)
			}
			usage := x509.ExtKeyUsageClientAuth
			if req.Server {
				usage = x509.ExtKeyUsageServerAuth
			}
			roots := x509.NewCertPool()
			roots.AddCert(ca.Cert)
			if _, err := rc.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
				t.Errorf("Go does not verify Rust's certificate: %v", err)
			}
			if req.Server && slicesContain(req.DNSNames, ServerName) {
				if _, err := NewServerCert(ca.CertPEM, []byte(a.str("cert")), []byte(a.str("key"))); err != nil {
					t.Errorf("Go does not serve Rust's server certificate: %v", err)
				}
			}
			if name == "capped" && !rc.NotAfter.Equal(ca.Cert.NotAfter) {
				t.Errorf("not capped at the CA: %v, CA %v", rc.NotAfter, ca.Cert.NotAfter)
			}
			if d := time.Until(rc.NotBefore) + ClockSkew; d > 2*time.Second || d < -5*time.Second {
				t.Errorf("NotBefore %v not backdated by the clock skew", rc.NotBefore)
			}
		})
	}
	for _, tc := range []struct {
		kind, name     string
		server, client bool
	}{{"root", "x", false, true}, {KindUser, "../x", false, true}, {KindUser, "", false, true}, {KindUser, "x", false, false}, {"", "", true, false}} {
		req := IssueRequest{Identity: Identity{Kind: tc.kind, Name: tc.name}, Server: tc.server, Client: tc.client}
		_, _, goErr := ca.Issue(req)
		a := rust(t, "issue", map[string]any{"caCert": string(ca.CertPEM), "caKey": caKey, "kind": tc.kind, "name": tc.name, "server": tc.server, "client": tc.client})
		if goErr == nil || a.err() != goErr.Error() {
			t.Errorf("Issue(%+v): Go %v, Rust %q", req, goErr, a.err())
		}
	}
}

func slicesContain(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestArmadaPKICAMatchesGo(t *testing.T) {
	pkiBin(t)
	goCA, err := NewCA("lab-1")
	if err != nil {
		t.Fatal(err)
	}
	a := rustOK(t, "new-ca", map[string]any{"name": "lab-1"})
	rc := mustParse(t, a.str("cert"))
	sameShape(t, "CA", goCA.Cert, rc)
	if !shapeOf(t, rc).SubjectKeyIDFromKey || !shapeOf(t, goCA.Cert).SubjectKeyIDFromKey {
		t.Error("subject key identifier is not the truncated SHA-256 of the key")
	}
	keyMatchesGo(t, a.str("key"))
	rustCA, err := LoadCA([]byte(a.str("cert")), []byte(a.str("key")))
	if err != nil {
		t.Fatalf("Go does not load Rust's CA: %v", err)
	}
	if err := rc.CheckSignatureFrom(rc); err != nil {
		t.Errorf("self-signature: %v", err)
	}

	// Go issues from Rust's CA; Rust reads and checks it, and the reverse.
	srv, srvKey, err := rustCA.Issue(IssueRequest{Identity: Identity{Kind: KindServer, Name: "cp-1"}, DNSNames: []string{ServerName}, IPs: []net.IP{net.ParseIP("10.0.0.2")}, Server: true})
	if err != nil {
		t.Fatal(err)
	}
	rustOK(t, "verify-server", map[string]any{"ca": a.str("cert"), "cert": string(srv)})
	d := rustOK(t, "read-cert", map[string]any{"cert": string(srv)})
	if d.str("identity") != "server:cp-1" || d.str("fingerprint") != Fingerprint(mustParse(t, string(srv))) {
		t.Errorf("Rust reads %v", d)
	}
	if _, err := NewServerCert([]byte(a.str("cert")), srv, srvKey); err != nil {
		t.Error(err)
	}
	g := rustOK(t, "load-ca", map[string]any{"cert": string(goCA.CertPEM), "key": caKeyPEM(t, goCA)})
	if g.str("fingerprint") != Fingerprint(goCA.Cert) {
		t.Errorf("fingerprint %q, want %q", g.str("fingerprint"), Fingerprint(goCA.Cert))
	}
	k := rustOK(t, "key", map[string]any{"key": caKeyPEM(t, goCA)})
	der, _ := x509.MarshalPKCS8PrivateKey(goCA.key)
	if k.str("pkcs8") != base64.StdEncoding.EncodeToString(der) {
		t.Error("Rust reads Go's key as other bytes")
	}

	// LoadCA's refusals.
	other, _ := NewCA("other")
	leaf, leafKey, _ := goCA.Issue(IssueRequest{Identity: Identity{Kind: KindUser, Name: "u"}, Client: true})
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER})
	for name, tc := range map[string][2]string{
		"no cert":   {"junk", caKeyPEM(t, goCA)},
		"not a CA":  {string(leaf), string(leafKey)},
		"no key":    {string(goCA.CertPEM), "junk"},
		"cert key":  {string(goCA.CertPEM), string(goCA.CertPEM)},
		"other key": {string(goCA.CertPEM), caKeyPEM(t, other)},
		"rsa key":   {string(goCA.CertPEM), string(rsaPEM)},
	} {
		_, goErr := LoadCA([]byte(tc[0]), []byte(tc[1]))
		r := rust(t, "load-ca", map[string]any{"cert": tc[0], "key": tc[1]})
		if goErr == nil || r.err() != goErr.Error() {
			t.Errorf("%s: Go %v, Rust %q", name, goErr, r.err())
		}
	}
}

func TestArmadaPKISignsCSRs(t *testing.T) {
	pkiBin(t)
	ca, _ := NewCA("c")
	caKey := caKeyPEM(t, ca)
	_, csr, err := NewCSR(Identity{Kind: KindServer, Name: "asks-for-more"})
	if err != nil {
		t.Fatal(err)
	}
	sign := func(as, name string, csr []byte, validity time.Duration) rustAnswer {
		return rust(t, "sign-csr", map[string]any{"caCert": string(ca.CertPEM), "caKey": caKey, "csr": base64.StdEncoding.EncodeToString(csr),
			"as": as, "name": name, "validitySeconds": int64(validity / time.Second)})
	}
	goSign := map[string]func([]byte, string, time.Duration) (NodeCert, error){
		"node":    func(c []byte, n string, v time.Duration) (NodeCert, error) { return ca.SignNodeCSR(c, n, v) },
		"user":    func(c []byte, n string, _ time.Duration) (NodeCert, error) { return ca.SignUserCSR(c, n) },
		"service": func(c []byte, n string, _ time.Duration) (NodeCert, error) { return ca.SignServiceCSR(c, n) },
		"metrics": func(c []byte, n string, _ time.Duration) (NodeCert, error) { return ca.SignMetricsCSR(c, n) },
	}
	for as, f := range goSign {
		for _, validity := range []time.Duration{0, time.Hour, 400 * 24 * time.Hour} {
			goNC, err := f(csr, "n-1", validity)
			if err != nil {
				t.Fatal(err)
			}
			a := sign(as, "n-1", csr, validity)
			if a.err() != "" {
				t.Fatalf("%s: %s", as, a.err())
			}
			rc := mustParse(t, a.str("cert"))
			sameShape(t, as, mustParse(t, string(goNC.PEM)), rc)
			if a.str("serial") != SerialString(rc) {
				t.Errorf("%s: serial %q, certificate's %q", as, a.str("serial"), SerialString(rc))
			}
			if nb, _ := a["notBefore"].(float64); int64(nb) != rc.NotBefore.Unix() {
				t.Errorf("%s: notBefore %v, certificate's %v", as, nb, rc.NotBefore)
			}
			if id, _ := IdentityFromCert(rc); id.String() != map[string]string{"node": "node", "user": "user", "service": "service", "metrics": "metrics"}[as]+":n-1" {
				t.Errorf("%s: identity %v", as, id)
			}
		}
	}

	// A request Rust made is one Go signs, and looks like Go's own.
	a := rustOK(t, "new-csr", map[string]any{"kind": KindNode, "name": "web-1"})
	rustCSR, _ := base64.StdEncoding.DecodeString(a.str("csr"))
	keyMatchesGo(t, a.str("key"))
	nc, err := ca.SignNodeCSR(rustCSR, "web-1", 0)
	if err != nil {
		t.Fatalf("Go does not sign Rust's CSR: %v", err)
	}
	if _, err := tls.X509KeyPair(nc.PEM, []byte(a.str("key"))); err != nil {
		t.Error(err)
	}
	_, goCSR, _ := NewNodeCSR("web-1")
	gr, _ := x509.ParseCertificateRequest(goCSR)
	rr, err := x509.ParseCertificateRequest(rustCSR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gr.RawSubject, rr.RawSubject) || gr.SignatureAlgorithm != rr.SignatureAlgorithm || len(rr.RawTBSCertificateRequest) != len(gr.RawTBSCertificateRequest) || len(rr.Extensions) != 0 || rr.Version != gr.Version {
		t.Errorf("Rust's CSR differs: subject %q, %v, request %x", rr.Subject, rr.SignatureAlgorithm, rr.RawTBSCertificateRequest)
	}
	if r := rust(t, "new-csr", map[string]any{"kind": "root", "name": "x"}); r.err() != `unknown identity kind "root"` {
		t.Errorf("new-csr of a bad identity: %q", r.err())
	}

	// Refusals: the same outcome, and Go's text where it is Armada's own.
	tampered := append([]byte(nil), csr...)
	tampered[len(tampered)-5] ^= 0xff
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "node:x"}}, rsaKey)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384CSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "node:x"}}, p384)
	for name, tc := range map[string]struct {
		csr        []byte
		node       string
		prefixOnly bool
	}{
		"garbage":       {[]byte("not a csr"), "n", true},
		"empty":         {nil, "n", true},
		"trailing":      {append(append([]byte(nil), csr...), 0), "n", true},
		"bad signature": {tampered, "n", false},
		"rsa key":       {rsaCSR, "n", false},
		"p384 key":      {p384CSR, "n", false},
		"bad node name": {csr, "../x", false},
		"empty name":    {csr, "", false},
		"long name":     {csr, strings.Repeat("a", 64), false},
	} {
		for as, f := range goSign {
			_, goErr := f(tc.csr, tc.node, 0)
			r := sign(as, tc.node, tc.csr, 0)
			switch {
			case goErr == nil || r.err() == "":
				t.Errorf("%s/%s: Go %v, Rust %q", name, as, goErr, r.err())
			case tc.prefixOnly:
				if !strings.HasPrefix(goErr.Error(), "parse CSR: ") || !strings.HasPrefix(r.err(), "parse CSR: ") {
					t.Errorf("%s/%s: Go %v, Rust %q", name, as, goErr, r.err())
				}
			case r.err() != goErr.Error():
				t.Errorf("%s/%s: Go %q, Rust %q", name, as, goErr, r.err())
			}
		}
	}
}

func TestArmadaPKIReissues(t *testing.T) {
	pkiBin(t)
	ca, _ := NewCA("c")
	caKey := caKeyPEM(t, ca)
	certPEM, keyPEM, _ := ca.Issue(IssueRequest{Identity: Identity{Kind: KindServer, Name: "cp-1"}, DNSNames: []string{ServerName}, IPs: []net.IP{net.ParseIP("10.0.0.2")}, Server: true, Validity: time.Hour})
	old := mustParse(t, string(certPEM))
	for _, validity := range []time.Duration{0, 2 * time.Hour} {
		goNew, err := ca.Reissue(old, validity)
		if err != nil {
			t.Fatal(err)
		}
		a := rustOK(t, "reissue", map[string]any{"caCert": string(ca.CertPEM), "caKey": caKey, "cert": string(certPEM), "validitySeconds": int64(validity / time.Second)})
		rc := mustParse(t, a.str("cert"))
		sameShape(t, "reissue", mustParse(t, string(goNew)), rc)
		if _, err := tls.X509KeyPair([]byte(a.str("cert")), keyPEM); err != nil {
			t.Errorf("the reissued certificate does not match the old key: %v", err)
		}
		if rc.SerialNumber.Cmp(old.SerialNumber) == 0 {
			t.Error("serial unchanged")
		}
	}
	// Go reissues what Rust issued, and Rust reads it.
	a := rustOK(t, "issue", map[string]any{"caCert": string(ca.CertPEM), "caKey": caKey, "kind": KindUser, "name": "u", "client": true})
	goNew, err := ca.Reissue(mustParse(t, a.str("cert")), 0)
	if err != nil {
		t.Fatal(err)
	}
	if d := rustOK(t, "read-cert", map[string]any{"cert": string(goNew)}); d.str("identity") != "user:u" || d.str("principal") != "user:u" {
		t.Errorf("Rust reads %v", d)
	}

	other, _ := NewCA("c")
	foreign, _, _ := other.Issue(IssueRequest{Identity: Identity{Kind: KindAdmin, Name: "eve"}, Client: true})
	noEKU := signRaw(t, ca, &x509.Certificate{Subject: pkix.Name{CommonName: "user:x"}, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true})
	notIdentity := signRaw(t, ca, &x509.Certificate{Subject: pkix.Name{CommonName: "x"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true})
	for name, c := range map[string][]byte{"other CA": foreign, "no usage": noEKU, "not an identity": notIdentity, "the CA": ca.CertPEM} {
		_, goErr := ca.Reissue(mustParse(t, string(c)), 0)
		r := rust(t, "reissue", map[string]any{"caCert": string(ca.CertPEM), "caKey": caKey, "cert": string(c)})
		if goErr == nil || r.err() != goErr.Error() {
			t.Errorf("%s: Go %v, Rust %q", name, goErr, r.err())
		}
	}
}

// signRaw has the CA sign a template as is, for certificates Armada never
// issues.
func signRaw(t *testing.T, ca *CA, tmpl *x509.Certificate) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := newSerial()
	tmpl.SerialNumber = serial
	tmpl.NotBefore = time.Now().Add(-time.Minute)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return encodeCert(der)
}

func TestArmadaPKIReadsIdentities(t *testing.T) {
	pkiBin(t)
	for _, cn := range []string{"node:web-1", "user:a", "admin:root", "automation:ci", "service:ci", "metrics:p", "etcd:member", "server:s",
		"web-1", "root:x", "node:", "node:../x", "node:-x", "node:a:b", "node:a\nb", ":", "node:" + strings.Repeat("a", 63), "node:" + strings.Repeat("a", 64), "node:é", "node:\u00a0"} {
		id, goErr := ParseIdentity(cn)
		a := rust(t, "parse-identity", map[string]any{"cn": cn})
		if goErr != nil {
			if a.err() != goErr.Error() {
				t.Errorf("%q: Go %q, Rust %q", cn, goErr, a.err())
			}
			continue
		}
		if a.str("kind") != id.Kind || a.str("name") != id.Name {
			t.Errorf("%q: Go %v, Rust %v", cn, id, a)
		}
	}
	ca, _ := NewCA("c")
	for _, id := range []Identity{{KindAdmin, "root"}, {KindAutomation, "ci"}, {KindUser, "u"}, {KindNode, "n"}, {KindMetrics, "m"}} {
		c, _, _ := ca.Issue(IssueRequest{Identity: id, Client: true})
		a := rustOK(t, "read-cert", map[string]any{"cert": string(c)})
		want := ""
		if p, ok := id.Principal(); ok {
			want = p.String()
		}
		if a.str("identity") != id.String() || a.str("principal") != want {
			t.Errorf("%v: Rust reads %s, principal %q", id, a.str("identity"), a.str("principal"))
		}
		gc := mustParse(t, string(c))
		if a.str("serial") != SerialString(gc) || a.str("caHash") != CAHash(gc) {
			t.Errorf("%v: serial %q/%q, hash %q/%q", id, a.str("serial"), SerialString(gc), a.str("caHash"), CAHash(gc))
		}
	}
	bad := signRaw(t, ca, &x509.Certificate{Subject: pkix.Name{CommonName: "nobody"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	_, goErr := IdentityFromCert(mustParse(t, string(bad)))
	if a := rustOK(t, "read-cert", map[string]any{"cert": string(bad)}); goErr == nil || a.str("identityError") != goErr.Error() {
		t.Errorf("Go %v, Rust %q", goErr, a.str("identityError"))
	}
	if a := rust(t, "read-cert", map[string]any{"cert": "junk"}); a.err() != "no PEM certificate found" {
		t.Errorf("junk: %q", a.err())
	}
}

func TestArmadaPKIRenewal(t *testing.T) {
	pkiBin(t)
	ca, _ := NewCA("c")
	now := time.Now()
	for _, validity := range []time.Duration{time.Minute, time.Hour, NodeValidity, ServiceValidity, LeafValidity} {
		c, _, _ := ca.Issue(IssueRequest{Identity: Identity{Kind: KindNode, Name: "n"}, Client: true, Validity: validity})
		gc := mustParse(t, string(c))
		for _, at := range []time.Duration{0, validity / 2, validity * 2 / 3, validity*2/3 + 10*time.Minute, validity, 2 * validity, -time.Hour} {
			when := now.Add(at)
			a := rustOK(t, "renewal", map[string]any{"cert": string(c), "now": when.UnixNano()})
			if a["renewDue"] != RenewDue(gc, when) || a["needsRenewal"] != NeedsRenewal(gc, when) {
				t.Errorf("validity %v at +%v: Rust %v/%v, Go %v/%v", validity, at, a["renewDue"], a["needsRenewal"], RenewDue(gc, when), NeedsRenewal(gc, when))
			}
		}
	}
}

func TestArmadaPKIVerifiesServers(t *testing.T) {
	pkiBin(t)
	ca, _ := NewCA("c")
	other, _ := NewCA("c")
	issue := func(ca *CA, req IssueRequest) []byte {
		c, _, err := ca.Issue(req)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	good := issue(ca, IssueRequest{Identity: Identity{Kind: KindServer, Name: "s"}, DNSNames: []string{ServerName}, Server: true})
	cases := map[string]struct {
		cert []byte
		at   time.Time
	}{
		"good":      {good, time.Now()},
		"expired":   {good, time.Now().Add(400 * 24 * time.Hour)},
		"early":     {good, time.Now().Add(-time.Hour)},
		"other CA":  {issue(other, IssueRequest{Identity: Identity{Kind: KindServer, Name: "s"}, DNSNames: []string{ServerName}, Server: true}), time.Now()},
		"name":      {issue(ca, IssueRequest{Identity: Identity{Kind: KindServer, Name: "s"}, DNSNames: []string{"a", "b"}, Server: true}), time.Now()},
		"no names":  {issue(ca, IssueRequest{Identity: Identity{Kind: KindServer, Name: "s"}, IPs: []net.IP{net.ParseIP("10.0.0.1")}, Server: true}), time.Now()},
		"client":    {issue(ca, IssueRequest{Identity: Identity{Kind: KindServer, Name: "s"}, DNSNames: []string{ServerName}, Client: true}), time.Now()},
		"etcd both": {issue(ca, IssueRequest{Identity: EtcdMember, DNSNames: []string{ServerName}, Server: true, Client: true}), time.Now()},
	}
	for name, tc := range cases {
		roots := x509.NewCertPool()
		roots.AddCert(ca.Cert)
		_, goErr := mustParse(t, string(tc.cert)).Verify(x509.VerifyOptions{Roots: roots, DNSName: ServerName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: tc.at})
		a := rust(t, "verify-server", map[string]any{"ca": string(ca.CertPEM), "cert": string(tc.cert), "now": tc.at.UnixNano()})
		want := ""
		if goErr != nil {
			want = "server certificate: " + goErr.Error()
		}
		if a.err() != want {
			t.Errorf("%s:\nGo   %q\nRust %q", name, want, a.err())
		}
	}
}

func TestArmadaPKIPinsCAs(t *testing.T) {
	pkiBin(t)
	ca, _ := NewCA("c")
	other, _ := NewCA("c")
	srv := func(ca *CA, names ...string) *x509.Certificate {
		c, _, _ := ca.Issue(IssueRequest{Identity: Identity{Kind: KindServer, Name: "s"}, DNSNames: names, Server: true})
		return mustParse(t, string(c))
	}
	leaf, mitm := srv(ca, ServerName), srv(other, ServerName)
	pin := Fingerprint(ca.Cert)
	for name, tc := range map[string]struct {
		chain []*x509.Certificate
		hash  string
	}{
		"good":        {[]*x509.Certificate{leaf, ca.Cert}, pin},
		"extra":       {[]*x509.Certificate{leaf, other.Cert, ca.Cert}, pin},
		"leaf only":   {[]*x509.Certificate{leaf}, pin},
		"other CA":    {[]*x509.Certificate{mitm, other.Cert}, pin},
		"mitm leaf":   {[]*x509.Certificate{mitm, ca.Cert}, pin},
		"leaf pinned": {[]*x509.Certificate{leaf, leaf}, Fingerprint(leaf)},
		"wrong name":  {[]*x509.Certificate{srv(ca, "other"), ca.Cert}, pin},
		"no names":    {[]*x509.Certificate{srv(ca), ca.Cert}, pin},
		"upper-case":  {[]*x509.Certificate{leaf, ca.Cert}, strings.ToUpper(pin)},
	} {
		got, goErr := pinCA(tc.chain, tc.hash)
		var chain []string
		for _, c := range tc.chain {
			chain = append(chain, string(encodeCert(c.Raw)))
		}
		a := rust(t, "pin-ca", map[string]any{"chain": chain, "hash": tc.hash})
		switch {
		case goErr != nil && a.err() != goErr.Error():
			t.Errorf("%s: Go %q, Rust %q", name, goErr, a.err())
		case goErr == nil && (a.err() != "" || a.str("fingerprint") != Fingerprint(got)):
			t.Errorf("%s: Go pinned %s, Rust %v", name, Fingerprint(got), a)
		}
	}
}

func TestArmadaPKIJoinTokens(t *testing.T) {
	pkiBin(t)
	tok, _ := NewJoinToken()
	a := rustOK(t, "join-token", map[string]any{"token": " " + tok.Reveal() + "\n"})
	if a.str("id") != tok.ID || a.str("hash") != tok.SecretHash() || a.str("shown") != tok.String() || a.str("debug") != fmt.Sprintf("%#v", tok) {
		t.Errorf("Rust reads %v", a)
	}
	for _, s := range []string{"", tok.ID, tok.ID + ".", "." + tok.Secret, tok.ID + "." + tok.Secret[:63], tok.Reveal() + "0",
		strings.ToUpper(tok.Reveal()), tok.ID + ":" + tok.Secret, tok.Reveal() + ".x", "\u00a0" + tok.Reveal() + "\u2028"} {
		_, goErr := ParseJoinToken(s)
		r := rust(t, "join-token", map[string]any{"token": s})
		if (goErr == nil) != (r.err() == "") || (goErr != nil && r.err() != goErr.Error()) {
			t.Errorf("%q: Go %v, Rust %q", s, goErr, r.err())
		}
	}
	other, _ := NewJoinToken()
	for _, tc := range []struct{ secret, hash string }{{tok.Secret, tok.SecretHash()}, {other.Secret, tok.SecretHash()}, {"", tok.SecretHash()}, {tok.Secret, ""}, {tok.Secret, strings.ToUpper(tok.SecretHash())}} {
		r := rustOK(t, "token-matches", map[string]any{"secret": tc.secret, "hash": tc.hash})
		if r["match"] != TokenSecretMatches(tc.secret, tc.hash) || r.str("hash") != HashTokenSecret(tc.secret) {
			t.Errorf("%+v: Rust %v", tc, r)
		}
	}
	ca, _ := NewCA("c")
	for _, s := range []string{CAHash(ca.Cert), " " + CAHash(ca.Cert) + "\n", "", Fingerprint(ca.Cert), "sha1:" + Fingerprint(ca.Cert), "sha256:" + Fingerprint(ca.Cert)[:10], strings.ToUpper(CAHash(ca.Cert))} {
		h, goErr := ParseCAHash(s)
		r := rust(t, "ca-hash", map[string]any{"hash": s})
		if (goErr != nil && r.err() != goErr.Error()) || (goErr == nil && r.str("hex") != h) {
			t.Errorf("%q: Go %q %v, Rust %v", s, h, goErr, r)
		}
	}
}

func TestArmadaPKIFiles(t *testing.T) {
	pkiBin(t)
	// Go writes the CA as init does; Rust reads it.
	dir := t.TempDir()
	ca, _ := NewCA("c")
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, "ca.crt"), ca.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, "ca.key"), []byte(caKeyPEM(t, ca)), 0o600); err != nil {
		t.Fatal(err)
	}
	if a := rustOK(t, "load-ca-dir", map[string]any{"dir": dir}); a.str("fingerprint") != Fingerprint(ca.Cert) {
		t.Errorf("Rust reads %v", a)
	}
	// Rust writes one; Go reads it with the checks the daemon makes.
	rdir := t.TempDir()
	a := rustOK(t, "write-ca-dir", map[string]any{"dir": rdir, "name": "c"})
	var files [2][]byte
	for i, f := range []string{"ca.crt", "ca.key"} {
		fi, err := os.Stat(filepath.Join(rdir, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, fi.Mode(), err)
		}
		if files[i], err = fsutil.ReadPrivateFile(filepath.Join(rdir, f)); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := LoadCA(files[0], files[1]); err != nil || Fingerprint(got.Cert) != a.str("fingerprint") {
		t.Errorf("Go reads Rust's CA files: %v", err)
	}
	// Modes the daemon refuses, and missing files, with Go's texts.
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644} {
		path := filepath.Join(dir, "ca.key")
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, goErr := fsutil.ReadPrivateFile(path)
		if r := rust(t, "load-ca-dir", map[string]any{"dir": dir}); goErr == nil || r.err() != goErr.Error() {
			t.Errorf("mode %04o: Go %v, Rust %q", mode, goErr, r.err())
		}
	}
	missing := filepath.Join(t.TempDir(), "none")
	_, goErr := fsutil.ReadPrivateFile(filepath.Join(missing, "ca.crt"))
	if r := rust(t, "load-ca-dir", map[string]any{"dir": missing}); goErr == nil || r.err() != goErr.Error() {
		t.Errorf("missing: Go %v, Rust %q", goErr, r.err())
	}
}
