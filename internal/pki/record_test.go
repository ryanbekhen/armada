package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/fsutil"
)

// The parity cases of native_test.go recorded once from Go (ADR 0055,
// item 20): -record-fixtures writes the certificates, requests, keys, and
// tokens Go made and what Go answered about each as
// pki/tests/testdata/parity.json, which the crate's tests
// (pki/tests/parity.rs) replay with no Go: Rust issues and signs from Go's
// CA what Go issued and signed (compared by shape), reads what Go wrote,
// and refuses what Go refused with Go's texts. Test keys only, made for
// the fixture.
//
//	go test ./internal/pki -run TestRecordPKIFixtures -record-fixtures
var recordFixtures = flag.Bool("record-fixtures", false, "write pki/tests/testdata/parity.json from Go's answers")

const fixturePath = "../../pki/tests/testdata/parity.json"

// shapeJSON is shapeOf as the fixture holds it: every extension in order
// (the subject key identifier, which depends on the key, as "ski"), the
// raw names, the algorithms, and the lifetime in seconds.
func shapeJSON(t *testing.T, c *x509.Certificate) map[string]any {
	t.Helper()
	s := shapeOf(t, c)
	return map[string]any{
		"version": s.Version, "sigAlg": s.SigAlg, "pubAlg": s.PubAlg, "curve256": s.Curve256,
		"rawSubject": base64.StdEncoding.EncodeToString(s.RawSubject), "rawIssuer": base64.StdEncoding.EncodeToString(s.RawIssuer),
		"extensions": s.Extensions, "lifeSeconds": int64(c.NotAfter.Sub(c.NotBefore) / time.Second),
		"skiFromKey": s.SubjectKeyIDFromKey, "hasSKI": len(c.SubjectKeyId) > 0,
	}
}

func pemOf(c *x509.Certificate) string { return string(encodeCert(c.Raw)) }

func errText(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}

type pkiCase = map[string]any

func TestRecordPKIFixtures(t *testing.T) {
	if !*recordFixtures {
		t.Skip("-record-fixtures is not set")
	}
	now := time.Now().Truncate(time.Second)
	out := map[string]any{"recordedAt": now.UnixNano(), "clockSkewSeconds": int64(ClockSkew / time.Second)}

	ca, err := NewCA("lab_1")
	if err != nil {
		t.Fatal(err)
	}
	caKey := caKeyPEM(t, ca)
	out["ca"] = map[string]any{"cert": string(ca.CertPEM), "key": caKey, "fingerprint": Fingerprint(ca.Cert)}
	der, _ := x509.MarshalPKCS8PrivateKey(ca.key)
	point, _ := ca.key.PublicKey.Bytes()
	out["caKeyDER"] = map[string]any{"pkcs8": base64.StdEncoding.EncodeToString(der),
		"d": base64.StdEncoding.EncodeToString(mustBytes(t, ca.key)), "point": base64.StdEncoding.EncodeToString(point)}

	// What Go issues from its CA, by shape.
	issues := map[string]IssueRequest{
		"server":  {Identity: Identity{Kind: KindServer, Name: "cp-1"}, DNSNames: []string{ServerName}, IPs: []net.IP{net.ParseIP("10.0.0.2")}, Server: true},
		"etcd":    {Identity: EtcdMember, IPs: []net.IP{net.ParseIP("10.0.0.2"), net.ParseIP("192.168.1.9"), net.ParseIP("fd00::7")}, Server: true, Client: true},
		"user":    {Identity: Identity{Kind: KindUser, Name: "ada_l"}, Client: true},
		"admin":   {Identity: Identity{Kind: KindAdmin, Name: "root"}, Client: true},
		"service": {Identity: Identity{Kind: KindService, Name: "ci"}, Client: true, Validity: ServiceValidity},
		"metrics": {Identity: Identity{Kind: KindMetrics, Name: "prom"}, Client: true},
		"node":    {Identity: Identity{Kind: KindNode, Name: "web-1"}, Client: true, Validity: NodeValidity},
		"short":   {Identity: Identity{Kind: KindServer, Name: "s"}, DNSNames: []string{ServerName, "other.example"}, Server: true, Validity: time.Hour},
		"capped":  {Identity: Identity{Kind: KindUser, Name: "u"}, Client: true, Validity: 20 * 365 * 24 * time.Hour},
	}
	var issued []any
	for _, name := range sortedKeys(issues) {
		req := issues[name]
		goPEM, _, err := ca.Issue(req)
		if err != nil {
			t.Fatal(err)
		}
		issued = append(issued, pkiCase{"case": name, "req": issueReq(req), "shape": shapeJSON(t, mustParse(t, string(goPEM))), "identity": req.Identity.String()})
	}
	out["issue"] = issued
	var issueRefused []any
	for _, tc := range []struct {
		kind, name     string
		server, client bool
	}{{"root", "x", false, true}, {KindUser, "../x", false, true}, {KindUser, "", false, true}, {KindUser, "x", false, false}, {"", "", true, false}} {
		req := IssueRequest{Identity: Identity{Kind: tc.kind, Name: tc.name}, Server: tc.server, Client: tc.client}
		_, _, goErr := ca.Issue(req)
		if goErr == nil {
			t.Fatalf("Go issued %+v", req)
		}
		issueRefused = append(issueRefused, pkiCase{"req": issueReq(req), "error": goErr.Error()})
	}
	out["issueRefused"] = issueRefused

	// The CA: Go's shape of a new one, and LoadCA's refusals.
	goCA, _ := NewCA("lab-1")
	out["newCA"] = pkiCase{"name": "lab-1", "shape": shapeJSON(t, goCA.Cert)}
	other, _ := NewCA("other")
	leaf, leafKey, _ := ca.Issue(IssueRequest{Identity: Identity{Kind: KindUser, Name: "u"}, Client: true})
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER})
	var loadRefused []any
	for _, tc := range []struct{ name, cert, key string }{
		{"no cert", "junk", caKey},
		{"not a CA", string(leaf), string(leafKey)},
		{"no key", string(ca.CertPEM), "junk"},
		{"cert key", string(ca.CertPEM), string(ca.CertPEM)},
		{"other key", string(ca.CertPEM), caKeyPEM(t, other)},
		{"rsa key", string(ca.CertPEM), string(rsaPEM)},
	} {
		_, goErr := LoadCA([]byte(tc.cert), []byte(tc.key))
		if goErr == nil {
			t.Fatalf("%s: Go loaded it", tc.name)
		}
		loadRefused = append(loadRefused, pkiCase{"case": tc.name, "cert": tc.cert, "key": tc.key, "error": goErr.Error()})
	}
	out["loadRefused"] = loadRefused

	// CSRs: what Go's signers make of a request, by shape, and their
	// refusals.
	_, csr, err := NewCSR(Identity{Kind: KindServer, Name: "asks-for-more"})
	if err != nil {
		t.Fatal(err)
	}
	goSign := map[string]func([]byte, string, time.Duration) (NodeCert, error){
		"node":    func(c []byte, n string, v time.Duration) (NodeCert, error) { return ca.SignNodeCSR(c, n, v) },
		"user":    func(c []byte, n string, _ time.Duration) (NodeCert, error) { return ca.SignUserCSR(c, n) },
		"service": func(c []byte, n string, _ time.Duration) (NodeCert, error) { return ca.SignServiceCSR(c, n) },
		"metrics": func(c []byte, n string, _ time.Duration) (NodeCert, error) { return ca.SignMetricsCSR(c, n) },
	}
	var signed []any
	for _, as := range sortedKeys(goSign) {
		for _, validity := range []time.Duration{0, time.Hour, 400 * 24 * time.Hour} {
			nc, err := goSign[as](csr, "n-1", validity)
			if err != nil {
				t.Fatal(err)
			}
			c := mustParse(t, string(nc.PEM))
			id, _ := IdentityFromCert(c)
			signed = append(signed, pkiCase{"as": as, "validitySeconds": int64(validity / time.Second), "shape": shapeJSON(t, c), "identity": id.String()})
		}
	}
	out["csr"] = base64.StdEncoding.EncodeToString(csr)
	out["signed"] = signed
	_, goCSR, _ := NewNodeCSR("web-1")
	gr, _ := x509.ParseCertificateRequest(goCSR)
	out["nodeCSR"] = pkiCase{"csr": base64.StdEncoding.EncodeToString(goCSR), "rawSubject": base64.StdEncoding.EncodeToString(gr.RawSubject),
		"tbsLength": len(gr.RawTBSCertificateRequest), "sigAlg": gr.SignatureAlgorithm.String(), "version": gr.Version}
	_, _, goErr := NewCSR(Identity{Kind: "root", Name: "x"})
	out["newCSRRefused"] = pkiCase{"kind": "root", "name": "x", "error": errText(goErr)}
	tampered := append([]byte(nil), csr...)
	tampered[len(tampered)-5] ^= 0xff
	rsaCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "node:x"}}, rsaKey)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384CSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "node:x"}}, p384)
	var signRefused []any
	for _, tc := range []struct {
		name       string
		csr        []byte
		node       string
		prefixOnly bool
	}{
		{"garbage", []byte("not a csr"), "n", true},
		{"empty", nil, "n", true},
		{"trailing", append(append([]byte(nil), csr...), 0), "n", true},
		{"bad signature", tampered, "n", false},
		{"rsa key", rsaCSR, "n", false},
		{"p384 key", p384CSR, "n", false},
		{"bad node name", csr, "../x", false},
		{"empty name", csr, "", false},
		{"long name", csr, strings.Repeat("a", 64), false},
	} {
		for _, as := range sortedKeys(goSign) {
			_, goErr := goSign[as](tc.csr, tc.node, 0)
			if goErr == nil {
				t.Fatalf("%s/%s: Go signed it", tc.name, as)
			}
			signRefused = append(signRefused, pkiCase{"case": tc.name, "as": as, "csr": base64.StdEncoding.EncodeToString(tc.csr),
				"name": tc.node, "prefixOnly": tc.prefixOnly, "error": goErr.Error()})
		}
	}
	out["signRefused"] = signRefused

	// Reissues of a certificate Go issued, by shape, and refusals.
	certPEM, keyPEM, _ := ca.Issue(IssueRequest{Identity: Identity{Kind: KindServer, Name: "cp-1"}, DNSNames: []string{ServerName}, IPs: []net.IP{net.ParseIP("10.0.0.2")}, Server: true, Validity: time.Hour})
	old := mustParse(t, string(certPEM))
	var reissued []any
	for _, validity := range []time.Duration{0, 2 * time.Hour} {
		goNew, err := ca.Reissue(old, validity)
		if err != nil {
			t.Fatal(err)
		}
		reissued = append(reissued, pkiCase{"validitySeconds": int64(validity / time.Second), "shape": shapeJSON(t, mustParse(t, string(goNew)))})
	}
	out["reissue"] = pkiCase{"cert": string(certPEM), "key": string(keyPEM), "cases": reissued}
	foreignCA, _ := NewCA("lab_1")
	foreign, _, _ := foreignCA.Issue(IssueRequest{Identity: Identity{Kind: KindAdmin, Name: "eve"}, Client: true})
	noEKU := signRaw(t, ca, &x509.Certificate{Subject: pkix.Name{CommonName: "user:x"}, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true})
	notIdentity := signRaw(t, ca, &x509.Certificate{Subject: pkix.Name{CommonName: "x"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true})
	var reissueRefused []any
	for _, tc := range []struct {
		name string
		cert []byte
	}{{"other CA", foreign}, {"no usage", noEKU}, {"not an identity", notIdentity}, {"the CA", ca.CertPEM}} {
		_, goErr := ca.Reissue(mustParse(t, string(tc.cert)), 0)
		if goErr == nil {
			t.Fatalf("%s: Go reissued it", tc.name)
		}
		reissueRefused = append(reissueRefused, pkiCase{"case": tc.name, "cert": string(tc.cert), "error": goErr.Error()})
	}
	out["reissueRefused"] = reissueRefused

	// Identities, and what Go reads of certificates it issued.
	var identities []any
	for _, cn := range []string{"node:web-1", "user:a", "admin:root", "automation:ci", "service:ci", "metrics:p", "etcd:member", "server:s",
		"web-1", "root:x", "node:", "node:../x", "node:-x", "node:a:b", "node:a\nb", ":", "node:" + strings.Repeat("a", 63), "node:" + strings.Repeat("a", 64), "node:é", "node: "} {
		id, goErr := ParseIdentity(cn)
		c := pkiCase{"cn": cn}
		if goErr != nil {
			c["error"] = goErr.Error()
		} else {
			c["kind"], c["name"] = id.Kind, id.Name
		}
		identities = append(identities, c)
	}
	out["identities"] = identities
	var read []any
	for _, id := range []Identity{{KindAdmin, "root"}, {KindAutomation, "ci"}, {KindUser, "u"}, {KindNode, "n"}, {KindMetrics, "m"}, {KindServer, "cp-1"}} {
		c, _, _ := ca.Issue(IssueRequest{Identity: id, Client: true})
		gc := mustParse(t, string(c))
		principal := ""
		if p, ok := id.Principal(); ok {
			principal = p.String()
		}
		read = append(read, pkiCase{"cert": string(c), "identity": id.String(), "principal": principal, "serial": SerialString(gc),
			"caHash": CAHash(gc), "fingerprint": Fingerprint(gc)})
	}
	bad := signRaw(t, ca, &x509.Certificate{Subject: pkix.Name{CommonName: "nobody"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	_, goErr = IdentityFromCert(mustParse(t, string(bad)))
	read = append(read, pkiCase{"cert": string(bad), "identityError": errText(goErr), "fingerprint": Fingerprint(mustParse(t, string(bad)))})
	out["readCert"] = read
	_, goErr = ParseCertPEM([]byte("junk"))
	out["junkCert"] = errText(goErr)

	// Renewal at times around each lifetime.
	var renewal []any
	for _, validity := range []time.Duration{time.Minute, time.Hour, NodeValidity, ServiceValidity, LeafValidity} {
		c, _, _ := ca.Issue(IssueRequest{Identity: Identity{Kind: KindNode, Name: "n"}, Client: true, Validity: validity})
		gc := mustParse(t, string(c))
		var at []any
		for _, d := range []time.Duration{0, validity / 2, validity * 2 / 3, validity*2/3 + 10*time.Minute, validity, 2 * validity, -time.Hour} {
			when := now.Add(d)
			at = append(at, pkiCase{"now": when.UnixNano(), "renewDue": RenewDue(gc, when), "needsRenewal": NeedsRenewal(gc, when)})
		}
		renewal = append(renewal, pkiCase{"cert": string(c), "at": at})
	}
	out["renewal"] = renewal

	// Server certificates verified as Go's Verify does.
	otherCA, _ := NewCA("c")
	issue := func(ca *CA, req IssueRequest) []byte {
		c, _, err := ca.Issue(req)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	good := issue(ca, IssueRequest{Identity: Identity{Kind: KindServer, Name: "s"}, DNSNames: []string{ServerName}, Server: true})
	var verify []any
	for _, tc := range []struct {
		name string
		cert []byte
		at   time.Time
	}{
		{"good", good, now},
		{"expired", good, now.Add(400 * 24 * time.Hour)},
		{"early", good, now.Add(-time.Hour)},
		{"other CA", issue(otherCA, IssueRequest{Identity: Identity{Kind: KindServer, Name: "s"}, DNSNames: []string{ServerName}, Server: true}), now},
		{"name", issue(ca, IssueRequest{Identity: Identity{Kind: KindServer, Name: "s"}, DNSNames: []string{"a", "b"}, Server: true}), now},
		{"no names", issue(ca, IssueRequest{Identity: Identity{Kind: KindServer, Name: "s"}, IPs: []net.IP{net.ParseIP("10.0.0.1")}, Server: true}), now},
		{"client", issue(ca, IssueRequest{Identity: Identity{Kind: KindServer, Name: "s"}, DNSNames: []string{ServerName}, Client: true}), now},
		{"etcd both", issue(ca, IssueRequest{Identity: EtcdMember, DNSNames: []string{ServerName}, Server: true, Client: true}), now},
	} {
		roots := x509.NewCertPool()
		roots.AddCert(ca.Cert)
		_, goErr := mustParse(t, string(tc.cert)).Verify(x509.VerifyOptions{Roots: roots, DNSName: ServerName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: tc.at})
		want := ""
		if goErr != nil {
			want = "server certificate: " + goErr.Error()
		}
		verify = append(verify, pkiCase{"case": tc.name, "cert": string(tc.cert), "now": tc.at.UnixNano(), "error": want})
	}
	out["verifyServer"] = verify

	// CA pins, at the moment Go checked them.
	srv := func(ca *CA, names ...string) *x509.Certificate {
		c, _, _ := ca.Issue(IssueRequest{Identity: Identity{Kind: KindServer, Name: "s"}, DNSNames: names, Server: true})
		return mustParse(t, string(c))
	}
	pleaf, mitm := srv(ca, ServerName), srv(otherCA, ServerName)
	pin := Fingerprint(ca.Cert)
	var pins []any
	for _, tc := range []struct {
		name  string
		chain []*x509.Certificate
		hash  string
	}{
		{"good", []*x509.Certificate{pleaf, ca.Cert}, pin},
		{"extra", []*x509.Certificate{pleaf, otherCA.Cert, ca.Cert}, pin},
		{"leaf only", []*x509.Certificate{pleaf}, pin},
		{"other CA", []*x509.Certificate{mitm, otherCA.Cert}, pin},
		{"mitm leaf", []*x509.Certificate{mitm, ca.Cert}, pin},
		{"leaf pinned", []*x509.Certificate{pleaf, pleaf}, Fingerprint(pleaf)},
		{"wrong name", []*x509.Certificate{srv(ca, "other"), ca.Cert}, pin},
		{"no names", []*x509.Certificate{srv(ca), ca.Cert}, pin},
		{"upper-case", []*x509.Certificate{pleaf, ca.Cert}, strings.ToUpper(pin)},
	} {
		at := time.Now()
		got, goErr := pinCA(tc.chain, tc.hash)
		var chain []string
		for _, c := range tc.chain {
			chain = append(chain, pemOf(c))
		}
		c := pkiCase{"case": tc.name, "chain": chain, "hash": tc.hash, "now": at.UnixNano()}
		if goErr != nil {
			c["error"] = goErr.Error()
		} else {
			c["fingerprint"] = Fingerprint(got)
		}
		pins = append(pins, c)
	}
	out["pinCA"] = pins

	// Join tokens and CA hashes.
	tok, _ := NewJoinToken()
	out["joinToken"] = pkiCase{"token": " " + tok.Reveal() + "\n", "id": tok.ID, "hash": tok.SecretHash(), "shown": tok.String(), "debug": fmt.Sprintf("%#v", tok)}
	var tokens []any
	for _, s := range []string{"", tok.ID, tok.ID + ".", "." + tok.Secret, tok.ID + "." + tok.Secret[:63], tok.Reveal() + "0",
		strings.ToUpper(tok.Reveal()), tok.ID + ":" + tok.Secret, tok.Reveal() + ".x", " " + tok.Reveal() + " "} {
		_, goErr := ParseJoinToken(s)
		tokens = append(tokens, pkiCase{"token": s, "error": errText(goErr)})
	}
	out["joinTokens"] = tokens
	otherTok, _ := NewJoinToken()
	var matches []any
	for _, tc := range []struct{ secret, hash string }{{tok.Secret, tok.SecretHash()}, {otherTok.Secret, tok.SecretHash()}, {"", tok.SecretHash()}, {tok.Secret, ""}, {tok.Secret, strings.ToUpper(tok.SecretHash())}} {
		matches = append(matches, pkiCase{"secret": tc.secret, "hash": tc.hash, "match": TokenSecretMatches(tc.secret, tc.hash), "secretHash": HashTokenSecret(tc.secret)})
	}
	out["tokenMatches"] = matches
	var hashes []any
	for _, s := range []string{CAHash(ca.Cert), " " + CAHash(ca.Cert) + "\n", "", Fingerprint(ca.Cert), "sha1:" + Fingerprint(ca.Cert), "sha256:" + Fingerprint(ca.Cert)[:10], strings.ToUpper(CAHash(ca.Cert))} {
		h, goErr := ParseCAHash(s)
		c := pkiCase{"hash": s}
		if goErr != nil {
			c["error"] = goErr.Error()
		} else {
			c["hex"] = h
		}
		hashes = append(hashes, c)
	}
	out["caHashes"] = hashes

	// The CA's files: the modes the daemon refuses, with the directory as
	// {dir}.
	dir := t.TempDir()
	var modes []any
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644} {
		path := filepath.Join(dir, "ca.key")
		if err := os.WriteFile(path, []byte(caKey), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, goErr := fsutil.ReadPrivateFile(path)
		modes = append(modes, pkiCase{"mode": int(mode), "error": strings.ReplaceAll(errText(goErr).(string), dir, "{dir}")})
	}
	_, goErr = fsutil.ReadPrivateFile(filepath.Join(dir, "none", "ca.crt"))
	out["caFiles"] = pkiCase{"modes": modes, "missing": strings.ReplaceAll(errText(goErr).(string), dir, "{dir}")}

	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixturePath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func issueReq(req IssueRequest) map[string]any {
	ips := []string{}
	for _, ip := range req.IPs {
		ips = append(ips, ip.String())
	}
	dns := req.DNSNames
	if dns == nil {
		dns = []string{}
	}
	return map[string]any{"kind": req.Identity.Kind, "name": req.Identity.Name, "dns": dns, "ips": ips,
		"server": req.Server, "client": req.Client, "validitySeconds": int64(req.Validity / time.Second)}
}

func sortedKeys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mustBytes(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
