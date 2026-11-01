package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// JoinToken authorizes one node to join the cluster. It is written as
// "<id>.<secret>": the ID is public and names the token, the secret proves
// possession. The server stores only a hash of the secret.
type JoinToken struct {
	ID     string
	Secret string
}

var (
	joinTokenRe = regexp.MustCompile(`^([a-f0-9]{12})\.([a-f0-9]{64})$`)
	caHashRe    = regexp.MustCompile(`^sha256:([a-f0-9]{64})$`)
)

// NewJoinToken creates a token with a 48-bit ID and a 256-bit secret.
func NewJoinToken() (JoinToken, error) {
	id := make([]byte, 6)
	secret := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return JoinToken{}, err
	}
	if _, err := rand.Read(secret); err != nil {
		return JoinToken{}, err
	}
	return JoinToken{ID: hex.EncodeToString(id), Secret: hex.EncodeToString(secret)}, nil
}

// ParseJoinToken parses "<id>.<secret>".
func ParseJoinToken(s string) (JoinToken, error) {
	m := joinTokenRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return JoinToken{}, errors.New("malformed join token (want <12 hex>.<64 hex>)")
	}
	return JoinToken{ID: m[1], Secret: m[2]}, nil
}

// Reveal returns the full token. Only `armada token create` prints it.
func (t JoinToken) Reveal() string { return t.ID + "." + t.Secret }

// String implements fmt.Stringer without the secret.
func (t JoinToken) String() string { return t.ID + ".[REDACTED]" }

// GoString implements fmt.GoStringer without the secret.
func (t JoinToken) GoString() string { return t.String() }

// SecretHash is what the server stores for the token.
func (t JoinToken) SecretHash() string { return HashTokenSecret(t.Secret) }

// HashTokenSecret hashes a token secret for storage.
func HashTokenSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// TokenSecretMatches compares a presented secret with a stored hash in
// constant time.
func TokenSecretMatches(secret, storedHash string) bool {
	got := HashTokenSecret(secret)
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}

// CAHash formats the pin of a CA certificate, e.g. "sha256:ab12...".
func CAHash(ca *x509.Certificate) string { return "sha256:" + Fingerprint(ca) }

// ParseCAHash validates a CA pin and returns its hex digest.
func ParseCAHash(s string) (string, error) {
	m := caHashRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", errors.New("malformed CA hash (want sha256:<64 hex>)")
	}
	return m[1], nil
}

// NewNodeCSR creates a node key and a certificate request for it. The key
// never leaves the node.
func NewNodeCSR(node string) (keyPEM, csrDER []byte, err error) {
	id := Identity{Kind: KindNode, Name: node}
	if _, err := ParseIdentity(id.String()); err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: id.String()},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encodeKey(key)
	return keyPEM, csrDER, err
}

// NodeCert is a node certificate issued from a CSR.
type NodeCert struct {
	PEM      []byte
	Serial   string
	NotAfter time.Time
}

// SignNodeCSR issues a client certificate for node from a CSR. Only the
// CSR's public key is used: the identity, usages, and lifetime come from
// the CA, so a node cannot request a different name, a server certificate,
// or extra extensions. The key must be ECDSA P-256 and the CSR self-signed.
func (ca *CA) SignNodeCSR(csrDER []byte, node string, validity time.Duration) (NodeCert, error) {
	id := Identity{Kind: KindNode, Name: node}
	if _, err := ParseIdentity(id.String()); err != nil {
		return NodeCert{}, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return NodeCert{}, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return NodeCert{}, fmt.Errorf("CSR signature: %w", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return NodeCert{}, errors.New("CSR key must be ECDSA P-256")
	}
	if validity <= 0 || validity > NodeValidity {
		validity = NodeValidity
	}
	serial, err := newSerial()
	if err != nil {
		return NodeCert{}, err
	}
	now := time.Now()
	notAfter := now.Add(validity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: id.String(), Organization: []string{"armada"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.key)
	if err != nil {
		return NodeCert{}, err
	}
	return NodeCert{PEM: encodeCert(der), Serial: SerialString(tmpl), NotAfter: notAfter}, nil
}

// SerialString returns a certificate's serial number as lowercase hex.
func SerialString(c *x509.Certificate) string { return c.SerialNumber.Text(16) }

// NeedsRenewal reports whether a node certificate should be renewed: in the
// last third of its lifetime, or if it outlives NodeValidity (issued before
// node certificates became short-lived).
func NeedsRenewal(c *x509.Certificate, now time.Time) bool {
	// NotBefore is backdated by clockSkew; measure from the issue time.
	life := c.NotAfter.Sub(c.NotBefore) - clockSkew
	return life > NodeValidity+clockSkew || c.NotAfter.Sub(now) < life/3
}

// JoinServerTLS returns the TLS config of the join listener: server
// authentication only (joining nodes have no certificate yet), with the CA
// certificate in the chain so clients can check it against their pin.
func JoinServerTLS(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	ca, err := ParseCertPEM(caPEM)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	cert.Certificate = append(cert.Certificate, ca.Raw)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
	}, nil
}

// FetchPinnedCA learns the cluster CA from the join listener at addr and
// returns it only if its hash matches caHash (from ParseCAHash).
//
// It never disables certificate verification: the first handshake runs
// against an empty root pool, so it always fails verification before any
// application data is sent; the CA is taken from the rejected chain and
// pinned, and the server certificate is then verified against it. Callers
// connect again with JoinClientTLS for the actual request.
func FetchPinnedCA(ctx context.Context, addr, caHash string) (*x509.Certificate, error) {
	d := tls.Dialer{Config: &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    x509.NewCertPool(),
		ServerName: ServerName,
	}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = conn.Close()
		return nil, errors.New("join listener passed verification against an empty trust store")
	}
	var verr *tls.CertificateVerificationError
	if !errors.As(err, &verr) {
		var nerr net.Error
		if errors.As(err, &nerr) {
			return nil, fmt.Errorf("connect to %s: %w", addr, err)
		}
		return nil, fmt.Errorf("TLS handshake with %s: %w", addr, err)
	}
	return pinCA(verr.UnverifiedCertificates, caHash)
}

// pinCA finds the certificate matching caHash in a presented chain and
// verifies the leaf against it.
func pinCA(chain []*x509.Certificate, caHash string) (*x509.Certificate, error) {
	if len(chain) < 2 {
		return nil, errors.New("server did not present its CA certificate")
	}
	var ca *x509.Certificate
	for _, c := range chain[1:] {
		if subtle.ConstantTimeCompare([]byte(Fingerprint(c)), []byte(caHash)) == 1 {
			ca = c
		}
	}
	if ca == nil {
		return nil, errors.New("the server's CA does not match the CA hash in the join command; refusing to join (possible man-in-the-middle)")
	}
	if !ca.IsCA || !ca.BasicConstraintsValid {
		return nil, errors.New("pinned certificate is not a CA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: pool, DNSName: ServerName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, fmt.Errorf("server certificate is not valid for the pinned CA: %w", err)
	}
	return ca, nil
}

// JoinClientTLS trusts only ca and requires the ServerName SAN; it presents
// no client certificate.
func JoinClientTLS(ca *x509.Certificate) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: ServerName}
}

// RotatingClientTLS is like ClientTLS but takes the client certificate from
// get on every handshake, so a renewed certificate is used by the next
// connection without rebuilding the config.
func RotatingClientTLS(caPEM []byte, get func() (*tls.Certificate, error)) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid CA certificate")
	}
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		RootCAs:              pool,
		ServerName:           ServerName,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return get() },
	}, nil
}
