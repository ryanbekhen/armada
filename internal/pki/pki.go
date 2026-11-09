// Package pki implements the cluster's internal certificate authority and the
// mTLS configuration used between the CLI, the server, and agents.
//
// Identities are encoded in the certificate common name as "<kind>:<name>",
// where kind is "admin", "node", or "server".
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strings"
	"time"
)

// Identity kinds.
const (
	KindAdmin  = "admin"
	KindNode   = "node"
	KindServer = "server"
	// KindEtcd identifies the embedded etcd members of the control plane.
	// Every member shares one identity (EtcdMember), so servers can join
	// without reconfiguring the others; the Armada API never authorizes it.
	KindEtcd = "etcd"
	// KindMetrics may only scrape the metrics endpoint (ADR 0017).
	KindMetrics = "metrics"
	// KindAutomation manages the apps of the projects in its scope and
	// nothing else (ADR 0026).
	KindAutomation = "automation"
)

// EtcdMember is the identity of every etcd member certificate.
var EtcdMember = Identity{Kind: KindEtcd, Name: "member"}

// ServerName is the DNS SAN every server certificate carries. Clients verify
// against it so the server's IP can change without reissuing client config.
const ServerName = "armada-server"

// Validity periods.
const (
	CAValidity   = 10 * 365 * 24 * time.Hour
	LeafValidity = 365 * 24 * time.Hour // server and admin certificates
	// NodeValidity is the lifetime of node certificates; agents renew them
	// automatically (see NeedsRenewal).
	NodeValidity = 30 * 24 * time.Hour
	// AutomationValidity is the lifetime of automation certificates; tools
	// renew them with `armada automation renew`.
	AutomationValidity = 90 * 24 * time.Hour
	clockSkew          = 5 * time.Minute
)

var identityNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)

// Identity is the authenticated principal of a TLS peer.
type Identity struct {
	Kind string
	Name string
}

func (i Identity) String() string { return i.Kind + ":" + i.Name }

// ValidName reports whether name may be an identity's name.
func ValidName(name string) bool { return identityNameRe.MatchString(name) }

// ParseIdentity parses a "<kind>:<name>" common name.
func ParseIdentity(cn string) (Identity, error) {
	kind, name, ok := strings.Cut(cn, ":")
	if !ok {
		return Identity{}, fmt.Errorf("common name %q is not an armada identity", cn)
	}
	switch kind {
	case KindAdmin, KindNode, KindServer, KindEtcd, KindMetrics, KindAutomation:
	default:
		return Identity{}, fmt.Errorf("unknown identity kind %q", kind)
	}
	if !identityNameRe.MatchString(name) {
		return Identity{}, fmt.Errorf("invalid identity name %q", name)
	}
	return Identity{Kind: kind, Name: name}, nil
}

// IdentityFromCert extracts the identity of a verified peer certificate.
func IdentityFromCert(cert *x509.Certificate) (Identity, error) {
	return ParseIdentity(cert.Subject.CommonName)
}

// CA is the cluster certificate authority.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     *ecdsa.PrivateKey
}

// NewCA generates a new self-signed CA.
func NewCA(clusterName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "armada-ca:" + clusterName, Organization: []string{"armada"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertPEM: encodeCert(der), key: key}, nil
}

// LoadCA parses a CA certificate and its private key.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, errors.New("certificate is not a CA")
	}
	key, err := ParseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("CA key does not match certificate")
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key}, nil
}

// KeyPEM returns the CA private key in PEM form. Callers must store it with
// mode 0600.
func (ca *CA) KeyPEM() ([]byte, error) { return encodeKey(ca.key) }

// IssueRequest describes a leaf certificate.
type IssueRequest struct {
	Identity Identity
	DNSNames []string
	IPs      []net.IP
	Server   bool // add server auth usage
	Client   bool // add client auth usage
	Validity time.Duration
}

// Issue creates a new key pair and a certificate signed by the CA.
func (ca *CA) Issue(req IssueRequest) (certPEM, keyPEM []byte, err error) {
	if _, err := ParseIdentity(req.Identity.String()); err != nil {
		return nil, nil, err
	}
	if !req.Server && !req.Client {
		return nil, nil, errors.New("certificate needs server or client usage")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	validity := req.Validity
	if validity == 0 {
		validity = LeafValidity
	}
	now := time.Now()
	notAfter := now.Add(validity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	var usage []x509.ExtKeyUsage
	if req.Server {
		usage = append(usage, x509.ExtKeyUsageServerAuth)
	}
	if req.Client {
		usage = append(usage, x509.ExtKeyUsageClientAuth)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: req.Identity.String(), Organization: []string{"armada"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usage,
		BasicConstraintsValid: true,
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return encodeCert(der), keyPEM, nil
}

// Fingerprint returns the hex SHA-256 of a certificate's DER bytes.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// ParseCertPEM parses the first certificate in a PEM block.
func ParseCertPEM(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM certificate found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParseKeyPEM parses a PKCS#8 ECDSA private key.
func ParseKeyPEM(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("no PEM private key found")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not ECDSA")
	}
	return ek, nil
}

// ServerTLS returns a TLS 1.3 server config that requires client
// certificates signed by the CA.
func ServerTLS(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	pool, cert, err := loadPair(caPEM, certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

// ClientTLS returns a TLS 1.3 client config that presents certPEM and only
// trusts servers signed by the CA with the ServerName SAN.
func ClientTLS(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	pool, cert, err := loadPair(caPEM, certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   ServerName,
	}, nil
}

func loadPair(caPEM, certPEM, keyPEM []byte) (*x509.CertPool, tls.Certificate, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, tls.Certificate{}, errors.New("invalid CA certificate")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	return pool, cert, nil
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func encodeKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
