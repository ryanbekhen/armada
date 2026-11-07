package pki

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"sync"
	"time"
)

// RenewDue reports whether a certificate that renews itself should be
// renewed now: once less than a third of its lifetime is left.
func RenewDue(c *x509.Certificate, now time.Time) bool {
	life := c.NotAfter.Sub(c.NotBefore) - clockSkew
	return c.NotAfter.Sub(now) < life/3
}

// Reissue signs a new certificate for the key, identity, names, and usages
// of old, which this CA must have signed, valid for validity from now (or
// LeafValidity). Only the serial and the validity period change, so the
// private key on disk stays as it is.
func (ca *CA) Reissue(old *x509.Certificate, validity time.Duration) ([]byte, error) {
	if err := old.CheckSignatureFrom(ca.Cert); err != nil {
		return nil, fmt.Errorf("certificate is not signed by this CA: %w", err)
	}
	if _, err := ParseIdentity(old.Subject.CommonName); err != nil {
		return nil, err
	}
	if len(old.ExtKeyUsage) == 0 {
		return nil, errors.New("certificate has no extended key usage")
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	if validity <= 0 {
		validity = LeafValidity
	}
	now := time.Now()
	notAfter := now.Add(validity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: old.Subject.CommonName, Organization: []string{"armada"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           old.ExtKeyUsage,
		BasicConstraintsValid: true,
		DNSNames:              old.DNSNames,
		IPAddresses:           old.IPAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, old.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	return encodeCert(der), nil
}

// SignAdminCSR issues an admin client certificate for name from a CSR, like
// SignNodeCSR. It lasts LeafValidity.
func (ca *CA) SignAdminCSR(csrDER []byte, name string) (NodeCert, error) {
	return ca.signClientCSR(csrDER, Identity{Kind: KindAdmin, Name: name}, LeafValidity)
}

// ServerCert is a server's certificate, replaced in place when it is
// renewed: the TLS configs it returns pick the current one on every
// handshake.
type ServerCert struct {
	ca *x509.Certificate

	mu   sync.RWMutex
	pair *tls.Certificate // leaf only, for the mTLS API and metrics
	join *tls.Certificate // leaf and CA, so joining nodes can pin the CA
	leaf *x509.Certificate
}

// NewServerCert loads a server certificate signed by the CA in caPEM.
func NewServerCert(caPEM, certPEM, keyPEM []byte) (*ServerCert, error) {
	ca, err := ParseCertPEM(caPEM)
	if err != nil {
		return nil, err
	}
	s := &ServerCert{ca: ca}
	if err := s.Set(certPEM, keyPEM); err != nil {
		return nil, err
	}
	return s, nil
}

// Set installs a new certificate after checking it is a server certificate
// of this CA for ServerName.
func (s *ServerCert) Set(certPEM, keyPEM []byte) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(s.ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: ServerName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("server certificate: %w", err)
	}
	pair.Leaf = leaf
	join := pair
	join.Certificate = append(append([][]byte(nil), pair.Certificate...), s.ca.Raw)
	s.mu.Lock()
	s.pair, s.join, s.leaf = &pair, &join, leaf
	s.mu.Unlock()
	return nil
}

// Leaf returns the current certificate.
func (s *ServerCert) Leaf() *x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.leaf
}

// TLS returns the API's config: TLS 1.3, client certificates of the CA
// required.
func (s *ServerCert) TLS() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(s.ca)
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.mu.RLock()
			defer s.mu.RUnlock()
			return s.pair, nil
		},
	}
}

// JoinTLS returns the join listener's config, like JoinServerTLS.
func (s *ServerCert) JoinTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.NoClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.mu.RLock()
			defer s.mu.RUnlock()
			return s.join, nil
		},
	}
}
