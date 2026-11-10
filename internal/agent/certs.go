package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/proxy"
)

// certBatch is how many certificates one GetCertificates call asks for: the
// server's bound, and a few MiB per answer.
const certBatch = 256

type cachedCert struct {
	sum [sha256.Size]byte
	pem []byte
}

// withCertificates turns want into a proxy configuration, fetching the
// certificates it names by reference that the agent does not have yet, or
// whose content changed. Each one is checked against the digest in the
// assignment, and certificates no longer named are forgotten.
func (a *Agent) withCertificates(ctx context.Context, want *armadav1.ProxyConfig) (proxy.Config, error) {
	cfg := proxy.FromProto(want)
	have := a.certs
	next := make(map[string]cachedCert, len(want.GetCertificates()))
	var missing []string
	wantSum := map[string][]byte{}
	for _, c := range want.GetCertificates() {
		if len(c.GetPem()) > 0 {
			continue
		}
		wantSum[c.GetName()] = c.GetSha256()
		if h, ok := have[c.GetName()]; ok && bytes.Equal(h.sum[:], c.GetSha256()) {
			next[c.GetName()] = h
			continue
		}
		missing = append(missing, c.GetName())
	}
	for start := 0; start < len(missing); start += certBatch {
		names := missing[start:min(start+certBatch, len(missing))]
		resp, err := a.cfg.Client.GetCertificates(ctx, &armadav1.GetCertificatesRequest{Names: names})
		if err != nil {
			return proxy.Config{}, err
		}
		for _, c := range resp.GetCertificates() {
			want, ok := wantSum[c.GetName()]
			sum := sha256.Sum256(c.GetPem())
			if !ok || !bytes.Equal(sum[:], want) {
				// Renewed since this assignment: the next one names it.
				continue
			}
			next[c.GetName()] = cachedCert{sum: sum, pem: c.GetPem()}
		}
	}
	for i, c := range cfg.Certificates {
		if len(c.PEM) > 0 {
			continue
		}
		got, ok := next[c.Name]
		if !ok {
			return proxy.Config{}, fmt.Errorf("certificate %s is not available", c.Name)
		}
		cfg.Certificates[i].PEM = got.pem
	}
	a.certs = next
	return cfg, nil
}
