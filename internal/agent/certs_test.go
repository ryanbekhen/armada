package agent

import (
	"context"
	"crypto/sha256"
	"testing"

	"google.golang.org/grpc"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

type certServer struct {
	armadav1.AgentServiceClient
	pems  map[string][]byte
	calls int
}

func (c *certServer) GetCertificates(_ context.Context, in *armadav1.GetCertificatesRequest, _ ...grpc.CallOption) (*armadav1.GetCertificatesResponse, error) {
	c.calls++
	resp := &armadav1.GetCertificatesResponse{}
	for _, n := range in.GetNames() {
		if p, ok := c.pems[n]; ok {
			resp.Certificates = append(resp.Certificates, &armadav1.ProxyCertificate{Name: n, Pem: p})
		}
	}
	return resp, nil
}

func refsFor(pems map[string][]byte, names ...string) *armadav1.ProxyConfig {
	px := &armadav1.ProxyConfig{}
	for _, n := range names {
		sum := sha256.Sum256(pems[n])
		px.Certificates = append(px.Certificates, &armadav1.ProxyCertificate{Name: n, Sha256: sum[:]})
	}
	return px
}

func TestCertificatesByReference(t *testing.T) {
	t.Parallel()
	a, _ := newAgent(t)
	srv := &certServer{pems: map[string][]byte{"a.example.org": []byte("pem a"), "b.example.org": []byte("pem b")}}
	a.cfg.Client = srv
	ctx := context.Background()

	cfg, err := a.withCertificates(ctx, refsFor(srv.pems, "a.example.org", "b.example.org"))
	if err != nil || string(cfg.Certificates[0].PEM) != "pem a" || string(cfg.Certificates[1].PEM) != "pem b" || srv.calls != 1 {
		t.Fatalf("first: %v %v calls=%d", cfg.Certificates, err, srv.calls)
	}
	// Unchanged certificates come from the cache.
	if _, err := a.withCertificates(ctx, refsFor(srv.pems, "a.example.org", "b.example.org")); err != nil || srv.calls != 1 {
		t.Errorf("cached: %v calls=%d", err, srv.calls)
	}
	// A renewed one is fetched again; a dropped one is forgotten.
	srv.pems["a.example.org"] = []byte("pem a2")
	cfg, err = a.withCertificates(ctx, refsFor(srv.pems, "a.example.org"))
	if err != nil || string(cfg.Certificates[0].PEM) != "pem a2" || srv.calls != 2 || len(a.certs) != 1 {
		t.Errorf("renewed: %v %v calls=%d cached=%d", cfg.Certificates, err, srv.calls, len(a.certs))
	}
	// A certificate that does not match its digest is never used.
	want := refsFor(map[string][]byte{"b.example.org": []byte("what the assignment named")}, "b.example.org")
	if _, err := a.withCertificates(ctx, want); err == nil {
		t.Error("certificate with another digest accepted")
	}
}
