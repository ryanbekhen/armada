package server

import (
	"crypto/sha256"
	"strings"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// Agents that take certificates by reference get digests, others the PEMs;
// GetCertificates answers only names the cluster serves.
func TestCertificatesByReference(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	fc := &fakeCerts{issued: map[string][]byte{}}
	c.srv.certs = fc
	if err := c.st.SetMeta(c.ctx, metaRootDomain, "apps.example.org"); err != nil {
		t.Fatal(err)
	}
	fc.issue(t, "web.apps.example.org")
	c.deploy("name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n")
	full, refs := c.srv.lastProxy, c.srv.lastProxyRefs
	if len(full.GetCertificates()) != 1 || len(full.Certificates[0].GetPem()) == 0 {
		t.Fatalf("full config certificates: %v", full.GetCertificates())
	}
	pem := full.Certificates[0].GetPem()
	sum := sha256.Sum256(pem)
	if len(refs.GetCertificates()) != 1 || len(refs.Certificates[0].GetPem()) != 0 || string(refs.Certificates[0].GetSha256()) != string(sum[:]) {
		t.Errorf("reference config certificates: %v", refs.GetCertificates())
	}

	got, err := c.srv.GetCertificates(c.ctx, &armadav1.GetCertificatesRequest{Names: []string{"web.apps.example.org", "web.apps.example.org", "other.example.org"}})
	if err != nil || len(got.GetCertificates()) != 1 || string(got.Certificates[0].GetPem()) != string(pem) {
		t.Errorf("GetCertificates: %v %v", got, err)
	}
	// A certificate the manager has but the cluster does not serve stays.
	fc.issue(t, "unrouted.example.org")
	if got, _ := c.srv.GetCertificates(c.ctx, &armadav1.GetCertificatesRequest{Names: []string{"unrouted.example.org"}}); len(got.GetCertificates()) != 0 {
		t.Error("handed out a certificate the cluster does not serve")
	}
	many := make([]string, maxCertificateNames+1)
	if _, err := c.srv.GetCertificates(c.ctx, &armadav1.GetCertificatesRequest{Names: many}); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("too many names: %v", err)
	}
}

// An agent from before references gets the PEMs, so a rolling upgrade
// keeps every node's certificates.
func TestOldAgentsGetCertificates(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	fc := &fakeCerts{issued: map[string][]byte{}}
	c.srv.certs = fc
	if err := c.st.SetMeta(c.ctx, metaRootDomain, "apps.example.org"); err != nil {
		t.Fatal(err)
	}
	fc.issue(t, "web.apps.example.org")
	old := &session{nodeID: "n1", send: make(chan *armadav1.ServerMessage, 4), done: make(chan struct{})}
	nw := &session{nodeID: "n2", certRefs: true, send: make(chan *armadav1.ServerMessage, 4), done: make(chan struct{})}
	c.srv.mu.Lock()
	c.srv.sessions["n1"], c.srv.sessions["n2"] = old, nw
	c.srv.mu.Unlock()
	c.deploy("name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n")
	last := func(s *session) *armadav1.ProxyConfig {
		var a *armadav1.Assignment
		for {
			select {
			case m := <-s.send:
				a = m.GetAssignment()
			default:
				return a.GetProxy()
			}
		}
	}
	if p := last(old); len(p.GetCertificates()) != 1 || len(p.Certificates[0].GetPem()) == 0 {
		t.Errorf("old agent: %v", p.GetCertificates())
	}
	if p := last(nw); len(p.GetCertificates()) != 1 || len(p.Certificates[0].GetPem()) != 0 || len(p.Certificates[0].GetSha256()) != sha256.Size {
		t.Errorf("new agent: %v", p.GetCertificates())
	}
}

// A certificate is read from storage once, and again after the manager
// obtains it anew (a renewal).
func TestCertificateKeptUntilRenewed(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	fc := &fakeCerts{issued: map[string][]byte{}}
	c.srv.certs = fc
	if err := c.st.SetMeta(c.ctx, metaRootDomain, "apps.example.org"); err != nil {
		t.Fatal(err)
	}
	const name = "web.apps.example.org"
	fc.issue(t, name)
	c.deploy("name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n")
	first := c.srv.lastProxy.GetCertificates()[0].GetPem()
	fc.issue(t, name) // renewed in storage
	c.reconcile()
	if got := c.srv.lastProxy.GetCertificates()[0].GetPem(); string(got) != string(first) {
		t.Fatal("re-read without a certificate event")
	}
	c.srv.CertificateEvent(name, nil)
	c.reconcile()
	if got := c.srv.lastProxy.GetCertificates()[0].GetPem(); string(got) == string(first) {
		t.Error("the renewed certificate did not reach the proxy")
	}
}
