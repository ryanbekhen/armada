package server

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/agent"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/pki"
	proxyfake "github.com/ryanbekhen/armada/internal/proxy/fake"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
	"github.com/ryanbekhen/armada/internal/store"
)

func withJoin(t *testing.T) func(*Config) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return func(c *Config) { c.JoinAddr = addr }
}

// joinClient connects to the join listener the way `armada join` does:
// learn the CA from the pin, then verify the server against it.
func (c *cluster) joinClient(tok *armadav1.CreateJoinTokenResponse) armadav1.JoinServiceClient {
	c.t.Helper()
	pin, err := pki.ParseCAHash(tok.CaHash)
	if err != nil {
		c.t.Fatal(err)
	}
	ca, err := pki.FetchPinnedCA(c.ctx, tok.JoinAddr, pin)
	if err != nil {
		c.t.Fatal(err)
	}
	conn, err := grpc.NewClient(tok.JoinAddr, grpc.WithTransportCredentials(credentials.NewTLS(pki.JoinClientTLS(ca))))
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { _ = conn.Close() })
	return armadav1.NewJoinServiceClient(conn)
}

func (c *cluster) token() *armadav1.CreateJoinTokenResponse {
	c.t.Helper()
	tok, err := c.admin.CreateJoinToken(c.ctx, &armadav1.CreateJoinTokenRequest{})
	if err != nil {
		c.t.Fatal(err)
	}
	return tok
}

func joinReq(t *testing.T, tok, name, ip string) (*armadav1.JoinRequest, []byte) {
	t.Helper()
	keyPEM, csr, err := pki.NewNodeCSR(name)
	if err != nil {
		t.Fatal(err)
	}
	id, secret, _ := strings.Cut(tok, ".")
	return &armadav1.JoinRequest{TokenId: id, TokenSecret: secret, NodeName: name, PrivateIp: ip, Csr: csr}, keyPEM
}

// runJoinedAgent starts an agent with the certificate a join returned.
func (c *cluster) runJoinedAgent(name, ip string, resp *armadav1.JoinResponse, keyPEM []byte) *fake.Driver {
	c.t.Helper()
	tlsCfg, err := pki.ClientTLS(resp.CaCert, resp.NodeCert, keyPEM)
	if err != nil {
		c.t.Fatal(err)
	}
	conn, err := grpc.NewClient(resp.Servers[0], grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { _ = conn.Close() })
	d := fake.New()
	px := &proxyfake.Driver{}
	c.proxies[name] = px
	hc := &healthChecks{broken: map[string]bool{}, d: d}
	c.checks[name] = hc
	a := agent.New(agent.Config{NodeID: name, PrivateIP: ip, Driver: d, Client: armadav1.NewAgentServiceClient(conn), Proxy: px, Runtime: "embedded",
		Resync: 50 * time.Millisecond, CPUMillis: 2000, MemoryBytes: 2 << 30, Check: hc.check})
	go func() { _ = a.Run(c.ctx) }()
	c.eventually("joined node "+name+" ready", func() bool {
		n, err := c.store.GetNode(c.ctx, name)
		return err == nil && n.State == store.NodeReady
	})
	return d
}

func TestJoin(t *testing.T) {
	t.Parallel()
	c := newCluster(t, withJoin(t))
	c.srv.joinLimit = newKeyedLimiter(100, time.Second) // this test makes many attempts
	c.srv.joinGlobal = newLimiter(100, time.Second)
	d1 := c.addNode("n1", "10.0.0.11")
	tok := c.token()
	if tok.JoinAddr == "" || !strings.HasPrefix(tok.CaHash, "sha256:") || time.Until(tok.ExpiresAt.AsTime()) > time.Hour {
		t.Fatalf("token = %v", tok)
	}
	jc := c.joinClient(tok)

	bad := tok.Token[:len(tok.Token)-1] + "0"
	if strings.HasSuffix(tok.Token, "0") {
		bad = tok.Token[:len(tok.Token)-1] + "1"
	}
	for name, mod := range map[string]func(*armadav1.JoinRequest){
		"wrong secret":   func(r *armadav1.JoinRequest) { _, r.TokenSecret, _ = strings.Cut(bad, ".") },
		"unknown token":  func(r *armadav1.JoinRequest) { r.TokenId = "000000000000" },
		"malformed":      func(r *armadav1.JoinRequest) { r.TokenSecret = "x" },
		"public IP":      func(r *armadav1.JoinRequest) { r.PrivateIp = "8.8.8.8" },
		"bad node name":  func(r *armadav1.JoinRequest) { r.NodeName = "../etc" },
		"taken name":     func(r *armadav1.JoinRequest) { r.NodeName = "n1" },
		"taken IP":       func(r *armadav1.JoinRequest) { r.PrivateIp = "10.0.0.11" },
		"loopback IP":    func(r *armadav1.JoinRequest) { r.PrivateIp = "127.0.0.1" },
		"zoned IP":       func(r *armadav1.JoinRequest) { r.PrivateIp = "fd00::1%x\n    global" },
		"no CSR":         func(r *armadav1.JoinRequest) { r.Csr = nil },
		"garbage CSR":    func(r *armadav1.JoinRequest) { r.Csr = []byte("nope") },
		"oversized CSR":  func(r *armadav1.JoinRequest) { r.Csr = make([]byte, 5000) },
		"admin-ish name": func(r *armadav1.JoinRequest) { r.NodeName = "admin:x" },
	} {
		req, _ := joinReq(t, tok.Token, "n2", "10.0.0.12")
		mod(req)
		if _, err := jc.Join(c.ctx, req); err == nil {
			t.Errorf("%s: join succeeded", name)
		}
	}

	req, key := joinReq(t, tok.Token, "n2", "10.0.0.12")
	resp, err := jc.Join(c.ctx, req)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if len(resp.Servers) != 1 || resp.Servers[0] != c.addr {
		t.Errorf("servers = %q, want [%q]", resp.Servers, c.addr)
	}
	cert, _ := pki.ParseCertPEM(resp.NodeCert)
	if id, _ := pki.IdentityFromCert(cert); id.String() != "node:n2" || time.Until(cert.NotAfter) > pki.NodeValidity {
		t.Errorf("cert = %v until %v", id, cert.NotAfter)
	}
	// Single use.
	again, _ := joinReq(t, tok.Token, "n3", "10.0.0.13")
	if _, err := jc.Join(c.ctx, again); status.Code(err) != codes.Unauthenticated {
		t.Errorf("token reuse = %v", err)
	}

	d2 := c.runJoinedAgent("n2", "10.0.0.12", resp, key)
	c.deploy(webSpec("nginx:1", 2))
	c.eventually("one replica per node", func() bool { return containerCount(d1) == 1 && containerCount(d2) == 1 })

	audit, _ := c.store.ListAudit(c.ctx, 50)
	var joined, created bool
	for _, e := range audit {
		joined = joined || (e.Action == "node.join" && e.Target == "n2")
		created = created || (e.Action == "token.create" && e.Actor == "admin:ryan")
		if strings.Contains(e.Detail, req.TokenSecret) {
			t.Error("audit log holds a token secret")
		}
	}
	if !joined || !created {
		t.Errorf("audit = %+v", audit)
	}
}

func TestJoinListenerServesOnlyJoin(t *testing.T) {
	t.Parallel()
	c := newCluster(t, withJoin(t))
	tok := c.token()
	pin, _ := pki.ParseCAHash(tok.CaHash)
	ca, _ := pki.FetchPinnedCA(c.ctx, tok.JoinAddr, pin)
	conn, _ := grpc.NewClient(tok.JoinAddr, grpc.WithTransportCredentials(credentials.NewTLS(pki.JoinClientTLS(ca))))
	defer conn.Close()
	// No client certificate here, so the admin API must not be reachable.
	if _, err := armadav1.NewAdminServiceClient(conn).Status(c.ctx, &armadav1.StatusRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("admin RPC on the join listener = %v", err)
	}
	// And Join is not served on the mTLS port.
	main := armadav1.NewJoinServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindAdmin, Name: "ryan"}))
	req, _ := joinReq(t, tok.Token, "n9", "10.0.0.19")
	if _, err := main.Join(c.ctx, req); status.Code(err) != codes.Unimplemented {
		t.Errorf("Join on the main port = %v", err)
	}

	// Guessing tokens is rate limited.
	jc := armadav1.NewJoinServiceClient(conn)
	limited := false
	for range joinBurst + 2 {
		bad, _ := joinReq(t, "000000000000."+strings.Repeat("0", 64), "n9", "10.0.0.19")
		_, err := jc.Join(c.ctx, bad)
		limited = limited || status.Code(err) == codes.ResourceExhausted
	}
	if !limited {
		t.Error("join attempts are not rate limited")
	}
}

func TestJoinDisabledWithoutListener(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	if _, err := c.admin.CreateJoinToken(c.ctx, &armadav1.CreateJoinTokenRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("CreateJoinToken = %v", err)
	}
	cw := newCluster(t, withJoin(t))
	for _, ttl := range []int64{1, 30, 25 * 3600} {
		if _, err := cw.admin.CreateJoinToken(cw.ctx, &armadav1.CreateJoinTokenRequest{TtlSeconds: ttl}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("ttl %d = %v", ttl, err)
		}
	}
}

func TestJoinRateLimit(t *testing.T) {
	t.Parallel()
	now := time.Now()
	l := newLimiter(3, time.Second)
	for i := range 3 {
		if !l.allow(now) {
			t.Fatalf("attempt %d refused", i)
		}
	}
	if l.allow(now) {
		t.Error("burst exceeded")
	}
	if !l.allow(now.Add(1100 * time.Millisecond)) {
		t.Error("not refilled")
	}
}

func TestRenewAndRevoke(t *testing.T) {
	t.Parallel()
	c := newCluster(t, withJoin(t), func(cfg *Config) { cfg.NodeCertValidity = time.Hour })
	tok := c.token()
	req, key := joinReq(t, tok.Token, "n2", "10.0.0.12")
	resp, err := c.joinClient(tok).Join(c.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if cert, _ := pki.ParseCertPEM(resp.NodeCert); time.Until(cert.NotAfter) > time.Hour {
		t.Errorf("validity not applied: %v", cert.NotAfter)
	}
	agentClient := func(certPEM, keyPEM []byte) armadav1.AgentServiceClient {
		cfg, err := pki.ClientTLS(resp.CaCert, certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := grpc.NewClient(c.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return armadav1.NewAgentServiceClient(conn)
	}
	old := agentClient(resp.NodeCert, key)

	newKey, csr, _ := pki.NewNodeCSR("n2")
	renewed, err := old.RenewCertificate(c.ctx, &armadav1.RenewCertificateRequest{Csr: csr})
	if err != nil {
		t.Fatal(err)
	}
	fresh := agentClient(renewed.Cert, newKey)
	// Renewing again from the new certificate revokes the first one.
	_, csr2, _ := pki.NewNodeCSR("n2")
	if _, err := fresh.RenewCertificate(c.ctx, &armadav1.RenewCertificateRequest{Csr: csr2}); err != nil {
		t.Fatal(err)
	}
	if _, err := old.RenewCertificate(c.ctx, &armadav1.RenewCertificateRequest{Csr: csr2}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("superseded certificate still works: %v", err)
	}
	// The renewed certificate keeps the identity; a CSR naming someone else
	// still yields a certificate for the caller.
	if cert, _ := pki.ParseCertPEM(renewed.Cert); cert.Subject.CommonName != "node:n2" {
		t.Errorf("renewed CN = %q", cert.Subject.CommonName)
	}
	_, otherCSR, _ := pki.NewNodeCSR("n1")
	if r, err := fresh.RenewCertificate(c.ctx, &armadav1.RenewCertificateRequest{Csr: otherCSR}); err != nil {
		t.Error(err)
	} else if cert, _ := pki.ParseCertPEM(r.Cert); cert.Subject.CommonName != "node:n2" {
		t.Errorf("CSR picked the identity: %q", cert.Subject.CommonName)
	}
	if _, err := fresh.RenewCertificate(c.ctx, &armadav1.RenewCertificateRequest{Csr: []byte("x")}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("garbage CSR = %v", err)
	}

	// A certificate the CA signed but the server never recorded is refused,
	// e.g. one minted with a stolen CA key... or simply never issued here.
	minted, mintedKey, _ := c.ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindNode, Name: "n2"}, Client: true})
	if _, err := agentClient(minted, mintedKey).RenewCertificate(c.ctx, &armadav1.RenewCertificateRequest{Csr: csr}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("unrecorded certificate = %v", err)
	}

	// Removing the node revokes every certificate it had.
	if _, err := c.admin.RemoveNode(c.ctx, &armadav1.RemoveNodeRequest{Node: "n2"}); err != nil {
		t.Fatal(err)
	}
	for name, cl := range map[string]armadav1.AgentServiceClient{"old": old, "renewed": fresh} {
		if _, err := cl.RenewCertificate(c.ctx, &armadav1.RenewCertificateRequest{Csr: csr}); status.Code(err) != codes.Unauthenticated {
			t.Errorf("%s certificate after removal = %v", name, err)
		}
	}
}

func TestRemoveDisconnectsAgent(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	c.addNode("n1", "127.0.0.1")
	if _, err := c.admin.RemoveNode(c.ctx, &armadav1.RemoveNodeRequest{Node: "n1"}); err != nil {
		t.Fatal(err)
	}
	c.eventually("session closed", func() bool { return c.srv.session("n1") == nil })
	// The agent reconnects with a revoked certificate and stays out.
	time.Sleep(300 * time.Millisecond)
	if c.srv.session("n1") != nil {
		t.Error("removed node reconnected")
	}
	if _, err := c.store.GetNode(c.ctx, "n1"); err == nil {
		t.Error("removed node re-registered")
	}
	if _, err := c.admin.RemoveNode(c.ctx, &armadav1.RemoveNodeRequest{Node: "n1"}); status.Code(err) != codes.NotFound {
		t.Errorf("remove twice = %v", err)
	}
}

func TestCordonEvacuates(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d1 := c.addNode("n1", "127.0.0.1")
	d2 := c.addNode("n2", "10.0.0.12")
	c.deploy(webSpec("nginx:1", 2))
	c.eventually("spread", func() bool { return containerCount(d1) == 1 && containerCount(d2) == 1 && len(c.running("web")) == 2 })
	if _, err := c.admin.RemoveNode(c.ctx, &armadav1.RemoveNodeRequest{Node: "n1"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("remove of a busy node = %v", err)
	}
	// Both replicas serve before the cordon.
	c.eventually("both in the proxy", func() bool {
		h := c.proxies["n2"].History()
		return len(h) > 0 && len(backendServers(h[len(h)-1], "web")) == 2
	})
	start := len(c.proxies["n2"].History()) - 1

	if _, err := c.admin.CordonNode(c.ctx, &armadav1.CordonNodeRequest{Node: "n1", Cordoned: true}); err != nil {
		t.Fatal(err)
	}
	c.eventually("evacuated", func() bool { return containerCount(d1) == 0 && containerCount(d2) == 2 && len(c.running("web")) == 2 })
	// Capacity never dropped below the desired count.
	for i, cfg := range c.proxies["n2"].History()[start:] {
		if n := len(backendServers(cfg, "web")); n < 2 {
			t.Errorf("proxy config %d had %d servers", i, n)
		}
	}
	st, _ := c.admin.Status(c.ctx, &armadav1.StatusRequest{})
	for _, n := range st.Nodes {
		if n.Id == "n1" && !n.Cordoned {
			t.Error("status does not show n1 cordoned")
		}
	}
	if _, err := c.admin.RemoveNode(c.ctx, &armadav1.RemoveNodeRequest{Node: "n1"}); err != nil {
		t.Errorf("remove of an evacuated node = %v", err)
	}
}

func TestCordonOnlyNodeKeepsReplicas(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d1 := c.addNode("n1", "127.0.0.1")
	c.deploy(webSpec("nginx:1", 1))
	c.eventually("running", func() bool { return len(c.running("web")) == 1 })
	if _, err := c.admin.CordonNode(c.ctx, &armadav1.CordonNodeRequest{Node: "n1", Cordoned: true}); err != nil {
		t.Fatal(err)
	}
	// Nowhere to go: the replica stays rather than leaving the app down.
	time.Sleep(300 * time.Millisecond)
	if containerCount(d1) != 1 || len(c.running("web")) != 1 {
		t.Error("the only replica was evacuated to nowhere")
	}
	if _, err := c.admin.CordonNode(c.ctx, &armadav1.CordonNodeRequest{Node: "ghost", Cordoned: true}); status.Code(err) != codes.NotFound {
		t.Errorf("cordon unknown = %v", err)
	}
}

// A replica of an app that publishes no port works without being in any
// proxy: cordoning its only node keeps it, and once another node can take
// it, it leaves only after its replacement runs.
func TestCordonKeepsWorkerReplicas(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d1 := c.addNode("n1", "10.0.0.11")
	c.deploy("name: worker\nimage: busybox:1\nscale:\n  min: 1\n  max: 1\n")
	c.eventually("running", func() bool { return len(c.running("worker")) == 1 })
	if _, err := c.admin.CordonNode(c.ctx, &armadav1.CordonNodeRequest{Node: "n1", Cordoned: true}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if containerCount(d1) != 1 || len(c.running("worker")) != 1 {
		t.Fatal("the only worker replica was evacuated to nowhere")
	}

	// Watch from here on: worker must never have no running replica.
	stop := make(chan struct{})
	gap := make(chan bool, 1)
	go func() {
		for {
			select {
			case <-stop:
				gap <- false
				return
			default:
			}
			if len(c.running("worker")) == 0 {
				gap <- true
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	d2 := c.addNode("n2", "10.0.0.12")
	c.eventually("moved to n2", func() bool {
		rs := c.running("worker")
		return containerCount(d1) == 0 && containerCount(d2) == 1 && len(rs) == 1 && rs[0].NodeId == "n2"
	})
	close(stop)
	if <-gap {
		t.Error("worker had no running replica during the move")
	}
}

// TestAgentRenewsBeforeExpiry runs a joined agent whose certificates live
// three seconds: it must keep its session past the first certificate's expiry
// by renewing and reconnecting.
func TestAgentRenewsBeforeExpiry(t *testing.T) {
	t.Parallel()
	c := newCluster(t, withJoin(t), func(cfg *Config) { cfg.NodeCertValidity = 3 * time.Second })
	tok := c.token()
	req, key := joinReq(t, tok.Token, "n2", "10.0.0.12")
	resp, err := c.joinClient(tok).Join(c.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{agent.FileCACert: resp.CaCert, agent.FileNodeCert: resp.NodeCert, agent.FileNodeKey: key} {
		if err := fsutil.WriteFileAtomic(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	creds, err := agent.LoadCredentials(dir, "n2")
	if err != nil {
		t.Fatal(err)
	}
	first := creds.Leaf()
	tlsCfg, err := creds.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := agent.NewServerConn(func() (*grpc.ClientConn, error) {
		return grpc.NewClient(resp.Servers[0], grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	a := agent.New(agent.Config{NodeID: "n2", PrivateIP: "10.0.0.12", Driver: fake.New(), Client: conn.Client(), Proxy: &proxyfake.Driver{},
		Resync: 50 * time.Millisecond, CPUMillis: 1000, MemoryBytes: 1 << 30})
	go func() { _ = a.Run(c.ctx) }()
	go agent.RenewLoop(c.ctx, creds, conn, 200*time.Millisecond, slog.New(slog.DiscardHandler))

	c.eventually("n2 ready", func() bool { return c.srv.session("n2") != nil })
	time.Sleep(time.Until(first.NotAfter) + time.Second)
	c.eventually("n2 connected after the first certificate expired", func() bool {
		n, err := c.store.GetNode(c.ctx, "n2")
		return err == nil && n.State == store.NodeReady && c.srv.session("n2") != nil
	})
	if creds.Leaf().SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Error("certificate was not renewed")
	}
	// Renewed files are on disk with private permissions.
	reloaded, err := agent.LoadCredentials(dir, "n2")
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Leaf().SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Error("renewed certificate not persisted")
	}
	// Expired certificates are no longer allowed.
	if ok, _ := c.store.NodeCertAllowed(c.ctx, "n2", pki.SerialString(first)); ok {
		t.Error("expired certificate still allowed")
	}
}

func TestRenewRateLimit(t *testing.T) {
	t.Parallel()
	l := newKeyedLimiter(5, time.Hour)
	now := time.Now()
	for i := range 5 {
		if !l.allow("n1", now) {
			t.Fatalf("renewal %d refused", i)
		}
	}
	if l.allow("n1", now) {
		t.Error("renewals not limited")
	}
	if !l.allow("n2", now) {
		t.Error("limit is not per node")
	}
}

func TestValidReplicaAddress(t *testing.T) {
	t.Parallel()
	if !validReplicaAddress("10.0.0.2:32768", "10.0.0.2", "") || !validReplicaAddress("[fd00::2]:80", "fd00::2", "") {
		t.Error("valid address rejected")
	}
	// With the cluster network: the node's private IP or its own subnet.
	sub := "10.120.3.0/24"
	if !validReplicaAddress("10.120.3.7:8080", "10.0.0.2", sub) || !validReplicaAddress("10.0.0.2:21000", "10.0.0.2", sub) {
		t.Error("valid subnet address rejected")
	}
	for _, a := range []string{
		"10.120.4.7:8080",   // another node's subnet
		"10.120.3.0:8080",   // the node's tunnel end
		"10.120.3.1:8080",   // the node's bridge gateway (internal ingress, DNS)
		"10.120.3.255:8080", // broadcast
		"10.120.3.7:0",
		"10.120.3.7",
	} {
		if validReplicaAddress(a, "10.0.0.2", sub) {
			t.Errorf("%q accepted with subnet %s", a, sub)
		}
	}
	if validReplicaAddress("10.120.3.7:8080", "10.0.0.2", "") {
		t.Error("subnet address accepted on a node without one")
	}
	for _, a := range []string{
		"10.0.0.3:80",               // another node
		"10.0.0.2:0",                // port 0 would break every node's config
		"10.0.0.2:abc",              // not a port
		"10.0.0.2",                  // no port
		"[fd00::2%x\n global x]:80", // zone smuggling directives
		"010.0.0.2:80",              // non-canonical
		"10.0.0.2:80 backup",        // trailing directive
	} {
		if validReplicaAddress(a, "10.0.0.2", "") {
			t.Errorf("%q accepted", a)
		}
	}
}

func TestLostNodeReplicasAreRescheduled(t *testing.T) {
	t.Parallel()
	c := newCluster(t, func(cfg *Config) { cfg.NodeLostTimeout = 500 * time.Millisecond })
	d1 := c.addNode("n1", "10.0.0.11")
	d2 := c.addNode("n2", "10.0.0.12")
	c.deploy(webSpec("nginx:1", 2))
	c.eventually("spread", func() bool { return containerCount(d1) == 1 && containerCount(d2) == 1 && len(c.running("web")) == 2 })

	start := len(c.proxies["n1"].History())

	// n2 goes down. Its replica is replaced on n1 once the timeout passes,
	// and the lost one leaves the records after the replacement serves.
	c.stopAgent("n2")
	c.eventually("rescheduled", func() bool {
		rs := c.running("web")
		if len(rs) != 2 || containerCount(d1) != 2 {
			return false
		}
		for _, r := range rs {
			if r.NodeId != "n1" {
				return false
			}
		}
		return true
	})
	reps, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{NodeID: "n2"})
	c.eventually("lost replica removed", func() bool {
		reps, _ = c.store.ListReplicas(c.ctx, store.ReplicaFilter{NodeID: "n2"})
		return len(reps) == 0
	})
	st, _ := c.admin.Status(c.ctx, &armadav1.StatusRequest{})
	for _, n := range st.Nodes {
		if n.Id == "n2" && n.State != nodeStateLost {
			t.Errorf("n2 state = %q, want lost", n.State)
		}
	}
	// The loss is one event, however many reconciles see it.
	evs, _ := c.store.ListEvents(c.ctx, time.Time{})
	lost, evacuated := 0, 0
	for _, e := range evs {
		switch {
		case e.Kind == eventNode && e.Object == "n2" && e.Reason == "Lost":
			lost += e.Count
		case e.Reason == "Evacuating" && e.Node == "n2":
			evacuated++
		}
	}
	if lost != 1 || evacuated != 1 {
		t.Errorf("events: lost %d, evacuating %d; want 1 each", lost, evacuated)
	}
	// n1's proxy never lost the app entirely.
	for i, cfg := range c.proxies["n1"].History()[start:] {
		if len(backendServers(cfg, "web")) == 0 {
			t.Errorf("proxy config %d had no web servers", i)
		}
	}

	// n2 comes back: its stale container is removed, then one replica
	// moves back to spread the app again, without the proxy ever having
	// fewer than two servers.
	back := len(c.proxies["n1"].History())
	c.startAgent("n2")
	c.eventually("spread again", func() bool {
		rs, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "web"})
		return containerCount(d1) == 1 && containerCount(d2) == 1 && len(rs) == 2 && len(c.running("web")) == 2
	})
	for i, cfg := range c.proxies["n1"].History()[back:] {
		if n := len(backendServers(cfg, "web")); n < 2 {
			t.Errorf("proxy config %d after the return had %d servers", i, n)
		}
	}
}

// A single replica on a lost node is replaced, never just dropped.
func TestLostNodeSingleReplica(t *testing.T) {
	t.Parallel()
	c := newCluster(t, func(cfg *Config) { cfg.NodeLostTimeout = 300 * time.Millisecond })
	c.addNode("n1", "10.0.0.11")
	c.deploy(webSpec("nginx:1", 1))
	c.eventually("running on n1", func() bool { rs := c.running("web"); return len(rs) == 1 && rs[0].NodeId == "n1" })
	d2 := c.addNode("n2", "10.0.0.12")
	c.stopAgent("n1")
	c.eventually("moved to n2", func() bool {
		rs := c.running("web")
		return len(rs) == 1 && rs[0].NodeId == "n2" && containerCount(d2) == 1
	})
}

func TestLostNodesPartitionGuard(t *testing.T) {
	t.Parallel()
	now := time.Now()
	s := &Server{nodeLostTimeout: time.Minute, log: slog.New(slog.DiscardHandler)}
	gone := now.Add(-2 * time.Minute)
	node := func(id, state string, seen time.Time) store.Node {
		return store.Node{ID: id, State: state, LastSeen: seen}
	}
	tests := map[string]struct {
		nodes []store.Node
		want  []string
	}{
		"one of two lost": {[]store.Node{node("a", store.NodeReady, now), node("b", store.NodeUnknown, gone)}, []string{"b"}},
		"not long enough": {[]store.Node{node("a", store.NodeReady, now), node("b", store.NodeUnknown, now.Add(-10*time.Second))}, nil},
		"never connected": {[]store.Node{node("a", store.NodeReady, now), node("b", store.NodeUnknown, time.Time{})}, nil},
		// The control plane only reaches its own node: it is the one cut off.
		"most lost": {[]store.Node{node("a", store.NodeReady, now), node("b", store.NodeUnknown, gone), node("c", store.NodeUnknown, gone)}, nil},
		"all lost":  {[]store.Node{node("b", store.NodeUnknown, gone)}, nil},
	}
	for name, tt := range tests {
		rc := &reconcileRun{now: now}
		got := s.lostNodes(context.Background(), rc, tt.nodes)
		if len(got) != len(tt.want) {
			t.Errorf("%s: lost = %v, want %v", name, got, tt.want)
			continue
		}
		for _, id := range tt.want {
			if !got[id] {
				t.Errorf("%s: %s not lost", name, id)
			}
		}
	}
	// A disconnected node not yet lost schedules a wake-up for when it is.
	rc := &reconcileRun{now: now}
	s.lostNodes(context.Background(), rc, []store.Node{node("a", store.NodeReady, now), node("b", store.NodeUnknown, now.Add(-50*time.Second))})
	if rc.wake <= 0 || rc.wake > 11*time.Second {
		t.Errorf("wake = %v, want about 10s", rc.wake)
	}
}

// In a cluster with a network (ADR 0027), a joining node gets its subnet in
// the response; a node whose private IP is inside the cluster CIDR is
// refused and leaves the token usable.
func TestJoinGivesNodeSubnet(t *testing.T) {
	t.Parallel()
	c := newCluster(t, withJoin(t))
	if err := c.store.InitNetwork(c.ctx, store.Network{Mode: store.NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	tok := c.token()
	jc := c.joinClient(tok)
	inside, _ := joinReq(t, tok.Token, "n1", "10.120.7.7")
	if _, err := jc.Join(c.ctx, inside); err == nil || !strings.Contains(err.Error(), "cluster CIDR") {
		t.Errorf("private IP inside the cluster CIDR = %v", err)
	}
	req, _ := joinReq(t, tok.Token, "n1", "10.0.0.11")
	resp, err := jc.Join(c.ctx, req)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if resp.NodeSubnet != "10.120.0.0/24" {
		t.Errorf("node subnet = %q, want 10.120.0.0/24", resp.NodeSubnet)
	}
	if n, _ := c.store.GetNode(c.ctx, "n1"); n.Subnet != resp.NodeSubnet {
		t.Errorf("stored subnet = %q", n.Subnet)
	}
}
