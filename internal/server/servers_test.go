package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/store"
)

// fakeCluster is an etcd membership in memory.
type fakeCluster struct {
	mu       sync.Mutex
	members  []etcd.MemberInfo
	next     uint64
	addErr   error
	promoted int
}

func (f *fakeCluster) Members(context.Context) ([]etcd.MemberInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]etcd.MemberInfo(nil), f.members...), nil
}

func (f *fakeCluster) AddLearner(_ context.Context, name string, addr netip.Addr, port int) (uint64, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addErr != nil {
		return 0, "", f.addErr
	}
	f.next++
	f.members = append(f.members, etcd.MemberInfo{ID: f.next, Name: name, Learner: true})
	return f.next, "cp-1=https://10.0.0.1:2380," + name + "=https://" + netip.AddrPortFrom(addr, uint16(port)).String(), nil
}

func (f *fakeCluster) Promote(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for i := range f.members {
		if f.members[i].Learner {
			f.members[i].Learner = false
			f.promoted++
			out = append(out, f.members[i].Name)
		}
	}
	return out, nil
}

func (f *fakeCluster) Reachable(_ context.Context, m etcd.MemberInfo) bool { return !m.Learner }

func (f *fakeCluster) RemoveMember(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, m := range f.members {
		if m.ID == id {
			f.members = append(f.members[:i], f.members[i+1:]...)
			return nil
		}
	}
	return errors.New("no such member")
}

// withHA gives the server a name, a membership, and the master key, and
// records it as the first control plane node.
func withHA(t *testing.T, fc *fakeCluster) func(*Config) {
	t.Helper()
	keys, err := secrets.NewKeyring(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	fc.members = []etcd.MemberInfo{{ID: 100, Name: "cp-1"}}
	return func(c *Config) {
		c.Name, c.Cluster, c.Secrets = "cp-1", fc, keys
		if err := c.Store.UpsertServer(context.Background(), store.Server{Name: "cp-1", PrivateIP: "10.0.0.1", APIAddr: c.APIAddr, MemberID: 100}); err != nil {
			t.Fatal(err)
		}
	}
}

func (c *cluster) serverToken() *armadav1.CreateJoinTokenResponse {
	c.t.Helper()
	tok, err := c.admin.CreateJoinToken(c.ctx, &armadav1.CreateJoinTokenRequest{Server: true, TtlSeconds: 600})
	if err != nil {
		c.t.Fatal(err)
	}
	return tok
}

func joinServerReq(t *testing.T, tok, name, ip string) *armadav1.JoinServerRequest {
	t.Helper()
	_, csr, err := pki.NewNodeCSR(name)
	if err != nil {
		t.Fatal(err)
	}
	id, secret, _ := strings.Cut(tok, ".")
	return &armadav1.JoinServerRequest{TokenId: id, TokenSecret: secret, Name: name, PrivateIp: ip, NodeCsr: csr,
		ApiPort: 7443, JoinPort: 7444, EtcdPeerPort: 2380}
}

func TestJoinServer(t *testing.T) {
	t.Parallel()
	fc := &fakeCluster{}
	c := newCluster(t, withJoin(t), withHA(t, fc))

	if _, err := c.admin.CreateJoinToken(c.ctx, &armadav1.CreateJoinTokenRequest{Server: true, TtlSeconds: 7200}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("2h server token: %v", err)
	}
	nodeTok := c.token()
	tok := c.serverToken()
	jc := c.joinClient(tok)

	// A node token cannot add a server, nor a server token a node.
	if _, err := jc.JoinServer(c.ctx, joinServerReq(t, nodeTok.Token, "cp-2", "10.0.0.2")); status.Code(err) != codes.Unauthenticated {
		t.Errorf("server joined with a node token: %v", err)
	}
	nreq, _ := joinReq(t, tok.Token, "n9", "10.0.0.9")
	if _, err := jc.Join(c.ctx, nreq); status.Code(err) != codes.Unauthenticated {
		t.Errorf("node joined with a server token: %v", err)
	}
	bad := joinServerReq(t, tok.Token, "cp-2", "10.0.0.2")
	bad.TokenSecret = strings.Repeat("0", 64)
	if _, err := jc.JoinServer(c.ctx, bad); status.Code(err) != codes.Unauthenticated {
		t.Errorf("wrong secret: %v", err)
	}
	for name, mod := range map[string]func(*armadav1.JoinServerRequest){
		"public IP":   func(r *armadav1.JoinServerRequest) { r.PrivateIp = "8.8.8.8" },
		"bad name":    func(r *armadav1.JoinServerRequest) { r.Name = "../x" },
		"bad port":    func(r *armadav1.JoinServerRequest) { r.ApiPort = 70000 },
		"no etcd":     func(r *armadav1.JoinServerRequest) { r.EtcdPeerPort = 0 },
		"no CSR":      func(r *armadav1.JoinServerRequest) { r.NodeCsr = nil },
		"giant CSR":   func(r *armadav1.JoinServerRequest) { r.NodeCsr = make([]byte, maxCSRSize+1) },
		"unspecified": func(r *armadav1.JoinServerRequest) { r.PrivateIp = "0.0.0.0" },
	} {
		r := joinServerReq(t, tok.Token, "cp-2", "10.0.0.2")
		mod(r)
		// Directly, past the join listener's rate limit.
		if _, err := (&joinService{s: c.srv}).JoinServer(c.ctx, r); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The joining machine names the user of its admin configs: the leader
	// records it with cluster-admin before the machine signs its
	// certificate, which the cluster then accepts.
	req := joinServerReq(t, tok.Token, "cp-2", "10.0.0.2")
	req.UserName = "joiner"
	resp, err := (&joinService{s: c.srv}).JoinServer(c.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetUserRecorded() {
		t.Error("user not recorded")
	}
	if p, err := c.store.GetPrincipal(c.ctx, store.KindUser, "joiner"); err != nil || !p.Has(store.Grant{Role: store.RoleClusterAdmin}) {
		t.Errorf("joined user: %+v %v", p, err)
	}
	jca, err := pki.LoadCA(resp.CaCert, resp.CaKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := armadav1.NewAdminServiceClient(c.dial(jca, pki.Identity{Kind: pki.KindUser, Name: "joiner"})).Status(c.ctx, &armadav1.StatusRequest{}); err != nil {
		t.Errorf("the joined machine's user certificate: %v", err)
	}
	if _, err := pki.LoadCA(resp.CaCert, resp.CaKey); err != nil {
		t.Errorf("CA key: %v", err)
	}
	if _, err := pki.ServerTLS(resp.CaCert, resp.ServerCert, resp.ServerKey); err != nil {
		t.Errorf("server certificate: %v", err)
	}
	leaf, _ := pki.ParseCertPEM(resp.ServerCert)
	if id, _ := pki.IdentityFromCert(leaf); id.String() != "server:cp-2" || len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "10.0.0.2" {
		t.Errorf("server certificate %s %v", leaf.Subject.CommonName, leaf.IPAddresses)
	}
	if string(resp.MasterKey) != string(c.srv.keys.Export().Bytes()) {
		t.Error("wrong master key")
	}
	if !strings.Contains(resp.InitialCluster, "cp-2=https://10.0.0.2:2380") {
		t.Errorf("initial cluster %q", resp.InitialCluster)
	}
	if strings.Join(resp.Servers, ",") != c.addr+",10.0.0.2:7443" {
		t.Errorf("servers %v", resp.Servers)
	}
	if _, err := (&joinService{s: c.srv}).JoinServer(c.ctx, joinServerReq(t, tok.Token, "cp-3", "10.0.0.3")); status.Code(err) != codes.Unauthenticated {
		t.Errorf("token reused: %v", err)
	}

	// The joined server is listed, and promoted by the leader.
	c.eventually("promotion", func() bool {
		l, err := c.admin.ListServers(c.ctx, &armadav1.ListServersRequest{})
		return err == nil && len(l.Servers) == 2 && l.Servers[0].Leader && l.Servers[1].Name == "cp-2" && l.Servers[1].Voting && !l.Servers[1].Leader
	})
	if _, err := c.store.GetNode(c.ctx, "cp-2"); err != nil {
		t.Errorf("server's node not registered: %v", err)
	}
	// An invalid user name records nothing; the join still succeeds.
	req = joinServerReq(t, c.serverToken().Token, "cp-3", "10.0.0.3")
	req.UserName = "Bad Name"
	if resp, err := (&joinService{s: c.srv}).JoinServer(c.ctx, req); err != nil || resp.GetUserRecorded() {
		t.Errorf("invalid user name: recorded=%v %v", resp.GetUserRecorded(), err)
	}
}

// If the etcd member cannot be added, the registration is undone so the
// name and IP can be used again.
func TestJoinServerUndoesFailedJoin(t *testing.T) {
	t.Parallel()
	fc := &fakeCluster{}
	c := newCluster(t, withJoin(t), withHA(t, fc))
	fc.mu.Lock()
	fc.addErr = errors.New("etcdserver: unhealthy cluster")
	fc.mu.Unlock()
	tok := c.serverToken()
	if _, err := c.joinClient(tok).JoinServer(c.ctx, joinServerReq(t, tok.Token, "cp-2", "10.0.0.2")); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "unhealthy") {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.store.GetNode(c.ctx, "cp-2"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("node left behind: %v", err)
	}
	if list, _ := c.store.ListServers(c.ctx); len(list) != 1 {
		t.Errorf("servers left behind: %+v", list)
	}
	fc.mu.Lock()
	fc.addErr = nil
	fc.mu.Unlock()
	tok = c.serverToken()
	if _, err := c.joinClient(tok).JoinServer(c.ctx, joinServerReq(t, tok.Token, "cp-2", "10.0.0.2")); err != nil {
		t.Errorf("retry with a new token: %v", err)
	}
}

func TestServerTokenNeedsMembership(t *testing.T) {
	t.Parallel()
	c := newCluster(t, withJoin(t))
	if _, err := c.admin.CreateJoinToken(c.ctx, &armadav1.CreateJoinTokenRequest{Server: true}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err = %v", err)
	}
}

func TestRemoveServer(t *testing.T) {
	t.Parallel()
	fc := &fakeCluster{}
	c := newCluster(t, withJoin(t), withHA(t, fc))
	tok := c.serverToken()
	if _, err := c.joinClient(tok).JoinServer(c.ctx, joinServerReq(t, tok.Token, "cp-2", "10.0.0.2")); err != nil {
		t.Fatal(err)
	}
	// A record without a member (a join that never completed, or a server
	// from before a restore) is listed and can be removed.
	_ = c.store.UpsertServer(c.ctx, store.Server{Name: "old", PrivateIP: "10.0.0.7", APIAddr: "10.0.0.7:7443", MemberID: 999})

	if _, err := c.admin.RemoveServer(c.ctx, &armadav1.RemoveServerRequest{Name: "cp-1"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("leader removed itself: %v", err)
	}
	if _, err := c.admin.RemoveServer(c.ctx, &armadav1.RemoveServerRequest{Name: "nope"}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown server: %v", err)
	}
	l, _ := c.admin.ListServers(c.ctx, &armadav1.ListServersRequest{})
	if len(l.Servers) != 3 || l.Servers[2].Name != "old" || l.Servers[2].Member {
		t.Errorf("list = %v", l.Servers)
	}
	for _, name := range []string{"cp-2", "old"} {
		if _, err := c.admin.RemoveServer(c.ctx, &armadav1.RemoveServerRequest{Name: name}); err != nil {
			t.Fatalf("remove %s: %v", name, err)
		}
	}
	if m, _ := fc.Members(c.ctx); len(m) != 1 {
		t.Errorf("members after remove = %+v", m)
	}
	if l, _ := c.admin.ListServers(c.ctx, &armadav1.ListServersRequest{}); len(l.Servers) != 1 {
		t.Errorf("list after remove = %v", l.Servers)
	}
}

// Agents learn every control plane address from their assignments, but
// only of servers that are etcd members.
func TestAssignmentsListServers(t *testing.T) {
	t.Parallel()
	fc := &fakeCluster{}
	c := newCluster(t, withHA(t, fc))
	_ = c.store.UpsertServer(c.ctx, store.Server{Name: "cp-2", PrivateIP: "10.0.0.2", APIAddr: "10.0.0.2:7443", MemberID: 7})
	_ = c.store.UpsertServer(c.ctx, store.Server{Name: "gone", PrivateIP: "10.0.0.9", APIAddr: "10.0.0.9:7443", MemberID: 9})
	fc.mu.Lock()
	fc.members = append(fc.members, etcd.MemberInfo{ID: 7, Name: "cp-2"})
	fc.mu.Unlock()
	c.addNode("n1", "10.0.0.11")
	c.eventually("servers in assignment", func() bool {
		sess := c.srv.session("n1")
		if sess == nil {
			return false
		}
		sess.mu.Lock()
		defer sess.mu.Unlock()
		return sess.last != nil && strings.Join(sess.last.Servers, ",") == c.addr+",10.0.0.2:7443"
	})
}

// A new leader cannot know whether nodes that were connected to the old one
// are alive: they start over as unknown, last seen now.
func TestStartTermResetsReadyNodes(t *testing.T) {
	t.Parallel()
	st := newCluster(t).store
	ctx := context.Background()
	old := time.Now().Add(-time.Hour)
	_ = st.UpsertNode(ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.11"})
	_ = st.SetNodeStatus(ctx, "n1", store.NodeStatus{State: store.NodeReady, LastSeen: old, CPUMillis: 2000, MemoryBytes: 1 << 30})
	srv := &Server{store: st, now: time.Now, sessions: map[string]*session{}}
	if err := srv.startTerm(ctx); err != nil {
		t.Fatal(err)
	}
	n, _ := st.GetNode(ctx, "n1")
	if n.State != store.NodeUnknown || time.Since(n.LastSeen) > time.Minute || n.CPUMillis != 2000 {
		t.Errorf("node = %+v", n)
	}
}

// A deposed leader's writes fail with Unavailable, not Internal.
func TestNotLeaderIsUnavailable(t *testing.T) {
	t.Parallel()
	if code := status.Code(storeErr(store.ErrNotLeader)); code != codes.Unavailable {
		t.Errorf("code = %v", code)
	}
}

// A server of another site joins over the leader's endpoint like a node
// (ADR 0050): with its key and endpoint, its etcd member at its node
// address, and the peer list to bring its tunnels up with.
func TestSiteServerJoin(t *testing.T) {
	t.Parallel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fc := &fakeCluster{}
	c := newCluster(t, withJoin(t), withHA(t, fc), withSiteJoin(t, l))
	if err := c.store.InitNetwork(c.ctx, store.Network{Mode: store.NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	office, err := c.admin.CreateJoinToken(c.ctx, &armadav1.CreateJoinTokenRequest{Site: "office", Server: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(office.JoinAddr, "203.0.113.1:") || time.Until(office.ExpiresAt.AsTime()) > 10*time.Minute {
		t.Errorf("server token for another site %v", office)
	}
	cloud, err := c.admin.CreateJoinToken(c.ctx, &armadav1.CreateJoinTokenRequest{Site: "cloud", Server: true})
	if err != nil {
		t.Fatal(err)
	}
	var jc armadav1.JoinServiceClient
	c.eventually("join listener open", func() bool {
		jc, err = meshJoinClient(c.ctx, t, l.Addr().String(), office.CaHash)
		return err == nil
	})
	// A leader's-site server token stays on the private listener.
	first := c.serverToken()
	key := testKey(t)
	req := joinServerReq(t, first.Token, "cp-2", "10.1.0.5")
	req.NetworkKey, req.Endpoint = key, "198.51.100.2"
	if _, err := jc.JoinServer(c.ctx, req); status.Code(err) != codes.PermissionDenied {
		t.Errorf("first-site server token over the public address = %v", err)
	}
	req = joinServerReq(t, office.Token, "cp-2", "10.1.0.5")
	if _, err := jc.JoinServer(c.ctx, req); status.Code(err) != codes.InvalidArgument {
		t.Errorf("server of another site without a key = %v", err)
	}
	req.NetworkKey, req.Endpoint = key, "198.51.100.2"
	resp, err := jc.JoinServer(c.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetMeshIp() != "" || !strings.Contains(resp.GetInitialCluster(), "cp-2=https://10.1.0.5:2380") {
		t.Errorf("join answer: mesh IP %q, initial cluster %q", resp.GetMeshIp(), resp.GetInitialCluster())
	}
	var self *armadav1.NetworkPeer
	for _, p := range resp.GetNetwork().GetPeers() {
		if p.GetNode() == "cp-2" {
			self = p
		}
	}
	if self == nil || self.GetSite() != "office" || self.GetPublicKey() != key || self.GetEndpoint() != "198.51.100.2" {
		t.Errorf("peer list %v", resp.GetNetwork().GetPeers())
	}
	if n, err := c.store.GetNode(c.ctx, "cp-2"); err != nil || n.Site != "office" || n.Endpoint != "198.51.100.2" || n.PrivateIP != "10.1.0.5" {
		t.Errorf("node %+v, %v", n, err)
	}
	// With no private network, the server's etcd member and API are at a
	// mesh address.
	req = joinServerReq(t, cloud.Token, "cp-3", "")
	req.NetworkKey, req.Endpoint = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "198.51.100.3"
	if resp, err = jc.JoinServer(c.ctx, req); err != nil {
		t.Fatal(err)
	}
	if resp.GetMeshIp() != "10.122.0.1" || !strings.Contains(resp.GetInitialCluster(), "cp-3=https://10.122.0.1:2380") || resp.GetNetwork().GetMeshCidr() != store.DefaultMeshCIDR {
		t.Errorf("mesh server join answer: mesh IP %q, initial cluster %q, network %v", resp.GetMeshIp(), resp.GetInitialCluster(), resp.GetNetwork())
	}
	srvs, err := c.store.ListServers(c.ctx)
	if err != nil {
		t.Fatal(err)
	}
	apis := map[string]string{}
	for _, s := range srvs {
		apis[s.Name] = s.APIAddr
	}
	if apis["cp-2"] != "10.1.0.5:7443" || apis["cp-3"] != "10.122.0.1:7443" {
		t.Errorf("servers %v", apis)
	}
}
