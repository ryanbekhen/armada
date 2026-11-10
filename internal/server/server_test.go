package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/agent"
	"github.com/ryanbekhen/armada/internal/conntrack"
	"github.com/ryanbekhen/armada/internal/pki"
	proxyfake "github.com/ryanbekhen/armada/internal/proxy/fake"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/store/storetest"
)

type cluster struct {
	t     *testing.T
	ctx   context.Context
	ca    *pki.CA
	store *store.Etcd
	srv   *Server
	addr  string
	// stop cancels the server's context; stopped closes when Serve returns.
	stop    context.CancelFunc
	stopped chan struct{}
	admin   armadav1.AdminServiceClient

	proxies map[string]*proxyfake.Driver
	checks  map[string]*healthChecks
	nodes   map[string]*testNode
}

// testNode is a node whose agent can be stopped and started again with the
// same containers, like a machine going down and coming back.
type testNode struct {
	ip      string
	d       *fake.Driver
	volumes string
	cancel  context.CancelFunc
	done    chan struct{}
}

// healthChecks stands in for probing containers: every check passes unless
// the container's image is marked broken.
type healthChecks struct {
	mu     sync.Mutex
	broken map[string]bool // image -> failing
	d      *fake.Driver
}

func (h *healthChecks) check(ctx context.Context, addr, _ string) error {
	cs, err := h.d.List(ctx, nil)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range cs {
		if net.JoinHostPort(c.HostIP, strconv.Itoa(c.HostPort)) == addr && h.broken[c.Image] {
			return errors.New("connection refused")
		}
	}
	return nil
}

func (h *healthChecks) breakImage(image string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.broken[image] = true
}

func newCluster(t *testing.T, opts ...func(*Config)) *cluster {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	ca, err := pki.NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindServer, Name: "armada"}, DNSNames: []string{pki.ServerName}, Server: true})
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := pki.ServerTLS(ca.CertPEM, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	st := storetest.Open(t)

	joinTLS, err := pki.JoinServerTLS(ca.CertPEM, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Store: st, TLS: tlsCfg, Resync: 50 * time.Millisecond, Resolver: noTXT{},
		DrainTimeout: 50 * time.Millisecond, Warmup: 20 * time.Millisecond,
		CA: ca, JoinTLS: joinTLS, APIAddr: lis.Addr().String()}
	for _, o := range opts {
		o(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx, lis)
	}()
	t.Cleanup(func() { cancel(); <-done })

	c := &cluster{t: t, ctx: ctx, ca: ca, store: st, srv: srv, addr: lis.Addr().String(), stop: cancel, stopped: done, proxies: map[string]*proxyfake.Driver{},
		checks: map[string]*healthChecks{}, nodes: map[string]*testNode{}}
	c.admin = armadav1.NewAdminServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindAdmin, Name: "ryan"}))
	return c
}

func (c *cluster) dial(ca *pki.CA, id pki.Identity) *grpc.ClientConn {
	c.t.Helper()
	certPEM, keyPEM, err := ca.Issue(pki.IssueRequest{Identity: id, Client: true})
	if err != nil {
		c.t.Fatal(err)
	}
	if id.Kind == pki.KindNode {
		// Record the certificate as the server would on join; nodes that
		// are not registered stay unrecorded (and are rejected).
		cert, _ := pki.ParseCertPEM(certPEM)
		_ = c.store.RecordNodeCert(c.ctx, id.Name, store.NodeCert{Serial: pki.SerialString(cert), NotAfter: cert.NotAfter}, "")
	}
	return c.dialPEM(certPEM, keyPEM)
}

// dialPEM connects with a client certificate and key.
func (c *cluster) dialPEM(certPEM, keyPEM []byte) *grpc.ClientConn {
	c.t.Helper()
	cfg, err := pki.ClientTLS(c.ca.CertPEM, certPEM, keyPEM)
	if err != nil {
		c.t.Fatal(err)
	}
	conn, err := grpc.NewClient(c.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// addNode registers a node and starts an agent with a fake runtime.
func (c *cluster) addNode(id, ip string) *fake.Driver {
	c.t.Helper()
	if err := c.store.UpsertNode(c.ctx, store.Node{ID: id, PrivateIP: ip}); err != nil {
		c.t.Fatal(err)
	}
	d := fake.New()
	d.Digests = map[string]string{"nginx:1": "nginx@sha256:" + strings.Repeat("1", 64), "nginx:2": "nginx@sha256:" + strings.Repeat("2", 64)}
	d.LogLines = []runtime.LogFrame{{Stream: runtime.Stdout, Data: []byte("hello from " + id + "\n")}, {Stream: runtime.Stderr, Data: []byte("warn\n")}}
	c.proxies[id] = &proxyfake.Driver{}
	c.checks[id] = &healthChecks{broken: map[string]bool{}, d: d}
	c.nodes[id] = &testNode{ip: ip, d: d, volumes: filepath.Join(c.t.TempDir(), "volumes")}
	c.startAgent(id)
	return d
}

// conntrackTable is a connection tracking table for a test agent, with 7
// connections and a limit the agent raises.
func (c *cluster) conntrackTable() *conntrack.Table {
	c.t.Helper()
	dir := c.t.TempDir()
	for name, v := range map[string]string{"nf_conntrack_count": "7\n", "nf_conntrack_max": "65536\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o600); err != nil {
			c.t.Fatal(err)
		}
	}
	return conntrack.At(dir, 4<<30)
}

// startAgent runs the agent of a node added with addNode and waits until
// the server sees it.
func (c *cluster) startAgent(id string) {
	c.t.Helper()
	n := c.nodes[id]
	conn := c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: id})
	a := agent.New(agent.Config{
		NodeID: id, PrivateIP: n.ip, Driver: n.d, Client: armadav1.NewAgentServiceClient(conn), Proxy: c.proxies[id],
		Resync: 50 * time.Millisecond, UsageInterval: 20 * time.Millisecond, CPUMillis: 2000, MemoryBytes: 2 << 30, Check: c.checks[id].check,
		VolumesDir: n.volumes, VolumeInterval: 50 * time.Millisecond,
		Conntrack: c.conntrackTable(),
	})
	ctx, cancel := context.WithCancel(c.ctx)
	n.cancel, n.done = cancel, make(chan struct{})
	go func() {
		defer close(n.done)
		_ = a.Run(ctx)
	}()
	c.eventually("node "+id+" ready", func() bool {
		st, err := c.store.GetNode(c.ctx, id)
		return err == nil && st.State == store.NodeReady
	})
}

// stopAgent stops a node's agent; its containers keep "running".
func (c *cluster) stopAgent(id string) {
	c.t.Helper()
	n := c.nodes[id]
	n.cancel()
	<-n.done
	c.eventually("node "+id+" disconnected", func() bool {
		st, err := c.store.GetNode(c.ctx, id)
		return err == nil && st.State != store.NodeReady
	})
}

func (c *cluster) eventually(what string, cond func() bool) {
	c.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	c.t.Fatalf("timed out waiting for %s", what)
}

func (c *cluster) deploy(yaml string) *armadav1.DeployResponse {
	c.t.Helper()
	resp, err := c.admin.Deploy(c.ctx, &armadav1.DeployRequest{Spec: []byte(yaml)})
	if err != nil {
		c.t.Fatal(err)
	}
	return resp
}

func (c *cluster) running(app string) []*armadav1.ReplicaStatus {
	resp, err := c.admin.Status(c.ctx, &armadav1.StatusRequest{App: app})
	if err != nil {
		return nil
	}
	var out []*armadav1.ReplicaStatus
	for _, r := range resp.Apps[0].Replicas {
		if r.State == store.ReplicaRunning {
			out = append(out, r)
		}
	}
	return out
}

func webSpec(image string, replicas int) string {
	return fmt.Sprintf("name: web\nimage: %s\ningress:\n  type: external\n  port: 80\nscale:\n  min: %d\n  max: 10\n", image, replicas)
}

func TestDeployScaleRedeploy(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d1 := c.addNode("n1", "127.0.0.1")
	d2 := c.addNode("n2", "127.0.0.2")

	resp := c.deploy(webSpec("nginx:1", 2))
	if resp.App != "web" || resp.Revision != "web--r1" {
		t.Errorf("deploy = %v", resp)
	}
	c.eventually("2 running replicas", func() bool { return len(c.running("web")) == 2 })

	// Spread across nodes, each published on its node's private IP.
	nodes := map[string]bool{}
	for _, r := range c.running("web") {
		nodes[r.NodeId] = true
		wantIP := map[string]string{"n1": "127.0.0.1", "n2": "127.0.0.2"}[r.NodeId]
		if !strings.HasPrefix(r.Address, wantIP+":") {
			t.Errorf("replica %s address %q not on %s", r.Id, r.Address, wantIP)
		}
	}
	if len(nodes) != 2 {
		t.Errorf("replicas not spread: %v", nodes)
	}
	c.eventually("digest pinned", func() bool {
		rev, err := c.store.GetRevision(c.ctx, "web--r1")
		return err == nil && strings.HasPrefix(rev.ImageDigest, "nginx@sha256:1111")
	})

	// Environment and limits reach the container.
	cs, _ := d1.List(c.ctx, map[string]string{runtime.LabelApp: "web"})
	spec, _ := d1.Spec(cs[0].ID)
	env := strings.Join(spec.Env, " ")
	for _, want := range []string{"ARMADA_APP=web", "ARMADA_REVISION=web--r1", "PORT=80", "ARMADA_REPLICA=web-r1-"} {
		if !strings.Contains(env, want) {
			t.Errorf("env %q missing %q", env, want)
		}
	}
	if spec.MemoryBytes != 256<<20 || spec.PidsLimit == 0 {
		t.Errorf("limits = %+v", spec)
	}

	if _, err := c.admin.Scale(c.ctx, &armadav1.ScaleRequest{App: "web", Replicas: 4}); err != nil {
		t.Fatal(err)
	}
	c.eventually("4 running replicas", func() bool { return len(c.running("web")) == 4 })
	if _, err := c.admin.Scale(c.ctx, &armadav1.ScaleRequest{App: "web", Replicas: 1}); err != nil {
		t.Fatal(err)
	}
	c.eventually("1 replica left", func() bool {
		all, _ := d1.List(c.ctx, nil)
		all2, _ := d2.List(c.ctx, nil)
		return len(c.running("web")) == 1 && len(all)+len(all2) == 1
	})

	resp = c.deploy(webSpec("nginx:2", 2))
	if resp.Revision != "web--r2" {
		t.Errorf("redeploy revision = %s", resp.Revision)
	}
	c.eventually("revision 2 running everywhere", func() bool {
		rs := c.running("web")
		if len(rs) != 2 {
			return false
		}
		for _, r := range rs {
			if r.Revision != "web--r2" {
				return false
			}
		}
		all, _ := d1.List(c.ctx, nil)
		all2, _ := d2.List(c.ctx, nil)
		return len(all)+len(all2) == 2
	})

	// Deploying the same spec again is a no-op.
	if resp := c.deploy(webSpec("nginx:2", 2)); resp.Revision != "web--r2" {
		t.Errorf("idempotent deploy created %s", resp.Revision)
	}
}

func TestLogs(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	c.addNode("n1", "127.0.0.1")
	c.addNode("n2", "127.0.0.2")
	c.deploy(webSpec("nginx:1", 2))
	c.eventually("2 running", func() bool { return len(c.running("web")) == 2 })

	stream, err := c.admin.Logs(c.ctx, &armadav1.LogsRequest{App: "web", Tail: 10})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for {
		e, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, e.Stream.String()+" "+string(e.Data))
	}
	joined := strings.Join(got, "")
	for _, want := range []string{"STREAM_STDOUT hello from n1", "STREAM_STDOUT hello from n2", "STREAM_STDERR warn"} {
		if !strings.Contains(joined, want) {
			t.Errorf("logs missing %q:\n%s", want, joined)
		}
	}

	rs := c.running("web")
	stream, err = c.admin.Logs(c.ctx, &armadav1.LogsRequest{App: "web", Replica: rs[0].Id})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		if _, err := stream.Recv(); err != nil {
			break
		}
		n++
	}
	if n != 2 {
		t.Errorf("single-replica logs returned %d entries, want 2", n)
	}

	for _, req := range []*armadav1.LogsRequest{{App: "ghost"}, {App: "web", Replica: "ghost"}} {
		stream, err := c.admin.Logs(c.ctx, req)
		if err == nil {
			_, err = stream.Recv()
		}
		if status.Code(err) != codes.NotFound {
			t.Errorf("Logs(%v) = %v, want NotFound", req, err)
		}
	}
}

// A replica that has written nothing yet returns no logs at once, not a
// notice that its node did not answer.
func TestLogsOfSilentReplica(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d := c.addNode("n1", "127.0.0.1")
	d.LogLines = nil // no log requests run before the deploy
	c.deploy(webSpec("nginx:1", 1))
	c.eventually("running", func() bool { return len(c.running("web")) == 1 })

	start := time.Now()
	stream, err := c.admin.Logs(c.ctx, &armadav1.LogsRequest{App: "web"})
	if err != nil {
		t.Fatal(err)
	}
	for {
		e, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Errorf("entry %q", e.Data)
	}
	if took := time.Since(start); took >= attachTimeout {
		t.Errorf("took %v", took)
	}
}

func TestLogsFromDisconnectedNode(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	if err := c.store.UpsertNode(c.ctx, store.Node{ID: "off", PrivateIP: "10.0.0.9"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.store.Deploy(c.ctx, mustSpec(t, "name: w\nimage: nginx\n"), "t"); err != nil {
		t.Fatal(err)
	}
	if err := c.store.CreateReplica(c.ctx, store.Replica{ID: "w-1", App: "w", Revision: "w--r1", NodeID: "off"}); err != nil {
		t.Fatal(err)
	}
	stream, err := c.admin.Logs(c.ctx, &armadav1.LogsRequest{App: "w"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := stream.Recv()
	if err != nil || !strings.Contains(string(e.Data), "not connected") {
		t.Errorf("Recv = %v, %v", e, err)
	}
}

func TestDeployRejectsInvalidSpec(t *testing.T) {
	t.Parallel()
	c := newCluster(t)

	_, err := c.admin.Deploy(c.ctx, &armadav1.DeployRequest{Spec: []byte("name: BAD\nimage: nginx\n")})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "name") {
		t.Errorf("err = %v", err)
	}
	for _, req := range []*armadav1.ScaleRequest{{App: "web", Replicas: 0}, {App: "web", Replicas: 101}} {
		if _, err := c.admin.Scale(c.ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("Scale(%v) = %v", req, err)
		}
	}
	if _, err := c.admin.Scale(c.ctx, &armadav1.ScaleRequest{App: "ghost", Replicas: 2}); status.Code(err) != codes.NotFound {
		t.Errorf("Scale(ghost) = %v", err)
	}
	if _, err := c.admin.Status(c.ctx, &armadav1.StatusRequest{App: "ghost"}); status.Code(err) != codes.NotFound {
		t.Errorf("Status(ghost) = %v", err)
	}
}

func TestAuthorization(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	if err := c.store.UpsertNode(c.ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.2"}); err != nil {
		t.Fatal(err)
	}

	t.Run("node cannot call admin API", func(t *testing.T) {
		admin := armadav1.NewAdminServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: "n1"}))
		_, err := admin.Status(c.ctx, &armadav1.StatusRequest{})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("err = %v, want PermissionDenied", err)
		}
	})

	t.Run("etcd member certificate cannot call any API", func(t *testing.T) {
		admin := armadav1.NewAdminServiceClient(c.dial(c.ca, pki.EtcdMember))
		if _, err := admin.Status(c.ctx, &armadav1.StatusRequest{}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("admin API: err = %v, want PermissionDenied", err)
		}
		ag := armadav1.NewAgentServiceClient(c.dial(c.ca, pki.EtcdMember))
		if _, err := ag.RenewCertificate(c.ctx, &armadav1.RenewCertificateRequest{Csr: []byte("x")}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("agent API: err = %v, want PermissionDenied", err)
		}
	})

	t.Run("only nodes get proxy certificates", func(t *testing.T) {
		for _, id := range []pki.Identity{{Kind: pki.KindAdmin, Name: "ryan"}, pki.EtcdMember, {Kind: pki.KindNode, Name: "intruder"}} {
			ag := armadav1.NewAgentServiceClient(c.dial(c.ca, id))
			_, err := ag.GetCertificates(c.ctx, &armadav1.GetCertificatesRequest{Names: []string{"web.example.org"}})
			if code := status.Code(err); code != codes.PermissionDenied && code != codes.Unauthenticated {
				t.Errorf("%s: err = %v, want refused", id, err)
			}
		}
	})

	t.Run("admin cannot impersonate an agent", func(t *testing.T) {
		ag := armadav1.NewAgentServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindAdmin, Name: "ryan"}))
		stream, err := ag.Connect(c.ctx)
		if err == nil {
			_, err = stream.Recv()
		}
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("err = %v, want PermissionDenied", err)
		}
	})

	t.Run("unregistered node is rejected", func(t *testing.T) {
		ag := armadav1.NewAgentServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: "intruder"}))
		stream, err := ag.Connect(c.ctx)
		if err == nil {
			_ = stream.Send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Hello{Hello: &armadav1.Hello{PrivateIp: "10.0.0.66"}}})
			_, err = stream.Recv()
		}
		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("err = %v, want Unauthenticated", err)
		}
	})

	t.Run("client from another CA cannot connect", func(t *testing.T) {
		evil, _ := pki.NewCA("evil")
		admin := armadav1.NewAdminServiceClient(c.dial(evil, pki.Identity{Kind: pki.KindAdmin, Name: "ryan"}))
		_, err := admin.Status(c.ctx, &armadav1.StatusRequest{})
		if status.Code(err) != codes.Unavailable {
			t.Errorf("err = %v, want Unavailable (handshake failure)", err)
		}
	})

	t.Run("hello must come first and match private IP", func(t *testing.T) {
		ag := armadav1.NewAgentServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: "n1"}))
		stream, _ := ag.Connect(c.ctx)
		_ = stream.Send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Report{Report: &armadav1.ReplicaReport{}}})
		if _, err := stream.Recv(); status.Code(err) != codes.InvalidArgument {
			t.Errorf("report-first err = %v", err)
		}
		stream, _ = ag.Connect(c.ctx)
		_ = stream.Send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Hello{Hello: &armadav1.Hello{PrivateIp: "10.0.0.99"}}})
		if _, err := stream.Recv(); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("wrong IP err = %v", err)
		}
	})

	t.Run("node cannot attach to another node's log request", func(t *testing.T) {
		id, p := c.srv.logs.register("n1")
		defer c.srv.logs.cancel(id, p)
		if err := c.store.UpsertNode(c.ctx, store.Node{ID: "n2", PrivateIP: "10.0.0.3"}); err != nil {
			t.Fatal(err)
		}
		ag := armadav1.NewAgentServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: "n2"}))
		push, err := ag.PushLogs(c.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = push.Send(&armadav1.LogPush{RequestId: id, Data: []byte("spoofed")})
		if _, err := push.CloseAndRecv(); status.Code(err) != codes.PermissionDenied {
			t.Errorf("err = %v, want PermissionDenied", err)
		}
	})
}

func TestNodeDisconnectMarksUnknown(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	if err := c.store.UpsertNode(c.ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(c.ctx)
	ag := armadav1.NewAgentServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: "n1"}))
	stream, err := ag.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Hello{Hello: &armadav1.Hello{PrivateIp: "10.0.0.2", CpuMillis: 1000}}})
	c.eventually("ready", func() bool { n, _ := c.store.GetNode(c.ctx, "n1"); return n.State == store.NodeReady })
	cancel()
	c.eventually("unknown", func() bool { n, _ := c.store.GetNode(c.ctx, "n1"); return n.State == store.NodeUnknown })

	resp, err := c.admin.Status(c.ctx, &armadav1.StatusRequest{})
	if err != nil || len(resp.Nodes) != 1 || resp.Nodes[0].State != store.NodeUnknown || resp.Nodes[0].LastSeen == nil {
		t.Errorf("Status = %v, %v", resp, err)
	}
}

func TestNewRequiresClientAuth(t *testing.T) {
	t.Parallel()

	ca, _ := pki.NewCA("t")
	c, k, _ := ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindServer, Name: "a"}, Server: true})
	cfg, _ := pki.ServerTLS(ca.CertPEM, c, k)
	cfg.ClientAuth = 0
	if _, err := New(Config{Store: &store.Etcd{}, TLS: cfg}); err == nil {
		t.Error("New accepted TLS without client auth")
	}
	if _, err := New(Config{}); err == nil {
		t.Error("New accepted empty config")
	}
}

// Reports after the hello must keep the capacity the hello reported, also
// on a node's first connection, when the stored record has none yet.
func TestReportsKeepNodeCapacity(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	if err := c.store.UpsertNode(c.ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.11"}); err != nil {
		t.Fatal(err)
	}
	client := armadav1.NewAgentServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: "n1"}))
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	stream, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello := &armadav1.Hello{PrivateIp: "10.0.0.11", CpuMillis: 2000, MemoryBytes: 2 << 30}
	if err := stream.Send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Hello{Hello: hello}}); err != nil {
		t.Fatal(err)
	}
	// The session exists before the hello is stored.
	c.eventually("hello stored", func() bool {
		n, _ := c.store.GetNode(c.ctx, "n1")
		return c.srv.session("n1") != nil && n.CPUMillis == 2000
	})
	if err := stream.Send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Report{Report: &armadav1.ReplicaReport{}}}); err != nil {
		t.Fatal(err)
	}
	// The report is applied asynchronously and, as it changes nothing but
	// the time, may write nothing: the capacity must hold either way.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		n, _ := c.store.GetNode(c.ctx, "n1")
		if n.CPUMillis != 2000 || n.MemoryBytes != 2<<30 {
			t.Fatalf("after a report: cpu %d, memory %d; want the hello's 2000, %d", n.CPUMillis, n.MemoryBytes, 2<<30)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A remote agent's stream never ends on its own; shutdown must not wait
// for it forever.
func TestShutdownWithConnectedAgent(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	if err := c.store.UpsertNode(c.ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.11"}); err != nil {
		t.Fatal(err)
	}
	client := armadav1.NewAgentServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: "n1"}))
	stream, err := client.Connect(context.Background()) // outlives the server's context
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Hello{Hello: &armadav1.Hello{PrivateIp: "10.0.0.11"}}}); err != nil {
		t.Fatal(err)
	}
	c.eventually("n1 connected", func() bool { return c.srv.session("n1") != nil })

	c.stop()
	select {
	case <-c.stopped:
	case <-time.After(shutdownGrace + 5*time.Second):
		t.Fatal("Serve did not return with an agent connected")
	}
	// Buffered assignments may still arrive; then the stream must end.
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, err := stream.Recv(); err != nil {
				return
			}
		}
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Error("agent stream still open after shutdown")
	}
}
