package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
)

// Parity of what the agent does outside a reconcile pass: its Hello, the
// reconnect timing, the spec hash, the health check, and a whole session
// with a control plane over mTLS.

// rustOnly starts the Rust program for a test that needs no scenario.
func rustOnly(t *testing.T) *rustAgent {
	t.Helper()
	r := startRust(t, newPfake(&testClock{t: parityT0}))
	t.Cleanup(r.stop)
	return r
}

func TestAgentParityHello(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*parityOpts){
		"default":               nil,
		"no members or volumes": func(o *parityOpts) { o.members, o.volumes = false, false },
		"no volume directory":   func(o *parityOpts) { o.volumesDir = false },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := defaultOpts()
			if change != nil {
				change(&opts)
			}
			runAgentParity(t, opts, func(p *parityRun) {
				h := p.a.hello()
				h.Version = "VERSION"
				p.note("hello", compact(h))
			})
		})
	}
}

func TestAgentParityReconnect(t *testing.T) {
	t.Parallel()
	if agentBin() == "" {
		t.Skip("ARMADA_AGENT_BIN not set")
	}
	r := rustOnly(t)
	now := time.Date(2026, 11, 22, 9, 31, 30, 0, time.UTC)
	cases := []struct {
		accepted bool
		backoff  time.Duration
		lost     time.Time
		at       time.Time
	}{
		{true, 8 * time.Second, time.Time{}, now},
		{false, time.Second, now, now.Add(5 * time.Second)},
		{false, time.Second, now, now.Add(failoverWindow - time.Nanosecond)},
		{false, time.Second, now, now.Add(failoverWindow)},
		{false, 16 * time.Second, now, now.Add(time.Hour)},
		{false, 30 * time.Second, now, now.Add(time.Hour)},
		{false, time.Second, time.Time{}, now},
	}
	for _, c := range cases {
		wait, backoff, lost := reconnectWait(c.accepted, c.backoff, c.lost, c.at)
		ans := r.request("reconnect", map[string]any{"accepted": c.accepted, "backoffNs": int64(c.backoff), "lostNs": unixNs(c.lost), "nowNs": c.at.UnixNano()})
		var rw, rb, rl int64
		_ = json.Unmarshal(ans["waitNs"], &rw)
		_ = json.Unmarshal(ans["backoffNs"], &rb)
		_ = json.Unmarshal(ans["lostNs"], &rl)
		// Go adds a random jitter below a quarter of the retry; the Rust
		// program is asked without one.
		if failover := !c.accepted && !c.lost.IsZero() && c.at.Sub(c.lost) < failoverWindow; failover {
			if wait < failoverRetry || wait >= failoverRetry*5/4 || time.Duration(rw) != failoverRetry {
				t.Errorf("%+v: wait go %s rust %s", c, wait, time.Duration(rw))
			}
		} else if time.Duration(rw) != wait {
			t.Errorf("%+v: wait go %s rust %s", c, wait, time.Duration(rw))
		}
		if time.Duration(rb) != backoff || rl != unixNs(lost) {
			t.Errorf("%+v: go %s %s, rust %s %d", c, backoff, lost, time.Duration(rb), rl)
		}
	}
}

func TestAgentParitySpecHash(t *testing.T) {
	t.Parallel()
	if agentBin() == "" {
		t.Skip("ARMADA_AGENT_BIN not set")
	}
	r := rustOnly(t)
	full := pr("web-r1-a", "nginx:1", 8080)
	full.Startup = &armadav1.Probe{Path: "/s", Port: 81, InitialDelayMs: 5, PeriodMs: 6, TimeoutMs: 7, FailureThreshold: 8, Command: []string{"a", "b"}}
	full.Liveness = &armadav1.Probe{Path: "/l"}
	full.SecretFiles = []*armadav1.SecretFile{{Path: "/f", Data: []byte("secret"), Ref: "f/2"}}
	full.Registry = &armadav1.RegistryAuth{Server: "r", Username: "u", Password: "p", Ref: "reg/1"}
	full.Job = &armadav1.JobAttempt{Job: "j", Run: 3, Done: true}
	full.Volumes = []*armadav1.VolumeSpec{{Name: "v", Path: "/v", Owner: "1:2"}, {Name: "n", Path: "/n", Nfs: &armadav1.NfsSource{Server: "10.0.0.1", Path: "/e", ReadOnly: true}}}
	full.Queues = []*armadav1.QueueProbe{{Type: "redis", Url: "redis://x", Name: "q"}}
	full.InitContainers = []*armadav1.ContainerSpec{{Name: "i", Image: "i:1", Command: []string{"c"}, Args: []string{"a"},
		Env: []*armadav1.EnvVar{{Name: "E", Value: "v", Ref: "e/1"}, {Name: "P", Value: "plain"}}, MemoryBytes: 1, NanoCpus: 2, CpuReserveMillis: 3, PidsLimit: 4, Volumes: []string{"v"}, SecretFiles: []string{"/f"}}}
	full.Sidecars = []*armadav1.ContainerSpec{{Name: "s", Image: "s:1"}}
	full.Hold, full.FenceAfterSeconds = true, 30
	specs := []*armadav1.ReplicaSpec{{}, {Id: "x"}, pr("web-r1-a", "nginx:1", 0), full}
	for i := range 20 {
		s := proto.Clone(full).(*armadav1.ReplicaSpec)
		s.Port = int32(i * 1000)
		s.Env = s.Env[:i%3]
		s.Args = append(s.Args, string(rune('a'+i)))
		specs = append(specs, s)
	}
	for _, s := range specs {
		var got string
		_ = json.Unmarshal(r.request("hash", map[string]any{"spec": protoJSON(s)})["hash"], &got)
		if want := specHash(s); got != want {
			t.Errorf("hash of %s: go %s, rust %s", compact(s), want, got)
		}
	}
}

func TestAgentParityCheck(t *testing.T) {
	t.Parallel()
	if agentBin() == "" {
		t.Skip("ARMADA_AGENT_BIN not set")
	}
	r := rustOnly(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("fine"))
		case "/moved":
			http.Redirect(w, req, "/elsewhere", http.StatusFound)
		case "/slow":
			time.Sleep(time.Second)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := closed.Addr().String()
	_ = closed.Close()
	cases := []struct{ addr, path string }{
		{addr, "/ok"}, {addr, "/moved"}, {addr, "/down"}, {addr, "/slow"}, {addr, ""},
		{refused, ""}, {refused, "/ok"},
	}
	for _, c := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		goErr := ""
		if err := DefaultCheck(ctx, c.addr, c.path); err != nil {
			goErr = err.Error()
		}
		cancel()
		var rustErr string
		_ = json.Unmarshal(r.request("check", map[string]any{"addr": c.addr, "path": c.path, "timeoutMs": 300})["error"], &rustErr)
		if goErr != rustErr {
			t.Errorf("check %s %q: go %q, rust %q", c.addr, c.path, goErr, rustErr)
		}
	}
}

// sessionServer is a control plane's AgentService for one node: it
// records each session's Hello and reports, sends the assignment, and
// ends the first session once the replica is ready.
type sessionServer struct {
	armadav1.UnimplementedAgentServiceServer
	assignment *armadav1.Assignment

	mu      sync.Mutex
	hellos  []*armadav1.Hello
	reports []*armadav1.ReplicaReport
	second  chan struct{}
}

func (s *sessionServer) Connect(stream grpc.BidiStreamingServer[armadav1.AgentMessage, armadav1.ServerMessage]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.hellos = append(s.hellos, first.GetHello())
	n := len(s.hellos)
	s.mu.Unlock()
	if err := stream.Send(&armadav1.ServerMessage{Msg: &armadav1.ServerMessage_Assignment{Assignment: s.assignment}}); err != nil {
		return err
	}
	if n > 1 {
		close(s.second)
		<-stream.Context().Done()
		return nil
	}
	for {
		m, err := stream.Recv()
		if err != nil {
			return err
		}
		if r := m.GetReport(); r != nil {
			s.mu.Lock()
			s.reports = append(s.reports, r)
			s.mu.Unlock()
			if len(r.GetReplicas()) == 1 && r.GetReplicas()[0].GetReady() {
				return nil // the session ends: the agent reconnects
			}
		}
	}
}

// runSession runs one agent against a fresh control plane and returns its
// transcript: both Hellos and the reports of the first session.
func runSession(t *testing.T, rust bool) []string {
	t.Helper()
	ca, err := pki.NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	dir := writeCreds(t, ca, "n1")
	certPEM, keyPEM, err := ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindServer, Name: "s1"}, DNSNames: []string{pki.ServerName}, Server: true})
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := pki.ServerTLS(ca.CertPEM, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	ss := &sessionServer{second: make(chan struct{}), assignment: &armadav1.Assignment{Replicas: []*armadav1.ReplicaSpec{noProbe(pr("web-r1-a", "nginx:1", 0))}}}
	armadav1.RegisterAgentServiceServer(srv, ss)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	clk := &testClock{t: parityT0}
	f := newPfake(clk)
	if rust {
		r := startRust(t, f)
		t.Cleanup(r.stop)
		r.request("config", map[string]any{"config": map[string]any{
			"nodeId": "n1", "privateIp": "10.0.0.2", "cpuMillis": 2000, "memoryBytes": 1 << 30, "nowNs": parityT0.UnixNano(),
			"os": "linux", "arch": "amd64", "caps": map[string]any{"members": true, "exec": true, "stats": true},
		}})
		r.request("run", map[string]any{"dataDir": dir, "node": "n1", "servers": []string{lis.Addr().String()}})
	} else {
		creds, err := LoadCredentials(dir, "n1")
		if err != nil {
			t.Fatal(err)
		}
		cc, err := creds.TLSConfig()
		if err != nil {
			t.Fatal(err)
		}
		conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(cc)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		a := New(Config{NodeID: "n1", PrivateIP: "10.0.0.2", Driver: f, Check: f.Check, Client: armadav1.NewAgentServiceClient(conn),
			CPUMillis: 2000, MemoryBytes: 1 << 30, OS: "linux", Arch: "amd64", ImagePrune: -1, UsageInterval: time.Hour})
		a.now, a.began = clk.Now, clk.Now()
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go func() { _ = a.Run(ctx) }()
	}
	select {
	case <-ss.second:
	case <-time.After(20 * time.Second):
		t.Fatal("the agent never came back for a second session")
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	var out []string
	for _, h := range ss.hellos {
		h = proto.Clone(h).(*armadav1.Hello)
		h.Version = "VERSION"
		out = append(out, "hello "+compact(h))
	}
	// The first report (sent before the start: nothing to say yet) and the
	// last; reports in between depend on when the probe answered.
	out = append(out, "first "+compact(ss.reports[0]), "last "+compact(ss.reports[len(ss.reports)-1]))
	return out
}

func TestAgentParitySession(t *testing.T) {
	t.Parallel()
	g := runSession(t, false)
	if os.Getenv("ARMADA_AGENT_PARITY_DUMP") != "" {
		t.Log(g)
	}
	if agentBin() == "" {
		return
	}
	compareAgentTranscripts(t, g, runSession(t, true))
}
