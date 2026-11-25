package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/store/storetest"
)

// The scenario parity harness of the Rust control plane (ADR 0055). A
// scenario is a test body that drives a control plane through the API
// alone: AdminService and JoinService calls, fake agents on
// AgentService.Connect, the store seeded and read on the server's own
// prefix of the package's etcd member, and a test clock. runParity runs
// it against Go's server in process and, with ARMADA_SERVER_BIN (cargo
// build -p armada-server --features parity), against the Rust server as a
// program on another prefix of the same member; each run records a
// transcript of answers, errors, assignments, and keyspaces, normalized
// where the two may differ by chance (times, serials, keys, addresses),
// and the transcripts must be equal step by step.
//
// Go's server runs coreParts: what the Rust server does so far. Each pull
// request of ADR 0055 that ports more widens both, and moves more of this
// package's scenarios onto the harness. Neither server runs a pass on its
// own (manualPasses): the scenario runs every pass, so both pass at the
// same steps, and replica IDs are predictable (parityIDs) so both name
// and order their replicas alike. Neither evaluates autoscaled apps nor
// starts volume backups on its own either: the scenario runs every
// evaluation (autoscale) and every round of backups (backups).

// parityConfig is how a scenario's control plane is set up.
type parityConfig struct {
	// join opens a join listener.
	join bool
	// joinBurst replaces the join listener's rate limit per source (the
	// scenarios that try many joins).
	joinBurst int
	// masterKey gives the server the master key.
	masterKey bool
	// cluster gives the server an etcd membership (a fakeCluster with
	// cp-1 as member 100) and records it as server cp-1.
	cluster bool
	// nodeLost and nodeCertValidity replace the defaults.
	nodeLost         time.Duration
	nodeCertValidity time.Duration
	// drain, warmup, and progress replace the rollout timing's defaults.
	drain, warmup, progress time.Duration
	// plainHTTP is a cluster without certificates (http URLs).
	plainHTTP bool
}

// serverUnderTest is one control plane a scenario drives.
type serverUnderTest interface {
	kind() string
	api() string
	join() string
	// reconcile runs one pass now.
	reconcile(t *testing.T)
	// autoscale runs one evaluation of the autoscaler now.
	autoscale(t *testing.T)
	// backups runs one round of the backup loop now and waits for the
	// backups it started.
	backups(t *testing.T)
	// settingsChanged counts OnSettingsChanged calls.
	settingsChanged() int
	stop()
}

// parityFixtures are shared by both runs of a scenario: the CA, the
// server certificate, and the master key.
type parityFixtures struct {
	ca              *pki.CA
	certPEM, keyPEM []byte
	keys            *secrets.Keyring
	masterKey       []byte
	start           time.Time
}

func newParityFixtures(t *testing.T) *parityFixtures {
	t.Helper()
	ca, err := pki.NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindServer, Name: "cp-1"}, DNSNames: []string{pki.ServerName}, Server: true})
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	keys, err := secrets.NewKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	return &parityFixtures{ca: ca, certPEM: certPEM, keyPEM: keyPEM, keys: keys, masterKey: key,
		start: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)}
}

// parityClock is a scenario's test clock.
type parityClock struct{ ms atomic.Int64 }

func (c *parityClock) now() time.Time { return time.UnixMilli(c.ms.Load()) }

// parityEntry is one step of a transcript.
type parityEntry struct{ label, value string }

// scenario is one run of a scenario against one server.
type scenario struct {
	t     *testing.T
	ctx   context.Context
	cfg   parityConfig
	fx    *parityFixtures
	st    *store.Etcd
	pfx   string
	clock *parityClock
	fc    *fakeCluster
	sut   serverUnderTest
	admin armadav1.AdminServiceClient

	mu      sync.Mutex
	log     []parityEntry
	aliases [][2]string
	seen    map[string]map[string]string
	// marks counts the replica messages barrier sent.
	marks int
}

func serverBin() string { return os.Getenv("ARMADA_SERVER_BIN") }

// runParity runs body against Go's server and, with ARMADA_SERVER_BIN,
// against the Rust server, and compares their transcripts.
func runParity(t *testing.T, cfg parityConfig, body func(sc *scenario)) {
	t.Helper()
	fx := newParityFixtures(t)
	var logs [][]parityEntry
	kinds := []string{"go"}
	if serverBin() != "" {
		kinds = append(kinds, "rust")
	}
	for _, kind := range kinds {
		ok := t.Run(kind, func(t *testing.T) {
			sc := newScenario(t, kind, cfg, fx)
			if dir := os.Getenv("ARMADA_PARITY_DUMP"); dir != "" {
				// Each run's transcript, also of a run that failed.
				t.Cleanup(func() {
					var b strings.Builder
					sc.mu.Lock()
					for _, e := range sc.log {
						fmt.Fprintf(&b, "%s: %s\n", e.label, e.value)
					}
					sc.mu.Unlock()
					_ = os.WriteFile(dir+"/"+strings.ReplaceAll(t.Name(), "/", "_")+".txt", []byte(b.String()), 0o600)
				})
			}
			body(sc)
			sc.mu.Lock()
			logs = append(logs, sc.log)
			sc.mu.Unlock()
		})
		if !ok {
			return
		}
	}
	if dir := os.Getenv("ARMADA_PARITY_DUMP"); dir != "" && len(logs) > 0 {
		// Go's transcript, to read what a scenario records.
		var b strings.Builder
		for _, e := range logs[0] {
			fmt.Fprintf(&b, "%s: %s\n", e.label, e.value)
		}
		name := strings.ReplaceAll(t.Name(), "/", "_") + ".txt"
		if err := os.WriteFile(dir+"/"+name, []byte(b.String()), 0o600); err != nil {
			t.Error(err)
		}
	}
	if len(logs) == 2 {
		compareTranscripts(t, logs[0], logs[1])
	}
}

func compareTranscripts(t *testing.T, g, r []parityEntry) {
	t.Helper()
	bad := 0
	for i := 0; i < max(len(g), len(r)); i++ {
		var ge, re parityEntry
		if i < len(g) {
			ge = g[i]
		}
		if i < len(r) {
			re = r[i]
		}
		if ge != re {
			gv, rv := ge.value, re.value
			if len(gv) > 400 || len(rv) > 400 {
				// Long values (keyspaces): around the first difference.
				at := 0
				for at < len(gv) && at < len(rv) && gv[at] == rv[at] {
					at++
				}
				from := max(0, at-200)
				gv, rv = "…"+gv[from:min(len(gv), at+300)], "…"+rv[from:min(len(rv), at+300)]
			}
			t.Errorf("step %d differs:\n go   %s: %s\n rust %s: %s", i, ge.label, gv, re.label, rv)
			if bad++; bad == 5 {
				t.Fatal("too many differences")
			}
		}
	}
}

func newScenario(t *testing.T, kind string, cfg parityConfig, fx *parityFixtures) *scenario {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	st, pfx := storetest.OpenNamed(t)
	sc := &scenario{t: t, ctx: ctx, cfg: cfg, fx: fx, st: st, pfx: pfx, clock: &parityClock{}, seen: map[string]map[string]string{}}
	sc.clock.ms.Store(fx.start.UnixMilli())
	st.SetNow(sc.clock.now)
	if err := st.KnowUser(ctx, "ryan"); err != nil {
		t.Fatal(err)
	}
	if cfg.cluster {
		sc.fc = &fakeCluster{members: []etcd.MemberInfo{{ID: 100, Name: "cp-1"}}}
	}
	switch kind {
	case "go":
		sc.sut = startGoServer(sc)
	default:
		sc.sut = startRustServer(sc)
	}
	t.Cleanup(sc.sut.stop)
	sc.alias(sc.sut.api(), "<api>")
	if sc.sut.join() != "" {
		sc.alias(sc.sut.join(), "<join>")
	}
	if cfg.cluster {
		if err := st.UpsertServer(ctx, store.Server{Name: "cp-1", PrivateIP: "10.0.0.1", APIAddr: sc.sut.api(), MemberID: 100}); err != nil {
			t.Fatal(err)
		}
	}
	sc.admin = sc.adminClient(pki.Identity{Kind: pki.KindAdmin, Name: "ryan"})
	return sc
}

// goServer is Go's control plane in process, running coreParts.
type goServer struct {
	srv     *Server
	addr    string
	joinAt  string
	cancel  context.CancelFunc
	done    chan struct{}
	changed atomic.Int32
}

func startGoServer(sc *scenario) *goServer {
	t := sc.t
	fx := sc.fx
	tlsCfg, err := pki.ServerTLS(fx.ca.CertPEM, fx.certPEM, fx.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	joinTLS, err := pki.JoinServerTLS(fx.ca.CertPEM, fx.certPEM, fx.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &goServer{addr: lis.Addr().String(), done: make(chan struct{})}
	cfg := Config{Store: sc.st, TLS: tlsCfg, Resync: time.Hour, Resolver: noTXT{}, StreamRecheck: testStreamRecheck,
		CA: fx.ca, JoinTLS: joinTLS, APIAddr: g.addr, Now: sc.clock.now, Name: "cp-1",
		NodeLostTimeout: sc.cfg.nodeLost, NodeCertValidity: sc.cfg.nodeCertValidity,
		DrainTimeout: sc.cfg.drain, Warmup: sc.cfg.warmup, ProgressDeadline: sc.cfg.progress, PlainHTTP: sc.cfg.plainHTTP,
		OnSettingsChanged: func() { g.changed.Add(1) }}
	if sc.cfg.masterKey {
		cfg.Secrets = fx.keys
	}
	if sc.cfg.join {
		jl, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		g.joinAt = jl.Addr().String()
		cfg.JoinAddr, cfg.JoinListener = g.joinAt, jl
	}
	if sc.cfg.cluster {
		cfg.Cluster = sc.fc
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.parts = coreParts
	srv.manualPasses = true
	srv.newID = parityIDs()
	if sc.cfg.joinBurst > 0 {
		srv.joinLimit = newKeyedLimiter(sc.cfg.joinBurst, joinRefill)
	}
	g.srv = srv
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel
	go func() {
		defer close(g.done)
		_ = srv.Serve(ctx, lis)
	}()
	return g
}

func (g *goServer) kind() string         { return "go" }
func (g *goServer) api() string          { return g.addr }
func (g *goServer) join() string         { return g.joinAt }
func (g *goServer) settingsChanged() int { return int(g.changed.Load()) }
func (g *goServer) stop()                { g.cancel(); <-g.done }
func (g *goServer) reconcile(t *testing.T) {
	t.Helper()
	if err := g.srv.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}
func (g *goServer) autoscale(t *testing.T) {
	t.Helper()
	if err := g.srv.autoscale(context.Background()); err != nil {
		t.Fatalf("autoscale: %v", err)
	}
}
func (g *goServer) backups(t *testing.T) {
	t.Helper()
	if err := g.srv.scheduleBackups(context.Background()); err != nil {
		t.Fatalf("backups: %v", err)
	}
	// Each backup it started holds its volume until it ends.
	deadline := time.Now().Add(30 * time.Second)
	for {
		g.srv.backups.mu.Lock()
		n := len(g.srv.backups.volumes)
		g.srv.backups.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("backups did not end")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// rustServer is armada-server-parity, the Rust control plane as a program.
type rustServer struct {
	t       *testing.T
	cmd     *exec.Cmd
	in      io.WriteCloser
	addr    string
	joinAt  string
	changed atomic.Int32
	mu      sync.Mutex
	next    int64
	waiting map[int64]chan map[string]any
	ready   chan map[string]any
	sc      *scenario
	exited  chan struct{}
}

func startRustServer(sc *scenario) *rustServer {
	t := sc.t
	fx := sc.fx
	endpoint, dir := storetest.Member()
	conf := map[string]any{
		"endpoint": endpoint, "dir": dir, "prefix": sc.pfx,
		"caCert": string(fx.ca.CertPEM), "caKey": mustKeyPEM(t, fx.ca),
		"serverCert": string(fx.certPEM), "serverKey": string(fx.keyPEM),
		"name": "cp-1", "apiListen": "127.0.0.1:0", "join": sc.cfg.join,
		"nowMs": sc.clock.ms.Load(), "resyncMs": time.Hour.Milliseconds(),
		"streamRecheckMs":         testStreamRecheck.Milliseconds(),
		"nodeLostSeconds":         int64(sc.cfg.nodeLost / time.Second),
		"nodeCertValiditySeconds": int64(sc.cfg.nodeCertValidity / time.Second),
		"cluster":                 sc.cfg.cluster, "joinBurst": sc.cfg.joinBurst,
		"verbose":        os.Getenv("ARMADA_SERVER_VERBOSE") != "",
		"drainTimeoutMs": sc.cfg.drain.Milliseconds(), "warmupMs": sc.cfg.warmup.Milliseconds(),
		"progressDeadlineMs": sc.cfg.progress.Milliseconds(), "plainHttp": sc.cfg.plainHTTP,
		"manualPasses": true, "predictableIds": true,
	}
	if sc.cfg.masterKey {
		conf["masterKey"] = base64.StdEncoding.EncodeToString(fx.masterKey)
	}
	r := &rustServer{t: t, waiting: map[int64]chan map[string]any{}, ready: make(chan map[string]any, 1), sc: sc, exited: make(chan struct{})}
	r.cmd = exec.Command(serverBin())
	r.cmd.Env = append(os.Environ(), "TZ=UTC")
	r.cmd.Stderr = os.Stderr
	in, err := r.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r.in = in
	go r.read(out)
	r.write(conf)
	select {
	case m := <-r.ready:
		r.addr, _ = m["api"].(string)
		r.joinAt, _ = m["join"].(string)
	case <-r.exited:
		t.Fatal("armada-server-parity exited before it was ready")
	case <-time.After(30 * time.Second):
		t.Fatal("armada-server-parity did not get ready")
	}
	return r
}

// parityIDs makes the random part of replica IDs predictable: the count of
// IDs made so far, in base 36 over randomID's alphabet (armada-server-parity
// makes the same).
func parityIDs() func(int) string {
	var next atomic.Uint64
	return func(n int) string {
		k := next.Add(1)
		b := make([]byte, n)
		for i := n - 1; i >= 0; i-- {
			b[i] = idAlphabet[k%36]
			k /= 36
		}
		return string(b)
	}
}

func mustKeyPEM(t *testing.T, ca *pki.CA) string {
	t.Helper()
	k, err := ca.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	return string(k)
}

func (r *rustServer) write(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _ = r.in.Write(append(b, '\n'))
}

func (r *rustServer) read(out io.Reader) {
	defer close(r.exited)
	sc := bufio.NewScanner(out)
	sc.Buffer(nil, 16<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			continue
		}
		switch {
		case m["ready"] != nil:
			r.ready <- m["ready"].(map[string]any)
		case m["call"] != nil:
			go r.answerCluster(m)
		case m["event"] == "settingsChanged":
			r.changed.Add(1)
		case m["id"] != nil:
			id := int64(m["id"].(float64))
			r.mu.Lock()
			ch := r.waiting[id]
			delete(r.waiting, id)
			r.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		}
	}
}

// answerCluster answers the Rust server's membership calls from the
// scenario's fakeCluster, as Go's server calls it.
func (r *rustServer) answerCluster(m map[string]any) {
	fc := r.sc.fc
	ctx := context.Background()
	ans := map[string]any{"op": "answer", "call": m["call"]}
	fail := func(err error) {
		if err != nil {
			ans["error"] = err.Error()
		}
	}
	switch m["cluster"] {
	case "Members":
		ms, err := fc.Members(ctx)
		fail(err)
		ans["value"] = ms
	case "AddLearner":
		addr, _ := netip.ParseAddr(m["addr"].(string))
		id, initial, err := fc.AddLearner(ctx, m["name"].(string), addr, int(m["port"].(float64)))
		fail(err)
		ans["value"] = map[string]any{"id": id, "initial": initial}
	case "Promote":
		names, err := fc.Promote(ctx)
		fail(err)
		ans["value"] = names
	case "Reachable":
		b, _ := json.Marshal(m["member"])
		var mi etcd.MemberInfo
		_ = json.Unmarshal(b, &mi)
		ans["value"] = fc.Reachable(ctx, mi)
	case "RemoveMember":
		fail(fc.RemoveMember(ctx, uint64(m["id"].(float64))))
	}
	r.write(ans)
}

func (r *rustServer) do(req map[string]any) map[string]any {
	r.mu.Lock()
	r.next++
	id := r.next
	ch := make(chan map[string]any, 1)
	r.waiting[id] = ch
	r.mu.Unlock()
	req["id"] = id
	r.write(req)
	select {
	case m := <-ch:
		return m
	case <-time.After(time.Minute):
		r.t.Fatalf("armada-server-parity did not answer %v", req)
		return nil
	}
}

func (r *rustServer) kind() string         { return "rust" }
func (r *rustServer) api() string          { return r.addr }
func (r *rustServer) join() string         { return r.joinAt }
func (r *rustServer) settingsChanged() int { return int(r.changed.Load()) }
func (r *rustServer) reconcile(t *testing.T) {
	t.Helper()
	if m := r.do(map[string]any{"op": "reconcile"}); m["error"] != "" && m["error"] != nil {
		t.Fatalf("reconcile: %v", m["error"])
	}
}

func (r *rustServer) autoscale(t *testing.T) {
	t.Helper()
	if m := r.do(map[string]any{"op": "autoscale"}); m["error"] != "" && m["error"] != nil {
		t.Fatalf("autoscale: %v", m["error"])
	}
}

func (r *rustServer) backups(t *testing.T) {
	t.Helper()
	if m := r.do(map[string]any{"op": "backups"}); m["error"] != "" && m["error"] != nil {
		t.Fatalf("backups: %v", m["error"])
	}
}

func (r *rustServer) setNow(ms int64) { r.do(map[string]any{"op": "now", "ms": ms}) }

func (r *rustServer) stop() {
	done := make(chan struct{})
	go func() {
		r.do(map[string]any{"op": "stop"})
		close(done)
	}()
	select {
	case <-done:
	case <-r.exited:
	case <-time.After(15 * time.Second):
	}
	_ = r.in.Close()
	_ = r.cmd.Process.Kill()
	_ = r.cmd.Wait()
}

// advance moves the scenario's clock, on both the store and the server.
func (sc *scenario) advance(d time.Duration) {
	sc.clock.ms.Add(d.Milliseconds())
	if r, ok := sc.sut.(*rustServer); ok {
		r.setNow(sc.clock.ms.Load())
	}
}

// alias replaces value by name wherever a transcript holds it.
func (sc *scenario) alias(value, name string) {
	if value == "" {
		return
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.aliases = append(sc.aliases, [2]string{value, name})
	slices.SortStableFunc(sc.aliases, func(a, b [2]string) int { return len(b[0]) - len(a[0]) })
}

// adminClient dials the API as id, with a certificate of the CA. Node
// certificates are recorded as a join would.
func (sc *scenario) adminClient(id pki.Identity) armadav1.AdminServiceClient {
	return armadav1.NewAdminServiceClient(sc.dial(id))
}

func (sc *scenario) dial(id pki.Identity) *grpc.ClientConn {
	sc.t.Helper()
	certPEM, keyPEM, err := sc.fx.ca.Issue(pki.IssueRequest{Identity: id, Client: true})
	if err != nil {
		sc.t.Fatal(err)
	}
	if id.Kind == pki.KindNode {
		cert, _ := pki.ParseCertPEM(certPEM)
		// A node that is not registered stays unrecorded (and refused).
		_ = sc.st.RecordNodeCert(sc.ctx, id.Name, store.NodeCert{Serial: pki.SerialString(cert), NotAfter: cert.NotAfter}, "")
	}
	return sc.dialPEM(certPEM, keyPEM)
}

func (sc *scenario) dialPEM(certPEM, keyPEM []byte) *grpc.ClientConn {
	sc.t.Helper()
	cfg, err := pki.ClientTLS(sc.fx.ca.CertPEM, certPEM, keyPEM)
	if err != nil {
		sc.t.Fatal(err)
	}
	conn, err := grpc.NewClient(sc.sut.api(), grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		sc.t.Fatal(err)
	}
	sc.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// joinClient connects to the join listener as `armadad join` does.
func (sc *scenario) joinClient(tok *armadav1.CreateJoinTokenResponse) armadav1.JoinServiceClient {
	sc.t.Helper()
	pin, err := pki.ParseCAHash(tok.CaHash)
	if err != nil {
		sc.t.Fatal(err)
	}
	ca, err := pki.FetchPinnedCA(sc.ctx, tok.JoinAddr, pin)
	if err != nil {
		sc.t.Fatal(err)
	}
	conn, err := grpc.NewClient(tok.JoinAddr, grpc.WithTransportCredentials(credentials.NewTLS(pki.JoinClientTLS(ca))))
	if err != nil {
		sc.t.Fatal(err)
	}
	sc.t.Cleanup(func() { _ = conn.Close() })
	return armadav1.NewJoinServiceClient(conn)
}

func (sc *scenario) eventually(what string, cond func() bool) {
	sc.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	sc.t.Fatalf("%s: timed out waiting for %s", sc.sut.kind(), what)
}

// eventCount sums the counts of the stored events of object for reason.
func (sc *scenario) eventCount(object, reason string) int {
	evs, err := sc.st.ListEvents(sc.ctx, time.Time{})
	if err != nil {
		sc.t.Fatal(err)
	}
	n := 0
	for _, e := range evs {
		if e.Object == object && e.Reason == reason {
			n += e.Count
		}
	}
	return n
}

// note records a value in the transcript.
func (sc *scenario) note(label string, v any) {
	sc.t.Helper()
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.log = append(sc.log, parityEntry{label: label, value: sc.encode(v)})
}

// answer records a call's answer or error.
func (sc *scenario) answer(label string, m proto.Message, err error) {
	sc.t.Helper()
	if err != nil {
		sc.note(label, err)
		return
	}
	sc.note(label, m)
}

// keyspace records the server's keyspace.
func (sc *scenario) keyspace(label string) {
	sc.t.Helper()
	resp, err := storetest.Client().Get(sc.ctx, sc.pfx, clientv3.WithPrefix())
	if err != nil {
		sc.t.Fatal(err)
	}
	type kv struct {
		k string
		v any
	}
	var all []kv
	for _, e := range resp.Kvs {
		var v any
		if json.Unmarshal(e.Value, &v) != nil {
			v = string(e.Value)
		}
		all = append(all, kv{strings.TrimPrefix(string(e.Key), sc.pfx), v})
	}
	// Random values (serials) are named before any is replaced, so keys
	// and texts holding them read the same on both servers.
	for _, e := range all {
		sc.collect(e.v, "")
	}
	// Records in key order once keys are normalized: keys holding random
	// values sort apart from them.
	var keys, events, audit []string
	for _, e := range all {
		switch {
		case strings.HasPrefix(e.k, "events/"):
			events = append(events, sc.encode(rawJSON{e.v}))
		case strings.HasPrefix(e.k, "audit/"):
			audit = append(audit, sc.encode(rawJSON{e.v}))
		default:
			keys = append(keys, sc.replace(e.k)+" = "+sc.encode(rawJSON{e.v}))
		}
	}
	sort.Strings(keys)
	sort.Strings(events)
	sort.Strings(audit)
	sc.note(label, rawJSON{map[string]any{"keys": keys, "events": events, "audit": audit}})
}

type rawJSON struct{ v any }

// encode is a value's normalized JSON.
func (sc *scenario) encode(v any) string {
	var tree any
	switch x := v.(type) {
	case nil:
		tree = nil
	case error:
		st := status.Convert(x)
		msg := st.Message()
		// encoding/asn1's texts for a malformed CSR, which armada-pki
		// words its own way (its parity tests compare that it refuses).
		if i := strings.Index(msg, "parse CSR: "); i >= 0 {
			msg = msg[:i] + "parse CSR: <asn1 error>"
		}
		tree = map[string]any{"code": st.Code().String(), "message": msg}
	case proto.Message:
		b, err := protojson.Marshal(x)
		if err != nil {
			sc.t.Fatal(err)
		}
		if err := json.Unmarshal(b, &tree); err != nil {
			sc.t.Fatal(err)
		}
	case rawJSON:
		tree = x.v
	default:
		b, err := json.Marshal(x)
		if err != nil {
			sc.t.Fatal(err)
		}
		if err := json.Unmarshal(b, &tree); err != nil {
			sc.t.Fatal(err)
		}
	}
	sc.collect(tree, "")
	out, err := json.Marshal(sc.normalize(tree, ""))
	if err != nil {
		sc.t.Fatal(err)
	}
	return string(out)
}

// Fields the two servers may fill differently by chance, normalized by
// name: times (the servers read the wall clock where Go's code does, and
// the test clock elsewhere), random values (serials, secret hashes and
// ciphertexts, keys), and certificates and keys (summarized).
var (
	parityTimeKeys = map[string]bool{
		"at": true, "addedat": true, "attemptat": true, "createdat": true, "cutoff": true, "drainingsince": true,
		"expiresat": true, "finishedat": true, "first": true, "last": true, "lastrestartat": true, "lastscheduled": true,
		"lastseen": true, "movingsince": true, "notafter": true, "readysince": true, "rolloutprogressat": true,
		"scaledat": true, "since": true, "startedat": true, "updatedat": true, "usedat": true, "verifiedat": true,
		"waitingsince": true, "certexpiresat": true, "certnotafter": true,
	}
	parityRandomKeys = map[string]bool{
		"serial": true, "sinceserial": true, "secrethash": true, "ciphertext": true, "wrappedkey": true,
	}
	parityCertKeys   = map[string]bool{"cert": true, "cacert": true, "nodecert": true, "servercert": true}
	paritySecretKeys = map[string]bool{"cakey": true, "serverkey": true, "masterkey": true}
	paritySerialText = regexp.MustCompile(`serial=[0-9a-f]+`)
	parityRFC3339    = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$`)
)

func (sc *scenario) normalize(v any, key string) any {
	lk := strings.ToLower(key)
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[sc.replace(k)] = sc.normalize(e, k)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = sc.normalize(e, key)
		}
		return out
	case float64:
		if parityTimeKeys[lk] && x != 0 {
			return "<time>"
		}
		return x
	case string:
		switch {
		case x == "":
			return x
		case parityTimeKeys[lk] || parityRFC3339.MatchString(x):
			if strings.HasPrefix(x, "0001-01-01") {
				return x
			}
			return "<time>"
		case parityRandomKeys[lk]:
			return sc.placeholder(lk, x)
		case parityCertKeys[lk]:
			return sc.certSummary(x)
		case paritySecretKeys[lk]:
			return sc.secretSummary(lk, x)
		}
		if nested := nestedJSON(x); nested != nil {
			b, _ := json.Marshal(sc.normalize(nested, key))
			return string(b)
		}
		return sc.replace(x)
	}
	return v
}

func (sc *scenario) replace(s string) string {
	for _, a := range sc.aliases {
		s = strings.ReplaceAll(s, a[0], a[1])
	}
	// Serials the audit log names in its details.
	return paritySerialText.ReplaceAllString(s, "serial=<serial>")
}

// placeholder names a random value by the order it was first seen in.
func (sc *scenario) placeholder(cat, v string) string {
	m := sc.seen[cat]
	if m == nil {
		m = map[string]string{}
		sc.seen[cat] = m
	}
	if p, ok := m[v]; ok {
		return p
	}
	// No number: which of several a key holds is told by the record it
	// is in, and the servers may make them in another order.
	p := "<" + cat + ">"
	m[v] = p
	sc.aliases = append(sc.aliases, [2]string{v, p})
	slices.SortStableFunc(sc.aliases, func(a, b [2]string) int { return len(b[0]) - len(a[0]) })
	return p
}

// collect names the random values of a tree, nested JSON included.
func (sc *scenario) collect(v any, key string) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			sc.collect(e, k)
		}
	case []any:
		for _, e := range x {
			sc.collect(e, key)
		}
	case string:
		if lk := strings.ToLower(key); parityRandomKeys[lk] && x != "" {
			sc.placeholder(lk, x)
		} else if nested := nestedJSON(x); nested != nil {
			sc.collect(nested, key)
		}
	}
}

// nestedJSON is a JSON object a string holds (meta records), or nil.
func nestedJSON(s string) any {
	if !strings.HasPrefix(s, "{") {
		return nil
	}
	var v map[string]any
	if json.Unmarshal([]byte(s), &v) != nil {
		return nil
	}
	return v
}

// pemOf decodes a protojson bytes field, or takes a PEM as it is.
func pemOf(s string) []byte {
	if strings.HasPrefix(s, "-----BEGIN") {
		return []byte(s)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []byte(s)
	}
	return b
}

func (sc *scenario) certSummary(s string) string {
	cert, err := pki.ParseCertPEM(pemOf(s))
	if err != nil {
		return "<not a certificate>"
	}
	id, _ := pki.IdentityFromCert(cert)
	days := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	signed := cert.CheckSignatureFrom(sc.fx.ca.Cert) == nil
	if cert.Equal(sc.fx.ca.Cert) {
		return "<the CA>"
	}
	return fmt.Sprintf("<cert %s days=%d ca=%t ips=%v dns=%v client=%t server=%t>", id, days, signed, cert.IPAddresses, cert.DNSNames,
		slices.Contains(cert.ExtKeyUsage, 2), slices.Contains(cert.ExtKeyUsage, 1))
}

func (sc *scenario) secretSummary(key, s string) string {
	b := pemOf(s)
	switch key {
	case "masterkey":
		return fmt.Sprintf("<master key %t>", string(b) == string(sc.fx.masterKey))
	case "cakey":
		k, _ := sc.fx.ca.KeyPEM()
		return fmt.Sprintf("<CA key %t>", string(b) == string(k))
	}
	if _, err := pki.ParseKeyPEM(b); err != nil {
		return "<not a key>"
	}
	return "<key>"
}

// parityAgent is a fake agent on AgentService.Connect.
type parityAgent struct {
	sc     *scenario
	id     string
	stream armadav1.AgentService_ConnectClient
	cancel context.CancelFunc
	msgs   chan *armadav1.ServerMessage
	errc   chan error
	last   *armadav1.Assignment
	others []*armadav1.ServerMessage
	// volume serves the volume requests the server sends, when set
	// (parity_volumes_test.go).
	volume atomic.Pointer[func(*armadav1.VolumeRequest)]
}

// connectAgent connects node id as its agent with hello and waits until
// the server recorded the connection, or returns the stream's error.
func (sc *scenario) connectAgent(id string, client armadav1.AgentServiceClient, hello *armadav1.Hello) (*parityAgent, error) {
	sc.t.Helper()
	before := sc.eventCount(id, "Connected")
	ctx, cancel := context.WithCancel(sc.ctx)
	stream, err := client.Connect(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	if hello != nil {
		if err := stream.Send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Hello{Hello: hello}}); err != nil {
			cancel()
			return nil, err
		}
	} else {
		_ = stream.CloseSend()
	}
	a := &parityAgent{sc: sc, id: id, stream: stream, cancel: cancel, msgs: make(chan *armadav1.ServerMessage, 256), errc: make(chan error, 1)}
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				a.errc <- err
				close(a.msgs)
				return
			}
			if vr := m.GetVolumeRequest(); vr != nil {
				if h := a.volume.Load(); h != nil {
					go (*h)(vr)
					continue
				}
			}
			a.msgs <- m
		}
	}()
	deadline := time.After(15 * time.Second)
	for sc.eventCount(id, "Connected") == before {
		select {
		case err := <-a.errc:
			cancel()
			return nil, err
		case <-deadline:
			cancel()
			sc.t.Fatalf("%s: agent %s did not connect", sc.sut.kind(), id)
		case <-time.After(10 * time.Millisecond):
		}
	}
	sc.t.Cleanup(cancel)
	return a, nil
}

// nodeAgent is a node's agent client with a recorded certificate.
func (sc *scenario) nodeAgent(id string) armadav1.AgentServiceClient {
	return armadav1.NewAgentServiceClient(sc.dial(pki.Identity{Kind: pki.KindNode, Name: id}))
}

// assignment drains what the server sent and returns the latest
// assignment, once nothing new arrived for a moment.
func (a *parityAgent) assignment() *armadav1.Assignment {
	quiet := time.After(300 * time.Millisecond)
	for {
		select {
		case m, ok := <-a.msgs:
			if !ok {
				return a.last
			}
			if as := m.GetAssignment(); as != nil {
				a.last = as
			} else {
				a.others = append(a.others, m)
			}
			quiet = time.After(300 * time.Millisecond)
		case <-quiet:
			return a.last
		}
	}
}

func (a *parityAgent) send(m *armadav1.AgentMessage) {
	if err := a.stream.Send(m); err != nil {
		a.sc.t.Fatalf("send: %v", err)
	}
}

// end waits for the stream's end and returns why it ended, with the
// assignments sent before.
func (a *parityAgent) end() error {
	for {
		select {
		case m, ok := <-a.msgs:
			if !ok {
				continue
			}
			if as := m.GetAssignment(); as != nil {
				a.last = as
			}
		case err := <-a.errc:
			// What arrived before the end, in order.
			for m := range a.msgs {
				if as := m.GetAssignment(); as != nil {
					a.last = as
				}
			}
			return err
		case <-time.After(15 * time.Second):
			a.sc.t.Fatalf("%s: agent %s stream did not end", a.sc.sut.kind(), a.id)
			return nil
		}
	}
}

// waitErr is end for a call that may have failed before its stream.
func errOf(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
