package cli

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/store"

	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
)

// A second control plane node joins with a server token and receives the
// cluster's keys; it shows up as catching up until it starts, and can be
// removed again.
func TestServerJoinCommand(t *testing.T) {
	orig, origWait, origTmpfs := newDriver, proxyStartWait, checkTmpfs
	newDriver = func(string, *agentConfig) (runtime.Driver, error) { return fake.New(), nil }
	proxyStartWait = time.Millisecond
	checkTmpfs = func(string) error { return nil }
	t.Cleanup(func() { newDriver, proxyStartWait, checkTmpfs = orig, origWait, origTmpfs })

	dataDir, config, _ := initCluster(t)
	join := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	logs := &lockedBuffer{}
	wg.Go(func() {
		args := []string{"server", "--data-dir", dataDir, "--join-listen", join, "--secrets-dir", filepath.Join(t.TempDir(), "s"), "--proxy", "none", "--tls=false"}
		if code := Execute(ctx, args, logs, logs); code != 0 && ctx.Err() == nil {
			t.Errorf("server exited with %d:\n%s", code, logs.String())
		}
	})
	t.Cleanup(func() { cancel(); wg.Wait() })
	cli := func(args ...string) (int, string, string) { return run(t, append(args, "--config", config)...) }
	deadline := time.Now().Add(15 * time.Second)
	for code, _, _ := cli("node", "list"); code != 0; code, _, _ = cli("node", "list") {
		if time.Now().After(deadline) {
			t.Fatalf("server not up:\n%s", logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	code, out, stderr := cli("token", "create", "--server")
	if code != 0 {
		t.Fatalf("token create --server: %s", stderr)
	}
	tok := regexp.MustCompile(`Token \(shown once\): (\S+)`).FindStringSubmatch(out)
	line := regexp.MustCompile(`armada server join (\S+) --ca-hash (\S+)`).FindStringSubmatch(out)
	if tok == nil || line == nil || !strings.Contains(out, "Server token created") {
		t.Fatalf("token output = %q", out)
	}
	if code, _, _ := cli("token", "create", "--server", "--ttl", "2h"); code == 0 {
		t.Error("2h server token accepted")
	}

	cp2 := filepath.Join(t.TempDir(), "cp2")
	serverJoin := func(token string) (int, string, string) {
		var o, e bytes.Buffer
		c := execute(context.Background(), []string{"server", "join", line[1], "--ca-hash", line[2], "--private-ip", "10.0.0.5", "--name", "cp-2", "--data-dir", cp2},
			strings.NewReader(token+"\n"), &o, &e)
		return c, o.String(), e.String()
	}
	// A node token does not add a server.
	_, nout, _ := cli("token", "create")
	nodeTok := regexp.MustCompile(`Token \(shown once\): (\S+)`).FindStringSubmatch(nout)
	if c, _, e := serverJoin(nodeTok[1]); c == 0 || !strings.Contains(e, "invalid join token") {
		t.Errorf("server join with a node token: %d %q", c, e)
	}
	code, out, stderr = serverJoin(tok[1])
	if code != 0 || !strings.Contains(out, "Joined as control plane node cp-2") || !strings.Contains(out, "add a third") {
		t.Fatalf("server join: %d %q %q", code, out, stderr)
	}
	if strings.Contains(out+stderr, strings.SplitN(tok[1], ".", 2)[1]) {
		t.Error("server join printed the token secret")
	}
	for _, f := range []string{fileCACert, fileCAKey, fileServerCert, fileServerKey, fileNodeCert, fileNodeKey, fileMasterKey, fileAgent, fileEtcdInitial} {
		if err := fsutil.CheckPrivate(filepath.Join(cp2, f)); err != nil {
			t.Error(err)
		}
	}
	for _, f := range []string{fileCACert, fileCAKey, fileMasterKey} {
		a, _ := os.ReadFile(filepath.Join(dataDir, f))
		b, _ := os.ReadFile(filepath.Join(cp2, f))
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs from the first server's", f)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(cp2, fileEtcdInitial)); !strings.Contains(string(b), "cp-2=https://10.0.0.5:") {
		t.Errorf("initial cluster = %q", b)
	}
	if c, _, e := serverJoin(tok[1]); c == 0 || !strings.Contains(e, "already belongs") {
		t.Errorf("second join into the same dir: %q", e)
	}

	// The list updates the client config with every member's address.
	code, out, stderr = cli("server", "list")
	if code != 0 || !regexp.MustCompile(`node-1\s+127\.0\.0\.1:\d+\s+leader\s+voting`).MatchString(out) ||
		!regexp.MustCompile(`cp-2\s+10\.0\.0\.5:7443\s+standby\s+catching up`).MatchString(out) {
		t.Fatalf("server list: %d %q %q", code, out, stderr)
	}
	if cc, err := clientconfig.Load(config); err != nil || len(cc.Servers) != 2 || !strings.HasPrefix(cc.Servers[0], "127.0.0.1:") || cc.Servers[1] != "10.0.0.5:7443" {
		t.Errorf("client config servers = %v, %v", cc.Servers, err)
	}
	// The CLI still reaches the leader with an unreachable address listed.
	if code, _, stderr := cli("node", "list"); code != 0 {
		t.Errorf("node list with two addresses: %s", stderr)
	}

	if code, _, stderr := cli("server", "remove", "node-1"); code == 0 || !strings.Contains(stderr, "leader") {
		t.Errorf("leader removed itself: %q", stderr)
	}
	if code, out, stderr := cli("server", "remove", "cp-2"); code != 0 || !strings.Contains(out, "Wipe its data directory") {
		t.Fatalf("server remove: %q %q", out, stderr)
	}
	if _, out, _ := cli("server", "list"); strings.Contains(out, "cp-2") {
		t.Errorf("removed server listed: %q", out)
	}
}

// Leadership moves to another control plane node when the leader stops,
// and only one node leads at a time.
func TestLeadFailover(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ca, _ := pki.NewCA("test")
	cfg := func(name string) etcd.Config {
		c := memberConfig(filepath.Join(t.TempDir(), name))
		c.Name, c.CA, c.Addr = name, ca, netip.MustParseAddr("127.0.0.1")
		return c
	}
	m1, err := etcd.Start(ctx, cfg("cp-1"))
	if err != nil {
		t.Fatal(err)
	}
	defer m1.Close()
	c2 := cfg("cp-2")
	_, initial, err := etcd.AddLearner(ctx, m1.Client(), "cp-2", c2.Addr, c2.PeerPort)
	if err != nil {
		t.Fatal(err)
	}
	c2.InitialCluster = initial
	m2, err := etcd.Start(ctx, c2)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	for m2.IsLearner() {
		_, _ = etcd.Promote(ctx, m1.Client())
		time.Sleep(100 * time.Millisecond)
	}

	var leaders atomic.Int32
	var mu sync.Mutex
	var order []string
	term := func(name string) func(context.Context, *etcd.Leadership) error {
		return func(ctx context.Context, _ *etcd.Leadership) error {
			if leaders.Add(1) != 1 {
				t.Error("two leaders at once")
			}
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			<-ctx.Done()
			leaders.Add(-1)
			return nil
		}
	}
	log := slog.New(slog.DiscardHandler)
	ctx1, stop1 := context.WithCancel(ctx)
	done1 := make(chan error, 1)
	go func() { done1 <- lead(ctx1, m1, "cp-1", log, noWait, term("cp-1")) }()
	// waitTerms waits until n terms have started.
	waitTerms := func(n int) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			got := len(order)
			mu.Unlock()
			if got >= n {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("term %d never started", n)
	}
	waitTerms(1)
	done2 := make(chan error, 1)
	go func() { done2 <- lead(ctx, m2, "cp-2", log, noWait, term("cp-2")) }()
	time.Sleep(500 * time.Millisecond)

	stop1()
	if err := <-done1; err != nil {
		t.Errorf("cp-1 lead: %v", err)
	}
	waitTerms(2)
	cancel()
	if err := <-done2; err != nil {
		t.Errorf("cp-2 lead: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(order, ",") != "cp-1,cp-2" {
		t.Errorf("terms = %v", order)
	}
}

func noWait(context.Context) error { return nil }

// A server whose binary knows a newer schema leads only once every server
// knows it; state from a newer binary is refused.
func TestLeadReadyDuringUpgrade(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ca, _ := pki.NewCA("test")
	c := memberConfig(filepath.Join(t.TempDir(), "cp-1"))
	c.Name, c.CA, c.Addr = "cp-1", ca, netip.MustParseAddr("127.0.0.1")
	m, err := etcd.Start(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	st, err := store.NewEtcd(ctx, m.Client(), "/armada/")
	if err != nil {
		t.Fatal(err)
	}
	cur := store.SchemaVersion()
	for _, s := range []store.Server{
		{Name: "cp-1", PrivateIP: "10.0.0.1", APIAddr: "10.0.0.1:7443", Schema: cur + 1},
		{Name: "cp-2", PrivateIP: "10.0.0.2", APIAddr: "10.0.0.2:7443"}, // older binary, no schema recorded
	} {
		if err := st.UpsertServer(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := leadReadyNow(ctx, st, cur); !ok || err != nil {
		t.Errorf("same schema: ready %v, %v", ok, err)
	}
	ok, old, err := leadReady(ctx, st, cur+1)
	if ok || err != nil || len(old) != 1 || old[0] != "cp-2" {
		t.Errorf("newer binary with an old server left: ready %v, waiting for %v, %v", ok, old, err)
	}
	if err := st.UpsertServer(ctx, store.Server{Name: "cp-2", PrivateIP: "10.0.0.2", APIAddr: "10.0.0.2:7443", Schema: cur + 1}); err != nil {
		t.Fatal(err)
	}
	if ok, err := leadReadyNow(ctx, st, cur+1); !ok || err != nil {
		t.Errorf("every server upgraded: ready %v, %v", ok, err)
	}
	if _, _, err := leadReady(ctx, st, cur-1); err == nil {
		t.Error("an older binary accepted newer state")
	}
}

func leadReadyNow(ctx context.Context, st *store.Etcd, mine int) (bool, error) {
	ok, _, err := leadReady(ctx, st, mine)
	return ok, err
}
