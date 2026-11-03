package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
)

func TestJoinEndToEnd(t *testing.T) {
	// Each agent gets its own fake runtime: the first call is the server's
	// embedded agent, the second the joined node's.
	var mu sync.Mutex
	var drivers []*fake.Driver
	orig, origWait, origCheck, origPoll, origTmpfs, origPollNode := newDriver, proxyStartWait, probeCheck, waitPoll, checkTmpfs, pollInterval
	newDriver = func(string, *agentConfig) (runtime.Driver, error) {
		mu.Lock()
		defer mu.Unlock()
		d := fake.New()
		drivers = append(drivers, d)
		return d, nil
	}
	proxyStartWait = time.Millisecond
	probeCheck = func(context.Context, string, string) error { return nil }
	waitPoll = 50 * time.Millisecond
	pollInterval = 50 * time.Millisecond
	checkTmpfs = func(string) error { return nil }
	t.Cleanup(func() {
		newDriver, proxyStartWait, probeCheck, waitPoll, checkTmpfs, pollInterval = orig, origWait, origCheck, origPoll, origTmpfs, origPollNode
	})
	count := func(i int) int {
		mu.Lock()
		defer mu.Unlock()
		if i >= len(drivers) {
			return -1
		}
		cs, _ := drivers[i].List(context.Background(), map[string]string{"armada.app": "web"})
		return len(cs)
	}

	dataDir, config, _ := initCluster(t)
	join := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	start := func(args ...string) {
		wg.Add(1)
		logs := &lockedBuffer{}
		go func() {
			defer wg.Done()
			if code := Execute(ctx, args, logs, logs); code != 0 && ctx.Err() == nil {
				t.Errorf("%s exited with %d:\n%s", args[0], code, logs.String())
			}
		}()
	}
	t.Cleanup(func() { cancel(); wg.Wait() })
	start("server", "--data-dir", dataDir, "--join-listen", join, "--secrets-dir", filepath.Join(t.TempDir(), "s1"), "--proxy", "none")

	cli := func(args ...string) (int, string, string) { return run(t, append(args, "--config", config)...) }
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", what)
	}
	waitFor("server up", func() bool { code, _, _ := cli("node", "list"); return code == 0 })

	code, out, stderr := cli("token", "create", "--ttl", "10m")
	if code != 0 {
		t.Fatalf("token create: %s", stderr)
	}
	tok := regexp.MustCompile(`Token \(shown once\): ([0-9a-f]{12}\.[0-9a-f]{64})`).FindStringSubmatch(out)
	cmdLine := regexp.MustCompile(`armada join (\S+) --ca-hash (sha256:[0-9a-f]{64})`).FindStringSubmatch(out)
	if tok == nil || cmdLine == nil || cmdLine[1] != join || strings.Contains(cmdLine[0], tok[1]) {
		t.Fatalf("token create output = %q", out)
	}
	if code, _, _ := cli("token", "create", "--ttl", "48h"); code == 0 {
		t.Error("48h token accepted")
	}

	node2 := filepath.Join(t.TempDir(), "node2")
	joinCmd := func(stdin string, extra ...string) (int, string, string) {
		var o, e bytes.Buffer
		args := append([]string{"join", cmdLine[1], "--ca-hash", cmdLine[2], "--private-ip", "10.0.0.2", "--node-name", "node-2", "--data-dir", node2}, extra...)
		c := execute(context.Background(), args, strings.NewReader(stdin), &o, &e)
		return c, o.String(), e.String()
	}
	// A wrong pin never sends the token.
	wrongPin := "sha256:" + strings.Repeat("0", 64)
	var o, e bytes.Buffer
	if c := execute(context.Background(), []string{"join", join, "--ca-hash", wrongPin, "--private-ip", "10.0.0.2", "--node-name", "node-2", "--data-dir", node2},
		strings.NewReader(tok[1]+"\n"), &o, &e); c == 0 || !strings.Contains(e.String(), "does not match the CA hash") {
		t.Errorf("wrong pin: %q", e.String())
	}
	if c, _, e := joinCmd("not-a-token\n"); c == 0 || !strings.Contains(e, "malformed") {
		t.Errorf("malformed token: %q", e)
	}
	if c, _, e := joinCmd(tok[1][:13] + strings.Repeat("0", 64) + "\n"); c == 0 || !strings.Contains(e, "invalid join token") {
		t.Errorf("wrong secret: %q", e)
	}
	code, out, stderr = joinCmd(tok[1] + "\n")
	if code != 0 || !strings.Contains(out, "Joined as node node-2") {
		t.Fatalf("join: code=%d out=%q err=%q", code, out, stderr)
	}
	if strings.Contains(out+stderr, tok[1][13:]) {
		t.Error("join printed the token secret")
	}
	// The node gets the next subnet of the cluster network as its bridge
	// subnet (ADR 0027).
	if ac, err := loadAgentConfig(node2); err != nil || ac.ContainerSubnet != "10.120.1.0/24" || !strings.Contains(out, "Container subnet: 10.120.1.0/24") {
		t.Errorf("joined node: config %+v, %v; output %q", ac, err, out)
	}
	for _, f := range []string{fileCACert, fileNodeCert, fileNodeKey, fileAgent} {
		if err := fsutil.CheckPrivate(filepath.Join(node2, f)); err != nil {
			t.Error(err)
		}
	}
	if _, err := os.Stat(filepath.Join(node2, fileCAKey)); err == nil {
		t.Error("joined node got the CA key")
	}
	if c, _, e := joinCmd(tok[1] + "\n"); c == 0 || !strings.Contains(e, "already belongs") {
		t.Errorf("second join into the same dir: %q", e)
	}

	start("agent", "--data-dir", node2, "--proxy", "none", "--secrets-dir", filepath.Join(t.TempDir(), "s2"))
	waitFor("node-2 ready", func() bool {
		_, out, _ := cli("node", "list")
		return regexp.MustCompile(`node-2\s+10\.0\.0\.2\s+ready\s`).MatchString(out) &&
			regexp.MustCompile(`node-1\s+127\.0\.0\.1\s+ready\s`).MatchString(out)
	})

	spec := filepath.Join(t.TempDir(), "web.yaml")
	if err := os.WriteFile(spec, []byte("name: web\nimage: nginx:1.27\nscale:\n  min: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := cli("deploy", "-f", spec, "--wait", "--timeout", "30s"); code != 0 {
		t.Fatalf("deploy: %s", stderr)
	}
	waitFor("spread over both nodes", func() bool { return count(0) == 1 && count(1) == 1 })

	code, out, stderr = cli("node", "remove", "node-2")
	if code != 0 || !strings.Contains(out, "Removed node node-2") {
		t.Fatalf("node remove: code=%d out=%q err=%q", code, out, stderr)
	}
	if count(0) != 2 || count(1) != 0 {
		t.Errorf("after remove: node-1 has %d, node-2 has %d", count(0), count(1))
	}
	_, out, _ = cli("node", "list")
	if strings.Contains(out, "node-2") {
		t.Errorf("node list after remove = %q", out)
	}
	// The removed node's agent stays locked out.
	time.Sleep(300 * time.Millisecond)
	if _, out, _ := cli("node", "list"); strings.Contains(out, "node-2") {
		t.Error("removed node came back")
	}

	if code, out, _ := cli("node", "cordon", "node-1"); code != 0 || !strings.Contains(out, "cordoned") {
		t.Errorf("cordon = %q", out)
	}
	if _, out, _ := cli("status"); !strings.Contains(out, "ready,cordoned") {
		t.Errorf("status does not show cordon: %q", out)
	}
	if code, _, _ := cli("node", "uncordon", "node-1"); code != 0 {
		t.Error("uncordon failed")
	}
	if code, _, stderr := cli("node", "remove", "ghost", "--force"); code == 0 || !strings.Contains(stderr, "not found") {
		t.Errorf("remove ghost: %q", stderr)
	}
}
