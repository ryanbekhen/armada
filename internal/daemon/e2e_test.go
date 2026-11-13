package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/cli"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func initCluster(t *testing.T) (dataDir, config string, port int) {
	t.Helper()
	dir := t.TempDir()
	dataDir, config = filepath.Join(dir, "data"), filepath.Join(dir, "home", "config")
	port = freePort(t)
	code, stdout, stderr := run(t, "init", "--data-dir", dataDir, "--config", config,
		"--private-ip", "127.0.0.1", "--node-name", "node-1", "--user-name", "ryan", "--port", strconv.Itoa(port))
	if code != 0 {
		t.Fatalf("init failed: %s", stderr)
	}
	if !strings.Contains(stdout, "Cluster initialized") {
		t.Errorf("init output = %q", stdout)
	}
	return dataDir, config, port
}

func TestInit(t *testing.T) {
	t.Parallel()
	dataDir, config, port := initCluster(t)

	for _, f := range []string{fileCACert, fileCAKey, fileServerCert, fileServerKey, fileNodeCert, fileNodeKey, fileAgent, fileEtcdKey} {
		if err := fsutil.CheckPrivate(filepath.Join(dataDir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	for _, p := range []string{dataDir, config, filepath.Dir(config)} {
		if err := fsutil.CheckPrivate(p); err != nil {
			t.Error(err)
		}
	}

	nodeCert, _ := os.ReadFile(filepath.Join(dataDir, fileNodeCert))
	c, err := pki.ParseCertPEM(nodeCert)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != "node:node-1" {
		t.Errorf("node CN = %q", c.Subject.CommonName)
	}
	var cfg struct {
		Servers []string `json:"servers"`
		Cert    string   `json:"cert"`
	}
	b, _ := os.ReadFile(config)
	_ = json.Unmarshal(b, &cfg)
	if len(cfg.Servers) != 1 || cfg.Servers[0] != "127.0.0.1:"+strconv.Itoa(port) {
		t.Errorf("client config servers = %q", cfg.Servers)
	}
	admin, _ := pki.ParseCertPEM([]byte(cfg.Cert))
	if admin.Subject.CommonName != "user:ryan" {
		t.Errorf("user CN = %q", admin.Subject.CommonName)
	}
	// The first node gets the first subnet of the cluster network
	// (ADR 0025) as its bridge subnet.
	ac, err := loadAgentConfig(dataDir)
	if err != nil || ac.ContainerSubnet != "10.120.0.0/24" || ac.Network != "plain" {
		t.Errorf("agent container subnet = %+v, %v", ac, err)
	}

	// A second init must not overwrite the CA.
	code, _, stderr := run(t, "init", "--data-dir", dataDir, "--config", config+"2", "--private-ip", "127.0.0.1")
	if code == 0 || !strings.Contains(stderr, "already initialized") {
		t.Errorf("re-init: code=%d stderr=%q", code, stderr)
	}
}

func TestInitWireGuard(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	code, out, stderr := run(t, "init", "--data-dir", dataDir, "--config", filepath.Join(dir, "home", "config"), "--private-ip", "10.0.0.1", "--network", "wireguard")
	if code != 0 || !strings.Contains(out, "network:     wireguard, 10.120.0.0/16") {
		t.Fatalf("init: %d %q %q", code, out, stderr)
	}
	if ac, err := loadAgentConfig(dataDir); err != nil || ac.Network != "wireguard" {
		t.Errorf("agent config %+v, %v", ac, err)
	}
}

func TestInitRejectsUnsafeInput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := []string{"init", "--data-dir", filepath.Join(dir, "d"), "--config", filepath.Join(dir, "c")}

	tests := map[string][]string{
		"public IP":      {"--private-ip", "8.8.8.8"},
		"unspecified IP": {"--private-ip", "0.0.0.0"},
		"bad port":       {"--private-ip", "10.0.0.1", "--port", "0"},
		"bad node name":  {"--private-ip", "10.0.0.1", "--node-name", "a b"},
		"public CIDR":    {"--private-ip", "10.0.0.1", "--cluster-cidr", "203.0.112.0/20"},
		"huge CIDR":      {"--private-ip", "10.0.0.1", "--cluster-cidr", "10.0.0.0/8"},
		"CIDR with IP":   {"--private-ip", "10.120.3.4", "--cluster-cidr", "10.120.0.0/16"},
		"subnet flag":    {"--private-ip", "10.0.0.1", "--container-subnet", "10.50.0.0/24"},
		"unknown mode":   {"--private-ip", "10.0.0.1", "--network", "ipsec"},
	}
	for name, extra := range tests {
		if code, _, _ := run(t, append(base, extra...)...); code == 0 {
			t.Errorf("%s accepted", name)
		}
	}

	loose := filepath.Join(dir, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(loose, 0o755)
	code, _, stderr := run(t, "init", "--data-dir", loose, "--config", filepath.Join(dir, "c2"), "--private-ip", "10.0.0.1")
	if code == 0 || !strings.Contains(stderr, "insecure permissions") {
		t.Errorf("world-readable data dir: code=%d stderr=%q", code, stderr)
	}

	existing := filepath.Join(dir, "existing-config")
	_ = os.WriteFile(existing, []byte("{}"), 0o600)
	code, _, stderr = run(t, "init", "--data-dir", filepath.Join(dir, "d3"), "--config", existing, "--private-ip", "10.0.0.1")
	if code == 0 || !strings.Contains(stderr, "already exists") {
		t.Errorf("existing client config: code=%d stderr=%q", code, stderr)
	}
}

func TestSanitizeName(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"Node-1.example.com": "node-1", "my_host": "my-host", "": "fb", "---": "fb",
		strings.Repeat("a", 70): strings.Repeat("a", 63), "Ryan Bekhen": "ryan-bekhen",
	} {
		if got := sanitizeName(in, "fb"); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEndToEnd runs init, server (with an embedded agent on a fake runtime),
// and the app commands through the real CLI entry point. It swaps the
// package-level driver factory, so it must not run in parallel.
func TestEndToEnd(t *testing.T) {
	d := fake.New()
	// Containers on the node's subnet of the cluster network, past its
	// gateway: 10.120.0.11, 10.120.0.12, ...
	d.BridgeIPs = "10.120.0.1"
	d.LogLines = []runtime.LogFrame{{Stream: runtime.Stdout, Data: []byte("listening on :80\n")}, {Stream: runtime.Stderr, Data: []byte("deprecated flag\n")}}
	orig, origWait, origCheck, origTmpfs, origUsage := newDriver, proxyStartWait, probeCheck, checkTmpfs, usageInterval
	newDriver = func(string, *agentConfig) (runtime.Driver, error) { return d, nil }
	proxyStartWait = time.Millisecond
	probeCheck = func(context.Context, string, string) error { return nil }
	t.Cleanup(cli.SetPollIntervals(50*time.Millisecond, 2*time.Second))
	checkTmpfs = func(string) error { return nil } // a temp dir stands in for tmpfs
	usageInterval = 20 * time.Millisecond
	t.Cleanup(func() {
		newDriver, proxyStartWait, probeCheck, checkTmpfs, usageInterval = orig, origWait, origCheck, origTmpfs, origUsage
	})
	secretsDir := filepath.Join(t.TempDir(), "secrets")

	dataDir, config, _ := initCluster(t)
	acme, join, metrics := freeAddr(t), freeAddr(t), freeAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	serverLog := &lockedBuffer{}
	go func() {
		// Never the production ACME endpoint in tests.
		done <- Execute(ctx, []string{"server", "--data-dir", dataDir, "--acme-ca", "letsencrypt-staging", "--acme-listen", acme,
			"--secrets-dir", secretsDir, "--log-format", "json", "--verbose", "--join-listen", join, "--metrics-listen", metrics}, serverLog, serverLog)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case code := <-done:
			if code != 0 {
				t.Errorf("server exited with %d:\n%s", code, serverLog.String())
			}
		case <-time.After(10 * time.Second):
			t.Error("server did not shut down")
		}
	})

	cli := func(args ...string) (int, string, string) {
		return run(t, append(args, "--config", config)...)
	}
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

	waitFor("node ready", func() bool {
		code, out, _ := cli("node", "list")
		return code == 0 && strings.Contains(out, "node-1") && strings.Contains(out, "ready")
	})
	// The agent applies the cluster network, with itself as the only peer.
	waitFor("cluster network", func() bool {
		n := testNets.get("node-1").applied()
		return n != nil && n.GetMode() == "plain" && n.GetClusterCidr() == "10.120.0.0/16" &&
			len(n.GetPeers()) == 1 && n.GetPeers()[0].GetSubnet() == "10.120.0.0/24"
	})
	// Network isolation of the default space reaches the node (ADR 0026).
	if code, out, stderr := cli("space", "set", "default", "--network-isolation"); code != 0 || !strings.Contains(out, "network isolation on") {
		t.Fatalf("space set: code=%d out=%q err=%q", code, out, stderr)
	}
	waitFor("isolated default", func() bool { return testNets.get("node-1").applied().GetIsolateDefault() })
	if code, out, _ := cli("space", "list"); code != 0 || !regexp.MustCompile(`default\s+0\s+isolated\s`).MatchString(out) {
		t.Errorf("space list:\n%s", out)
	}
	if code, _, stderr := cli("space", "set", "default"); code == 0 || !strings.Contains(stderr, "nothing to change") {
		t.Errorf("space set without a flag: %d %q", code, stderr)
	}
	if code, _, _ := cli("space", "set", "default", "--network-isolation=false"); code != 0 {
		t.Error("turning default isolation off failed")
	}

	spec := filepath.Join(t.TempDir(), "web.yaml")
	if err := os.WriteFile(spec, []byte("name: web\nimage: nginx:1.27\ningress:\n  type: external\n  port: 80\nscale:\n  min: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := cli("app", "create", "--file", spec)
	if code != 0 || out != "Created web (revision web--r1).\n" {
		t.Fatalf("app create: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := cli("app", "create", "--file", spec); code == 0 || !strings.Contains(stderr, "web exists") {
		t.Errorf("app create twice: code=%d err=%q", code, stderr)
	}
	waitFor("2/2 ready", func() bool {
		_, out, _ := cli("app", "show", "web")
		return strings.Contains(out, "2/2")
	})
	if code, out, _ := cli("app", "list"); code != 0 || !regexp.MustCompile(`^NAME\s+READY\s+STATE\s+REVISION\s+IMAGE\s+URL\nweb\s+2/2\s+ready\s+web--r1\s+nginx:1.27\s+-\n$`).MatchString(out) {
		t.Errorf("app list = %q", out)
	}
	if code, out, _ := cli("cluster", "status"); code != 0 || !strings.HasPrefix(out, "nodes 1/1 ready · apps 1 · ready 1 · rolling out 0 · failing 0 · jobs 0\n") {
		t.Errorf("cluster status = %q", out)
	}

	code, out, _ = cli("app", "show", "web", "-o", "json")
	if code != 0 {
		t.Fatal("app show -o json failed")
	}
	var st struct {
		Name     string `json:"name"`
		Replicas []struct {
			Address string `json:"address"`
		} `json:"replicas"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil || st.Name != "web" || len(st.Replicas) != 2 {
		t.Fatalf("app show json = %s (%v)", out, err)
	}
	// Replicas publish no port: they are reached at their own address in
	// the node's subnet, on the app's port (ADR 0025).
	if a := st.Replicas[0].Address; !strings.HasPrefix(a, "10.120.0.1") || !strings.HasSuffix(a, ":80") {
		t.Errorf("replica address = %q", a)
	}

	if code, out, stderr := cli("app", "scale", "web", "--replicas", "3"); code != 0 || out != "Scaled web to 3 replicas.\n" {
		t.Fatalf("scale: %q %s", out, stderr)
	}
	waitFor("3/3 ready", func() bool {
		_, out, _ := cli("app", "show", "web")
		return strings.Contains(out, "3/3")
	})

	code, out, stderr = cli("app", "logs", "web", "--tail", "5")
	if code != 0 || !strings.Contains(out, "| listening on :80") || !strings.Contains(stderr, "| deprecated flag") {
		t.Errorf("logs: code=%d out=%q err=%q", code, out, stderr)
	}

	// Exec: stdin, separate streams, and the command's exit code (the fake
	// runtime echoes stdin, writes the command name to stderr, and exits
	// with the argument count).
	var execOut, execErr bytes.Buffer
	code = execute(context.Background(), []string{"app", "exec", "web", "-i", "--config", config, "--", "cat", "a", "b"}, strings.NewReader("ping"), &execOut, &execErr)
	if code != 2 || execOut.String() != "ping" || execErr.String() != "cat" {
		t.Errorf("exec: code=%d out=%q err=%q", code, execOut.String(), execErr.String())
	}
	if code, out, stderr := run(t, "app", "exec", "web", "--config", config, "--", "true"); code != 0 || out != "" || stderr != "true" {
		t.Errorf("exec true: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := run(t, "app", "exec", "web", "-t", "--config", config, "--", "sh"); code != 1 || !strings.Contains(stderr, "needs a terminal") {
		t.Errorf("exec -t without a terminal: code=%d err=%q", code, stderr)
	}
	// --container reaches the replica's agent, which knows its sidecars
	// (ADR 0038); web has none.
	if code, _, stderr := run(t, "app", "exec", "web", "--container", "log", "--config", config, "--", "sh"); code != 1 || !strings.Contains(stderr, "no running sidecar log") {
		t.Errorf("exec --container: code=%d err=%q", code, stderr)
	}
	if code, out, stderr := cli("app", "logs", "web", "--container", "log"); code != 0 || !strings.Contains(out+stderr, "has no container log") {
		t.Errorf("logs --container: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := run(t, "app", "exec", "ghost", "--config", config, "--", "sh"); code != 1 || !strings.Contains(stderr, "not found") {
		t.Errorf("exec in a missing app: code=%d err=%q", code, stderr)
	}

	// Top: usage the fake runtime reports, per app, replica, and node.
	cs, _ := d.List(context.Background(), map[string]string{runtime.LabelApp: "web"})
	for _, c := range cs {
		d.SetUsage(c.Labels[runtime.LabelReplica], runtime.Stats{MemoryBytes: 30 << 20})
	}
	waitFor("top measures web", func() bool {
		code, out, _ := cli("app", "top")
		return code == 0 && strings.Contains(out, fmt.Sprintf("%d/%d", len(cs), len(cs))) && strings.Contains(out, fmt.Sprintf("%dMi/", 30*len(cs)))
	})
	if code, out, stderr := cli("app", "top", "web"); code != 0 || !strings.Contains(out, "REPLICA") || !strings.Contains(out, "0m/100m") || !strings.Contains(out, "30Mi/256Mi") {
		t.Errorf("top web: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, out, stderr := cli("node", "top"); code != 0 || !strings.Contains(out, "NODE") || !strings.Contains(out, fmt.Sprintf("%dMi ", 30*len(cs))) {
		t.Errorf("node top: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, out, _ := cli("app", "top", "-o", "json"); code != 0 || !regexp.MustCompile(`"measured":\s+true`).MatchString(out) {
		t.Errorf("app top -o json: code=%d out=%q", code, out)
	}
	if code, out, stderr := cli("app", "top", "--spaces"); code != 0 || !strings.Contains(out, "SPACE") || !strings.Contains(out, "default") {
		t.Errorf("app top --spaces: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := cli("app", "top", "web", "--spaces"); code != 1 || !strings.Contains(stderr, "--spaces") {
		t.Errorf("app top web --spaces: code=%d err=%q", code, stderr)
	}
	if code, _, stderr := cli("app", "top", "ghost"); code != 1 || !strings.Contains(stderr, "not found") {
		t.Errorf("app top ghost: code=%d err=%q", code, stderr)
	}

	// Events: what the cluster did, filtered, as text or JSON lines.
	if code, out, stderr := cli("app", "events", "web"); code != 0 || !strings.Contains(out, "REASON") || !strings.Contains(out, "Scheduled") || strings.Contains(out, " node ") {
		t.Errorf("app events web: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, out, _ := cli("app", "events"); code != 0 || !strings.Contains(out, "Scheduled") || strings.Contains(out, "Connected") {
		t.Errorf("app events: code=%d out=%q", code, out)
	}
	if code, out, _ := cli("cluster", "events", "-o", "json", "--since", "10m"); code != 0 || !strings.Contains(out, `"reason":"Connected"`) {
		t.Errorf("cluster events -o json: code=%d out=%q", code, out)
	}
	if code, _, stderr := cli("cluster", "events", "--since", "48h"); code != 1 || !strings.Contains(stderr, "--since") {
		t.Errorf("cluster events --since 48h: code=%d err=%q", code, stderr)
	}
	if code, out, _ := cli("app", "events", "ghost"); code != 0 || strings.Count(out, "\n") != 1 || !strings.Contains(out, "REASON") {
		t.Errorf("app events ghost: code=%d out=%q", code, out)
	}

	// Jobs: deploy, run to completion, inspect, read logs, delete.
	jobFile := filepath.Join(t.TempDir(), "job.yaml")
	if err := os.WriteFile(jobFile, []byte("kind: job\nname: report\nimage: busybox:1\nschedule: \"0 3 * * *\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := cli("app", "create", "--file", jobFile); code == 0 || !strings.Contains(stderr, "armada job create") {
		t.Errorf("app create with a job: code=%d err=%q", code, stderr)
	}
	if code, out, stderr := cli("job", "create", "--file", jobFile); code != 0 || out != "Created report (revision report--r1).\n" {
		t.Fatalf("job create: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, out, stderr := cli("job", "show", "report", "-o", "yaml"); code != 0 || !strings.Contains(out, "kind: job") || !strings.Contains(out, "schedule: 0 3 * * *") {
		t.Errorf("job show -o yaml: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, out, stderr := cli("job", "update", "report", "--retries", "2"); code != 0 || out != "Updated report (revision report--r2).\n" {
		t.Errorf("job update: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, out, stderr := cli("job", "run", "report"); code != 0 || !strings.Contains(out, "Started run 1 of report") {
		t.Fatalf("job run: code=%d out=%q err=%q", code, out, stderr)
	}
	waitFor("job container", func() bool {
		cs, _ := d.List(context.Background(), map[string]string{runtime.LabelApp: "report"})
		if len(cs) != 1 || cs[0].State != runtime.StateRunning {
			return false
		}
		d.SetState(cs[0].ID, runtime.StateExited, 0)
		return true
	})
	waitFor("run succeeded", func() bool {
		code, out, _ := cli("job", "run", "list", "report")
		return code == 0 && strings.Contains(out, "succeeded") && strings.Contains(out, "manual")
	})
	if code, out, stderr := cli("job", "ls"); code != 0 || !strings.Contains(out, "0 3 * * *") || !strings.Contains(out, "succeeded") || !strings.Contains(out, "in ") {
		t.Errorf("job ls: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, out, stderr := cli("job", "show", "report"); code != 0 || !strings.Contains(out, "succeeded") || !strings.Contains(out, "report--r2") {
		t.Errorf("job show: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, out, stderr := cli("job", "logs", "report"); code != 0 || !strings.Contains(out, "listening on :80") {
		t.Errorf("job logs: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := cli("job", "logs", "web", "--run", "1"); code != 1 || !strings.Contains(stderr, "for jobs") {
		t.Errorf("job logs --run on an app: code=%d err=%q", code, stderr)
	}
	if code, _, stderr := cli("job", "run", "web"); code != 1 || !strings.Contains(stderr, "not a job") {
		t.Errorf("job run on an app: code=%d err=%q", code, stderr)
	}
	if code, out, stderr := cli("job", "cancel", "report"); code != 0 || !strings.Contains(out, "no active runs") {
		t.Errorf("job cancel: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, out, stderr := cli("job", "rm", "report"); code != 0 || !strings.Contains(out, "Deleted job report") {
		t.Errorf("job rm: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := cli("job", "run", "list", "report"); code != 1 || !strings.Contains(stderr, "not found") {
		t.Errorf("job run list after rm: code=%d err=%q", code, stderr)
	}

	// Metrics: credentials that only scrape, written with private modes.
	credDir := filepath.Join(t.TempDir(), "prom")
	if code, out, stderr := cli("metrics", "credentials", "prom", "-o", credDir); code != 0 || !strings.Contains(out, "metrics:prom") {
		t.Fatalf("metrics credentials: code=%d out=%q err=%q", code, out, stderr)
	}
	if fi, err := os.Stat(credDir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("credentials directory: %v %v", fi, err)
	}
	pems := map[string][]byte{}
	for _, f := range []string{"ca.pem", "cert.pem", "key.pem"} {
		p := filepath.Join(credDir, f)
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, fi, err)
		}
		pems[f], _ = os.ReadFile(p)
	}
	if code, _, stderr := cli("metrics", "credentials", "prom", "-o", credDir); code != 1 || !strings.Contains(stderr, "already exists") {
		t.Errorf("credentials into an existing directory: code=%d err=%q", code, stderr)
	}
	if code, _, stderr := cli("metrics", "credentials", "../x"); code != 1 || !strings.Contains(stderr, "invalid name") {
		t.Errorf("credentials with a bad name: code=%d err=%q", code, stderr)
	}
	mtls, err := pki.ClientTLS(pems["ca.pem"], pems["cert.pem"], pems["key.pem"])
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: mtls}, Timeout: 5 * time.Second}
	waitFor("metrics endpoint", func() bool {
		resp, err := hc.Get("https://" + metrics + "/metrics")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode == http.StatusOK && strings.Contains(string(b), `armada_app_replicas_ready{app="web"}`)
	})

	// Ingress: HAProxy is started by the embedded agent and routes
	// <app>.<root> once a root domain is set.
	if code, out, stderr := cli("cluster", "set", "--root-domain", "apps.example.org"); code != 0 || !strings.Contains(out, "apps.example.org") {
		t.Fatalf("cluster set: %q %q", out, stderr)
	}
	if code, out, _ := cli("cluster", "show"); code != 0 || !strings.Contains(out, "root domain:       apps.example.org") {
		t.Errorf("cluster show = %q", out)
	}
	// The server's flags became the cluster's settings (ADR 0031), and a
	// change applies through a restart of the leader's term, keeping the
	// API and the agents.
	_, out, _ = cli("cluster", "show")
	if !strings.Contains(out, "certificates:      on, letsencrypt-staging") || !strings.Contains(out, "metrics:           port ") {
		t.Errorf("cluster show after adopting the flags = %q", out)
	}
	if code, _, stderr := cli("cluster", "set", "--node-lost-timeout", "2m"); code != 0 {
		t.Fatalf("cluster set --node-lost-timeout: %s", stderr)
	}
	// cluster set waited for the restarted API: the next command works.
	if code, _, stderr := cli("app", "show", "web"); code != 0 {
		t.Errorf("app show right after cluster set: %s", stderr)
	}
	if !strings.Contains(serverLog.String(), "cluster settings changed; applying them") {
		t.Error("the leader did not restart its term")
	}
	if _, out, _ := cli("cluster", "show"); !strings.Contains(out, "node lost timeout: 2m0s") {
		t.Errorf("cluster show after the restart = %q", out)
	}
	// Alerts (ADR 0045): a channel from a URL file, a test notice, and the
	// list, which never shows the URL.
	var hooks atomic.Int32
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hooks.Add(1) }))
	defer hook.Close()
	urlFile := filepath.Join(t.TempDir(), "hook-url")
	if err := os.WriteFile(urlFile, []byte(hook.URL+"/secret-path\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, stderr := cli("alert", "channel", "create", "ops", "--type", "webhook", "--url", urlFile); code != 0 || !strings.Contains(out, "armada alert test ops") {
		t.Errorf("alert channel create: %q %q", out, stderr)
	}
	if code, out, stderr := cli("alert", "test", "ops"); code != 0 || hooks.Load() != 1 {
		t.Errorf("alert test: %q %q", out, stderr)
	}
	if _, out, _ := cli("alert", "channel", "list"); !strings.Contains(out, "ops") || !strings.Contains(out, "warnings") || strings.Contains(out, "secret-path") {
		t.Errorf("alert channel list: %q", out)
	}
	if code, _, stderr := cli("alert", "channel", "update", "ops", "--reason", "Lost,Crashed", "--space", "default"); code != 0 {
		t.Errorf("alert channel update: %q", stderr)
	}
	if code, _, stderr := cli("alert", "channel", "create", "tg", "--type", "telegram", "--token", urlFile); code == 0 || !strings.Contains(stderr, "chat-id") {
		t.Errorf("telegram without a chat: %q", stderr)
	}
	if code, _, stderr := cli("alert", "channel", "delete", "ops"); code != 0 {
		t.Errorf("alert channel delete: %q", stderr)
	}
	waitFor("haproxy routes web", func() bool {
		maps, err := filepath.Glob(filepath.Join(dataDir, dirHAProxy, "etc", "routes-*.map"))
		if err != nil {
			return false
		}
		for _, m := range maps {
			if b, err := os.ReadFile(m); err == nil && strings.Contains(string(b), "web.apps.example.org be_web\n") {
				return true
			}
		}
		return false
	})
	if sys := d.SystemSpecs(); len(sys) == 0 || sys[0].Name != "armada-haproxy" {
		t.Errorf("HAProxy system container not started: %+v", sys)
	}
	waitFor("status shows URL", func() bool {
		_, out, _ := cli("app", "show", "web")
		return strings.Contains(out, "https://web.apps.example.org/")
	})
	if code, out, _ := cli("domain", "list"); code != 0 || out != "DOMAIN  APPS  VERIFIED  TLS\n" {
		t.Errorf("domain list = %q", out)
	}
	if err := os.WriteFile(spec, []byte("name: web\nimage: nginx:1.27\ningress:\n  type: external\n  port: 80\n  domains: [example.org]\nscale:\n  min: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// --diff shows the new domain (and the replica count the file sets
	// again) and changes nothing.
	if code, out, _ := cli("app", "update", "web", "--file", spec, "--diff"); code != 0 || !regexp.MustCompile(`(?m)^\+ .*example\.org$`).MatchString(out) {
		t.Errorf("app update --diff = %q", out)
	}
	if _, out, _ := cli("app", "show", "web"); !regexp.MustCompile(`Revision:\s+web--r1`).MatchString(out) {
		t.Errorf("--diff changed the app: %q", out)
	}
	if code, out, stderr := cli("app", "update", "web", "--file", spec); code != 0 || out != "Updated web (revision web--r2).\n" {
		t.Fatalf("app update with domain: %q %s", out, stderr)
	}
	code, out, stderr = cli("domain", "list", "--app", "web")
	if code != 0 || !strings.Contains(out, "example.org") || !strings.Contains(stderr, "TXT  _armada-verify.example.org") {
		t.Errorf("domain list = %q %q", out, stderr)
	}
	if code, _, stderr := cli("domain", "verify", "ghost.id"); code == 0 || !strings.Contains(stderr, "not found") {
		t.Errorf("domain verify ghost: %q", stderr)
	}
	if code, _, stderr := cli("cluster", "set", "--root-domain", "bad domain"); code == 0 || !strings.Contains(stderr, "root domain") {
		t.Errorf("invalid root domain accepted: %q", stderr)
	}

	// Rolling update: the domain deploy above is revision 2; wait for it.
	code, out, stderr = cli("app", "update", "web", "--file", spec, "--wait", "--timeout", "1m")
	if code != 0 || !strings.Contains(out, "web is unchanged (revision web--r2).") || !strings.Contains(out, "web--r2 is live (3/3 ready)") {
		t.Fatalf("app update --wait: code=%d out=%q err=%q", code, out, stderr)
	}
	code, out, _ = cli("app", "revision", "list", "web")
	if code != 0 || !regexp.MustCompile(`web--r2\s+active\s`).MatchString(out) || !strings.Contains(out, "web--r1") {
		t.Errorf("revision list = %q", out)
	}
	if code, out, _ := cli("app", "revision", "show", "web--r1"); code != 0 || !regexp.MustCompile(`Image:\s+nginx:1.27`).MatchString(out) {
		t.Errorf("revision show = %q", out)
	}
	code, out, stderr = cli("app", "rollback", "web", "--wait", "--timeout", "1m")
	if code != 0 || !strings.Contains(out, "Rolling web back to web--r1.") || !strings.Contains(out, "web--r1 is live (3/3 ready)") {
		t.Fatalf("rollback --wait: code=%d out=%q err=%q", code, out, stderr)
	}
	if _, out, _ := cli("app", "show", "web"); !regexp.MustCompile(`Revision:\s+web--r1`).MatchString(out) || !strings.Contains(out, "3/3") {
		t.Errorf("app show after rollback = %q", out)
	}
	if code, _, stderr := cli("app", "rollback", "web", "--to", "web--r99"); code == 0 || !strings.Contains(stderr, "not found") {
		t.Errorf("rollback to unknown revision: %q", stderr)
	}

	testSecrets(t, d, cli, config, dataDir, secretsDir, serverLog)
	testEnvFrom(t, d, cli, config)
	testExport(t, cli)

	// Errors from the server come back without gRPC noise.
	code, _, stderr = cli("app", "scale", "ghost", "--replicas", "2")
	if code == 0 || !strings.Contains(stderr, "app ghost: not found") || strings.Contains(stderr, "rpc error") {
		t.Errorf("scale ghost: code=%d stderr=%q", code, stderr)
	}
	code, _, stderr = cli("app", "create", "--file", "-")
	if code == 0 || !strings.Contains(stderr, "empty") {
		t.Errorf("app create from empty stdin: code=%d stderr=%q", code, stderr)
	}
	for _, args := range [][]string{{"app", "scale", "web", "--replicas", "zero"}, {"app", "scale", "web", "--replicas", "0"}, {"app", "list", "-o", "yaml"},
		{"app", "create"}, {"app", "update", "web"}, {"app", "create", "x", "--image", "nginx:1", "--file", spec}} {
		if code, _, _ := cli(args...); code == 0 {
			t.Errorf("%v accepted", args)
		}
	}

	testSpaces(t, d, cli, waitFor)
	// Client address rules with names show in app show (ADR 0035).
	if code, _, stderr := cli("app", "update", "web", "--ip-allow", "203.0.113.0/24,name=office,description=the VPN the admins use", "--ip-allow", "198.51.100.7"); code != 0 {
		t.Fatalf("ip rules: %s", stderr)
	}
	waitFor("rules in app show", func() bool {
		_, out, _ := cli("app", "show", "web")
		return regexp.MustCompile(`(?m)^Allowed from:\s+203\.0\.113\.0/24  office: the VPN the admins use\n\s+198\.51\.100\.7\n`).MatchString(out)
	})
	if code, _, stderr := cli("app", "update", "web", "--no-ip-rules"); code != 0 {
		t.Fatalf("no ip rules: %s", stderr)
	}
}

// testExport copies an app through its exported spec (ADR 0032): show -o
// yaml prints a file that create --file takes, and the copy runs the same
// spec.
func testExport(t *testing.T, cli func(...string) (int, string, string)) {
	t.Helper()
	if code, _, stderr := cli("app", "create", "hello", "--image", "traefik/whoami:v1.10", "--port", "80", "--ingress", "internal",
		"--replicas", "2", "--env", "GREETING=hi", "--health-path", "/health"); code != 0 {
		t.Fatalf("app create from flags: %s", stderr)
	}
	if code, _, stderr := cli("app", "update", "hello", "--replicas", "1"); code != 0 {
		t.Fatalf("app update: %s", stderr)
	}
	code, exported, stderr := cli("app", "show", "hello", "-o", "yaml")
	if code != 0 || !strings.Contains(exported, "name: hello\n") || !strings.Contains(exported, "GREETING") || !strings.Contains(exported, "path: /health") {
		t.Fatalf("app show -o yaml: %d %q %q", code, exported, stderr)
	}
	file := filepath.Join(t.TempDir(), "copy.yaml")
	if err := os.WriteFile(file, []byte(strings.Replace(exported, "name: hello\n", "name: hello-copy\n", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, stderr := cli("app", "create", "--file", file); code != 0 || out != "Created hello-copy (revision hello-copy--r1).\n" {
		t.Fatalf("app create from the export: %d %q %q", code, out, stderr)
	}
	_, copied, _ := cli("app", "show", "hello-copy", "-o", "yaml")
	if strings.Replace(copied, "name: hello-copy\n", "name: hello\n", 1) != exported {
		t.Errorf("the copy runs another spec:\n%s\nwant\n%s", copied, exported)
	}
	if code, out, _ := cli("app", "update", "hello-copy", "--file", file, "--diff"); code != 0 || out != "No changes.\n" {
		t.Errorf("diff against the export = %q", out)
	}
	for _, app := range []string{"hello", "hello-copy"} {
		if code, _, stderr := cli("app", "delete", app, "--yes"); code != 0 {
			t.Errorf("app delete %s: %s", app, stderr)
		}
	}
}

// testSpaces runs an app of the same name in another space (ADR 0026).
func testSpaces(t *testing.T, d *fake.Driver, cli func(...string) (int, string, string), waitFor func(string, func() bool)) {
	t.Helper()
	spec := filepath.Join(t.TempDir(), "web.yaml")
	if err := os.WriteFile(spec, []byte("name: web\nimage: nginx:1.28\ningress:\n  type: internal\n  port: 80\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := cli("app", "create", "--file", spec, "--space", "staging"); code == 0 || !strings.Contains(stderr, "space staging does not exist") {
		t.Fatalf("create in a missing space: code=%d err=%q", code, stderr)
	}
	if code, _, stderr := cli("space", "use", "staging"); code == 0 || !strings.Contains(stderr, "space staging not found") {
		t.Errorf("space use of a missing space: code=%d err=%q", code, stderr)
	}
	if code, out, stderr := cli("space", "create", "staging"); code != 0 || out != "Created space staging.\n" {
		t.Fatalf("space create: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := cli("space", "create", "staging"); code == 0 || !strings.Contains(stderr, "already exists") {
		t.Errorf("space create twice: %q", stderr)
	}
	code, out, stderr := cli("app", "create", "--file", spec, "--space", "staging")
	if code != 0 || out != "Created web.staging (revision web.staging--r1).\n" {
		t.Fatalf("create in staging: code=%d out=%q err=%q", code, out, stderr)
	}
	waitFor("web.staging ready", func() bool {
		_, out, _ := cli("app", "show", "web", "--space", "staging")
		return regexp.MustCompile(`Revision:\s+web\.staging--r1\n`).MatchString(out) && strings.Contains(out, "1/1")
	})
	// The default space's web is untouched, and listings follow --space.
	_, out, _ = cli("app", "list", "--space", "staging")
	if !regexp.MustCompile(`\nweb\s+1/1\s+ready\s+web\.staging--r1\s`).MatchString(out) || strings.Contains(out, "web--r1") {
		t.Errorf("app list --space staging = %q", out)
	}
	_, out, _ = cli("app", "list", "--space", "default")
	if strings.Contains(out, "web.staging") || !regexp.MustCompile(`\nweb\s+3/3\s+ready\s+web--r1\s`).MatchString(out) {
		t.Errorf("app list --space default = %q", out)
	}
	_, out, _ = cli("app", "list", "-A")
	if !regexp.MustCompile(`\ndefault\s+web\s+3/3`).MatchString(out) || !regexp.MustCompile(`\nstaging\s+web\s+1/1`).MatchString(out) {
		t.Errorf("app list -A = %q", out)
	}
	if code, _, stderr := cli("app", "scale", "web.staging", "--replicas", "2"); code != 0 {
		t.Fatalf("scale by ID: %s", stderr)
	}
	waitFor("web.staging 2/2", func() bool {
		_, out, _ := cli("app", "show", "web.staging")
		return strings.Contains(out, "2/2")
	})
	_, out, _ = cli("space", "list")
	if !regexp.MustCompile(`default\s+[1-9]\s`).MatchString(out) || !regexp.MustCompile(`staging\s+1\s+isolated\s`).MatchString(out) {
		t.Errorf("space list = %q", out)
	}
	if code, _, stderr := cli("space", "delete", "staging"); code == 0 || !strings.Contains(stderr, "apps (web.staging)") {
		t.Errorf("delete a space with apps: %q", stderr)
	}
	for _, args := range [][]string{
		{"app", "show", "web.staging", "--space", "prod"},
		{"app", "show", "web.default"},
		{"app", "show", "web", "--space", "Bad"},
		{"space", "delete", "default"},
		{"space", "create", "a.b"},
	} {
		if code, _, _ := cli(args...); code == 0 {
			t.Errorf("%v accepted", args)
		}
	}

	// A service with admin in staging manages staging and nothing else.
	if code, out, stderr := cli("rbac", "service", "create", "portal", "--role", "admin", "--space", "staging"); code != 0 || !strings.Contains(out, "Created service portal (admin in staging)") {
		t.Fatalf("service create: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := cli("rbac", "service", "create", "portal"); code == 0 || !strings.Contains(stderr, "exists") {
		t.Errorf("service create twice: code=%d err=%q", code, stderr)
	}
	if code, out, stderr := cli("rbac", "assignment", "create", "--service", "portal", "--role", "space-creator"); code != 0 || !strings.Contains(out, "space-creator, admin in staging") {
		t.Errorf("assignment create: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := cli("rbac", "assignment", "create", "--service", "portal", "--role", "deployer"); code == 0 || !strings.Contains(stderr, "one space") {
		t.Errorf("deployer without a space: code=%d err=%q", code, stderr)
	}
	toolConfig := filepath.Join(t.TempDir(), "portal.json")
	if code, out, stderr := cli("rbac", "service", "credentials", "portal", "-o", toolConfig); code != 0 || !strings.Contains(out, "Wrote "+toolConfig) {
		t.Fatalf("service credentials: code=%d out=%q err=%q", code, out, stderr)
	}
	if fi, err := os.Stat(toolConfig); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("tool config: %v %v", fi, err)
	}
	if code, _, stderr := cli("rbac", "service", "credentials", "portal", "-o", toolConfig); code == 0 || !strings.Contains(stderr, "already exists") {
		t.Errorf("credentials over an existing file: %q", stderr)
	}
	tool := func(args ...string) (int, string, string) {
		return run(t, append(args, "--config", toolConfig)...)
	}
	if code, _, stderr := tool("app", "scale", "web", "--replicas", "1", "--space", "staging"); code != 0 {
		t.Errorf("tool scales its app: %s", stderr)
	}
	_, out, _ = tool("app", "list", "-A")
	if !regexp.MustCompile(`\nstaging\s+web\s`).MatchString(out) || strings.Contains(out, "default") {
		t.Errorf("tool app list shows more than its spaces: %q", out)
	}
	for _, args := range [][]string{
		{"app", "scale", "web", "--replicas", "2"}, // the default space
		{"app", "list"},             // the default space
		{"node", "drain", "node-1"}, // the cluster
		{"node", "join-token"},      // joining nodes
		{"cluster", "status"},       // the cluster
		{"rbac", "assignment", "create", "--service", "portal", "--role", "cluster-admin"}, // its own roles
		{"app", "logs", "web"},
	} {
		if code, _, stderr := tool(args...); code == 0 || !strings.Contains(stderr, "may not") {
			t.Errorf("tool %v: code=%d err=%q", args, code, stderr)
		}
	}
	if code, _, stderr := tool("space", "create", "preview-1"); code != 0 {
		t.Errorf("tool creates a space: %s", stderr)
	}
	if _, out, _ := tool("space", "list"); !strings.Contains(out, "preview-1") || !strings.Contains(out, "staging") || strings.Contains(out, "default") {
		t.Errorf("tool space list = %q", out)
	}
	if code, out, stderr := tool("rbac", "service", "renew"); code != 0 || !strings.Contains(out, "Renewed service:portal") {
		t.Errorf("renew: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := tool("app", "show", "web", "--space", "staging"); code != 0 {
		t.Errorf("app show with the renewed certificate: %s", stderr)
	}
	if _, out, _ := cli("rbac", "service", "list"); !regexp.MustCompile(`portal\s+space-creator, admin in preview-1, admin in staging\s+2\s`).MatchString(out) {
		t.Errorf("service list = %q", out)
	}
	if _, out, _ := cli("rbac", "assignment", "list", "--service", "portal"); !regexp.MustCompile(`service\s+portal\s+space-creator\s+\(cluster\)`).MatchString(out) {
		t.Errorf("assignment list = %q", out)
	}
	if code, _, stderr := cli("rbac", "service", "delete", "portal"); code == 0 || !strings.Contains(stderr, "--yes") {
		t.Errorf("delete without --yes: %q", stderr)
	}
	if code, _, _ := cli("rbac", "service", "delete", "portal", "--yes"); code != 0 {
		t.Fatal("service delete failed")
	}
	if code, _, stderr := tool("app", "list", "-A"); code == 0 || !strings.Contains(stderr, "revoked") {
		t.Errorf("tool after removal: code=%d err=%q", code, stderr)
	}

	// A person who may only look.
	anaConfig := filepath.Join(t.TempDir(), "ana.json")
	if code, out, stderr := cli("rbac", "user", "create", "ana", "-o", anaConfig, "--role", "viewer"); code != 0 || !strings.Contains(out, "Wrote "+anaConfig+" for user:ana") {
		t.Fatalf("user create: code=%d out=%q err=%q", code, out, stderr)
	}
	ana := func(args ...string) (int, string, string) {
		return run(t, append(args, "--config", anaConfig)...)
	}
	if code, out, stderr := ana("app", "list", "-A"); code != 0 || !strings.Contains(out, "web") {
		t.Errorf("viewer lists apps: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := ana("app", "scale", "web", "--replicas", "2"); code == 0 || !strings.Contains(stderr, "no role that allows Scale") {
		t.Errorf("viewer scales: code=%d err=%q", code, stderr)
	}
	if _, out, _ := cli("rbac", "user", "list"); !regexp.MustCompile(`ana\s+viewer\s+active\s+user:ryan`).MatchString(out) ||
		!regexp.MustCompile(`ryan\s+cluster-admin\s+active \(you\)`).MatchString(out) {
		t.Errorf("user list = %q", out)
	}
	if _, out, _ := cli("rbac", "role", "show", "deployer"); !strings.Contains(out, "Deploy") || strings.Contains(out, "Exec") {
		t.Errorf("role show = %q", out)
	}
	if code, _, stderr := cli("rbac", "user", "delete", "ryan", "--yes"); code == 0 || !strings.Contains(stderr, "yourself") {
		t.Errorf("delete yourself: code=%d err=%q", code, stderr)
	}
}

// lockedBuffer is a bytes.Buffer safe for concurrent writes and reads.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestServerFlagValidation(t *testing.T) {
	dataDir, _, _ := initCluster(t)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("secret-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		args []string
		want string
	}{
		"http ACME CA":           {[]string{"--acme-ca", "http://acme.local/dir"}, "https://"},
		"public ACME listen":     {[]string{"--acme-ca", "letsencrypt-staging", "--acme-listen", "0.0.0.0:7480"}, "ACME responder"},
		"unknown DNS provider":   {[]string{"--acme-ca", "letsencrypt-staging", "--dns-provider", "route66"}, "unsupported --dns-provider"},
		"DNS without token":      {[]string{"--acme-ca", "letsencrypt-staging", "--dns-provider", "cloudflare"}, "--dns-token-file"},
		"token file world-read":  {[]string{"--acme-ca", "letsencrypt-staging", "--dns-provider", "cloudflare", "--dns-token-file", tokenFile}, "permissions"},
		"token without provider": {[]string{"--acme-ca", "letsencrypt-staging", "--dns-token-file", tokenFile}, "--dns-provider"},
		"DNS with TLS off":       {[]string{"--tls=false", "--dns-provider", "cloudflare"}, "--tls"},
		"unknown proxy":          {[]string{"--tls=false", "--proxy", "nginx"}, "unsupported --proxy"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var out, errOut strings.Builder
			code := Execute(ctx, append([]string{"server", "--data-dir", dataDir}, tt.args...), &out, &errOut)
			if code == 0 || !strings.Contains(errOut.String(), tt.want) {
				t.Errorf("code=%d stderr=%q, want %q", code, errOut.String(), tt.want)
			}
			if strings.Contains(errOut.String(), "secret-token") {
				t.Error("DNS token leaked into error output")
			}
		})
	}
}

func TestCommandsWithoutConfig(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "nope")
	for _, args := range [][]string{{"cluster", "status"}, {"app", "list"}, {"app", "scale", "a", "--replicas", "1"}, {"app", "logs", "a"}, {"app", "exec", "a", "--", "sh"},
		{"app", "top"}, {"cluster", "events"}, {"job", "ls"}, {"app", "create", "a", "--image", "nginx:1"}, {"metrics", "credentials", "p", "-o", filepath.Join(t.TempDir(), "m")}} {
		code, _, stderr := run(t, append(args, "--config", missing)...)
		if code == 0 || !strings.Contains(stderr, "armadad init") {
			t.Errorf("%v: code=%d stderr=%q", args, code, stderr)
		}
	}
	code, _, stderr := run(t, "server", "--data-dir", t.TempDir())
	if code == 0 || !strings.Contains(stderr, "not initialized") {
		t.Errorf("server on empty dir: code=%d stderr=%q", code, stderr)
	}
	code, _, _ = run(t, "agent", "--data-dir", t.TempDir())
	if code == 0 {
		t.Error("agent on empty dir succeeded")
	}
	if code, _, _ := run(t, "server", "--log-format", "xml", "--data-dir", t.TempDir()); code == 0 {
		t.Error("bad log format accepted")
	}
}
