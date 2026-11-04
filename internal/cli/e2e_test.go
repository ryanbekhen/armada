package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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
		"--private-ip", "127.0.0.1", "--node-name", "node-1", "--admin-name", "ryan", "--port", strconv.Itoa(port))
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
	if admin.Subject.CommonName != "admin:ryan" {
		t.Errorf("admin CN = %q", admin.Subject.CommonName)
	}
	// The first node gets the first subnet of the cluster network
	// (ADR 0027) as its bridge subnet.
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
	if code != 0 || !strings.Contains(out, "network:     wireguard, cluster CIDR 10.120.0.0/16") {
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
	// The node runs the sandbox, so replicas of sandboxed projects can run
	// on it (ADR 0029).
	d.Sandbox = true
	d.LogLines = []runtime.LogFrame{{Stream: runtime.Stdout, Data: []byte("listening on :80\n")}, {Stream: runtime.Stderr, Data: []byte("deprecated flag\n")}}
	orig, origWait, origCheck, origPoll, origTmpfs, origUsage := newDriver, proxyStartWait, probeCheck, waitPoll, checkTmpfs, usageInterval
	newDriver = func(string, *agentConfig) (runtime.Driver, error) { return d, nil }
	proxyStartWait = time.Millisecond
	probeCheck = func(context.Context, string, string) error { return nil }
	waitPoll = 50 * time.Millisecond
	checkTmpfs = func(string) error { return nil } // a temp dir stands in for tmpfs
	usageInterval = 20 * time.Millisecond
	t.Cleanup(func() {
		newDriver, proxyStartWait, probeCheck, waitPoll, checkTmpfs, usageInterval = orig, origWait, origCheck, origPoll, origTmpfs, origUsage
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
		code, out, _ := cli("status")
		return code == 0 && strings.Contains(out, "node-1") && strings.Contains(out, "ready")
	})
	// The agent applies the cluster network, with itself as the only peer.
	waitFor("cluster network", func() bool {
		n := testNets.get("node-1").applied()
		return n != nil && n.GetMode() == "plain" && n.GetClusterCidr() == "10.120.0.0/16" &&
			len(n.GetPeers()) == 1 && n.GetPeers()[0].GetSubnet() == "10.120.0.0/24"
	})
	// Network isolation of the default project reaches the node (ADR 0029).
	if code, out, stderr := cli("project", "set", "default", "--network-isolation"); code != 0 || !strings.Contains(out, "network isolation on") {
		t.Fatalf("project set: code=%d out=%q err=%q", code, out, stderr)
	}
	waitFor("isolated default", func() bool { return testNets.get("node-1").applied().GetIsolateDefault() })
	if code, out, _ := cli("project", "list"); code != 0 || !regexp.MustCompile(`default\s+0\s+container\s+isolated\s`).MatchString(out) {
		t.Errorf("project list:\n%s", out)
	}
	if code, _, stderr := cli("project", "set", "default"); code == 0 || !strings.Contains(stderr, "nothing to change") {
		t.Errorf("project set without a flag: %d %q", code, stderr)
	}
	if code, _, _ := cli("project", "set", "default", "--network-isolation=false"); code != 0 {
		t.Error("turning default isolation off failed")
	}

	spec := filepath.Join(t.TempDir(), "web.yaml")
	if err := os.WriteFile(spec, []byte("name: web\nimage: nginx:1.27\ningress:\n  type: external\n  port: 80\nscale:\n  min: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := cli("deploy", "-f", spec)
	if code != 0 || !strings.Contains(out, "Deployed web (revision web--r1)") {
		t.Fatalf("deploy: code=%d out=%q err=%q", code, out, stderr)
	}
	waitFor("2/2 ready", func() bool {
		_, out, _ := cli("status", "web")
		return strings.Contains(out, "2/2")
	})

	code, out, _ = cli("status", "-o", "json")
	if code != 0 {
		t.Fatal("status -o json failed")
	}
	var st struct {
		Apps []struct {
			Name     string `json:"name"`
			Replicas []struct {
				Address string `json:"address"`
			} `json:"replicas"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil || len(st.Apps) != 1 || len(st.Apps[0].Replicas) != 2 {
		t.Fatalf("status json = %s (%v)", out, err)
	}
	// Replicas publish no port: they are reached at their own address in
	// the node's subnet, on the app's port (ADR 0027).
	if a := st.Apps[0].Replicas[0].Address; !strings.HasPrefix(a, "10.120.0.1") || !strings.HasSuffix(a, ":80") {
		t.Errorf("replica address = %q", a)
	}

	if code, _, stderr := cli("scale", "web", "3"); code != 0 {
		t.Fatalf("scale: %s", stderr)
	}
	waitFor("3/3 ready", func() bool {
		_, out, _ := cli("status", "web")
		return strings.Contains(out, "3/3")
	})

	code, out, stderr = cli("logs", "web", "--tail", "5")
	if code != 0 || !strings.Contains(out, "| listening on :80") || !strings.Contains(stderr, "| deprecated flag") {
		t.Errorf("logs: code=%d out=%q err=%q", code, out, stderr)
	}

	// Exec: stdin, separate streams, and the command's exit code (the fake
	// runtime echoes stdin, writes the command name to stderr, and exits
	// with the argument count).
	var execOut, execErr bytes.Buffer
	code = execute(context.Background(), []string{"exec", "web", "-i", "--config", config, "--", "cat", "a", "b"}, strings.NewReader("ping"), &execOut, &execErr)
	if code != 2 || execOut.String() != "ping" || execErr.String() != "cat" {
		t.Errorf("exec: code=%d out=%q err=%q", code, execOut.String(), execErr.String())
	}
	if code, out, stderr := run(t, "exec", "web", "--config", config, "--", "true"); code != 0 || out != "" || stderr != "true" {
		t.Errorf("exec true: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := run(t, "exec", "web", "-t", "--config", config, "--", "sh"); code != 1 || !strings.Contains(stderr, "needs a terminal") {
		t.Errorf("exec -t without a terminal: code=%d err=%q", code, stderr)
	}
	if code, _, stderr := run(t, "exec", "ghost", "--config", config, "--", "sh"); code != 1 || !strings.Contains(stderr, "not found") {
		t.Errorf("exec in a missing app: code=%d err=%q", code, stderr)
	}

	// Top: usage the fake runtime reports, per app, replica, and node.
	cs, _ := d.List(context.Background(), map[string]string{runtime.LabelApp: "web"})
	for _, c := range cs {
		d.SetUsage(c.Labels[runtime.LabelReplica], runtime.Stats{MemoryBytes: 30 << 20})
	}
	waitFor("top measures web", func() bool {
		code, out, _ := cli("top")
		return code == 0 && strings.Contains(out, fmt.Sprintf("%d/%d", len(cs), len(cs))) && strings.Contains(out, fmt.Sprintf("%dMi/", 30*len(cs)))
	})
	if code, out, stderr := cli("top", "web"); code != 0 || !strings.Contains(out, "REPLICA") || !strings.Contains(out, "0m/100m") || !strings.Contains(out, "30Mi/256Mi") {
		t.Errorf("top web: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, out, stderr := cli("top", "--nodes"); code != 0 || !strings.Contains(out, "NODE") || !strings.Contains(out, fmt.Sprintf("%dMi ", 30*len(cs))) {
		t.Errorf("top --nodes: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, out, _ := cli("top", "-o", "json"); code != 0 || !regexp.MustCompile(`"measured":\s+true`).MatchString(out) {
		t.Errorf("top -o json: code=%d out=%q", code, out)
	}
	if code, _, stderr := cli("top", "web", "--nodes"); code != 1 || !strings.Contains(stderr, "--nodes") {
		t.Errorf("top web --nodes: code=%d err=%q", code, stderr)
	}
	if code, _, stderr := cli("top", "ghost"); code != 1 || !strings.Contains(stderr, "not found") {
		t.Errorf("top ghost: code=%d err=%q", code, stderr)
	}

	// Events: what the cluster did, filtered, as text or JSON lines.
	if code, out, stderr := cli("events", "web"); code != 0 || !strings.Contains(out, "REASON") || !strings.Contains(out, "Scheduled") || strings.Contains(out, " node ") {
		t.Errorf("events web: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, out, _ := cli("events", "-o", "json", "--since", "10m"); code != 0 || !strings.Contains(out, `"reason":"Connected"`) {
		t.Errorf("events -o json: code=%d out=%q", code, out)
	}
	if code, _, stderr := cli("events", "--since", "48h"); code != 1 || !strings.Contains(stderr, "--since") {
		t.Errorf("events --since 48h: code=%d err=%q", code, stderr)
	}
	if code, out, _ := cli("events", "ghost"); code != 0 || !strings.Contains(out, "No events.") {
		t.Errorf("events ghost: code=%d out=%q", code, out)
	}

	// Jobs: deploy, run to completion, inspect, read logs, delete.
	jobFile := filepath.Join(t.TempDir(), "job.yaml")
	if err := os.WriteFile(jobFile, []byte("kind: job\nname: report\nimage: busybox:1\nschedule: \"0 3 * * *\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, stderr := cli("deploy", "-f", jobFile); code != 0 || !strings.Contains(out, "Deployed job report") {
		t.Fatalf("deploy job: code=%d out=%q err=%q", code, out, stderr)
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
		code, out, _ := cli("job", "runs", "report")
		return code == 0 && strings.Contains(out, "succeeded") && strings.Contains(out, "manual")
	})
	if code, out, stderr := cli("job", "ls"); code != 0 || !strings.Contains(out, "0 3 * * *") || !strings.Contains(out, "succeeded") || !strings.Contains(out, "in ") {
		t.Errorf("job ls: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, out, stderr := cli("logs", "report"); code != 0 || !strings.Contains(out, "listening on :80") {
		t.Errorf("logs of a job: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := cli("logs", "web", "--run", "1"); code != 1 || !strings.Contains(stderr, "for jobs") {
		t.Errorf("logs --run on an app: code=%d err=%q", code, stderr)
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
	if code, _, stderr := cli("job", "runs", "report"); code != 1 || !strings.Contains(stderr, "not found") {
		t.Errorf("job runs after rm: code=%d err=%q", code, stderr)
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
	if code, out, _ := cli("cluster", "show"); code != 0 || !strings.Contains(out, "root domain: apps.example.org") {
		t.Errorf("cluster show = %q", out)
	}
	hapCfg := filepath.Join(dataDir, dirHAProxy, "etc", "haproxy.cfg")
	waitFor("haproxy routes web", func() bool {
		b, err := os.ReadFile(hapCfg)
		return err == nil && strings.Contains(string(b), "-m str web.apps.example.org }")
	})
	if sys := d.SystemSpecs(); len(sys) == 0 || sys[0].Name != "armada-haproxy" {
		t.Errorf("HAProxy system container not started: %+v", sys)
	}
	waitFor("status shows URL", func() bool {
		_, out, _ := cli("status", "web")
		return strings.Contains(out, "https://web.apps.example.org/")
	})
	if code, out, _ := cli("domain", "list"); code != 0 || !strings.Contains(out, "No custom domains") {
		t.Errorf("domain list = %q", out)
	}
	if err := os.WriteFile(spec, []byte("name: web\nimage: nginx:1.27\ningress:\n  type: external\n  port: 80\n  domains: [example.org]\nscale:\n  min: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := cli("deploy", "-f", spec); code != 0 {
		t.Fatalf("deploy with domain: %s", stderr)
	}
	code, out, _ = cli("domain", "list", "--app", "web")
	if code != 0 || !strings.Contains(out, "example.org") || !strings.Contains(out, "TXT  _armada-verify.example.org") {
		t.Errorf("domain list = %q", out)
	}
	if code, _, stderr := cli("domain", "verify", "ghost.id"); code == 0 || !strings.Contains(stderr, "not found") {
		t.Errorf("domain verify ghost: %q", stderr)
	}
	if code, _, stderr := cli("cluster", "set", "--root-domain", "bad domain"); code == 0 || !strings.Contains(stderr, "root domain") {
		t.Errorf("invalid root domain accepted: %q", stderr)
	}

	// Rolling update: the domain deploy above is revision 2; wait for it.
	code, out, stderr = cli("deploy", "-f", spec, "--wait", "--timeout", "1m")
	if code != 0 || !strings.Contains(out, "web--r2 is live (3/3 ready)") {
		t.Fatalf("deploy --wait: code=%d out=%q err=%q", code, out, stderr)
	}
	code, out, _ = cli("revisions", "web")
	if code != 0 || !regexp.MustCompile(`web--r2\s+active\s`).MatchString(out) || !strings.Contains(out, "web--r1") {
		t.Errorf("revisions = %q", out)
	}
	code, out, stderr = cli("rollback", "web", "--wait", "--timeout", "1m")
	if code != 0 || !strings.Contains(out, "Rolling web back to web--r1") || !strings.Contains(out, "web--r1 is live (3/3 ready)") {
		t.Fatalf("rollback --wait: code=%d out=%q err=%q", code, out, stderr)
	}
	if _, out, _ := cli("status", "web"); !regexp.MustCompile(`web\s+web--r1\s+3/3`).MatchString(out) {
		t.Errorf("status after rollback = %q", out)
	}
	if code, _, stderr := cli("rollback", "web", "web--r99"); code == 0 || !strings.Contains(stderr, "not found") {
		t.Errorf("rollback to unknown revision: %q", stderr)
	}

	testSecrets(t, d, cli, config, dataDir, secretsDir, serverLog)

	// Errors from the server come back without gRPC noise.
	code, _, stderr = cli("scale", "ghost", "2")
	if code == 0 || !strings.Contains(stderr, "app ghost: not found") || strings.Contains(stderr, "rpc error") {
		t.Errorf("scale ghost: code=%d stderr=%q", code, stderr)
	}
	code, _, stderr = cli("deploy", "-f", "-")
	if code == 0 || !strings.Contains(stderr, "empty") {
		t.Errorf("deploy empty stdin: code=%d stderr=%q", code, stderr)
	}
	for _, args := range [][]string{{"scale", "web", "zero"}, {"scale", "web", "0"}, {"status", "-o", "yaml"}, {"deploy"}} {
		if code, _, _ := cli(args...); code == 0 {
			t.Errorf("%v accepted", args)
		}
	}

	testProjects(t, d, cli, waitFor)
}

// testProjects runs an app of the same name in another project (ADR 0029).
func testProjects(t *testing.T, d *fake.Driver, cli func(...string) (int, string, string), waitFor func(string, func() bool)) {
	t.Helper()
	spec := filepath.Join(t.TempDir(), "web.yaml")
	if err := os.WriteFile(spec, []byte("name: web\nimage: nginx:1.28\ningress:\n  type: internal\n  port: 80\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := cli("deploy", "-f", spec, "--project", "staging"); code == 0 || !strings.Contains(stderr, "project staging does not exist") {
		t.Fatalf("deploy into a missing project: code=%d err=%q", code, stderr)
	}
	if code, out, stderr := cli("project", "create", "staging"); code != 0 || !strings.Contains(out, "Project staging created (isolation sandbox)") {
		t.Fatalf("project create: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := cli("project", "create", "staging"); code == 0 || !strings.Contains(stderr, "already exists") {
		t.Errorf("project create twice: %q", stderr)
	}
	code, out, stderr := cli("deploy", "-f", spec, "--project", "staging")
	if code != 0 || !strings.Contains(out, "Deployed web.staging (revision web.staging--r1)") {
		t.Fatalf("deploy into staging: code=%d out=%q err=%q", code, out, stderr)
	}
	waitFor("web.staging ready", func() bool {
		_, out, _ := cli("status", "web", "--project", "staging")
		return regexp.MustCompile(`web\.staging\s+web\.staging--r1\s+1/1`).MatchString(out)
	})
	cs, _ := d.List(context.Background(), map[string]string{runtime.LabelApp: "web.staging"})
	for _, c := range cs {
		if sp, ok := d.Spec(c.ID); !ok || !sp.Sandbox {
			t.Errorf("web.staging container %s not sandboxed", c.ID)
		}
	}
	if len(cs) == 0 {
		t.Error("no web.staging container")
	}
	if _, out, _ := cli("node", "list"); !regexp.MustCompile(`node-1\s+\S+\s+ready\s+yes\s`).MatchString(out) {
		t.Errorf("node list without the sandbox column: %q", out)
	}
	// The default project's web is untouched, and listings follow --project.
	_, out, _ = cli("status", "--project", "staging")
	if strings.Contains(out, "web--r1") || !strings.Contains(out, "web.staging-r1-") {
		t.Errorf("status --project staging = %q", out)
	}
	_, out, _ = cli("status", "--project", "default")
	if strings.Contains(out, "web.staging") || !regexp.MustCompile(`web\s+web--r1\s+3/3`).MatchString(out) {
		t.Errorf("status --project default = %q", out)
	}
	if code, _, stderr := cli("scale", "web.staging", "2"); code != 0 {
		t.Fatalf("scale by ID: %s", stderr)
	}
	waitFor("web.staging 2/2", func() bool {
		_, out, _ := cli("status", "web.staging")
		return strings.Contains(out, "2/2")
	})
	_, out, _ = cli("project", "list")
	if !regexp.MustCompile(`default\s+[1-9]\s+container\s`).MatchString(out) || !regexp.MustCompile(`staging\s+1\s+sandbox\s+isolated\s`).MatchString(out) {
		t.Errorf("project list = %q", out)
	}
	if code, _, stderr := cli("project", "remove", "staging"); code == 0 || !strings.Contains(stderr, "apps (web.staging)") {
		t.Errorf("remove a project with apps: %q", stderr)
	}
	for _, args := range [][]string{
		{"status", "web.staging", "--project", "prod"},
		{"status", "web.default"},
		{"status", "web", "--project", "Bad"},
		{"project", "remove", "default"},
		{"project", "create", "a.b"},
	} {
		if code, _, _ := cli(args...); code == 0 {
			t.Errorf("%v accepted", args)
		}
	}

	// A tool with an automation identity manages staging and nothing else.
	if code, out, stderr := cli("automation", "set", "portal", "--project", "staging", "--create-projects"); code != 0 || !strings.Contains(out, "manages projects staging and the projects it creates") {
		t.Fatalf("automation set: code=%d out=%q err=%q", code, out, stderr)
	}
	toolConfig := filepath.Join(t.TempDir(), "portal.json")
	if code, out, stderr := cli("automation", "credentials", "portal", "-o", toolConfig); code != 0 || !strings.Contains(out, "Wrote "+toolConfig) {
		t.Fatalf("automation credentials: code=%d out=%q err=%q", code, out, stderr)
	}
	if fi, err := os.Stat(toolConfig); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("tool config: %v %v", fi, err)
	}
	if code, _, stderr := cli("automation", "credentials", "portal", "-o", toolConfig); code == 0 || !strings.Contains(stderr, "already exists") {
		t.Errorf("credentials over an existing file: %q", stderr)
	}
	tool := func(args ...string) (int, string, string) {
		return run(t, append(args, "--config", toolConfig)...)
	}
	if code, _, stderr := tool("scale", "web", "1", "--project", "staging"); code != 0 {
		t.Errorf("tool scales its app: %s", stderr)
	}
	_, out, _ = tool("status")
	if !strings.Contains(out, "web.staging") || regexp.MustCompile(`(?m)^web\s`).MatchString(out) || strings.Contains(out, "PRIVATE IP") {
		t.Errorf("tool status shows more than its projects: %q", out)
	}
	for _, args := range [][]string{
		{"scale", "web", "2"},                                 // the default project
		{"node", "cordon", "node-1"},                          // the cluster
		{"token", "create"},                                   // joining nodes
		{"automation", "set", "portal", "--project", "other"}, // its own scope
		{"logs", "web"},
	} {
		if code, _, stderr := tool(args...); code == 0 || !strings.Contains(stderr, "may not") {
			t.Errorf("tool %v: code=%d err=%q", args, code, stderr)
		}
	}
	if code, _, stderr := tool("project", "create", "preview-1"); code != 0 {
		t.Errorf("tool creates a project: %s", stderr)
	}
	if _, out, _ := tool("project", "list"); !strings.Contains(out, "preview-1") || !strings.Contains(out, "staging") || strings.Contains(out, "default") {
		t.Errorf("tool project list = %q", out)
	}
	if code, out, stderr := tool("automation", "renew"); code != 0 || !strings.Contains(out, "Renewed automation:portal") {
		t.Errorf("renew: code=%d out=%q err=%q", code, out, stderr)
	}
	if code, _, stderr := tool("status", "web", "--project", "staging"); code != 0 {
		t.Errorf("status with the renewed certificate: %s", stderr)
	}
	if _, out, _ := cli("automation", "list"); !regexp.MustCompile(`portal\s+preview-1,staging\s+true`).MatchString(out) {
		t.Errorf("automation list = %q", out)
	}
	if code, _, _ := cli("automation", "remove", "portal"); code != 0 {
		t.Fatal("automation remove failed")
	}
	if code, _, stderr := tool("status"); code == 0 || !strings.Contains(stderr, "revoked") {
		t.Errorf("tool after removal: code=%d err=%q", code, stderr)
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
	for _, args := range [][]string{{"status"}, {"scale", "a", "1"}, {"logs", "a"}, {"exec", "a", "--", "sh"}, {"top"}, {"events"}, {"job", "ls"}, {"metrics", "credentials", "p", "-o", filepath.Join(t.TempDir(), "m")}} {
		code, _, stderr := run(t, append(args, "--config", missing)...)
		if code == 0 || !strings.Contains(stderr, "armada init") {
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

func TestHumanBytes(t *testing.T) {
	t.Parallel()

	for in, want := range map[int64]string{0: "-", 512 << 20: "512Mi", 2 << 30: "2.0Gi"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q", in, got)
		}
	}
}
