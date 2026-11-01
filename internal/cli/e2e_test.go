package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
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

	// A second init must not overwrite the CA.
	code, _, stderr := run(t, "init", "--data-dir", dataDir, "--config", config+"2", "--private-ip", "127.0.0.1")
	if code == 0 || !strings.Contains(stderr, "already initialized") {
		t.Errorf("re-init: code=%d stderr=%q", code, stderr)
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
	d.LogLines = []runtime.LogFrame{{Stream: runtime.Stdout, Data: []byte("listening on :80\n")}, {Stream: runtime.Stderr, Data: []byte("deprecated flag\n")}}
	orig, origWait, origCheck, origPoll, origTmpfs := newDriver, proxyStartWait, probeCheck, waitPoll, checkTmpfs
	newDriver = func(string, *agentConfig) (runtime.Driver, error) { return d, nil }
	proxyStartWait = time.Millisecond
	probeCheck = func(context.Context, string, string) error { return nil }
	waitPoll = 50 * time.Millisecond
	checkTmpfs = func(string) error { return nil } // a temp dir stands in for tmpfs
	t.Cleanup(func() {
		newDriver, proxyStartWait, probeCheck, waitPoll, checkTmpfs = orig, origWait, origCheck, origPoll, origTmpfs
	})
	secretsDir := filepath.Join(t.TempDir(), "secrets")

	dataDir, config, _ := initCluster(t)
	acme, join := freeAddr(t), freeAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	serverLog := &lockedBuffer{}
	go func() {
		// Never the production ACME endpoint in tests.
		done <- Execute(ctx, []string{"server", "--data-dir", dataDir, "--acme-ca", "letsencrypt-staging", "--acme-listen", acme,
			"--secrets-dir", secretsDir, "--log-format", "json", "--verbose", "--join-listen", join}, serverLog, serverLog)
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
	if !strings.HasPrefix(st.Apps[0].Replicas[0].Address, "127.0.0.1:") {
		t.Errorf("replica address = %q", st.Apps[0].Replicas[0].Address)
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

	// Ingress: HAProxy is started by the embedded agent and routes
	// <app>.<root> once a root domain is set.
	if code, out, stderr := cli("cluster", "set", "--root-domain", "apps.contoh.id"); code != 0 || !strings.Contains(out, "apps.contoh.id") {
		t.Fatalf("cluster set: %q %q", out, stderr)
	}
	if code, out, _ := cli("cluster", "show"); code != 0 || !strings.Contains(out, "root domain: apps.contoh.id") {
		t.Errorf("cluster show = %q", out)
	}
	hapCfg := filepath.Join(dataDir, dirHAProxy, "etc", "haproxy.cfg")
	waitFor("haproxy routes web", func() bool {
		b, err := os.ReadFile(hapCfg)
		return err == nil && strings.Contains(string(b), "-m str web.apps.contoh.id }")
	})
	if sys := d.SystemSpecs(); len(sys) == 0 || sys[0].Name != "armada-haproxy" {
		t.Errorf("HAProxy system container not started: %+v", sys)
	}
	waitFor("status shows URL", func() bool {
		_, out, _ := cli("status", "web")
		return strings.Contains(out, "https://web.apps.contoh.id/")
	})
	if code, out, _ := cli("domain", "list"); code != 0 || !strings.Contains(out, "No custom domains") {
		t.Errorf("domain list = %q", out)
	}
	if err := os.WriteFile(spec, []byte("name: web\nimage: nginx:1.27\ningress:\n  type: external\n  port: 80\n  domains: [contoh.id]\nscale:\n  min: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := cli("deploy", "-f", spec); code != 0 {
		t.Fatalf("deploy with domain: %s", stderr)
	}
	code, out, _ = cli("domain", "list", "--app", "web")
	if code != 0 || !strings.Contains(out, "contoh.id") || !strings.Contains(out, "TXT  _armada-verify.contoh.id") {
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
	for _, args := range [][]string{{"status"}, {"scale", "a", "1"}, {"logs", "a"}} {
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
