package daemon

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/proxy/haproxy"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
)

func healthyEnv(t *testing.T) doctorEnv {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{fileCAKey, fileMasterKey, fileAgent} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	d := fake.New()
	d.BridgeNet = runtime.Bridge{Gateway: netip.MustParseAddr("10.121.0.1"), Subnet: netip.MustParsePrefix("10.121.0.0/24")}
	return doctorEnv{
		euid:       0,
		driver:     d,
		detectIP:   func() (netip.Addr, error) { return netip.MustParseAddr("10.0.0.2"), nil },
		statFile:   os.Stat,
		checkTmpfs: func(string) error { return nil },
		listeners: func() ([]netip.AddrPort, error) {
			return []netip.AddrPort{netip.MustParseAddrPort("10.0.0.2:7443")}, nil
		},
		ntpSynced:   func(context.Context) (bool, error) { return true, nil },
		ufwActive:   func(context.Context) (bool, error) { return false, errors.New("not installed") },
		readFile:    os.ReadFile,
		now:         time.Now,
		adminConfig: filepath.Join(dir, "no-config"),
		dataDir:     dir,
		secretsDir:  "/run/armada/secrets",
		clusterPort: []uint16{7443, 7444, haproxy.MetricsPort},
	}
}

func statusOf(results []checkResult, name string) string {
	for _, r := range results {
		if r.Name == name {
			return r.Status
		}
	}
	return ""
}

func TestDoctorHealthy(t *testing.T) {
	t.Parallel()
	results := runDoctor(context.Background(), healthyEnv(t))
	var buf bytes.Buffer
	if failed := printChecks(&buf, results); failed != 0 {
		t.Errorf("healthy host has %d failures:\n%s", failed, buf.String())
	}
	if strings.Contains(buf.String(), "warn") {
		t.Errorf("healthy host has warnings:\n%s", buf.String())
	}
}

// TestDoctorNotLinux: nodes run Linux; elsewhere the OS check fails.
func TestDoctorFindsProblems(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		mutate func(*doctorEnv)
		check  string
		want   string
	}{
		"not root":    {func(e *doctorEnv) { e.euid = 1000 }, "user", checkWarn},
		"loopback ip": {func(e *doctorEnv) { e.privateIP = "127.0.0.1" }, "private-ip", checkFail},
		"public ip":   {func(e *doctorEnv) { e.privateIP = "8.8.8.8" }, "private-ip", checkFail},
		"no ip": {func(e *doctorEnv) {
			e.detectIP = func() (netip.Addr, error) { return netip.Addr{}, errors.New("none") }
		}, "private-ip", checkFail},
		"wildcard listener": {func(e *doctorEnv) {
			e.listeners = func() ([]netip.AddrPort, error) {
				return []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:7443")}, nil
			}
		}, "listeners", checkFail},
		"public listener": {func(e *doctorEnv) {
			e.listeners = func() ([]netip.AddrPort, error) {
				return []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::1]:8404")}, nil
			}
		}, "listeners", checkFail},
		"not tmpfs": {func(e *doctorEnv) { e.checkTmpfs = func(string) error { return errors.New("ext4") } }, "secrets-tmpfs", checkWarn},
		"clock":     {func(e *doctorEnv) { e.ntpSynced = func(context.Context) (bool, error) { return false, nil } }, "clock", checkWarn},
		"ufw":       {func(e *doctorEnv) { e.ufwActive = func(context.Context) (bool, error) { return true, nil } }, "firewall", checkWarn},
		"world-readable key": {func(e *doctorEnv) {
			_ = os.Chmod(filepath.Join(e.dataDir, fileMasterKey), 0o644)
		}, "data-dir", checkFail},
		"open data dir": {func(e *doctorEnv) { _ = os.Chmod(e.dataDir, 0o755) }, "data-dir", checkFail},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env := healthyEnv(t)
			tt.mutate(&env)
			if got := statusOf(runDoctor(context.Background(), env), tt.check); got != tt.want {
				t.Errorf("%s = %q, want %q", tt.check, got, tt.want)
			}
		})
	}
}

func TestDoctorRuntimeDown(t *testing.T) {
	t.Parallel()
	env := healthyEnv(t)
	d := fake.New()
	d.PingErr = errors.New("connection refused")
	env.driver = d
	// The embedded runtime only runs once the node is set up.
	env.runtimeHost = func(netip.Prefix) []checkResult { return []checkResult{{Name: "cgroup", Status: checkOK}} }
	if got := statusOf(runDoctor(context.Background(), env), "runtime"); got != checkFail {
		t.Errorf("initialized node, embedded runtime down = %q", got)
	}
	env.dataDir = t.TempDir()
	results := runDoctor(context.Background(), env)
	if got := statusOf(results, "runtime"); got != checkWarn {
		t.Errorf("fresh node, embedded runtime down = %q", got)
	}
	if statusOf(results, "cgroup") != checkOK {
		t.Error("host checks not run")
	}
	env.driverErr = errors.New("bad subnet")
	if got := statusOf(runDoctor(context.Background(), env), "runtime"); got != checkFail {
		t.Errorf("driver error = %q", got)
	}
}

func TestDoctorClusterNetwork(t *testing.T) {
	t.Parallel()
	env := healthyEnv(t)
	if statusOf(runDoctor(context.Background(), env), "network") != "" {
		t.Error("network checked on a node without a cluster network")
	}
	env.network = func() []checkResult { return []checkResult{{Name: "network", Status: checkFail}} }
	if got := statusOf(runDoctor(context.Background(), env), "network"); got != checkFail {
		t.Errorf("network check = %q", got)
	}
}

func TestParseRoutes(t *testing.T) {
	t.Parallel()
	table := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"eth0\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
		"armada0\t0000790A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
	routes, err := parseRoutes(strings.NewReader(table))
	if err != nil || len(routes) != 3 {
		t.Fatalf("%v %v", routes, err)
	}
	if routes[1].dst.String() != "10.0.0.0/24" || routes[2].dst.String() != "10.121.0.0/24" || routes[0].dst.Bits() != 0 {
		t.Errorf("%v", routes)
	}
}

func TestRuntimeFlags(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr("10.0.0.6")
	var ac agentConfig
	if err := (runtimeFlags{subnet: "10.121.0.0/24"}).apply(&ac, ip); err != nil || ac.Runtime != runtimeEmbedded || ac.ContainerSubnet != "10.121.0.0/24" {
		t.Errorf("%+v %v", ac, err)
	}
	if err := ac.checkRuntime(); err != nil {
		t.Errorf("embedded node refused: %v", err)
	}
	for _, bad := range []runtimeFlags{
		{subnet: "10.0.0.0/16"}, // holds the private IP
		{subnet: "1.2.3.0/24"},
		{subnet: "nope"},
	} {
		if err := bad.apply(&ac, ip); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	// A node recorded with another runtime (an external driver) is refused.
	for _, rt := range []string{"docker", "apple", "Other", "../x"} {
		if err := (agentConfig{Runtime: rt}).checkRuntime(); err == nil || !strings.Contains(err.Error(), "embedded runtime") {
			t.Errorf("runtime %q: %v", rt, err)
		}
	}
	if err := (agentConfig{}).checkRuntime(); err != nil {
		t.Errorf("agent.json without a runtime refused: %v", err)
	}
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	var rf runtimeFlags
	rf.register(fs)
	if err := fs.Parse([]string{"--runtime", "docker"}); err == nil {
		t.Error("--runtime still accepted")
	}
}

func TestDoctorMissingDataDir(t *testing.T) {
	t.Parallel()
	env := healthyEnv(t)
	env.dataDir = filepath.Join(env.dataDir, "missing")
	env.statFile = func(p string) (fs.FileInfo, error) { return os.Stat(p) }
	if got := statusOf(runDoctor(context.Background(), env), "data-dir"); got != checkOK {
		t.Errorf("missing data dir = %q", got)
	}
}

func TestParseProcNetTCP(t *testing.T) {
	t.Parallel()
	in := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0200000A:1D13 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 00000000:1D14 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0
   2: 0200000A:D2F0 0300000A:1D13 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
   3: 000000FD000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 4 1 0 100 0 0 10 0
`
	got, err := parseProcNetTCP(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.2:7443", "0.0.0.0:7444", "[fd00::]:8080"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("listener %d = %s, want %s", i, got[i], want[i])
		}
	}
	if _, err := parseProcNetTCP(strings.NewReader("h\n 0: zz:1 0:0 0A\n")); err == nil {
		t.Error("garbage accepted")
	}
}

func TestExistingAncestor(t *testing.T) {
	dir := t.TempDir()
	if got := existingAncestor(filepath.Join(dir, "a", "b")); got != dir {
		t.Errorf("existingAncestor = %q, want %q", got, dir)
	}
	if got := existingAncestor(dir); got != dir {
		t.Errorf("existingAncestor(existing) = %q", got)
	}
}

func TestDoctorRuntimeUnreachable(t *testing.T) {
	t.Parallel()
	env := healthyEnv(t)
	env.driver = failingPing{fake.New()}
	results := runDoctor(context.Background(), env)
	found := false
	for _, r := range results {
		if r.Name == "runtime" {
			found = true
			if r.Status != checkFail || !strings.Contains(r.Detail, "armada-runtime") {
				t.Errorf("unreachable runtime: %+v", r)
			}
		}
	}
	if !found {
		t.Error("no runtime check")
	}
}

type failingPing struct{ *fake.Driver }

func (failingPing) Ping(context.Context) error { return errors.New("connection refused") }

func TestConntrackCheck(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		entries, limit int64
		ok             bool
		status         string
	}{
		{0, 0, false, checkOK},
		{100, 262144, true, checkOK},
		{209714, 262144, true, checkOK},
		{209716, 262144, true, checkWarn},
		{65536, 65536, true, checkWarn},
	} {
		if got := conntrackCheck(c.entries, c.limit, c.ok); got.Name != "conntrack" || got.Status != c.status {
			t.Errorf("conntrackCheck(%d, %d, %v) = %+v, want %s", c.entries, c.limit, c.ok, got, c.status)
		}
	}
}

func TestDoctorCertificates(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("test")
	write := func(dir, name string, kind string, validity time.Duration) {
		t.Helper()
		req := pki.IssueRequest{Identity: pki.Identity{Kind: kind, Name: "x"}, Client: true, Validity: validity}
		if kind == pki.KindServer {
			req = pki.IssueRequest{Identity: pki.Identity{Kind: kind, Name: "x"}, DNSNames: []string{pki.ServerName}, Server: true, Validity: validity}
		}
		certPEM, keyPEM, err := ca.Issue(req)
		if err != nil {
			t.Fatal(err)
		}
		if name == "config" {
			cc := &clientconfig.Config{Servers: []string{"10.0.0.2:7443"}, CA: string(ca.CertPEM), Cert: string(certPEM), Key: string(keyPEM)}
			if err := cc.SaveFile(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			return
		}
		_ = os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o700)
		if err := os.WriteFile(filepath.Join(dir, name), certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	year := 365 * 24 * time.Hour
	for name, tt := range map[string]struct {
		server, admin time.Duration
		later         time.Duration
		want          string
		says          string
	}{
		"all valid":          {year, year, 0, checkOK, "server, administrator valid"},
		"admin expires soon": {year, 10 * 24 * time.Hour, 0, checkWarn, "armada admin renew"},
		"admin expired":      {year, -time.Hour, 0, checkFail, "admin renew --data-dir"},
		"server not renewed": {10 * 24 * time.Hour, year, 9 * 24 * time.Hour, checkWarn, "was not renewed"},
		"server expired":     {-time.Hour, year, 0, checkFail, "restart armada-server"},
	} {
		env := healthyEnv(t)
		write(env.dataDir, fileServerCert, pki.KindServer, tt.server)
		write(env.dataDir, "config", pki.KindAdmin, tt.admin)
		env.adminConfig = filepath.Join(env.dataDir, "config")
		env.now = func() time.Time { return time.Now().Add(tt.later) }
		var got []checkResult
		for _, r := range runDoctor(context.Background(), env) {
			if r.Name == "certificates" {
				got = append(got, r)
			}
		}
		worst, detail := checkOK, ""
		for _, r := range got {
			detail += r.Detail + "; "
			if r.Status == checkFail || (r.Status == checkWarn && worst == checkOK) {
				worst = r.Status
			}
		}
		if worst != tt.want || !strings.Contains(detail, tt.says) {
			t.Errorf("%s: %s %q", name, worst, detail)
		}
	}
	// Nothing to check before init: no line at all.
	env := healthyEnv(t)
	if s := statusOf(runDoctor(context.Background(), env), "certificates"); s != "" {
		t.Errorf("certificates on an empty host: %s", s)
	}
}

func TestDoctorRelease(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		latest string
		err    error
		want   string
	}{
		{"v0.2.0", nil, checkWarn},
		{"v0.1.0", nil, checkOK},
		{"", errors.New("timeout"), checkOK},
	} {
		env := healthyEnv(t)
		env.version = "v0.1.0"
		env.latest = func(context.Context) (string, error) { return tc.latest, tc.err }
		if got := statusOf(runDoctor(context.Background(), env), "release"); got != tc.want {
			t.Errorf("latest %q %v: %s, want %s", tc.latest, tc.err, got, tc.want)
		}
	}
	if got := statusOf(runDoctor(context.Background(), healthyEnv(t)), "release"); got != "" {
		t.Errorf("check ran while turned off: %s", got)
	}
}

func TestDoctorServerEnv(t *testing.T) {
	t.Parallel()
	env := healthyEnv(t)
	env.serverEnv = func() ([]byte, error) {
		return []byte(`ARMADA_SERVER_FLAGS="--acme-email ops@example.org --dns-provider=cloudflare --tls=false"` + "\n"), nil
	}
	results := runDoctor(context.Background(), env)
	if statusOf(results, "server-env") != checkWarn {
		t.Fatalf("no warning for cluster flags in server.env")
	}
	for _, r := range results {
		if r.Name == "server-env" && (!strings.Contains(r.Detail, "--acme-email") || !strings.Contains(r.Detail, "--dns-provider") || !strings.Contains(r.Detail, "--tls")) {
			t.Errorf("detail %q", r.Detail)
		}
	}
	env.serverEnv = func() ([]byte, error) { return []byte(`ARMADA_SERVER_FLAGS="--join-listen off"` + "\n"), nil }
	if got := statusOf(runDoctor(context.Background(), env), "server-env"); got != "" {
		t.Errorf("machine flags flagged: %s", got)
	}
}
