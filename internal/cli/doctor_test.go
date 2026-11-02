package cli

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

	"github.com/spf13/pflag"

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
		goos:       "linux",
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

// A Mac with a driver is a compute node run by a user (ADR 0016): no root
// warning, no checks of Linux services or listeners, and the secrets RAM
// disk is mounted by the agent.
func TestDoctorMacOSNode(t *testing.T) {
	t.Parallel()
	env := healthyEnv(t)
	env.goos, env.euid, env.runtimeName = "darwin", 501, "apple"
	env.listeners, env.ntpSynced, env.ufwActive = nil, nil, nil
	env.checkTmpfs = func(string) error { return errors.New("not mounted yet") }
	results := runDoctor(context.Background(), env)
	var buf bytes.Buffer
	if failed := printChecks(&buf, results); failed != 0 || strings.Contains(buf.String(), "warn") {
		t.Errorf("macOS node:\n%s", buf.String())
	}
	for _, name := range []string{"user", "listeners", "clock", "firewall"} {
		if got := statusOf(results, name); got != "" {
			t.Errorf("check %s ran on macOS (%s)", name, got)
		}
	}
	if !strings.Contains(buf.String(), "the agent mounts a RAM disk") {
		t.Errorf("no secrets check:\n%s", buf.String())
	}
	if got := driverHint("darwin", "apple"); got != "launchctl print gui/$(id -u)/io.github.ryanbekhen.armada.driver.apple" {
		t.Errorf("hint = %q", got)
	}
}

func TestDoctorFindsProblems(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		mutate func(*doctorEnv)
		check  string
		want   string
	}{
		"other os":           {func(e *doctorEnv) { e.goos = "freebsd" }, "os", checkFail},
		"mac without driver": {func(e *doctorEnv) { e.goos = "darwin" }, "os", checkFail},
		"not root":           {func(e *doctorEnv) { e.euid = 1000 }, "user", checkWarn},
		"loopback ip":        {func(e *doctorEnv) { e.privateIP = "127.0.0.1" }, "private-ip", checkFail},
		"public ip":          {func(e *doctorEnv) { e.privateIP = "8.8.8.8" }, "private-ip", checkFail},
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
	for _, rt := range []string{"", "Other", "../x", "a b"} {
		if err := (agentConfig{Runtime: rt}).checkRuntime(); err == nil {
			t.Errorf("runtime %q accepted", rt)
		}
	}

	// An external driver: no container subnet, which the driver chooses.
	ac = agentConfig{}
	if err := (runtimeFlags{runtime: "docker", subnet: "10.121.0.0/24"}).apply(&ac, ip); err != nil || ac.Runtime != "docker" || ac.ContainerSubnet != "" || !ac.external() {
		t.Errorf("%+v %v", ac, err)
	}
	if err := ac.checkRuntime(); err != nil {
		t.Errorf("driver node refused: %v", err)
	}
	for _, bad := range []string{"embedded-x/", "Docker", "x_y"} {
		if err := (runtimeFlags{runtime: bad}).apply(&ac, ip); err == nil {
			t.Errorf("--runtime %q accepted", bad)
		}
	}
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	var rf runtimeFlags
	rf.register(fs)
	if err := fs.Parse([]string{"--runtime", "docker", "--container-subnet", "10.122.0.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := rf.apply(&ac, ip); err == nil || !strings.Contains(err.Error(), "embedded runtime") {
		t.Errorf("--container-subnet with a driver: %v", err)
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

// appOnly is a driver without system containers or a bridge.
type appOnly struct{ runtime.Driver }

func TestDoctorExternalDriver(t *testing.T) {
	t.Parallel()
	env := healthyEnv(t)
	env.runtimeName = "docker"
	results := runDoctor(context.Background(), env)
	if statusOf(results, "runtime") != checkOK || statusOf(results, "system containers") != "" {
		t.Errorf("capable driver: %+v", results)
	}

	env.driver = appOnly{fake.New()}
	results = runDoctor(context.Background(), env)
	if statusOf(results, "system containers") != checkWarn || statusOf(results, "bridge") != "" {
		t.Errorf("driver without system containers: %+v", results)
	}

	env.driver = appOnly{&failingPing{fake.New()}}
	results = runDoctor(context.Background(), env)
	for _, r := range results {
		if r.Name == "runtime" && (r.Status != checkFail || !strings.Contains(r.Detail, "armada-driver-docker")) {
			t.Errorf("unreachable driver: %+v", r)
		}
	}
}

type failingPing struct{ *fake.Driver }

func (failingPing) Ping(context.Context) error { return errors.New("connection refused") }
