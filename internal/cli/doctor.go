package cli

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/clusternet"
	"github.com/ryanbekhen/armada/internal/conntrack"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/proxy/haproxy"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/containerd"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// Pre-flight check results.
const (
	checkOK   = "ok"
	checkWarn = "warn"
	checkFail = "FAIL"
)

type checkResult struct {
	Name   string
	Status string
	Detail string
}

// doctorEnv is what the checks read from the host; tests replace it.
type doctorEnv struct {
	euid      int
	driver    runtime.Driver
	driverErr error
	// runtimeHost checks what the embedded runtime needs from the host.
	runtimeHost func(subnet netip.Prefix) []checkResult
	// network checks the cluster network (ADR 0025); nil when the node is
	// not part of one.
	network     func() []checkResult
	subnet      netip.Prefix
	detectIP    func() (netip.Addr, error)
	statFile    func(string) (fs.FileInfo, error)
	checkTmpfs  func(string) error
	listeners   func() ([]netip.AddrPort, error)
	ntpSynced   func(context.Context) (bool, error)
	ufwActive   func(context.Context) (bool, error)
	privateIP   string
	dataDir     string
	secretsDir  string
	clusterPort []uint16
}

func newDoctorCommand() *cobra.Command {
	var (
		dataDir, secretsDir, privateIP string
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check that this host is ready to run Armada safely",
		Long: `Runs pre-flight checks on this host: the container runtime, the private IP,
ports bound publicly, file permissions in the data directory, the secrets tmpfs, the
clock, and the host firewall. Exits non-zero if a check fails.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			env := hostDoctorEnv(dataDir)
			env.privateIP, env.dataDir, env.secretsDir = privateIP, dataDir, secretsDir
			results := runDoctor(cmd.Context(), env)
			if failed := printChecks(cmd.OutOrStdout(), results); failed > 0 {
				return fmt.Errorf("%d check(s) failed", failed)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&dataDir, "data-dir", defaultDataDir, "Armada data directory")
	f.StringVar(&secretsDir, "secrets-dir", defaultSecretsDir, "tmpfs directory for secret files")
	f.StringVar(&privateIP, "private-ip", "", "this node's private (VPC) IP (default: detected)")
	return cmd
}

func hostDoctorEnv(dataDir string) doctorEnv {
	ac := &agentConfig{}
	if c, err := loadAgentConfig(dataDir); err == nil {
		ac = c
	}
	if ac.ContainerSubnet == "" {
		ac.ContainerSubnet = embedded.DefaultSubnet.String()
	}
	subnet, _ := netip.ParsePrefix(ac.ContainerSubnet)
	driver, err := newDriver(dataDir, ac)
	var network func() []checkResult
	if ip, err := netip.ParseAddr(ac.PrivateIP); err == nil && ac.Network != "" {
		network = func() []checkResult { return clusterNetChecks(ac.Network, ip) }
	}
	return doctorEnv{
		euid:        os.Geteuid(),
		driver:      driver,
		driverErr:   err,
		runtimeHost: embeddedHostChecks,
		network:     network,
		subnet:      subnet,
		detectIP:    netutil.DetectPrivateIP,
		statFile:    os.Stat,
		checkTmpfs:  checkTmpfs,
		listeners:   procListeners,
		ntpSynced:   timedatectlSynced,
		ufwActive:   ufwActive,
		clusterPort: []uint16{defaultPort, defaultPort + 1, haproxy.MetricsPort},
	}
}

// printChecks writes one line per result and returns the number of failures.
func printChecks(w io.Writer, results []checkResult) int {
	failed := 0
	for _, r := range results {
		if r.Status == checkFail {
			failed++
		}
		_, _ = fmt.Fprintf(w, "[%-4s] %-14s %s\n", r.Status, r.Name, r.Detail)
	}
	return failed
}

func runDoctor(ctx context.Context, env doctorEnv) []checkResult {
	var out []checkResult
	add := func(name, status, format string, args ...any) {
		out = append(out, checkResult{Name: name, Status: status, Detail: fmt.Sprintf(format, args...)})
	}

	if env.euid != 0 {
		add("user", checkWarn, "not running as root; some checks may be incomplete")
	}

	out = append(out, checkRuntime(ctx, env)...)

	ip, err := doctorPrivateIP(env)
	if err != nil {
		add("private-ip", checkFail, "%v", err)
	} else {
		add("private-ip", checkOK, "%s", ip)
	}

	out = append(out, checkListeners(env)...)
	out = append(out, checkDataDir(env)...)

	// Before the first start the directory does not exist yet: systemd
	// creates /run/armada, so check the nearest directory that exists.
	dir := existingAncestor(env.secretsDir)
	switch err := env.checkTmpfs(dir); {
	case err != nil:
		add("secrets-tmpfs", checkWarn, "secret files will be disabled: %v (mount: mount -t tmpfs -o mode=0700,size=16m tmpfs %s)", err, filepath.Dir(env.secretsDir))
	case dir != env.secretsDir:
		add("secrets-tmpfs", checkOK, "%s will be created on tmpfs (%s)", env.secretsDir, dir)
	default:
		add("secrets-tmpfs", checkOK, "%s is on tmpfs", env.secretsDir)
	}

	switch synced, err := env.ntpSynced(ctx); {
	case err != nil:
		add("clock", checkWarn, "cannot tell whether the clock is synchronized (%v); certificates and tokens depend on it", err)
	case !synced:
		add("clock", checkWarn, "the clock is not NTP-synchronized; certificates and tokens depend on it")
	default:
		add("clock", checkOK, "NTP-synchronized")
	}

	switch active, err := env.ufwActive(ctx); {
	case err != nil:
		// ufw not installed: nothing to say about it.
	case active:
		br := embedded.BridgeName
		add("firewall", checkWarn, "ufw is active: published container ports bypass ufw rules, and containers need %[1]s → 53/udp,tcp and 80/tcp allowed for internal names (ufw allow in on %[1]s to any port 53; ufw allow in on %[1]s to any port 80 proto tcp)", br)
	default:
		add("firewall", checkOK, "ufw inactive; restrict the cluster ports to the VPC in the provider firewall")
	}
	return out
}

// checkRuntime checks the container runtime and its bridge network.
func checkRuntime(ctx context.Context, env doctorEnv) []checkResult {
	var out []checkResult
	add := func(name, status, format string, args ...any) {
		out = append(out, checkResult{Name: name, Status: status, Detail: fmt.Sprintf(format, args...)})
	}
	if env.runtimeHost != nil {
		out = append(out, env.runtimeHost(env.subnet)...)
	}
	if env.network != nil {
		out = append(out, env.network()...)
	}
	if env.driverErr != nil {
		add("runtime", checkFail, "%v", env.driverErr)
		return out
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err := env.driver.Ping(pingCtx)
	cancel()
	switch {
	case err != nil && !env.initialized():
		add("runtime", checkWarn, "embedded runtime not running yet; it starts with armada-server or armada-agent after init or join")
		return out
	case err != nil:
		add("runtime", checkFail, "embedded runtime: %v (systemctl status armada-runtime)", err)
		return out
	default:
		add("runtime", checkOK, "embedded runtime reachable")
	}
	if bi, ok := env.driver.(runtime.BridgeInspector); ok && runtime.HasBridge(env.driver) {
		b, err := bi.Bridge(ctx)
		switch {
		case err != nil:
			add("bridge", checkWarn, "cannot inspect the container bridge (internal ingress and DNS will be off): %v", err)
		case !netutil.IsPrivate(b.Gateway):
			add("bridge", checkFail, "container bridge gateway %s is not a private address", b.Gateway)
		default:
			add("bridge", checkOK, "gateway %s, subnet %s", b.Gateway, b.Subnet)
		}
	}
	return out
}

// clusterNetChecks are the cluster network's checks on this host.
func clusterNetChecks(mode string, ip netip.Addr) []checkResult {
	levels := map[int]string{clusternet.CheckOK: checkOK, clusternet.CheckWarn: checkWarn, clusternet.CheckFail: checkFail}
	var out []checkResult
	for _, c := range clusternet.Diagnose(mode, ip) {
		out = append(out, checkResult{Name: c.Name, Status: levels[c.Level], Detail: c.Detail})
	}
	return out
}

func (env doctorEnv) initialized() bool {
	_, err := env.statFile(filepath.Join(env.dataDir, fileAgent))
	return err == nil
}

// conntrackCheck warns while the connection tracking table is close to full:
// past its limit the kernel drops new connections, and clients wait a second
// or more for a retransmit (ADR 0025).
func conntrackCheck(entries, limit int64, ok bool) checkResult {
	c := checkResult{Name: "conntrack", Status: checkOK}
	switch {
	case !ok:
		c.Detail = "no connections tracked yet"
	case entries*100 >= limit*conntrack.WarnPercent:
		c.Status = checkWarn
		c.Detail = fmt.Sprintf("%d of %d tracked connections in use; past the limit new connections are dropped, so raise net.netfilter.nf_conntrack_max or keep connections open longer", entries, limit)
	default:
		c.Detail = fmt.Sprintf("%d of %d tracked connections in use", entries, limit)
	}
	return c
}

// embeddedHostChecks verifies the kernel features the embedded runtime
// uses and that the container subnet is free.
func embeddedHostChecks(subnet netip.Prefix) []checkResult {
	var out []checkResult
	add := func(name, status, format string, args ...any) {
		out = append(out, checkResult{Name: name, Status: status, Detail: fmt.Sprintf(format, args...)})
	}
	if b, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		add("cgroup", checkFail, "cgroup v2 (unified hierarchy) is required")
	} else if missing := missingFields(string(b), "cpu", "memory", "pids"); len(missing) > 0 {
		add("cgroup", checkFail, "cgroup v2 controllers missing: %s", strings.Join(missing, ", "))
	} else {
		add("cgroup", checkOK, "cgroup v2 with cpu, memory, pids")
	}
	if b, err := os.ReadFile("/proc/filesystems"); err == nil && !strings.Contains(string(b), "\toverlay\n") {
		add("overlayfs", checkWarn, "overlay filesystem not loaded yet (armada-runtime.service loads it; otherwise modprobe overlay)")
	} else if err == nil {
		add("overlayfs", checkOK, "available")
	}
	switch containerd.SELinux() {
	case containerd.SELinuxConfined:
		add("selinux", checkOK, "containers run as container_t, each with its own categories")
	case containerd.SELinuxNoPolicy:
		add("selinux", checkWarn, "SELinux is enabled but its policy has no container types, so containers are not confined by it; install the container-selinux policy")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		add("iptables", checkFail, "iptables not found; container networking needs it")
	} else {
		add("iptables", checkOK, "found")
	}
	out = append(out, conntrackCheck(conntrack.New().Read()))
	if subnet.IsValid() {
		routes, err := readRoutes("/proc/net/route")
		switch {
		case err != nil:
			add("subnet", checkWarn, "cannot read routes: %v", err)
		default:
			clash := ""
			for _, r := range routes {
				if r.iface != embedded.BridgeName && r.dst.Bits() > 0 && r.dst.Overlaps(subnet) {
					clash = fmt.Sprintf("%s via %s", r.dst, r.iface)
					break
				}
			}
			if clash != "" {
				add("subnet", checkFail, "container subnet %s overlaps route %s; pick another with --container-subnet", subnet, clash)
			} else {
				add("subnet", checkOK, "container subnet %s is free", subnet)
			}
		}
	}
	return out
}

func missingFields(s string, want ...string) []string {
	have := map[string]bool{}
	for _, f := range strings.Fields(s) {
		have[f] = true
	}
	var missing []string
	for _, w := range want {
		if !have[w] {
			missing = append(missing, w)
		}
	}
	return missing
}

type route struct {
	iface string
	dst   netip.Prefix
}

// readRoutes parses the IPv4 routing table in /proc/net/route format.
func readRoutes(path string) ([]route, error) {
	f, err := os.Open(path) //nolint:gosec // a fixed /proc path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parseRoutes(f)
}

func parseRoutes(r io.Reader) ([]route, error) {
	var out []route
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		dst, err1 := procHexAddr(f[1])
		mask, err2 := procHexAddr(f[7])
		if err1 != nil || err2 != nil {
			continue
		}
		bits := 0
		for _, b := range mask.As4() {
			for ; b&0x80 != 0; b <<= 1 {
				bits++
			}
		}
		out = append(out, route{iface: f[0], dst: netip.PrefixFrom(dst, bits).Masked()})
	}
	return out, sc.Err()
}

// procHexAddr decodes a little-endian hex IPv4 address from /proc.
func procHexAddr(s string) (netip.Addr, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return netip.Addr{}, fmt.Errorf("bad address %q", s)
	}
	return netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]}), nil
}

func doctorPrivateIP(env doctorEnv) (netip.Addr, error) {
	if env.privateIP != "" {
		return netutil.CheckNodeIP(env.privateIP)
	}
	ip, err := env.detectIP()
	if err != nil {
		return netip.Addr{}, err
	}
	return netutil.CheckNodeIP(ip.String())
}

// checkListeners reports Armada's ports listening on a wildcard or public
// address (e.g. an older version, or another service in the way).
func checkListeners(env doctorEnv) []checkResult {
	ls, err := env.listeners()
	if err != nil {
		return []checkResult{{Name: "listeners", Status: checkWarn, Detail: fmt.Sprintf("cannot list listening sockets: %v", err)}}
	}
	var bad []string
	for _, l := range ls {
		for _, p := range env.clusterPort {
			if l.Port() == p && (l.Addr().IsUnspecified() || !netutil.IsPrivate(l.Addr())) {
				bad = append(bad, l.String())
			}
		}
	}
	if len(bad) > 0 {
		return []checkResult{{Name: "listeners", Status: checkFail, Detail: "cluster ports listening publicly: " + strings.Join(bad, ", ")}}
	}
	return []checkResult{{Name: "listeners", Status: checkOK, Detail: "no cluster port listens on a public or wildcard address"}}
}

// checkDataDir verifies the permissions of key material, if present.
func checkDataDir(env doctorEnv) []checkResult {
	fi, err := env.statFile(env.dataDir)
	if err != nil {
		return []checkResult{{Name: "data-dir", Status: checkOK, Detail: env.dataDir + " does not exist yet"}}
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return []checkResult{{Name: "data-dir", Status: checkFail, Detail: fmt.Sprintf("%s is mode %o; want 0700", env.dataDir, fi.Mode().Perm())}}
	}
	var bad []string
	for _, name := range []string{fileCAKey, fileServerKey, fileNodeKey, fileMasterKey, fileEtcdKey, fileAgent} {
		fi, err := env.statFile(filepath.Join(env.dataDir, name))
		if err != nil {
			continue
		}
		if fi.Mode().Perm()&0o077 != 0 {
			bad = append(bad, fmt.Sprintf("%s (%o)", name, fi.Mode().Perm()))
		}
	}
	if len(bad) > 0 {
		return []checkResult{{Name: "data-dir", Status: checkFail, Detail: "readable by others, want 0600: " + strings.Join(bad, ", ")}}
	}
	return []checkResult{{Name: "data-dir", Status: checkOK, Detail: env.dataDir + " and its key files are private"}}
}

// procListeners returns listening TCP sockets from /proc/net/tcp{,6}.
func procListeners() ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(f) //nolint:gosec // fixed /proc paths
		if err != nil {
			if f == "/proc/net/tcp6" {
				continue // IPv6 disabled
			}
			return nil, err
		}
		ls, err := parseProcNetTCP(file)
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, ls...)
	}
	return out, nil
}

const tcpListen = "0A"

// parseProcNetTCP parses the format of /proc/net/tcp and /proc/net/tcp6
// and returns the local addresses of listening sockets.
func parseProcNetTCP(r io.Reader) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false // header
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != tcpListen {
			continue
		}
		ap, err := parseProcAddr(fields[1])
		if err != nil {
			return nil, err
		}
		out = append(out, ap)
	}
	return out, sc.Err()
}

// parseProcAddr decodes "0100007F:1F90": the address is in host byte order
// per 32-bit word (little-endian on every platform Armada supports).
func parseProcAddr(s string) (netip.AddrPort, error) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", s)
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("bad port in %q", s)
	}
	raw, err := hex.DecodeString(host)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", s)
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	addr, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(addr.Unmap(), uint16(p)), nil
}

func timedatectlSynced(ctx context.Context) (bool, error) {
	out, err := exec.CommandContext(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value").Output()
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) == "yes", nil
}

func ufwActive(ctx context.Context) (bool, error) {
	out, err := exec.CommandContext(ctx, "ufw", "status").Output()
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(strings.TrimSpace(string(out)), "Status: active"), nil
}

// existingAncestor returns dir or its nearest parent that exists.
func existingAncestor(dir string) string {
	for {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return dir
		}
		dir = parent
	}
}
