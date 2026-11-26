package daemon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/cli"
	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/pki"
)

// The daemon parity harness (ADR 0055, pull request 18): every case runs
// Go's armadad in process (cli.Run with NewRootCommand) and the Rust one
// (ARMADA_DAEMON_BIN, a build of daemon/ with the test-hooks feature) with
// the same arguments, environment, standard input, and a case directory
// prepared afresh from the same fixtures before each run. Programs the
// commands start (systemctl, cosign, etcd) are stand-ins first in PATH
// that log what they were asked. Standard output, standard error, the exit
// code, and every file left in the case directory (with its mode; issued
// certificates by what they name, keys by mode) must match. Without
// ARMADA_DAEMON_BIN only Go's runs, which keeps the cases themselves
// checked.
//
// The cases are the ones below, every example line of every command the
// Rust armadad has, and every command's help (stubs included: the tree is
// whole).

// rustDaemonCommands are the commands the Rust armadad has (ADR 0055, pull
// requests 18a and 18b): every command.
var rustDaemonCommands = []string{
	"armadad version", "armadad endpoint", "armadad endpoint show", "armadad endpoint set",
	"armadad etcd", "armadad upgrade", "armadad runtime",
	"armadad backup", "armadad backup list", "armadad restore", "armadad user renew", "armadad runtime-log",
	"armadad init", "armadad join", "armadad server", "armadad server join", "armadad agent",
	"armadad runtime reset", "armadad runtime migrate", "armadad doctor",
}

// daemonCase is one case.
type daemonCase struct {
	name  string
	args  []string
	stdin string
	env   map[string]string
	// setup writes the case's files into dir, the case directory, whose
	// data directory is dir/data.
	setup func(t *testing.T, dir string)
	// active units the systemctl stand-in reports active; down are those
	// that stop answering after a restart; fail are systemctl verbs that
	// fail.
	active, down, fail []string
	// upgrade runs upgrader.run on Go's side (newUpgradeCommand refuses
	// anyone but root and looks for the latest release itself); the Rust
	// side runs `armadad upgrade` with the test hooks standing for both.
	upgrade *upgradeCase
	// during runs while the command runs (a lock another process holds).
	during func(t *testing.T, dir string) func()
	// state is what a case of the commands that need the cluster's state
	// needs (parity_state_test.go).
	state *stateCase
	// rust, when set, is where the Rust armadad does something else on
	// purpose (parity_units_test.go): it turns Go's result into the one
	// the Rust armadad must give.
	rust func(daemonResult) daemonResult
	// rustOnly cases run the Rust armadad alone, for a path Go's armadad
	// does not have (the rollback to the last Go release); it judges the
	// result.
	rustOnly func(t *testing.T, dir string, r daemonResult)
}

type upgradeCase struct {
	current, target    string
	noRestart, require bool
}

type daemonResult struct {
	Code           int
	Stdout, Stderr string
	Files          []string
}

type daemonHarness struct {
	// rec records the cases for the Rust replay (-record-fixtures).
	rec *daemonRecorder

	bin      string
	standins string
	fx       fixtures
	// sf, bucket, and etcdDir serve the state commands' cases: their
	// fixtures, the control plane's stand-in bucket, and the directory
	// holding the pinned etcd and etcdutl (ARMADA_ETCD_DIR).
	sf      stateFixtures
	bucket  *stateBucket
	etcdDir string
}

// fixtureValidity is the fixtures' certificates' (within the CA's ten
// years): the cases recorded for the Rust replay hold them.
const fixtureValidity = 9 * 365 * 24 * time.Hour

// fixtures are made once, so both runs of a case read the same bytes.
type fixtures struct {
	caCert, caKey, serverCert, serverKey, publicCert, publicKey, nodeCert, nodeKey []byte
}

func newFixtures(t *testing.T) fixtures {
	t.Helper()
	ca, err := pki.NewCA("parity")
	if err != nil {
		t.Fatal(err)
	}
	issue := func(id pki.Identity, ip string, server bool) ([]byte, []byte) {
		c, k, err := ca.Issue(pki.IssueRequest{Identity: id, DNSNames: []string{pki.ServerName}, IPs: []net.IP{net.ParseIP(ip)}, Server: server, Client: !server, Validity: fixtureValidity})
		if err != nil {
			t.Fatal(err)
		}
		return c, k
	}
	f := fixtures{caCert: ca.CertPEM}
	f.caKey, err = ca.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	f.serverCert, f.serverKey = issue(pki.Identity{Kind: pki.KindServer, Name: "s1"}, "10.0.0.5", true)
	f.publicCert, f.publicKey = issue(pki.Identity{Kind: pki.KindServer, Name: "s2"}, "203.0.113.9", true)
	f.nodeCert, f.nodeKey = issue(pki.Identity{Kind: pki.KindNode, Name: "n1"}, "10.0.0.6", false)
	return f
}

// Stand-ins first in PATH.
const (
	standinSystemctl = `#!/bin/sh
echo "systemctl $*" >> "$STANDIN_LOG"
if [ "$1" = is-active ]; then
	[ -e "$STANDIN_LOG.down.$3" ] && exit 3
	for u in $STANDIN_ACTIVE; do [ "$u" = "$3" ] && exit 0; done
	exit 3
fi
for v in $STANDIN_FAIL; do
	if [ "$v" = "$1" ]; then echo "Failed to $1 $2: Unit $2 not found."; exit 5; fi
done
if [ "$1" = restart ]; then
	for u in $STANDIN_DOWN; do [ "$u" = "$2" ] && : > "$STANDIN_LOG.down.$2"; done
fi
exit 0
`
	standinCosign = `#!/bin/sh
id=""
while [ $# -gt 0 ]; do
	[ "$1" = --certificate-identity ] && id="$2"
	shift
done
echo "cosign verify-blob for $id" >> "$STANDIN_LOG"
if [ -n "$STANDIN_COSIGN_FAIL" ]; then echo "Error: none of the expected identities matched"; exit 1; fi
echo "Verified OK"
`
	// timedatectl and ufw answer what the case says (doctor).
	standinTimedatectl = `#!/bin/sh
[ "$STANDIN_NTP" = fail ] && exit 1
echo "$STANDIN_NTP"
`
	standinUfw = `#!/bin/sh
[ -z "$STANDIN_UFW" ] && exit 1
printf '%s\n' "$STANDIN_UFW"
`
	standinEtcd = `#!/bin/sh
n=0
for v in $(env | cut -d= -f1); do case "$v" in ETCD_*) n=$((n+1));; esac; done
echo "etcd $*"
echo "etcd environment: $n ETCD_ variables"
`
)

func newDaemonHarness(t *testing.T) *daemonHarness {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{"systemctl": standinSystemctl, "cosign": standinCosign, "timedatectl": standinTimedatectl, "ufw": standinUfw} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bin := os.Getenv("ARMADA_DAEMON_BIN")
	if bin != "" {
		var err error
		if bin, err = filepath.Abs(bin); err != nil {
			t.Fatal(err)
		}
	}
	h := &daemonHarness{bin: bin, standins: dir, fx: newFixtures(t), bucket: newStateBucket(t)}
	h.sf = newStateFixtures(t, h.fx)
	if d := os.Getenv("ARMADA_ETCD_DIR"); d != "" {
		if d, err := filepath.Abs(d); err == nil {
			if _, err := os.Stat(filepath.Join(d, "etcdutl")); err == nil {
				h.etcdDir = d
			}
		}
	}
	return h
}

func (h *daemonHarness) env(dir string, c daemonCase) map[string]string {
	path := os.Getenv("PATH")
	if c.env["NO_COSIGN"] == "" {
		path = h.standins + string(os.PathListSeparator) + path
	} else {
		// systemctl only.
		only := filepath.Join(dir, "standins-no-cosign")
		_ = os.MkdirAll(only, 0o700)
		_ = os.Symlink(filepath.Join(h.standins, "systemctl"), filepath.Join(only, "systemctl"))
		path = only + string(os.PathListSeparator) + path
	}
	env := map[string]string{
		"HOME":                       filepath.Join(dir, "home"),
		"PATH":                       path,
		"XDG_CACHE_HOME":             filepath.Join(dir, "cache"),
		"TZ":                         "UTC",
		"ARMADA_NO_UPDATE_CHECK":     "1",
		"ARMADA_CONFIG":              "",
		"ARMADA_DOWNLOAD_BASE":       "",
		"ARMADA_REQUIRE_SIGNATURE":   "",
		"CI":                         "",
		"STANDIN_LOG":                filepath.Join(dir, "standin.log"),
		"STANDIN_ACTIVE":             strings.Join(c.active, " "),
		"STANDIN_DOWN":               strings.Join(c.down, " "),
		"STANDIN_FAIL":               strings.Join(c.fail, " "),
		"STANDIN_COSIGN_FAIL":        "",
		"ARMADA_DAEMON_TEST_RUN_DIR": filepath.Join(dir, "run"),
		// doctor's machine (parity_doctor_test.go).
		"ARMADA_DAEMON_TEST_HOST_ROOT":       filepath.Join(dir, "host"),
		"ARMADA_DAEMON_TEST_NEEDRESTART_DIR": filepath.Join(dir, "needrestart"),
		"STANDIN_NTP":                        "yes",
		"STANDIN_UFW":                        "",
	}
	if c.upgrade != nil {
		// The mirror is the case directory's: the same path in both runs.
		env["ARMADA_DOWNLOAD_BASE"] = "file://" + filepath.Join(dir, "releases")
	}
	for k, v := range c.env {
		if k != "NO_COSIGN" {
			env[k] = v
		}
	}
	h.stateEnv(env, c.state)
	return env
}

// prepare empties the case directory and writes the case's files.
func (h *daemonHarness) prepare(t *testing.T, dir string, c daemonCase) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"home", "cache"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if c.setup != nil {
		c.setup(t, dir)
	}
}

// collect lists every file left in the case directory.
func (h *daemonHarness) collect(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." || rel == "home" || rel == "cache" || strings.HasPrefix(rel, "standins-no-cosign") {
			return nil
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if fi.IsDir() {
			if what, ok := summarizeEtcd(p); ok {
				out = append(out, fmt.Sprintf("%s/ %04o %s", rel, fi.Mode().Perm(), what))
				return filepath.SkipDir
			}
		}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			target, _ := os.Readlink(p)
			out = append(out, fmt.Sprintf("%s -> %s", rel, target))
		case fi.IsDir():
			out = append(out, fmt.Sprintf("%s/ %04o", rel, fi.Mode().Perm()))
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out = append(out, fmt.Sprintf("%s %04o\n%s", rel, fi.Mode().Perm(), describe(rel, b)))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// describe is a file's content as compared: an issued certificate by what
// it names (its key and serial are new each run), a new key by being one,
// anything else as it is.
func describe(rel string, b []byte) string {
	switch {
	case strings.HasSuffix(rel, "member.crt"):
		c, err := pki.ParseCertPEM(b)
		if err != nil {
			return "bad certificate: " + err.Error()
		}
		var ips []string
		for _, ip := range c.IPAddresses {
			ips = append(ips, ip.String())
		}
		return fmt.Sprintf("certificate %s for %v, %v days, usages %v", c.Subject.CommonName, ips, int(c.NotAfter.Sub(c.NotBefore).Hours()/24), c.ExtKeyUsage)
	case strings.HasSuffix(rel, "member.key"):
		return fmt.Sprintf("a key: %v", bytes.Contains(b, []byte("PRIVATE KEY")))
	case strings.HasSuffix(rel, ".tar") && bytes.HasPrefix(b, []byte{0x1f, 0x8b}):
		return realDescribeArchive(b)
	case strings.HasSuffix(rel, ".config"):
		return describeClientConfig(b)
	}
	return string(b)
}

// realRestartService is restartService as the package has it (TestMain
// replaces it).
func realRestartService(ctx context.Context) (string, error) {
	for _, unit := range []string{"armada-server", "armada-agent"} {
		if unitActive(ctx, unit) {
			return unit, systemctl(ctx, "restart", unit)
		}
	}
	return "", nil
}

func (h *daemonHarness) runGo(t *testing.T, dir string, c daemonCase) daemonResult {
	t.Helper()
	h.prepare(t, dir, c)
	for k, v := range h.env(dir, c) {
		t.Setenv(k, v)
	}
	h.rec.snapshot(t, dir)
	oldRun, oldExec, oldDetect, oldRestart := runDir, execProgram, detectEndpoint, restartService
	runDir, detectEndpoint, restartService = filepath.Join(dir, "run"), netutil.DetectEndpoint, realRestartService
	// The package's tests run etcd members on loopback ports without
	// fsync (etcd_ports_test.go); armadad etcd works out the real member.
	oldAddr, oldPorts, oldFsync := etcdAddrOverride, etcdPorts, etcdNoFsync
	etcdAddrOverride, etcdNoFsync = netip.Addr{}, false
	etcdPorts = func(string) (int, int) { return etcd.DefaultClientPort, etcd.DefaultPeerPort }
	defer func() { etcdAddrOverride, etcdPorts, etcdNoFsync = oldAddr, oldPorts, oldFsync }()
	var out, errb bytes.Buffer
	// `armadad etcd` replaces itself with etcd: the stand-in runs here
	// with what it would have been given, writing where armadad wrote.
	execProgram = func(argv0 string, argv []string, envv []string) error {
		cmd := exec.Command(argv0, argv[1:]...)
		cmd.Env, cmd.Stdout, cmd.Stderr = envv, &out, &errb
		return cmd.Run()
	}
	defer func() { runDir, execProgram, detectEndpoint, restartService = oldRun, oldExec, oldDetect, oldRestart }()
	defer h.stateGo(c.state)()
	defer doctorGo(dir)()
	record, stop := h.stateRun(t, dir, c.state)
	defer stop()
	if c.during != nil {
		defer c.during(t, dir)()
	}
	code := 0
	if u := c.upgrade; u != nil {
		code = h.runGoUpgrade(dir, u, &out, &errb)
	} else {
		// cobra writes completion errors to os.Stderr itself.
		r0, w0, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		direct := make(chan []byte)
		go func() {
			b, _ := io.ReadAll(r0)
			direct <- b
		}()
		stderr := os.Stderr
		os.Stderr = w0
		// No arguments are none: cobra reads the test binary's own for nil.
		args := c.args
		if args == nil {
			args = []string{}
		}
		code = cli.Run(context.Background(), NewRootCommand(), args, strings.NewReader(c.stdin), &out, &errb)
		os.Stderr = stderr
		_ = w0.Close()
		pre := <-direct
		errb = *bytes.NewBuffer(append(pre, errb.Bytes()...))
	}
	record()
	return daemonResult{Code: code, Stdout: h.stdout(c, out.Bytes()), Stderr: errb.String(), Files: h.collect(t, dir)}
}

// runGoUpgrade is newUpgradeCommand's run past its root check and its look
// for the latest release, with the case directory's paths.
func (h *daemonHarness) runGoUpgrade(dir string, c *upgradeCase, out, errb *bytes.Buffer) int {
	u := upgrader{
		base:        os.Getenv("ARMADA_DOWNLOAD_BASE"),
		binDir:      filepath.Join(dir, "bin"),
		unitDir:     filepath.Join(dir, "units"),
		needrestart: filepath.Join(dir, "needrestart"),
		requireSig:  c.require || os.Getenv("ARMADA_REQUIRE_SIGNATURE") == "1",
		restart:     !c.noRestart,
		goarch:      runtime.GOARCH,
		systemctl:   systemctl,
		isActive:    unitActive,
		out:         out,
		warn:        errb,
	}
	if u.base == "" {
		u.base = defaultDownloadBase
	}
	if p, err := exec.LookPath("cosign"); err == nil {
		u.cosign = p
	}
	if err := u.run(context.Background(), c.current, c.target); err != nil {
		_, _ = fmt.Fprintf(errb, "Error: %v\n", err)
		return 1
	}
	return 0
}

func (h *daemonHarness) runRust(t *testing.T, dir string, c daemonCase) daemonResult {
	t.Helper()
	h.prepare(t, dir, c)
	args, env := h.rustInvocation(dir, c)
	h.rec.snapshot(t, dir)
	record, stop := h.stateRun(t, dir, c.state)
	defer stop()
	if c.during != nil {
		defer c.during(t, dir)()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.bin, args...)
	cmd.Dir = dir
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdin = strings.NewReader(c.stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %s: %v", h.bin, err)
	}
	record()
	return daemonResult{Code: code, Stdout: h.stdout(c, out.Bytes()), Stderr: errb.String(), Files: h.collect(t, dir)}
}

// rustInvocation is the arguments and environment the Rust armadad runs a
// case with (an upgrade's with the test hooks standing for root, the
// directories, and the version).
func (h *daemonHarness) rustInvocation(dir string, c daemonCase) ([]string, map[string]string) {
	args := c.args
	env := h.env(dir, c)
	if u := c.upgrade; u != nil {
		args = []string{"upgrade", "--version", u.target}
		if u.noRestart {
			args = append(args, "--no-restart")
		}
		if u.require {
			args = append(args, "--require-signature")
		}
		maps.Copy(env, map[string]string{
			"ARMADA_DAEMON_TEST_EUID":            "0",
			"ARMADA_DAEMON_TEST_BIN_DIR":         filepath.Join(dir, "bin"),
			"ARMADA_DAEMON_TEST_UNIT_DIR":        filepath.Join(dir, "units"),
			"ARMADA_DAEMON_TEST_NEEDRESTART_DIR": filepath.Join(dir, "needrestart"),
			"ARMADA_DAEMON_TEST_VERSION":         u.current,
		})
	}
	return args, env
}

// daemonToolchain is the compiler version names; elapsed are the times an
// upgrade's steps took.
var (
	daemonToolchain = regexp.MustCompile(`\b(go[0-9][0-9.a-z]*|rust[0-9][0-9.a-z-]*)\b`)
	elapsed         = regexp.MustCompile(`\b(in|after) [0-9][0-9.]*(ms|s|m[0-9.]*s?)\b`)
)

func normalizeDaemon(s string) string {
	s = daemonToolchain.ReplaceAllString(s, "TOOLCHAIN")
	s = stateTemp.ReplaceAllString(s, ".$1-N")
	return elapsed.ReplaceAllString(s, "$1 ELAPSED")
}

func compareDaemon(t *testing.T, goRes, rust daemonResult) {
	t.Helper()
	if goRes.Code != rust.Code {
		t.Errorf("exit code: Go %d, Rust %d", goRes.Code, rust.Code)
	}
	if normalizeDaemon(goRes.Stdout) != normalizeDaemon(rust.Stdout) {
		t.Errorf("stdout differs:\n--- Go\n%s--- Rust\n%s", goRes.Stdout, rust.Stdout)
	}
	if normalizeDaemon(goRes.Stderr) != normalizeDaemon(rust.Stderr) {
		t.Errorf("stderr differs:\n--- Go\n%s--- Rust\n%s", goRes.Stderr, rust.Stderr)
	}
	if !reflect.DeepEqual(goRes.Files, rust.Files) {
		t.Errorf("files differ:\n--- Go\n%s\n--- Rust\n%s", strings.Join(goRes.Files, "\n"), strings.Join(rust.Files, "\n"))
	}
}

func TestDaemonParity(t *testing.T) {
	if *recordFixtures {
		// The recording's commands find only what any Linux machine has,
		// so the replay's PATH can be the same.
		t.Setenv("PATH", recordPath)
	}
	h := newDaemonHarness(t)
	h.rec = newDaemonRecorder(t, h)
	t.Cleanup(func() { h.rec.write(t) })
	cases := daemonCases(h)
	cases = append(cases, h.stateCases(t)...)
	cases = append(cases, h.serveCases()...)
	cases = append(cases, h.doctorCases(t)...)
	cases = append(cases, daemonExampleCases(t)...)
	cases = append(cases, daemonHelpCases()...)
	cases = append(cases, h.unitCases()...)
	names := map[string]bool{}
	for _, c := range cases {
		if names[c.name] {
			t.Fatalf("two cases named %q", c.name)
		}
		names[c.name] = true
		t.Run(c.name, func(t *testing.T) {
			if s := c.state; s != nil {
				if s.etcd && h.bin != "" && h.etcdDir == "" {
					t.Skip("ARMADA_ETCD_DIR names no directory with the pinned etcd and etcdutl (sh scripts/etcd-cache.sh writes them into .cache/etcd)")
				}
				s := *s
				s.ports = [2]int{nextEtcdPort(), nextEtcdPort()}
				c.state = &s
			}
			dir := t.TempDir()
			t.Chdir(dir)
			if c.rustOnly != nil {
				if h.bin == "" {
					t.Skip("a case of the Rust armadad alone (ARMADA_DAEMON_BIN)")
				}
				r := h.runRust(t, dir, c)
				if os.Getenv("ARMADA_PARITY_VERBOSE") != "" {
					t.Logf("exit %d\n--- stdout\n%s--- stderr\n%s--- files\n%s", r.Code, r.Stdout, r.Stderr, strings.Join(r.Files, "\n"))
				}
				c.rustOnly(t, dir, r)
				h.rec.add(t, c, r)
				return
			}
			goRes := h.runGo(t, dir, c)
			if os.Getenv("ARMADA_PARITY_VERBOSE") != "" {
				t.Logf("exit %d\n--- stdout\n%s--- stderr\n%s", goRes.Code, goRes.Stdout, goRes.Stderr)
			}
			want := rustWants(c, goRes)
			h.rec.add(t, c, want)
			if h.bin == "" {
				return
			}
			compareDaemon(t, want, h.runRust(t, dir, c))
		})
	}
	t.Logf("%d cases", len(cases))
}

// rustDaemonCommand reports whether the Rust armadad has the command at
// path.
func rustDaemonCommand(path string) bool {
	return slices.Contains(rustDaemonCommands, path)
}

// daemonShellWords splits an example as a shell would, as far as the
// examples need (cli's shellWords).
func daemonShellWords(line string) []string {
	var words []string
	var cur strings.Builder
	in, quote := false, rune(0)
	flush := func() {
		if in {
			words = append(words, cur.String())
			cur.Reset()
			in = false
		}
	}
	for _, r := range line {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			quote, in = r, true
		case (r == '<' || r == '>') && !in:
			flush()
			return words
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
			in = true
		}
	}
	flush()
	return words
}

// daemonExampleCases runs every example line of every command the Rust
// armadad has, sudo left out. They name the machine's own data directory,
// which a test machine does not have: both fail alike, reading only.
func daemonExampleCases(t *testing.T) []daemonCase {
	t.Helper()
	var out []daemonCase
	seen := map[string]bool{}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		for _, line := range strings.Split(c.Example, "\n") {
			if i := strings.Index(line, "#"); i >= 0 {
				line = line[:i]
			}
			for _, part := range strings.FieldsFunc(strings.ReplaceAll(line, "&&", ";"), func(r rune) bool { return r == ';' || r == '|' }) {
				words := daemonShellWords(part)
				for len(words) > 0 && words[0] == "sudo" {
					words = words[1:]
				}
				if len(words) < 2 || words[0] != Name {
					continue
				}
				found, _, err := NewRootCommand().Find(words[1:])
				if err != nil || !rustDaemonCommand(found.CommandPath()) {
					continue
				}
				key := strings.Join(words, " ")
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, daemonCase{name: "example " + key, args: words[1:]})
			}
		}
	}
	walk(NewRootCommand())
	if len(out) == 0 {
		t.Fatal("no example lines")
	}
	return out
}

// daemonHelpCases asks every command for its help, hidden ones included,
// and the completion commands for theirs and their scripts.
func daemonHelpCases() []daemonCase {
	var out []daemonCase
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		args := append(strings.Fields(c.CommandPath())[1:], "--help")
		out = append(out, daemonCase{name: "help " + c.CommandPath(), args: args})
	}
	walk(NewRootCommand())
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		out = append(out,
			daemonCase{name: "help completion " + shell, args: []string{"completion", shell, "--help"}},
			daemonCase{name: "completion " + shell, args: []string{"completion", shell}},
			daemonCase{name: "completion " + shell + " no descriptions", args: []string{"completion", shell, "--no-descriptions"}})
	}
	return out
}

// writeFile writes a fixture file, making its directory.
func fxWrite(t *testing.T, p string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// agentJSON writes data/agent.json.
func agentJSON(body string) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		fxWrite(t, filepath.Join(dir, "data", fileAgent), []byte(body), 0o600)
	}
}

// serverDir writes a server's data directory: the CA, its certificate,
// and agent.json, each with mode.
func (h *daemonHarness) serverDir(cert, key []byte, mode os.FileMode, more ...func(*testing.T, string)) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		data := filepath.Join(dir, "data")
		fxWrite(t, filepath.Join(data, fileCACert), h.fx.caCert, 0o600)
		fxWrite(t, filepath.Join(data, fileCAKey), h.fx.caKey, mode)
		fxWrite(t, filepath.Join(data, fileServerCert), cert, 0o600)
		fxWrite(t, filepath.Join(data, fileServerKey), key, 0o600)
		if err := os.Chmod(data, 0o700); err != nil {
			t.Fatal(err)
		}
		fxWrite(t, filepath.Join(dir, "etcdbin", "etcd"), []byte(standinEtcd), 0o755)
		for _, m := range more {
			m(t, dir)
		}
	}
}

// ranMember gives the data directory an etcd member that ran: a
// write-ahead log and a database.
func ranMember(t *testing.T, dir string) {
	t.Helper()
	member := filepath.Join(dir, "data", "etcd", "data", "member")
	fxWrite(t, filepath.Join(member, "wal", "0000000000000000-0000000000000000.wal"), []byte("wal"), 0o600)
	fxWrite(t, filepath.Join(member, "snap", "db"), []byte("db"), 0o600)
	for _, d := range []string{filepath.Join(dir, "data", "etcd"), filepath.Join(dir, "data", "etcd", "data"), member, filepath.Join(member, "wal"), filepath.Join(member, "snap")} {
		if err := os.Chmod(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

// holdDB holds the member's database as a running member would.
func holdDB(t *testing.T, dir string) func() {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, "data", "etcd", "data", "member", "snap", "db"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	return func() { _ = f.Close() }
}

// release writes a release's files under dir/releases/TAG: the archive
// (with mod changing what it holds), checksums.txt, and the signature
// bundle.
func fxRelease(tag string, mod func(map[string]string), badSum bool) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		files := map[string]string{
			"armadad":                                "#!/bin/sh\necho new armadad\n",
			"armada":                                 "#!/bin/sh\necho new armada\n",
			"deploy/systemd/armada-server.service":   "[Service]\nExecStart=/usr/local/bin/armadad server\n",
			"deploy/systemd/armada-agent.service":    "[Service]\nExecStart=/usr/local/bin/armadad agent\n",
			"deploy/systemd/nested/armada-x.service": "skipped\n",
			"LICENSE":                                "Apache-2.0\n",
			"README.md":                              "readme\n",
		}
		if mod != nil {
			mod(files)
		}
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		names := slices.Sorted(maps.Keys(files))
		for _, n := range names {
			if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o755, Size: int64(len(files[n])), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(files[n])); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.WriteHeader(&tar.Header{Name: "deploy/", Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		archive := fmt.Sprintf("armada_%s_linux_%s.tar.gz", strings.TrimPrefix(tag, "v"), runtime.GOARCH)
		sum := sha256.Sum256(buf.Bytes())
		if badSum {
			sum[0] ^= 0xff
		}
		rel := filepath.Join(dir, "releases", tag)
		fxWrite(t, filepath.Join(rel, archive), buf.Bytes(), 0o644)
		fxWrite(t, filepath.Join(rel, "checksums.txt"), []byte(hex.EncodeToString(sum[:])+"  "+archive+"\n0000  other.tar.gz\n"), 0o644)
		fxWrite(t, filepath.Join(rel, "checksums.txt.sigstore.json"), []byte("{}\n"), 0o644)
	}
}

// machine makes the directories upgrade installs into.
func fxMachine(units, needrestart bool) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		fxWrite(t, filepath.Join(dir, "bin", "armadad"), []byte("old armadad\n"), 0o755)
		fxWrite(t, filepath.Join(dir, "bin", "armada"), []byte("old armada\n"), 0o755)
		if units {
			fxWrite(t, filepath.Join(dir, "units", "armada-server.service"), []byte("old\n"), 0o644)
		}
		if needrestart {
			if err := os.MkdirAll(filepath.Join(dir, "needrestart"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func fxAll(fs ...func(*testing.T, string)) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		for _, f := range fs {
			f(t, dir)
		}
	}
}

// daemonCases are the cases written for the harness.
func daemonCases(h *daemonHarness) []daemonCase {
	const plain = `{"nodeId": "n1", "privateIp": "10.0.0.6", "servers": ["10.0.0.5:7443"], "runtime": "supervisor", "network": "plain"}`
	dd := []string{"--data-dir", "data"}
	with := func(args ...string) []string { return append(slices.Clone(args), dd...) }
	server := h.serverDir(h.fx.serverCert, h.fx.serverKey, 0o600)
	up := func(tag string) *upgradeCase { return &upgradeCase{current: "v0.1.0-alpha.41", target: tag} }
	cases := []daemonCase{
		// The framework.
		{name: "root", args: nil},
		{name: "root help flag", args: []string{"-h"}},
		{name: "unknown command", args: []string{"nope"}},
		{name: "unknown command suggestion", args: []string{"doctr"}},
		{name: "help topic", args: []string{"help", "runtime", "migrate"}},
		{name: "help unknown topic", args: []string{"help", "nope"}},
		{name: "noun alone", args: []string{"endpoint"}},
		{name: "noun unknown verb", args: []string{"endpoint", "get"}},
		{name: "noun suggestion", args: []string{"user", "renw"}},
		{name: "too many arguments", args: []string{"version", "x"}},
		{name: "backup argument", args: []string{"backup", "x"}},
		{name: "unknown flag", args: []string{"doctor", "--nope"}},
		{name: "flag needs value", args: []string{"endpoint", "show", "--data-dir"}},
		{name: "bad bool", args: []string{"endpoint", "set", "x", "--no-restart=maybe"}},
		{name: "required flag", args: []string{"runtime", "migrate"}},
		{name: "required flag join", args: []string{"join", "10.0.0.2:7444"}},
		{name: "hidden command help", args: []string{"help", "runtime-log"}},
		{name: "servers alias help", args: []string{"servers", "--help"}},
		{name: "complete root", args: []string{"__complete", ""}},
		{name: "complete flags", args: []string{"__complete", "endpoint", "set", "--"}},
		{name: "complete persistent", args: []string{"__complete", "endpoint", "show", "--d"}},
		{name: "complete required", args: []string{"__complete", "join", "x", "-"}},
		{name: "complete hidden flag", args: []string{"__complete", "server", "--etcd"}},
		{name: "complete no desc", args: []string{"__completeNoDesc", "runtime", ""}},
		{name: "complete slice", args: []string{"__complete", "agent", "--server", "a,b", "--"}},
		{name: "complete unknown", args: []string{"__complete", "nope", ""}},
		{name: "complete etcd unknown flags", args: []string{"__complete", "etcd", "--x", "1", "--"}},

		// version.
		{name: "version", args: []string{"version"}},
		{name: "version json", args: []string{"version", "-o", "json"}},
		{name: "version yaml", args: []string{"version", "-o", "yaml"}},

		// endpoint.
		{name: "endpoint show no data", args: with("endpoint", "show")},
		{name: "endpoint show set", args: with("endpoint", "show"), setup: agentJSON(`{"nodeId": "n1", "privateIp": "10.0.0.6", "servers": ["10.0.0.5:7443"], "network": "plain", "endpoint": "203.0.113.7"}`)},
		{name: "endpoint show behind nat", args: with("endpoint", "show"), setup: agentJSON(`{"nodeId": "n1", "privateIp": "10.0.0.6", "servers": ["10.0.0.5:7443"], "network": "wireguard", "behindNat": true}`)},
		{name: "endpoint show no network", args: with("endpoint", "show"), setup: agentJSON(`{"nodeId": "n1", "privateIp": "10.0.0.6", "servers": ["10.0.0.5:7443"]}`)},
		{name: "endpoint show detected", args: with("endpoint", "show"), setup: agentJSON(plain)},
		{name: "endpoint show no servers", args: with("endpoint", "show"), setup: agentJSON(`{"nodeId": "n1", "servers": []}`)},
		{name: "endpoint show null servers", args: with("endpoint", "show"), setup: agentJSON(`{"nodeId": "n1", "servers": null}`)},
		{name: "endpoint show wrong type", args: with("endpoint", "show"), setup: agentJSON(`{"nodeId": "n1", "servers": ["a"], "mtu": "1400"}`)},
		{name: "endpoint show folded keys", args: with("endpoint", "show"), setup: agentJSON(`{"NODEID": "n1", "Servers": ["a"], "ENDPOINT": "198.51.100.4", "network": "plain"}`)},
		{name: "endpoint show open", args: with("endpoint", "show"), setup: func(t *testing.T, dir string) {
			fxWrite(t, filepath.Join(dir, "data", fileAgent), []byte(plain), 0o644)
		}},
		{name: "endpoint set invalid", args: with("endpoint", "set", "10.0.0.300")},
		{name: "endpoint set private", args: with("endpoint", "set", "127.0.0.1")},
		{name: "endpoint set ipv6", args: with("endpoint", "set", "2001:db8::1")},
		{name: "endpoint set no data", args: with("endpoint", "set", "203.0.113.7")},
		{name: "endpoint set no network", args: with("endpoint", "set", "203.0.113.7", "--no-restart"), setup: agentJSON(`{"nodeId": "n1", "servers": ["a"]}`)},
		{name: "endpoint set none on server", args: with("endpoint", "set", "none"), setup: h.serverDir(h.fx.serverCert, h.fx.serverKey, 0o600, agentJSON(plain))},
		{name: "endpoint set mesh without endpoint", args: with("endpoint", "set", "203.0.113.7"), setup: agentJSON(`{"nodeId": "n1", "servers": ["a"], "network": "mesh"}`)},
		{name: "endpoint set no restart", args: with("endpoint", "set", "203.0.113.7", "--no-restart"), setup: agentJSON(`{"nodeId": "n1", "privateIp": "10.0.0.6", "servers": ["10.0.0.5:7443"], "runtime": "supervisor", "network": "plain", "behindNat": true, "mtu": 1492, "netAgent": "go", "unknown": [1]}`)},
		{name: "endpoint set none", args: with("endpoint", "set", "none"), setup: agentJSON(`{"nodeId": "n1", "servers": ["a"], "network": "wireguard", "endpoint": "203.0.113.7"}`)},
		{name: "endpoint set restarts agent", args: with("endpoint", "set", "198.51.100.4"), setup: agentJSON(plain), active: []string{"armada-agent"}},
		{name: "endpoint set restarts server", args: with("endpoint", "set", "198.51.100.4"), setup: agentJSON(plain), active: []string{"armada-server", "armada-agent"}},
		{name: "endpoint set nothing runs", args: with("endpoint", "set", "198.51.100.4"), setup: agentJSON(plain)},
		{name: "endpoint set restart fails", args: with("endpoint", "set", "198.51.100.4"), setup: agentJSON(plain), active: []string{"armada-agent"}, fail: []string{"restart"}},
		{name: "endpoint set mesh", args: with("endpoint", "set", "198.51.100.4", "--no-restart"), setup: agentJSON(`{"nodeId": "n1", "privateIp": "10.122.0.2", "servers": ["10.122.0.1:7443"], "network": "mesh", "endpoint": "203.0.113.7", "clusterCidr": "10.120.0.0/16", "meshCidr": "10.122.0.0/16"}`)},

		// etcd.
		{name: "etcd not a server", args: with("etcd", "--bin-dir", "etcdbin")},
		{name: "etcd no ca key", args: with("etcd", "--bin-dir", "etcdbin"), setup: func(t *testing.T, dir string) {
			fxWrite(t, filepath.Join(dir, "data", fileServerCert), h.fx.serverCert, 0o600)
		}},
		{name: "etcd open ca key", args: with("etcd", "--bin-dir", "etcdbin"), setup: h.serverDir(h.fx.serverCert, h.fx.serverKey, 0o644)},
		{name: "etcd node certificate", args: with("etcd", "--bin-dir", "etcdbin"), setup: h.serverDir(h.fx.nodeCert, h.fx.nodeKey, 0o600)},
		{name: "etcd public address", args: with("etcd", "--bin-dir", "etcdbin"), setup: h.serverDir(h.fx.publicCert, h.fx.publicKey, 0o600)},
		{name: "etcd no program", args: with("etcd", "--bin-dir", "nothing"), setup: server},
		{name: "etcd no pack", args: with("etcd"), setup: server},
		{name: "etcd first start", args: with("etcd", "--bin-dir", "etcdbin"), setup: server},
		{name: "etcd server flags ignored", args: with("etcd", "--bin-dir", "etcdbin", "--acme-email", "ops@example.com", "--tls=false", "-v", "--metrics-listen", "10.0.0.5:9100", "--etcd-member", "unit"), setup: server},
		{name: "etcd environment", args: with("etcd", "--bin-dir", "etcdbin"), setup: server, env: map[string]string{"ETCD_NAME": "x", "ETCD_DATA_DIR": "/tmp/x"}},
		{name: "etcd joins", args: with("etcd", "--bin-dir", "etcdbin"), setup: h.serverDir(h.fx.serverCert, h.fx.serverKey, 0o600, func(t *testing.T, dir string) {
			fxWrite(t, filepath.Join(dir, "data", fileEtcdInitial), []byte("s0=https://10.0.0.4:2380,s1=https://10.0.0.5:2380\n"), 0o600)
		})},
		{name: "etcd member that ran", args: with("etcd", "--bin-dir", "etcdbin"), setup: h.serverDir(h.fx.serverCert, h.fx.serverKey, 0o600, ranMember)},
		{name: "etcd member that ran joined", args: with("etcd", "--bin-dir", "etcdbin"), setup: h.serverDir(h.fx.serverCert, h.fx.serverKey, 0o600, ranMember, func(t *testing.T, dir string) {
			fxWrite(t, filepath.Join(dir, "data", fileEtcdInitial), []byte("s0=https://10.0.0.4:2380\n"), 0o600)
		})},
		{name: "etcd copy kept", args: with("etcd", "--bin-dir", "etcdbin"), setup: h.serverDir(h.fx.serverCert, h.fx.serverKey, 0o600, ranMember, func(t *testing.T, dir string) {
			fxWrite(t, filepath.Join(dir, "data", "etcd", "data.before-unit", "kept"), []byte("x"), 0o600)
		})},
		{name: "etcd member held", args: with("etcd", "--bin-dir", "etcdbin"), setup: h.serverDir(h.fx.serverCert, h.fx.serverKey, 0o600, ranMember), during: holdDB},
		{name: "etcd member with a link", args: with("etcd", "--bin-dir", "etcdbin"), setup: h.serverDir(h.fx.serverCert, h.fx.serverKey, 0o600, ranMember, func(t *testing.T, dir string) {
			if err := os.Symlink("db", filepath.Join(dir, "data", "etcd", "data", "member", "snap", "link")); err != nil {
				t.Fatal(err)
			}
		})},
		{name: "etcd failed first start", args: with("etcd", "--bin-dir", "etcdbin"), setup: h.serverDir(h.fx.serverCert, h.fx.serverKey, 0o600, func(t *testing.T, dir string) {
			fxWrite(t, filepath.Join(dir, "data", "etcd", "data", "member", "snap", "db"), []byte("half"), 0o600)
		})},
		{name: "etcd certificate kept", args: with("etcd", "--bin-dir", "etcdbin"), setup: server},

		// runtime.
		{name: "runtime not initialized", args: with("runtime")},
		{name: "runtime unknown", args: with("runtime"), setup: agentJSON(`{"nodeId": "n1", "servers": ["a"], "runtime": "docker"}`)},
		{name: "runtime supervisor", args: with("runtime"), setup: agentJSON(plain)},
		{name: "runtime supervisor bin dir missing", args: with("runtime", "--bin-dir", "bins"), setup: agentJSON(plain)},
		{name: "runtime supervisor bin dir", args: with("runtime", "--bin-dir", "bins"), setup: fxAll(agentJSON(plain), func(t *testing.T, dir string) {
			for _, n := range []string{"containerd", "containerd-shim-runc-v2", "runc", "tini", "cni/bridge"} {
				fxWrite(t, filepath.Join(dir, "bins", n), []byte(n), 0o755)
			}
		})},
		{name: "runtime embedded no bundle", args: with("runtime"), setup: agentJSON(`{"nodeId": "n1", "servers": ["a"], "runtime": "embedded"}`)},
		{name: "runtime old agent json", args: with("runtime"), setup: agentJSON(`{"nodeId": "n1", "servers": ["a"]}`)},
		{name: "runtime run dir taken", args: with("runtime"), setup: fxAll(agentJSON(plain), func(t *testing.T, dir string) {
			fxWrite(t, filepath.Join(dir, "run"), []byte("a file"), 0o600)
		})},

		// upgrade.
		{name: "upgrade not root", args: []string{"upgrade", "--version", "v0.1.0-alpha.42"}},
		{name: "upgrade already", upgrade: up("v0.1.0-alpha.41")},
		{name: "upgrade older", upgrade: up("v0.1.0-alpha.40")},
		{name: "upgrade invalid", upgrade: up("1.2")},
	}
	type u = upgradeCase
	upgrades := []struct {
		name   string
		c      upgradeCase
		setup  func(*testing.T, string)
		active []string
		down   []string
		fail   []string
		env    map[string]string
	}{
		{name: "upgrade", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, true)), active: []string{"armada-runtime", "armada-server"}},
		{name: "upgrade agent", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, true)), active: []string{"armada-etcd", "armada-agent"}},
		{name: "upgrade nothing runs", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, false))},
		{name: "upgrade no restart", c: u{target: "v0.1.0-alpha.42", noRestart: true}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, true)), active: []string{"armada-server"}},
		{name: "upgrade no unit directory", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(false, false))},
		{name: "upgrade needrestart set", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, true), func(t *testing.T, dir string) {
			fxWrite(t, filepath.Join(dir, "needrestart", needrestartFile), []byte(needrestartConf), 0o644)
		})},
		{name: "upgrade checksum mismatch", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, true), fxMachine(true, true))},
		{name: "upgrade missing release", c: u{target: "v0.1.0-alpha.43"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, true))},
		{name: "upgrade no armada", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", func(f map[string]string) { delete(f, "armada") }, false), fxMachine(true, true))},
		{name: "upgrade no units in release", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", func(f map[string]string) {
			delete(f, "deploy/systemd/armada-server.service")
			delete(f, "deploy/systemd/armada-agent.service")
		}, false), fxMachine(true, true))},
		{name: "upgrade signature", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, true)), env: map[string]string{}},
		{name: "upgrade signature fails", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, true)), env: map[string]string{"STANDIN_COSIGN_FAIL": "1"}},
		{name: "upgrade no cosign", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, true)), env: map[string]string{"NO_COSIGN": "1"}},
		{name: "upgrade signature required", c: u{target: "v0.1.0-alpha.42", require: true}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, true)), env: map[string]string{"NO_COSIGN": "1"}},
		{name: "upgrade signature required by env", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, true)), env: map[string]string{"NO_COSIGN": "1", "ARMADA_REQUIRE_SIGNATURE": "1"}},
		{name: "upgrade restart fails", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, true)), active: []string{"armada-server"}, fail: []string{"restart"}},
		{name: "upgrade reload fails", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, true)), fail: []string{"daemon-reload"}},
		{name: "upgrade runtime down", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, true)), active: []string{"armada-runtime", "armada-server"}, down: []string{"armada-runtime"}},
		{name: "upgrade server down", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, true)), active: []string{"armada-server"}, down: []string{"armada-server"}},
		{name: "upgrade bad mirror", c: u{target: "v0.1.0-alpha.42"}, setup: fxMachine(true, true), env: map[string]string{"ARMADA_DOWNLOAD_BASE": "ftp://example.com/x"}},
		{name: "upgrade not gzip", c: u{target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, true), func(t *testing.T, dir string) {
			rel := filepath.Join(dir, "releases", "v0.1.0-alpha.42")
			archive := fmt.Sprintf("armada_0.1.0-alpha.42_linux_%s.tar.gz", runtime.GOARCH)
			sum := sha256.Sum256([]byte("not gzip"))
			fxWrite(t, filepath.Join(rel, archive), []byte("not gzip"), 0o644)
			fxWrite(t, filepath.Join(rel, "checksums.txt"), []byte(hex.EncodeToString(sum[:])+" *"+archive+"\n"), 0o644)
		})},
		{name: "upgrade to a pre-release from dev", c: u{current: "dev", target: "v0.1.0-alpha.42"}, setup: fxAll(fxRelease("v0.1.0-alpha.42", nil, false), fxMachine(true, false))},
	}
	for _, x := range upgrades {
		c := x.c
		if c.current == "" {
			c.current = "v0.1.0-alpha.41"
		}
		env := map[string]string{}
		maps.Copy(env, x.env)
		cases = append(cases, daemonCase{name: x.name, upgrade: &c, active: x.active, down: x.down, fail: x.fail, env: env, setup: x.setup})
	}
	return cases
}
