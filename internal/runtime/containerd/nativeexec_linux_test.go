package containerd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/supervisor"
)

// The parity tests of armada-node's runtime exec (ADR 0054 step 4, sixth
// part): ExecApp on the supervisor backend with Go starting runc exec and
// with armada-node starting it, against a fake runc that records what it
// was given. Neither needs root.

// fullProcess is a container's process spec with every field specs-go
// knows that a Linux container can have.
func fullProcess() *specs.Process {
	umask, oom := uint32(0o22), -5
	return &specs.Process{
		Terminal:    true,
		ConsoleSize: &specs.Box{Height: 5, Width: 6},
		User:        specs.User{UID: 1000, GID: 1001, Umask: &umask, AdditionalGids: []uint32{1001, 27}},
		Args:        []string{"/app", "--flag"},
		Env:         []string{"PATH=/usr/bin:/bin", `HTML=<a href="x">&amp;</a>`, "UNI=é\u2028\u2029\t\x01", "EMPTY="},
		Cwd:         "/srv/app",
		Capabilities: &specs.LinuxCapabilities{
			Bounding: []string{"CAP_CHOWN", "CAP_KILL"}, Effective: []string{"CAP_CHOWN"},
			Permitted: []string{"CAP_CHOWN", "CAP_KILL"},
		},
		Rlimits:         []specs.POSIXRlimit{{Type: "RLIMIT_NOFILE", Hard: 1048576, Soft: 1024}},
		NoNewPrivileges: true,
		ApparmorProfile: "armada-default",
		OOMScoreAdj:     &oom,
		Scheduler:       &specs.Scheduler{Policy: "SCHED_OTHER", Nice: 5, Flags: []specs.LinuxSchedulerFlag{"SCHED_FLAG_RESET_ON_FORK"}},
		SelinuxLabel:    "system_u:system_r:container_t:s0:c1,c2",
		IOPriority:      &specs.LinuxIOPriority{Class: "IOPRIO_CLASS_BE", Priority: 4},
		ExecCPUAffinity: &specs.CPUAffinity{Initial: "0", Final: "0-1"},
	}
}

// recordRunc is a fake runc's start: it records its arguments, the
// process spec, its modes, its descriptors and where they lead, its
// session and terminal, signals, umask, directory, environment, and the
// terminal's size into $C.
const recordRunc = `FDS=$(ls /proc/$$/fd | sort -n | tr '\n' ' ')
LINKS=$(for i in 0 1 2; do printf 'fd%s %s; ' $i "$(readlink /proc/$$/fd/$i | sed 's/:\[.*//; s,^/dev/pts/[0-9]*$,pts,')"; done)
{
echo "argv $ARGV"
echo "process $(cat "$PROCESS")"
echo "modes $(stat -c %a "$PROCESS" "$(dirname "$PROCESS")" | tr '\n' ' ')"
echo "fds $FDS"
echo "links $LINKS"
set -- $(cat /proc/$$/stat)
echo "session $([ "$6" = $$ ] && echo leader || echo member) tty $([ "$7" != 0 ] && echo yes || echo no)"
grep -E '^Sig(Blk|Ign)' /proc/$$/status
echo "umask $(umask) cwd $(pwd)"
if [ -t 0 ]; then echo "size $(stty size)"; fi
echo "env $(env | sort | grep -v '^_=' | sha256sum)"
} > "$C"
`

type execResult struct {
	Code           int
	Err            string
	Stdout, Stderr string
	Record         string
}

var (
	execID   = regexp.MustCompile(`exec-[0-9a-f]{12}`)
	fifoDirs = regexp.MustCompile(`fifo/[0-9]+/`)
)

// runExec runs ExecApp with opts on a driver whose fake runc is body
// after recordRunc, through native when set, and returns what the caller
// and the fake runc saw, with the test's directories named alike.
func runExec(ctx context.Context, t *testing.T, native *supervisor.Native, spec specs.Spec, body string, opts runtime.ExecOptions, missingRunc bool) execResult {
	t.Helper()
	rec := filepath.Join(t.TempDir(), "record")
	d := execDriverOn(t, "C="+rec+"\n"+recordRunc+body, spec, native)
	st := d.ctr.(*supervisor.Store)
	if missingRunc {
		if err := os.Remove(st.Shims.Runc); err != nil {
			t.Fatal(err)
		}
	}
	var out, errOut lockedBuffer
	opts.Stdout, opts.Stderr = &out, &errOut
	if opts.TTY {
		opts.Stderr = nil
	}
	code, err := d.ExecApp(ctx, "c1", opts)
	r := execResult{Code: code, Err: errText(err), Stdout: out.String(), Stderr: errOut.String()}
	b, _ := os.ReadFile(rec)
	r.Record = string(b)
	name := func(s string) string {
		s = strings.ReplaceAll(s, d.paths.DataDir, "DIR")
		s = strings.ReplaceAll(s, st.Shims.Dir, "SHIMS")
		return fifoDirs.ReplaceAllString(execID.ReplaceAllString(s, "exec-ID"), "fifo/N/")
	}
	r.Err, r.Record = name(r.Err), name(r.Record)
	return r
}

func nativeFor(t *testing.T) *supervisor.Native {
	t.Helper()
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		t.Skip("ARMADA_NODE_BIN names no armada-node to compare with")
	}
	return &supervisor.Native{Bin: bin}
}

// TestArmadaNodeExecMatchesGo: armada-node starts runc exec as Go does,
// so the caller and runc see the same: runc's arguments, the process spec
// (bytes, modes), standard streams and no other descriptors, the
// terminal as runc's controlling terminal with its size and a resize,
// signals, environment, exit codes (runc's own and a signal's), the end
// of the caller's deadline (runc killed), and runc that cannot be run.
func TestArmadaNodeExecMatchesGo(t *testing.T) {
	n := nativeFor(t)
	full := specs.Spec{Version: "1.3.0", Process: fullProcess(), Hostname: "h"}
	minimal := specs.Spec{Process: &specs.Process{Cwd: "/"}}
	bg := context.Background
	cases := []struct {
		name    string
		spec    specs.Spec
		body    string
		opts    runtime.ExecOptions
		resize  bool
		timeout time.Duration
		missing bool
		stdin   string
	}{
		{
			name: "streams", spec: full,
			body:  "echo $$ > \"$PIDFILE\"\nread x\necho \"out:$x\"\ncat\necho err >&2\nexit 3\n",
			opts:  runtime.ExecOptions{Cmd: []string{"sh", "-c", `a<b>&"c" é`, "\u2028", ""}},
			stdin: "first\nrest\n",
		},
		{
			name: "no stdin, minimal spec", spec: minimal,
			body: "echo $$ > \"$PIDFILE\"\necho hi\nexit 0\n",
			opts: runtime.ExecOptions{Cmd: []string{"true"}},
		},
		{
			name: "terminal with a size and a resize", spec: full, resize: true,
			body: "echo $$ > \"$PIDFILE\"\nfor i in $(seq 100); do s=$(stty size); [ \"$s\" = \"40 120\" ] && break; sleep 0.05; done\necho \"resized $s\"\nexit 7\n",
			opts: runtime.ExecOptions{Cmd: []string{"sh"}, TTY: true, Size: runtime.TermSize{Rows: 33, Cols: 101}},
		},
		{
			name: "terminal without a size", spec: minimal,
			body: "echo $$ > \"$PIDFILE\"\necho t\n",
			opts: runtime.ExecOptions{Cmd: []string{"sh"}, TTY: true},
		},
		{
			name: "runc killed by a signal", spec: minimal,
			body: "echo $$ > \"$PIDFILE\"\nkill -KILL $$\n",
			opts: runtime.ExecOptions{Cmd: []string{"x"}},
		},
		{
			// No pid file: runc failed before the process started, and
			// its exit code and error output reach the caller at once.
			name: "runc ends before the process starts", spec: minimal,
			body: "echo 'container not running' >&2\nexit 1\n",
			opts: runtime.ExecOptions{Cmd: []string{"x"}},
		},
		{
			name: "deadline", spec: minimal, timeout: 500 * time.Millisecond,
			body: "echo $$ > \"$PIDFILE\"\nexec sleep 30\n",
			opts: runtime.ExecOptions{Cmd: []string{"x"}},
		},
		{
			name: "runc missing", spec: minimal, missing: true,
			opts: runtime.ExecOptions{Cmd: []string{"x"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := func(native *supervisor.Native) (execResult, time.Duration) {
				ctx, cancel := bg(), context.CancelFunc(func() {})
				if tc.timeout > 0 {
					ctx, cancel = context.WithTimeout(ctx, tc.timeout)
				}
				defer cancel()
				opts := tc.opts
				if tc.resize {
					ch := make(chan runtime.TermSize, 1)
					ch <- runtime.TermSize{Rows: 40, Cols: 120}
					opts.Resize = ch
				}
				if tc.stdin != "" {
					opts.Stdin = strings.NewReader(tc.stdin)
				}
				start := time.Now()
				r := runExec(ctx, t, native, tc.spec, tc.body, opts, tc.missing)
				return r, time.Since(start)
			}
			goRes, goTook := run(nil)
			before := n.Ran("exec")
			nodeRes, nodeTook := run(n)
			if !reflect.DeepEqual(goRes, nodeRes) {
				t.Errorf("armada-node differs from Go:\n%s", resultDiff(nodeRes, goRes))
			}
			if got := n.Ran("exec") - before; got != 1 {
				t.Errorf("armada-node started %d execs, want 1", got)
			}
			if n.StoodIn("exec") != 0 {
				t.Errorf("Go stood in %d times", n.StoodIn("exec"))
			}
			if goTook > 5*time.Second || nodeTook > 5*time.Second {
				t.Errorf("Go took %s, armada-node %s", goTook, nodeTook)
			}
			if tc.timeout > 0 {
				if !strings.Contains(nodeRes.Err, "deadline exceeded") {
					t.Errorf("deadline: %q", nodeRes.Err)
				}
				if nodeTook > goTook+time.Second {
					t.Errorf("armada-node took %s, Go %s", nodeTook, goTook)
				}
			}
		})
	}
	// The terminal case's record names the sizes the fake runc saw.
	t.Run("records", func(t *testing.T) {
		r := runExec(bg(), t, n, full, "echo $$ > \"$PIDFILE\"\n", runtime.ExecOptions{Cmd: []string{"sh"}, TTY: true, Size: runtime.TermSize{Rows: 33, Cols: 101}}, false)
		for _, want := range []string{"size 33 101", "session leader tty yes", "fd0 pts", "--tty c1", `"consoleSize":{"height":33,"width":101}`, "modes 600 700"} {
			if !strings.Contains(r.Record, want) {
				t.Errorf("record lacks %q:\n%s", want, r.Record)
			}
		}
	})
}

// TestArmadaNodeExecKillsRunc: once the caller's deadline passes, the
// runc armada-node became is killed as Go's is, and nothing of it is
// left.
func TestArmadaNodeExecKillsRunc(t *testing.T) {
	n := nativeFor(t)
	pidAt := filepath.Join(t.TempDir(), "pid")
	d := execDriverOn(t, "echo $$ > \""+pidAt+"\"\necho $$ > \"$PIDFILE\"\nexec sleep 30\n", specs.Spec{Process: &specs.Process{Cwd: "/"}}, n)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := d.ExecApp(ctx, "c1", runtime.ExecOptions{Cmd: []string{"x"}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ExecApp: %v", err)
	}
	b, err := os.ReadFile(pidAt)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	for range 100 {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("runc (pid %d) still runs", pid)
}

// TestNativeExecFallsBackToGo: when armada-node does not run, fails
// before it becomes runc, or leaves the start to Go, Go starts runc
// itself on the same streams, and the caller sees what Go alone gives.
func TestNativeExecFallsBackToGo(t *testing.T) {
	dir := t.TempDir()
	stand := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	body := "echo $$ > \"$PIDFILE\"\nread x\necho \"out:$x\"\necho err >&2\nexit 4\n"
	spec := specs.Spec{Process: &specs.Process{Cwd: "/", Env: []string{"A=1"}}}
	opts := func() runtime.ExecOptions {
		return runtime.ExecOptions{Cmd: []string{"x"}, Stdin: strings.NewReader("in\n")}
	}
	want := withoutSigBlk(runExec(context.Background(), t, nil, spec, body, opts(), false))
	if want.Code != 4 || want.Stdout != "out:in\n" || want.Stderr != "err\n" {
		t.Fatalf("Go: %+v", want)
	}
	for _, tc := range []struct{ name, bin string }{
		{"missing", filepath.Join(dir, "none")},
		{"no answer", stand("silent", "exit 1\n")},
		{"error", stand("error", "printf '{\"error\":\"boom\"}' >&4\nexit 1\n")},
		{"redo", stand("redo", "printf '{\"redo\":\"read config.json: gone\"}' >&4\nexit 1\n")},
		{"unreadable", stand("junk", "printf 'exec\\nnot json' >&4\nexit 1\n")},
		{"killed", stand("killed", "kill -KILL $$\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := &supervisor.Native{Bin: tc.bin}
			got := withoutSigBlk(runExec(context.Background(), t, n, spec, body, opts(), false))
			if !reflect.DeepEqual(got, want) {
				t.Errorf("with armada-node %s, differs from Go:\n%s", tc.name, resultDiff(got, want))
			}
			if n.StoodIn("exec") != 1 || n.Ran("exec") != 0 {
				t.Errorf("stood in %d, ran %d; want 1, 0", n.StoodIn("exec"), n.Ran("exec"))
			}
		})
	}
}

// withoutSigBlk drops the blocked signal mask from a record. Both sides of
// the fallback test are Go's start, whose child keeps the mask of the OS
// thread that forked it: some of the runtime's threads have every signal
// blocked, so the line differs between two runs of the same code.
func withoutSigBlk(r execResult) execResult {
	var keep []string
	for _, l := range strings.Split(r.Record, "\n") {
		if !strings.HasPrefix(l, "SigBlk:") {
			keep = append(keep, l)
		}
	}
	r.Record = strings.Join(keep, "\n")
	return r
}

// resultDiff names what differs between two results, line by line for
// the record.
func resultDiff(got, want execResult) string {
	var b strings.Builder
	if got.Code != want.Code || got.Err != want.Err || got.Stdout != want.Stdout || got.Stderr != want.Stderr {
		fmt.Fprintf(&b, "got code %d err %q stdout %q stderr %q\nwant code %d err %q stdout %q stderr %q\n",
			got.Code, got.Err, got.Stdout, got.Stderr, want.Code, want.Err, want.Stdout, want.Stderr)
	}
	g, w := strings.Split(got.Record, "\n"), strings.Split(want.Record, "\n")
	for i := range max(len(g), len(w)) {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			fmt.Fprintf(&b, "record line %d:\n  got  %q\n  want %q\n", i, gl, wl)
		}
	}
	return b.String()
}
