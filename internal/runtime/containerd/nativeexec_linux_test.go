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
// part, and step 5, its last part: the session): ExecApp and Exec on the
// supervisor backend with Go running the exec and with armada-node
// running it, against a fake runc that records what it was given. None
// needs root.

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
	// A stream runc gets: the caller's FIFO when Go runs the session, a
	// pipe of armada-node's when it does; both are a pipe to runc.
	fifoLink = regexp.MustCompile(`(fd[0-2]) \S*/fifo/[0-9]+/exec-[0-9a-f]{12}-std(in|out|err);`)
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
		s = fifoLink.ReplaceAllString(s, "$1 pipe;")
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
// (bytes, modes), standard streams (pipes: the caller's FIFOs from Go,
// armada-node's own pipes from it) and no other descriptors, the
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
			if goRes, nodeRes := unblocked(t, goRes), unblocked(t, nodeRes); !reflect.DeepEqual(goRes, nodeRes) {
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
// before runc runs, or leaves the session to Go, Go runs it on the
// caller's untouched streams, and the caller sees what Go alone gives.
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
	want := unblocked(t, runExec(context.Background(), t, nil, spec, body, opts(), false))
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
			got := unblocked(t, runExec(context.Background(), t, n, spec, body, opts(), false))
			if !reflect.DeepEqual(got, want) {
				t.Errorf("with armada-node %s, differs from Go:\n%s", tc.name, resultDiff(got, want))
			}
			if n.StoodIn("exec") != 1 || n.Ran("exec") != 0 {
				t.Errorf("stood in %d, ran %d; want 1, 0", n.StoodIn("exec"), n.Ran("exec"))
			}
		})
	}
}

// unblocked checks that runc started with no signal blocked and drops
// the line from the record. A child keeps the signal mask of the thread
// that forked it, and some of the Go runtime's threads block every
// signal, so Go's runc started with whatever its thread had until
// startUnmasked; armada-node's starts with none (Rust's std), and both
// are checked, every run.
func unblocked(t *testing.T, r execResult) execResult {
	t.Helper()
	var keep []string
	for _, l := range strings.Split(r.Record, "\n") {
		if strings.HasPrefix(l, "SigBlk:") {
			if strings.TrimSpace(strings.TrimPrefix(l, "SigBlk:")) != "0000000000000000" {
				t.Errorf("runc started with signals blocked: %s", l)
			}
			continue
		}
		keep = append(keep, l)
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

// sessionResult is what the caller of ExecApp sees.
type sessionResult struct {
	Code           int
	Err            string
	Stdout, Stderr string
}

// sessionCase is one exec run through Go's session and armada-node's.
type sessionCase struct {
	name string
	// body is the fake runc's script; $LEFT names a file for the PID of
	// a background child it leaves (killed when the test ends).
	body    string
	tty     bool
	stdin   *string
	size    runtime.TermSize
	resize  []runtime.TermSize
	timeout time.Duration
	// drain sets ioDrainGrace; slow makes the caller take each write
	// after a pause; noOutput passes no writers (a command probe).
	drain    time.Duration
	slow     time.Duration
	noOutput bool
	// check compares the two results instead of equality (output whose
	// length depends on timing).
	check func(t *testing.T, goRes, nodeRes sessionResult)
	// within is how far apart the two durations may be (default 1s).
	within time.Duration
	// nodeAtMost, when set, replaces the comparison of durations: Go
	// takes longer (see the case), armada-node at most this long.
	nodeAtMost time.Duration
}

// runSession runs tc's exec on a fresh driver, through native when set.
func runSession(t *testing.T, native *supervisor.Native, tc sessionCase) (sessionResult, time.Duration) {
	t.Helper()
	left := filepath.Join(t.TempDir(), "left")
	leftover(t, left)
	d := execDriverOn(t, "LEFT="+left+"\n"+tc.body, specs.Spec{Process: &specs.Process{Cwd: "/", Env: []string{"A=1"}}}, native)
	ctx, cancel := context.Background(), context.CancelFunc(func() {})
	if tc.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, tc.timeout)
	}
	defer cancel()
	out, errOut := &slowWriter{pause: tc.slow}, &slowWriter{pause: tc.slow}
	opts := runtime.ExecOptions{Cmd: []string{"sh", "-c", "x"}, TTY: tc.tty, Size: tc.size}
	if !tc.noOutput {
		opts.Stdout, opts.Stderr = out, errOut
		if tc.tty {
			opts.Stderr = nil
		}
	}
	if tc.stdin != nil {
		opts.Stdin = strings.NewReader(*tc.stdin)
	}
	if len(tc.resize) > 0 {
		ch := make(chan runtime.TermSize, len(tc.resize))
		for _, s := range tc.resize {
			ch <- s
		}
		opts.Resize = ch
	}
	start := time.Now()
	code, err := d.ExecApp(ctx, "c1", opts)
	took := time.Since(start)
	return sessionResult{Code: code, Err: errText(err), Stdout: out.String(), Stderr: errOut.String()}, took
}

func str(s string) *string { return &s }

// awaitChild waits until the background child ignores SIGHUP (it made
// $LEFT.r), so runc, the terminal's session leader, ending first does not
// end it.
const awaitChild = "while [ ! -e \"$LEFT.r\" ]; do sleep 0.01; done\n"

// sessionCases are the sessions both sides run. Bodies write the pid file
// first unless the case is about runc ending before it.
func sessionCases() []sessionCase {
	const pid = "echo $$ > \"$PIDFILE\"\n"
	cutShort := func(t *testing.T, goRes, nodeRes sessionResult) {
		t.Helper()
		for _, r := range []sessionResult{goRes, nodeRes} {
			if r.Code != 0 || r.Err != "exec output cut short: context deadline exceeded" || !strings.HasPrefix(r.Stdout, "more\n") {
				t.Errorf("got code %d err %q stdout %.40q", r.Code, r.Err, r.Stdout)
			}
		}
	}
	return []sessionCase{
		{
			name: "large output on both streams",
			body: pid + "head -c 300000 /dev/zero | tr '\\0' o\nhead -c 200000 /dev/zero | tr '\\0' e >&2\nexit 0\n",
		},
		{
			name: "interleaved lines",
			body: pid + "i=0; while [ $i -lt 300 ]; do echo out$i; echo err$i >&2; i=$((i+1)); done\nexit 1\n",
		},
		{
			name: "slow reader", slow: 100 * time.Millisecond, drain: 200 * time.Millisecond, within: 3 * time.Second,
			body: pid + "head -c 262144 /dev/zero | tr '\\0' x\nexit 0\n",
		},
		{
			name: "slow reader on a terminal", tty: true, slow: 100 * time.Millisecond, drain: 200 * time.Millisecond, within: 3 * time.Second,
			body: pid + "head -c 262144 /dev/zero | tr '\\0' x\nexit 0\n",
		},
		{name: "exit 0", body: pid + "exit 0\n"},
		{name: "exit 3", body: pid + "echo a\nexit 3\n"},
		{name: "exit 255", body: pid + "exit 255\n"},
		{name: "runc ends on SIGTERM", body: pid + "kill -TERM $$\n"},
		{name: "runc ends on SIGKILL", body: pid + "kill -KILL $$\n"},
		{name: "runc ends before the process", body: "echo 'container not running' >&2\nexit 1\n"},
		{
			name: "stdin to the end", stdin: str("one\ntwo\nthree\n"),
			body: pid + "read x\necho \"first:$x\"\ncat\necho err >&2\nexit 2\n",
		},
		{
			name: "stdin closed at once", stdin: str(""),
			body: pid + "read x || echo eof\ncat\necho done\n",
		},
		{name: "no stdin", body: pid + "read x || echo eof\n"},
		{name: "no writers", noOutput: true, stdin: str("x\n"), body: pid + "cat\necho lost\necho lost >&2\nexit 5\n"},
		{
			name: "terminal with stdin", tty: true, stdin: str("abc\ndef\n"),
			body: pid + "read x\necho \"got:$x\"\ncat\necho end\nexit 2\n",
		},
		{
			name: "terminal with a size and resizes", tty: true, size: runtime.TermSize{Rows: 33, Cols: 101},
			resize: []runtime.TermSize{{Rows: 0, Cols: 5}, {Rows: 40, Cols: 120}},
			body:   pid + "echo \"first $(stty size)\"\nfor i in $(seq 100); do s=$(stty size); [ \"$s\" = \"40 120\" ] && break; sleep 0.05; done\necho \"resized $s\"\nexit 7\n",
		},
		{
			name: "terminal output after runc exited", tty: true,
			body: pid + "(trap '' HUP; : > \"$LEFT.r\"; sleep 0.3; echo late) &\necho $! > \"$LEFT\"\n" + awaitChild + "echo early\nexit 0\n",
		},
		{
			name: "child holds the output open", drain: 300 * time.Millisecond, within: 500 * time.Millisecond,
			body: pid + "sleep 30 &\necho $! > \"$LEFT\"\necho 5\nexit 3\n",
		},
		{
			// Go closes the terminal after its grace, but its read in
			// progress goes on until the child ends (closing the console
			// does not end it), so Go waits for the child; armada-node
			// ends the copy after the grace, as Go means to.
			name: "child holds the terminal open", tty: true, nodeAtMost: 3 * time.Second,
			body: pid + "(trap '' HUP; : > \"$LEFT.r\"; exec sleep 4) &\necho $! > \"$LEFT\"\n" + awaitChild + "echo 5\nexit 3\n",
		},
		{
			name: "child keeps writing", drain: 200 * time.Millisecond,
			body: pid + "(i=0; while [ $i -lt 20 ]; do echo line$i; i=$((i+1)); sleep 0.05; done) &\necho $! > \"$LEFT\"\nexit 0\n",
		},
		{
			name: "deadline before the exit", timeout: 500 * time.Millisecond, within: 500 * time.Millisecond,
			body: pid + "echo started\nexec sleep 30\n",
		},
		{
			// No pid ever comes. Go's cleanup cannot kill a process it
			// has no pid for (NotFound) and waits its five seconds for
			// the end; armada-node ends runc on the cleanup's kill, so
			// the call ends at the caller's deadline.
			name: "deadline before the start", timeout: 300 * time.Millisecond, nodeAtMost: 1500 * time.Millisecond,
			body: "sleep 30\n",
		},
		{
			name: "deadline while draining", timeout: time.Second, drain: 200 * time.Millisecond, check: cutShort,
			body: pid + "(while :; do echo more; sleep 0.02; done) &\necho $! > \"$LEFT\"\nexit 0\n",
		},
		{
			name: "runc copies until the end", timeout: 2 * time.Second, drain: 300 * time.Millisecond,
			body: pipeRunc,
		},
		{
			name: "runc copies to a terminal until the end", tty: true, timeout: 2 * time.Second,
			body: pipeRunc,
		},
	}
}

// TestArmadaNodeExecSessionMatchesGo: the caller of ExecApp sees the same
// from armada-node's session as from Go's: the bytes of each stream in
// order (large, interleaved, through a slow reader), exit codes (runc's,
// a signal's as 128 plus its number), runc ending before the process
// starts, input to its end and closed early (a terminal's end of
// transmission), terminals with a first size and resizes, output a
// child of the process keeps writing or holding open after it ended (the
// drains' graces), the caller's deadline before the start, before the
// exit, and while draining ("exec output cut short"), and about the same
// time taken.
func TestArmadaNodeExecSessionMatchesGo(t *testing.T) {
	n := nativeFor(t)
	for _, tc := range sessionCases() {
		t.Run(tc.name, func(t *testing.T) {
			if tc.drain > 0 {
				shortDrainGrace(t, tc.drain)
			}
			goRes, goTook := runSession(t, nil, tc)
			before, stood := n.Ran("exec"), n.StoodIn("exec")
			nodeRes, nodeTook := runSession(t, n, tc)
			if tc.check != nil {
				tc.check(t, goRes, nodeRes)
			} else if goRes != nodeRes {
				t.Errorf("armada-node differs from Go:\ngot  code %d err %q stdout %.200q stderr %.200q\nwant code %d err %q stdout %.200q stderr %.200q",
					nodeRes.Code, nodeRes.Err, nodeRes.Stdout, nodeRes.Stderr, goRes.Code, goRes.Err, goRes.Stdout, goRes.Stderr)
			}
			if got := n.Ran("exec") - before; got != 1 {
				t.Errorf("armada-node ran %d sessions, want 1", got)
			}
			if got := n.StoodIn("exec") - stood; got != 0 {
				t.Errorf("Go stood in %d times", got)
			}
			within := tc.within
			if within == 0 {
				within = time.Second
			}
			if tc.nodeAtMost > 0 {
				if nodeTook > tc.nodeAtMost || goTook < nodeTook {
					t.Errorf("armada-node took %s, Go %s", nodeTook, goTook)
				}
			} else if d := nodeTook - goTook; d > within || d < -within {
				t.Errorf("armada-node took %s, Go %s", nodeTook, goTook)
			}
		})
	}
}

// TestArmadaNodeExecRuncEndsWithIt: runc dies with the armada-node that
// started it (PR_SET_PDEATHSIG), so an armada-node killed mid-session
// leaves no runc running with nothing to reap it.
func TestArmadaNodeExecRuncEndsWithIt(t *testing.T) {
	n := nativeFor(t)
	dir := t.TempDir()
	runcAt, parentAt := filepath.Join(dir, "runc"), filepath.Join(dir, "parent")
	d := execDriverOn(t, "echo $$ > \""+runcAt+".tmp\"\nmv \""+runcAt+".tmp\" \""+runcAt+"\"\necho $PPID > \""+parentAt+"\"\necho $$ > \"$PIDFILE\"\nexec sleep 30\n", specs.Spec{Process: &specs.Process{Cwd: "/"}}, n)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := d.ExecApp(ctx, "c1", runtime.ExecOptions{Cmd: []string{"x"}})
		done <- err
	}()
	readPid := func(p string) int {
		for range 500 {
			if b, err := os.ReadFile(p); err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
					return pid
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("%s never came", p)
		return 0
	}
	runc, parent := readPid(runcAt), readPid(parentAt)
	if err := syscall.Kill(parent, syscall.SIGKILL); err != nil {
		t.Fatalf("kill armada-node (%d): %v", parent, err)
	}
	for range 200 {
		if syscall.Kill(runc, 0) != nil {
			if err := <-done; err == nil {
				t.Error("ExecApp succeeded with armada-node killed")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = syscall.Kill(runc, syscall.SIGKILL)
	t.Errorf("runc (pid %d) outlived armada-node", runc)
}

// TestArmadaNodeExecSystemBounded: the driver's Exec of a system
// container ends at the caller's deadline with the process killed, through
// armada-node and through Go alike, rather than waiting for a command that
// never ends.
func TestArmadaNodeExecSystemBounded(t *testing.T) {
	n := nativeFor(t)
	for _, native := range []*supervisor.Native{nil, n} {
		dir := t.TempDir()
		pidAt := filepath.Join(dir, "pid")
		d := execDriverOn(t, "echo $$ > \""+pidAt+"\"\necho $$ > \"$PIDFILE\"\nexec sleep 30\n", specs.Spec{Process: &specs.Process{Cwd: "/"}}, native)
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		start := time.Now()
		_, _, err := d.Exec(ctx, "c1", []string{"x"})
		took := time.Since(start)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || took > 2*time.Second {
			t.Errorf("native=%v: Exec: %v after %s", native != nil, err, took)
		}
		b, _ := os.ReadFile(pidAt)
		pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		gone := false
		for range 300 {
			if pid > 1 && syscall.Kill(pid, 0) != nil {
				gone = true
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !gone {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Errorf("native=%v: the process (pid %d) runs on", native != nil, pid)
		}
	}
}

// TestArmadaNodeExecSessionSystem: the driver's Exec (system containers:
// output of both streams in one buffer, copied to its end) gives the same
// through armada-node as through Go.
func TestArmadaNodeExecSessionSystem(t *testing.T) {
	n := nativeFor(t)
	body := "echo $$ > \"$PIDFILE\"\necho out\nsleep 0.1\necho err >&2\nexit 2\n"
	run := func(native *supervisor.Native) (string, int, string) {
		d := execDriverOn(t, body, specs.Spec{Process: &specs.Process{Cwd: "/"}}, native)
		out, code, err := d.Exec(context.Background(), "c1", []string{"x"})
		return out, code, errText(err)
	}
	gOut, gCode, gErr := run(nil)
	before := n.Ran("exec")
	nOut, nCode, nErr := run(n)
	if gOut != nOut || gCode != nCode || gErr != nErr {
		t.Errorf("armada-node: %q %d %q; Go: %q %d %q", nOut, nCode, nErr, gOut, gCode, gErr)
	}
	if gOut != "out\nerr\n" || gCode != 2 {
		t.Errorf("Go: %q %d", gOut, gCode)
	}
	if n.Ran("exec")-before != 1 {
		t.Error("the system exec did not go through armada-node")
	}
}

// TestNativeExecSessionFailsAfterSpawn: once armada-node said runc runs,
// its failure is the call's: Go does not run the exec again, and the
// caller's input is not replayed.
func TestNativeExecSessionFailsAfterSpawn(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "spawned")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '{\"spawned\":true}\\n' >&4\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := &supervisor.Native{Bin: bin}
	ran := filepath.Join(dir, "ran")
	d := execDriverOn(t, "touch \""+ran+"\"\necho $$ > \"$PIDFILE\"\n", specs.Spec{Process: &specs.Process{Cwd: "/"}}, n)
	out := &lockedBuffer{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code, err := d.ExecApp(ctx, "c1", runtime.ExecOptions{Cmd: []string{"x"}, Stdin: strings.NewReader("in\n"), Stdout: out, Stderr: out})
	if code != 0 || errText(err) != "exec: armada-node: ended the exec session" {
		t.Errorf("ExecApp = %d, %v", code, err)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Error("Go ran the exec again")
	}
	if n.StoodIn("exec") != 0 || n.Ran("exec") != 1 {
		t.Errorf("stood in %d, ran %d; want 0, 1", n.StoodIn("exec"), n.Ran("exec"))
	}
}

// TestArmadaNodeExecSessionAbandoned: a caller whose deadline passes while
// the process holds out is answered at the deadline, and armada-node's
// session ends with runc killed and its exec directory removed, as Go's
// cleanup leaves it.
func TestArmadaNodeExecSessionAbandoned(t *testing.T) {
	n := nativeFor(t)
	d := execDriverOn(t, "echo $$ > \"$PIDFILE\"\ntrap '' TERM\nexec sleep 30\n", specs.Spec{Process: &specs.Process{Cwd: "/"}}, n)
	st := d.ctr.(*supervisor.Store)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := d.ExecApp(ctx, "c1", runtime.ExecOptions{Cmd: []string{"x"}})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("ExecApp: %v after %s", err, time.Since(start))
	}
	shimRun := filepath.Dir(st.Shims.Get("web@pack").Root)
	for range 100 {
		m, _ := filepath.Glob(filepath.Join(shimRun, "exec-c1-*"))
		if len(m) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("the exec directory is left")
}
