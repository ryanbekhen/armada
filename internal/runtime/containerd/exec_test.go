package containerd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
	"github.com/ryanbekhen/armada/internal/runtime/supervisor"
)

// supervisorExecDriver is a driver on the supervisor backend with one
// running container, "c1", whose shim answers like armada-shim and whose
// runc is the script body (sh): it gets runc exec's arguments, and $PIDFILE
// is the --pid-file it was given.
func supervisorExecDriver(t *testing.T, body string) *Driver {
	t.Helper()
	dir := t.TempDir()
	// Unix socket paths are short: keep the shim directory near the root.
	shimDir, err := os.MkdirTemp("", "armada-exec")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shimDir) })
	runc := filepath.Join(dir, "runc")
	script := "#!/bin/sh\nset -u\nwhile [ $# -gt 0 ]; do case \"$1\" in --pid-file) PIDFILE=$2; shift;; esac; shift; done\n" + body
	if err := os.WriteFile(runc, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	s := &supervisor.Store{
		Bundles: supervisor.Bundles{Dir: filepath.Join(dir, "containers")},
		Shims:   &supervisor.Shims{Dir: shimDir, Runc: runc},
	}
	rec := supervisor.Record{ID: "c1", Group: "web@pack", Labels: map[string]string{runtime.LabelManaged: "true"}}
	bundle := s.Bundles.Path(rec.ID)
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		t.Fatal(err)
	}
	spec := specs.Spec{Process: &specs.Process{Args: []string{"/app"}, Cwd: "/"}}
	for name, v := range map[string]any{"config.json": spec, "record.json": rec} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bundle, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sh := s.Shims.Get(rec.Group)
	if err := os.MkdirAll(filepath.Dir(sh.Root), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", sh.Socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(c).ReadString('\n')
			answer := "ok"
			if strings.HasPrefix(line, "state ") {
				answer = "ok running 1"
			}
			_, _ = c.Write([]byte(answer + "\n"))
			_ = c.Close()
		}
	}()
	return &Driver{ctr: s, paths: embedded.Paths{DataDir: dir, RunDir: filepath.Join(dir, "run")}}
}

// leftover kills the background process a fake runc left, whose PID it
// wrote to path, once the test ends.
func leftover(t *testing.T, path string) {
	t.Cleanup(func() {
		b, err := os.ReadFile(path)
		if err != nil {
			return
		}
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
}

// TestExecAppBoundedWithLeftChild: a command that leaves a background
// child holding its output (sh -c 'sleep infinity & echo 5') must not hold
// ExecApp past its deadline plus a short grace, on the supervisor backend,
// whether the process holds runc's own streams or runc copies its output
// through a pipe until the end, as runc exec does in the foreground.
func TestExecAppBoundedWithLeftChild(t *testing.T) {
	const deadline = 2 * time.Second
	// Shorter than the deadline, so a process that exited ends on the
	// quiet output, not the deadline.
	shortDrainGrace(t, 300*time.Millisecond)
	for _, tc := range []struct {
		name string
		tty  bool
		// body gets $LEFT, where the background child's PID goes.
		body     string
		exited   bool // the exit status arrives before the deadline
		wantCode int
	}{
		{
			// The process holds runc's streams: runc exits with it, the
			// child keeps the output open.
			name:   "process holds the streams",
			body:   "echo $$ > \"$PIDFILE\"\nsleep 30 &\necho $! > \"$LEFT\"\necho 5\nexit 3\n",
			exited: true, wantCode: 3,
		},
		{
			// runc copies the output through a pipe until its end, which
			// the child holds: runc does not exit.
			name: "runc copies until the end",
			body: pipeRunc,
		},
		{
			name: "runc copies to a terminal until the end",
			tty:  true,
			body: pipeRunc,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left := filepath.Join(t.TempDir(), "left")
			leftover(t, left)
			d := supervisorExecDriver(t, "LEFT="+left+"\n"+tc.body)
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			defer cancel()
			out := &lockedBuffer{}
			start := time.Now()
			code, err := d.ExecApp(ctx, "c1", runtime.ExecOptions{
				Cmd: []string{"sh", "-c", "sleep infinity & echo 5"}, TTY: tc.tty,
				Stdout: out, Stderr: out,
			})
			took := time.Since(start)
			if limit := deadline + ioDrainGrace + execCleanupTimeout/2; took > limit {
				t.Fatalf("ExecApp took %s, more than %s", took, limit)
			}
			if tc.exited {
				if err != nil || code != tc.wantCode {
					t.Fatalf("ExecApp = %d, %v; want %d", code, err, tc.wantCode)
				}
			} else if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("ExecApp = %d, %v; want the deadline", code, err)
			}
			if !strings.Contains(out.String(), "5") {
				t.Errorf("output %q", out.String())
			}
		})
	}
}

// pipeRunc is a fake runc that copies the process's output through a pipe
// until its end, in its own process, as runc exec does in the foreground.
const pipeRunc = `p=$(mktemp -u)
mkfifo "$p"
sh -c 'echo $$ > "$1"; sleep 30 & echo $! > "$2"; echo 5' sh "$PIDFILE" "$LEFT" > "$p" &
while IFS= read -r line; do printf '%s\n' "$line"; done < "$p"
rm -f "$p"
wait $!
`

// TestExecAppReturnsAtOnce: a command that leaves nothing behind returns
// as soon as it exits, with all its output; the grace is only for output
// something else still holds.
func TestExecAppReturnsAtOnce(t *testing.T) {
	d := supervisorExecDriver(t, "echo $$ > \"$PIDFILE\"\necho hello\nexit 0\n")
	out := &lockedBuffer{}
	start := time.Now()
	code, err := d.ExecApp(context.Background(), "c1", runtime.ExecOptions{Cmd: []string{"true"}, Stdout: out, Stderr: out})
	if err != nil || code != 0 {
		t.Fatalf("ExecApp = %d, %v", code, err)
	}
	if took := time.Since(start); took >= ioDrainGrace {
		t.Errorf("ExecApp took %s", took)
	}
	if out.String() != "hello\n" {
		t.Errorf("output %q", out.String())
	}
}

// shortDrainGrace sets ioDrainGrace for one test.
func shortDrainGrace(t *testing.T, d time.Duration) {
	t.Helper()
	old := ioDrainGrace
	ioDrainGrace = d
	t.Cleanup(func() { ioDrainGrace = old })
}

// slowWriter takes every write after a pause, like a slow client of
// armada app exec.
type slowWriter struct {
	lockedBuffer
	pause time.Duration
}

func (s *slowWriter) Write(p []byte) (int, error) {
	time.Sleep(s.pause)
	return s.lockedBuffer.Write(p)
}

// TestExecAppCopiesOutputStillFlowing: output still on its way when the
// process exits is copied in full, however long past the grace it takes,
// whether a slow reader takes it or a child the process left keeps writing.
func TestExecAppCopiesOutputStillFlowing(t *testing.T) {
	const grace = 200 * time.Millisecond
	for _, tty := range []bool{false, true} {
		t.Run("slow reader tty="+strconv.FormatBool(tty), func(t *testing.T) {
			shortDrainGrace(t, grace)
			// 256 KiB: more than the pipe, the terminal, and the copy
			// buffer hold, so much of it is still to copy when the
			// process exits.
			d := supervisorExecDriver(t, "echo $$ > \"$PIDFILE\"\nhead -c 262144 /dev/zero | tr '\\0' x\nexit 0\n")
			out := &slowWriter{pause: 150 * time.Millisecond}
			start := time.Now()
			code, err := d.ExecApp(context.Background(), "c1", runtime.ExecOptions{Cmd: []string{"big"}, TTY: tty, Stdout: out, Stderr: out})
			if err != nil || code != 0 {
				t.Fatalf("ExecApp = %d, %v", code, err)
			}
			if n := len(out.String()); n != 262144 {
				t.Fatalf("copied %d bytes of 262144 in %s", n, time.Since(start))
			}
		})
	}
	t.Run("child keeps writing", func(t *testing.T) {
		shortDrainGrace(t, grace)
		left := filepath.Join(t.TempDir(), "left")
		leftover(t, left)
		// The child writes a line every 50ms for about a second after
		// the process exited, then ends.
		d := supervisorExecDriver(t, "LEFT="+left+"\necho $$ > \"$PIDFILE\"\n"+
			"(i=0; while [ $i -lt 20 ]; do echo line$i; i=$((i+1)); sleep 0.05; done) &\necho $! > \"$LEFT\"\nexit 0\n")
		out := &lockedBuffer{}
		code, err := d.ExecApp(context.Background(), "c1", runtime.ExecOptions{Cmd: []string{"trickle"}, Stdout: out, Stderr: out})
		if err != nil || code != 0 {
			t.Fatalf("ExecApp = %d, %v", code, err)
		}
		if !strings.Contains(out.String(), "line19\n") {
			t.Fatalf("output cut: %q", out.String())
		}
	})
}

// TestExecAppQuietLeftChildEnds: a child the process left holding the
// output open, writing nothing, ends the copy once the output has been
// quiet for the grace, with the process's exit code and all its output.
func TestExecAppQuietLeftChildEnds(t *testing.T) {
	const grace = 200 * time.Millisecond
	shortDrainGrace(t, grace)
	left := filepath.Join(t.TempDir(), "left")
	leftover(t, left)
	d := supervisorExecDriver(t, "LEFT="+left+"\necho $$ > \"$PIDFILE\"\nsleep 30 &\necho $! > \"$LEFT\"\necho 5\nexit 3\n")
	out := &lockedBuffer{}
	start := time.Now()
	code, err := d.ExecApp(context.Background(), "c1", runtime.ExecOptions{Cmd: []string{"left"}, Stdout: out, Stderr: out})
	took := time.Since(start)
	if err != nil || code != 3 {
		t.Fatalf("ExecApp = %d, %v; want 3", code, err)
	}
	if took < grace || took > grace+execCleanupTimeout/2 {
		t.Errorf("ExecApp took %s; want about %s", took, grace)
	}
	if out.String() != "5\n" {
		t.Errorf("output %q", out.String())
	}
}

// TestExecAppDeadlineBoundsFlowingOutput: output that never stops moving
// is copied only until the caller's deadline, which ExecApp reports, so a
// cut is never taken for the whole output.
func TestExecAppDeadlineBoundsFlowingOutput(t *testing.T) {
	shortDrainGrace(t, 200*time.Millisecond)
	left := filepath.Join(t.TempDir(), "left")
	leftover(t, left)
	d := supervisorExecDriver(t, "LEFT="+left+"\necho $$ > \"$PIDFILE\"\n"+
		"(while :; do echo more; sleep 0.02; done) &\necho $! > \"$LEFT\"\nexit 0\n")
	const deadline = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	out := &lockedBuffer{}
	start := time.Now()
	_, err := d.ExecApp(ctx, "c1", runtime.ExecOptions{Cmd: []string{"forever"}, Stdout: out, Stderr: out})
	took := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ExecApp error = %v; want the deadline", err)
	}
	if took > deadline+execCleanupTimeout/2 {
		t.Errorf("ExecApp took %s", took)
	}
	if !strings.Contains(out.String(), "more") {
		t.Errorf("output %q", out.String())
	}
}
