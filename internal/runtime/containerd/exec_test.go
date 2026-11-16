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
