// Package conformance tests that the container runtime behaves as Armada
// needs (ADR 0011): the security defaults, checked from inside containers,
// the container lifecycle, labels, publishing on a private address, logs,
// exec, stats, volumes, and errors. The embedded runtime runs it on a node
// (integration build tag).
//
// It needs root, network access to pull the test image, and leaves nothing
// behind. It can run on a node whose agent is running: its containers carry
// none of the labels the agent manages.
package conformance

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// Options configures a run.
type Options struct {
	// Image has a POSIX shell and busybox's httpd; default busybox:1.37.
	Image string
	// HostIP is a private address of this machine to publish a port on;
	// the publish test is skipped without one.
	HostIP string
	// Timeout bounds each step; default 2 minutes.
	Timeout time.Duration
}

// Linux capability numbers of runtime.DroppedCaps.
var capBits = map[string]uint{"NET_RAW": 13, "MKNOD": 27, "AUDIT_WRITE": 29}

// Run runs every check against d as subtests.
func Run(t *testing.T, d runtime.Driver, opts Options) {
	t.Helper()
	if opts.Image == "" {
		opts.Image = "busybox:1.37"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Minute
	}
	r := &runner{d: d, opts: opts, run: randomID()}
	t.Cleanup(r.cleanup)

	ctx, cancel := r.ctx()
	defer cancel()
	if err := d.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if _, err := d.Pull(ctx, opts.Image, nil); err != nil {
		t.Fatalf("Pull %s: %v", opts.Image, err)
	}

	t.Run("SecurityDefaults", r.securityDefaults)
	t.Run("Lifecycle", r.lifecycle)
	t.Run("Labels", r.labels)
	t.Run("Logs", r.logs)
	t.Run("NotFound", r.notFound)
	t.Run("Publish", r.publish)
	if sys, ok := d.(runtime.SystemRunner); ok {
		t.Run("SystemContainers", func(t *testing.T) { r.system(t, sys) })
	}
	if bi, ok := d.(runtime.BridgeInspector); ok {
		t.Run("Bridge", func(t *testing.T) { r.bridge(t, bi) })
	}
	if ex, ok := d.(runtime.Execer); ok {
		t.Run("Exec", func(t *testing.T) { r.exec(t, ex) })
	}
	if sr, ok := d.(runtime.StatsReader); ok {
		t.Run("Stats", func(t *testing.T) { r.stats(t, sr) })
		t.Run("StatsEgress", func(t *testing.T) { r.statsEgress(t, sr) })
	}
	if runtime.CanMountVolumes(d) {
		t.Run("Volumes", r.volumes)
	}
	if runtime.CanRunMembers(d) {
		t.Run("InitContainersAndSidecars", r.members)
	}
	if p, ok := d.(runtime.ImagePruner); ok {
		t.Run("PruneImages", func(t *testing.T) { r.pruneImages(t, p) })
	}
}

// pruneImages pulls a second image, then checks that pruning spares recent
// pulls, images containers use, and kept references, and removes the rest.
// It runs last: with no grace it also removes other unused images of the
// node, never those a container uses.
func (r *runner) pruneImages(t *testing.T, p runtime.ImagePruner) {
	ctx, cancel := r.ctx()
	defer cancel()
	const other = "busybox:1.36"
	pulled, err := r.d.Pull(ctx, other, nil)
	if err != nil {
		t.Fatalf("Pull %s: %v", other, err)
	}
	id, err := r.d.Run(ctx, r.spec("sleep", "300"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.d.Remove(ctx, id) }()
	has := func(names []string, image string) bool {
		for _, n := range names {
			if strings.HasSuffix(n, "/"+image) || n == image {
				return true
			}
		}
		return false
	}
	if removed, err := p.PruneImages(ctx, nil, time.Hour); err != nil || has(removed, other) || has(removed, r.opts.Image) {
		t.Fatalf("within grace: removed %v, %v", removed, err)
	}
	// Kept by its digest: the tag shares it.
	if removed, err := p.PruneImages(ctx, []string{pulled.Ref}, 0); err != nil || has(removed, other) {
		t.Fatalf("kept by digest: removed %v, %v", removed, err)
	}
	removed, err := p.PruneImages(ctx, nil, 0)
	if err != nil || !has(removed, other) || has(removed, r.opts.Image) {
		t.Fatalf("removed %v, %v; want %s gone and %s (in use) kept", removed, err, other, r.opts.Image)
	}
	// The removed image comes back with a pull; the used one still runs.
	if _, err := r.d.Pull(ctx, other, nil); err != nil {
		t.Fatalf("pull after prune: %v", err)
	}
	if c, err := r.d.Inspect(ctx, id); err != nil || c.State != runtime.StateRunning {
		t.Fatalf("container after prune: %+v, %v", c, err)
	}
}

type runner struct {
	d    runtime.Driver
	opts Options
	// run labels everything this run creates, for cleanup.
	run string
	n   int
}

const labelRun = "armada.conformance"

func randomID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (r *runner) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), r.opts.Timeout)
}

// spec returns an app container spec with Armada's defaults.
func (r *runner) spec(cmd ...string) runtime.ContainerSpec {
	r.n++
	return runtime.ContainerSpec{
		Name:  fmt.Sprintf("armada-conformance-%s-%d", r.run, r.n),
		Image: r.opts.Image,
		Cmd:   cmd,
		// Not armada.managed: an agent on the same node would remove
		// containers it does not know.
		Labels:      map[string]string{labelRun: r.run},
		MemoryBytes: 64 << 20,
		PidsLimit:   100,
	}
}

func (r *runner) cleanup() {
	ctx, cancel := r.ctx()
	defer cancel()
	cs, err := r.d.List(ctx, map[string]string{labelRun: r.run})
	if err != nil {
		return
	}
	for _, c := range cs {
		_ = r.d.Remove(ctx, c.ID)
	}
}

// wait polls until the container is no longer running.
func (r *runner) wait(ctx context.Context, t *testing.T, id string) runtime.Container {
	t.Helper()
	for {
		c, err := r.d.Inspect(ctx, id)
		if err != nil {
			t.Fatalf("Inspect: %v", err)
		}
		if c.State != runtime.StateRunning && c.State != runtime.StateCreated && c.State != runtime.StateRestarting && c.State != runtime.StateStarting {
			return c
		}
		select {
		case <-ctx.Done():
			t.Fatalf("container %s still %s", id, c.State)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// output runs spec to completion and returns stdout and stderr.
func (r *runner) output(t *testing.T, spec runtime.ContainerSpec) (stdout, stderr string, exit int) {
	t.Helper()
	ctx, cancel := r.ctx()
	defer cancel()
	id, err := r.d.Run(ctx, spec)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	c := r.wait(ctx, t, id)
	ls, err := r.d.Logs(ctx, id, runtime.LogOptions{})
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	defer ls.Close()
	var out, errOut strings.Builder
	for {
		f, err := ls.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Logs: %v", err)
		}
		if f.Stream == runtime.Stderr {
			errOut.Write(f.Data)
		} else {
			out.Write(f.Data)
		}
	}
	return out.String(), errOut.String(), c.ExitCode
}

func (r *runner) securityDefaults(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(file, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := r.spec("sh", "-c", `grep -E '^(NoNewPrivs|CapEff):' /proc/self/status
echo "memory $(cat /sys/fs/cgroup/memory.max)"
echo "pids $(cat /sys/fs/cgroup/pids.max)"
echo "file $(cat /run/secrets/s)"
if echo x > /run/secrets/s 2>/dev/null; then echo "write ok"; else echo "write refused"; fi
echo "env $GREETING"`)
	spec.Files = []runtime.FileMount{{Source: file, Target: "/run/secrets/s"}}
	spec.Env = []string{"GREETING=hello"}
	out, errOut, code := r.output(t, spec)
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	fields := map[string]string{}
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		fields[strings.TrimSuffix(f[0], ":")] = strings.Join(f[1:], " ")
	}
	if fields["NoNewPrivs"] != "1" {
		t.Errorf("NoNewPrivs = %q, want 1", fields["NoNewPrivs"])
	}
	capEff, err := strconv.ParseUint(fields["CapEff"], 16, 64)
	if err != nil {
		t.Errorf("CapEff %q: %v", fields["CapEff"], err)
	}
	for _, c := range runtime.DroppedCaps {
		if bit, ok := capBits[c]; ok && capEff&(1<<bit) != 0 {
			t.Errorf("capability %s not dropped (CapEff %s)", c, fields["CapEff"])
		}
	}
	if fields["memory"] != strconv.FormatInt(spec.MemoryBytes, 10) {
		t.Errorf("memory limit %q, want %d", fields["memory"], spec.MemoryBytes)
	}
	if fields["pids"] != strconv.FormatInt(spec.PidsLimit, 10) {
		t.Errorf("PID limit %q, want %d", fields["pids"], spec.PidsLimit)
	}
	if fields["file"] != "s3cret" {
		t.Errorf("mounted file reads %q", fields["file"])
	}
	if fields["write"] != "refused" {
		t.Error("mounted file is writable")
	}
	if fields["env"] != "hello" {
		t.Errorf("environment variable reads %q", fields["env"])
	}
	if t.Failed() {
		t.Logf("container stdout:\n%s\nstderr:\n%s", out, errOut)
	}
}

func (r *runner) lifecycle(t *testing.T) {
	ctx, cancel := r.ctx()
	defer cancel()
	spec := r.spec("sleep", "300")
	id, err := r.d.Run(ctx, spec)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	c, err := r.d.Inspect(ctx, id)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if c.State != runtime.StateRunning || c.Name != spec.Name || c.StartedAt.IsZero() {
		t.Errorf("after Run: state %q, name %q, started %v", c.State, c.Name, c.StartedAt)
	}
	if err := r.d.Stop(ctx, id, 2*time.Second); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if c := r.wait(ctx, t, id); c.State != runtime.StateExited && c.State != runtime.StateDead {
		t.Errorf("after Stop: state %q", c.State)
	}
	if err := r.d.Remove(ctx, id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := r.d.Inspect(ctx, id); !errors.Is(err, runtime.ErrNotFound) {
		t.Errorf("Inspect after Remove = %v, want ErrNotFound", err)
	}

	// Remove stops a running container too.
	id, err = r.d.Run(ctx, r.spec("sleep", "300"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := r.d.Remove(ctx, id); err != nil {
		t.Fatalf("Remove of a running container: %v", err)
	}
}

// labels checks that List finds containers by all given labels, running
// or not, as the agent does to adopt containers after a restart.
func (r *runner) labels(t *testing.T) {
	ctx, cancel := r.ctx()
	defer cancel()
	a, b := r.spec("sleep", "300"), r.spec("true")
	a.Labels["armada.replica"], b.Labels["armada.replica"] = "a", "b"
	ida, err := r.d.Run(ctx, a)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	idb, err := r.d.Run(ctx, b)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	r.wait(ctx, t, idb)
	all, err := r.d.List(ctx, map[string]string{labelRun: r.run})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := map[string]runtime.Container{}
	for _, c := range all {
		found[c.ID] = c
	}
	if _, ok := found[ida]; !ok {
		t.Error("List misses a running container")
	}
	if c, ok := found[idb]; !ok {
		t.Error("List misses an exited container")
	} else if c.Labels["armada.replica"] != "b" {
		t.Errorf("labels not kept: %v", c.Labels)
	}
	one, err := r.d.List(ctx, map[string]string{labelRun: r.run, "armada.replica": "a"})
	if err != nil || len(one) != 1 || one[0].ID != ida {
		t.Errorf("List by two labels = %v, %v", one, err)
	}
}

func (r *runner) logs(t *testing.T) {
	out, errOut, _ := r.output(t, r.spec("sh", "-c", "echo to-stdout; echo to-stderr >&2"))
	if !strings.Contains(out, "to-stdout") || strings.Contains(out, "to-stderr") {
		t.Errorf("stdout = %q", out)
	}
	if !strings.Contains(errOut, "to-stderr") {
		t.Errorf("stderr = %q", errOut)
	}
}

func (r *runner) notFound(t *testing.T) {
	ctx, cancel := r.ctx()
	defer cancel()
	const id = "armada-conformance-does-not-exist"
	if _, err := r.d.Inspect(ctx, id); !errors.Is(err, runtime.ErrNotFound) {
		t.Errorf("Inspect = %v", err)
	}
	if err := r.d.Remove(ctx, id); !errors.Is(err, runtime.ErrNotFound) {
		t.Errorf("Remove = %v", err)
	}
}

func (r *runner) publish(t *testing.T) {
	if r.opts.HostIP == "" {
		t.Skip("no Options.HostIP")
	}
	ctx, cancel := r.ctx()
	defer cancel()
	spec := r.spec("sh", "-c", "mkdir -p /www && echo conformance > /www/index.html && exec httpd -f -p 8080 -h /www")
	spec.Port, spec.HostIP = 8080, r.opts.HostIP
	id, err := r.d.Run(ctx, spec)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	c, err := r.d.Inspect(ctx, id)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if c.HostIP != r.opts.HostIP || c.HostPort <= 0 {
		t.Fatalf("published on %s:%d, want %s and a port", c.HostIP, c.HostPort, r.opts.HostIP)
	}
	addr := net.JoinHostPort(c.HostIP, strconv.Itoa(c.HostPort))
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("nothing answers on %s: %v", addr, err)
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func (r *runner) system(t *testing.T, sys runtime.SystemRunner) {
	ctx, cancel := r.ctx()
	defer cancel()
	id, err := sys.RunSystem(ctx, runtime.SystemSpec{
		Name:   fmt.Sprintf("armada-conformance-%s-system", r.run),
		Image:  r.opts.Image,
		Cmd:    []string{"sleep", "300"},
		Labels: map[string]string{labelRun: r.run, "armada.system": "conformance"},
	})
	if err != nil {
		t.Fatalf("RunSystem: %v", err)
	}
	out, code, err := sys.Exec(ctx, id, []string{"sh", "-c", "grep CapEff /proc/self/status"})
	if err != nil || code != 0 {
		t.Fatalf("Exec = %q, %d, %v", out, code, err)
	}
	if !strings.Contains(out, "0000000000000000") {
		t.Errorf("system container without CapAdd keeps capabilities: %q", strings.TrimSpace(out))
	}
	if err := sys.Signal(ctx, id, "SIGTERM"); err != nil {
		t.Errorf("Signal: %v", err)
	}
}

func (r *runner) bridge(t *testing.T, bi runtime.BridgeInspector) {
	ctx, cancel := r.ctx()
	defer cancel()
	b, err := bi.Bridge(ctx)
	if err != nil {
		t.Fatalf("Bridge: %v", err)
	}
	if !b.Gateway.IsPrivate() || !b.Subnet.Contains(b.Gateway) {
		t.Errorf("bridge gateway %s, subnet %s: want a private gateway inside the subnet", b.Gateway, b.Subnet)
	}
}

// exec checks ExecApp (ADR 0015): standard input and its end, separate
// output streams, the exit code, a terminal with its size and a resize, and
// that the command keeps the container's security defaults.
func (r *runner) exec(t *testing.T, ex runtime.Execer) {
	ctx, cancel := r.ctx()
	defer cancel()
	id, err := r.d.Run(ctx, r.spec("sleep", "300"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	run := func(opts runtime.ExecOptions) (string, string, int) {
		t.Helper()
		var out, errOut bytes.Buffer
		opts.Stdout, opts.Stderr = &out, &errOut
		code, err := ex.ExecApp(ctx, id, opts)
		if err != nil {
			t.Fatalf("ExecApp %q: %v", opts.Cmd, err)
		}
		return out.String(), errOut.String(), code
	}
	// Localhost works: a new network namespace starts with its loopback down.
	if out, _, code := run(runtime.ExecOptions{Cmd: []string{"sh", "-c", "[ $(( $(cat /sys/class/net/lo/flags) & 1 )) = 1 ] && echo up"}}); code != 0 || strings.TrimSpace(out) != "up" {
		t.Errorf("the container's loopback is not up: %q, exit %d", out, code)
	}

	out, errOut, code := run(runtime.ExecOptions{
		Cmd:   []string{"sh", "-c", `read x; echo "out:$x"; cat; echo err >&2; exit 3`},
		Stdin: strings.NewReader("first\nrest\n"),
	})
	if out != "out:first\nrest\n" || errOut != "err\n" || code != 3 {
		t.Errorf("stdin and streams: stdout %q, stderr %q, exit %d", out, errOut, code)
	}

	out, _, _ = run(runtime.ExecOptions{Cmd: []string{"sh", "-c", `grep -E '^(NoNewPrivs|CapEff):' /proc/self/status`}})
	fields := map[string]string{}
	for line := range strings.SplitSeq(out, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			fields[k] = strings.TrimSpace(v)
		}
	}
	if fields["NoNewPrivs"] != "1" {
		t.Errorf("exec process NoNewPrivs = %q, want 1", fields["NoNewPrivs"])
	}
	capEff, err := strconv.ParseUint(fields["CapEff"], 16, 64)
	if err != nil {
		t.Errorf("exec process CapEff %q: %v", fields["CapEff"], err)
	}
	for _, c := range runtime.DroppedCaps {
		if bit, ok := capBits[c]; ok && capEff&(1<<bit) != 0 {
			t.Errorf("exec process has capability %s (CapEff %s)", c, fields["CapEff"])
		}
	}

	// The size may arrive shortly after the command starts (ExecOptions),
	// so the command waits up to 2 seconds for it.
	waitSize := func(want string) string {
		return `for i in $(seq 20); do s=$(stty size 2>/dev/null); [ "$s" = "` + want + `" ] && break; sleep 0.1; done; echo "size:$s"`
	}
	out, _, code = run(runtime.ExecOptions{
		Cmd: []string{"sh", "-c", `test -t 1 && echo tty; ` + waitSize("33 101")}, TTY: true,
		Size: runtime.TermSize{Rows: 33, Cols: 101},
	})
	if !strings.Contains(out, "tty") || code != 0 {
		t.Errorf("terminal: output %q, exit %d", out, code)
	}
	if !strings.Contains(out, "size:33 101") {
		t.Errorf("terminal size: output %q, want 33 101", out)
	}
	resize := make(chan runtime.TermSize, 1)
	resize <- runtime.TermSize{Rows: 40, Cols: 120}
	out, _, _ = run(runtime.ExecOptions{
		Cmd: []string{"sh", "-c", waitSize("40 120")}, TTY: true,
		Size: runtime.TermSize{Rows: 33, Cols: 101}, Resize: resize,
	})
	if !strings.Contains(out, "size:40 120") {
		t.Errorf("terminal resize: output %q, want 40 120", out)
	}

	if _, err := ex.ExecApp(ctx, "armada-conformance-missing", runtime.ExecOptions{Cmd: []string{"true"}, Stdout: io.Discard, Stderr: io.Discard}); err == nil {
		t.Error("ExecApp in a missing container succeeded")
	}
}

// stats checks that a container which holds 16 MiB and keeps a CPU busy is
// measured as such: memory between 12 MiB and its limit, and CPU time that
// grows by at least a tenth of the wall time.
func (r *runner) stats(t *testing.T, sr runtime.StatsReader) {
	ctx, cancel := r.ctx()
	defer cancel()
	spec := r.spec("sh", "-c", `x=$(head -c 16777216 /dev/zero | tr '\0' a); while :; do :; done`)
	id, err := r.d.Run(ctx, spec)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	const minMemory = 12 << 20
	var first runtime.Stats
	deadline := time.Now().Add(20 * time.Second)
	for {
		if first, err = sr.Stats(ctx, id); err != nil {
			t.Fatalf("Stats: %v", err)
		}
		if first.MemoryBytes >= minMemory || time.Now().After(deadline) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if first.MemoryBytes < minMemory || first.MemoryBytes > spec.MemoryBytes {
		t.Errorf("memory %d bytes, want between %d and the limit %d", first.MemoryBytes, minMemory, spec.MemoryBytes)
	}
	start := time.Now()
	time.Sleep(2 * time.Second)
	second, err := sr.Stats(ctx, id)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if used, wall := second.CPU-first.CPU, time.Since(start); used < wall/10 {
		t.Errorf("CPU time grew by %s in %s of a busy loop", used, wall.Round(time.Millisecond))
	}

	if _, err := sr.Stats(ctx, "armada-conformance-missing"); err == nil {
		t.Error("Stats of a missing container succeeded")
	}
}

// statsEgress checks that what a container sends over its network is counted.
func (r *runner) statsEgress(t *testing.T, sr runtime.StatsReader) {
	ctx, cancel := r.ctx()
	defer cancel()
	id, err := r.d.Run(ctx, r.spec("sh", "-c",
		`gw=$(ip route | awk '/^default/ {print $3}'); while :; do wget -q -T 1 -O /dev/null "http://$gw:9/"; sleep 0.2; done`))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		st, err := sr.Stats(ctx, id)
		if err != nil {
			t.Fatalf("Stats: %v", err)
		}
		if st.EgressBytes > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no egress counted for a container that keeps sending")
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// volumes checks that a volume is the host directory, writable, kept after
// the container is gone, and mounted without setuid programs or device
// files: the agent's volume directory is a nosuid,nodev mount, and the
// runtime's mount must keep both flags.
func (r *runner) volumes(t *testing.T) {
	dir, checkFlags := volumeDir(t)
	if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // the image's user may not be root
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "before"), []byte("kept"), 0o644); err != nil { //nolint:gosec // test data
		t.Fatal(err)
	}
	spec := r.spec("sh", "-c", "cat /data/before && echo written > /data/after && grep ' /data ' /proc/mounts")
	spec.Volumes = []runtime.VolumeMount{{Source: dir, Target: "/data"}}
	out, errOut, exit := r.output(t, spec)
	if exit != 0 {
		t.Fatalf("exit %d: %s%s", exit, out, errOut)
	}
	if !strings.Contains(out, "kept") {
		t.Errorf("the volume's existing file is not visible: %q", out)
	}
	b, err := os.ReadFile(filepath.Join(dir, "after")) //nolint:gosec // the test's own directory
	if err != nil || strings.TrimSpace(string(b)) != "written" {
		t.Errorf("the container's write did not reach the host directory: %q, %v", b, err)
	}
	if checkFlags {
		for _, flag := range []string{"nosuid", "nodev"} {
			if !strings.Contains(out, flag) {
				t.Errorf("volume mounted without %s: %q", flag, out)
			}
		}
	}
}
