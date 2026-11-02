// Package conformance tests that a runtime driver behaves as Armada needs
// (ADR 0015): the security defaults, checked from inside containers, the
// container lifecycle, labels, publishing on a private address, logs, and
// errors. Drivers run it from a test against a real engine:
//
//	func TestConformance(t *testing.T) {
//		conformance.Run(t, myDriver, conformance.Options{HostIP: "10.0.0.5"})
//	}
//
// It needs root (or whatever the engine needs), network access to pull the
// test image, and leaves nothing behind. It can run on a node whose agent
// is running: its containers carry none of the labels the agent manages.
package conformance

import (
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

	"github.com/ryanbekhen/armada/driverkit"
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
	// Info is what the driver serves in its handshake. With VMIsolation the
	// suite checks that containers run on separate kernels instead of
	// checking no-new-privileges and the PID limit; test containers get at
	// least MinMemoryBytes.
	Info driverkit.Info
}

// Linux capability numbers of runtime.DroppedCaps.
var capBits = map[string]uint{"NET_RAW": 13, "MKNOD": 27, "AUDIT_WRITE": 29}

// Run runs every check against d as subtests.
func Run(t *testing.T, d driverkit.Driver, opts Options) {
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
	if opts.Info.VMIsolation {
		t.Run("VMIsolation", r.vmIsolation)
	}
	t.Run("Lifecycle", r.lifecycle)
	t.Run("Labels", r.labels)
	t.Run("Logs", r.logs)
	t.Run("NotFound", r.notFound)
	t.Run("Publish", r.publish)
	if sys, ok := d.(driverkit.SystemRunner); ok {
		t.Run("SystemContainers", func(t *testing.T) { r.system(t, sys) })
	}
	if bi, ok := d.(driverkit.BridgeInspector); ok {
		t.Run("Bridge", func(t *testing.T) { r.bridge(t, bi) })
	}
}

type runner struct {
	d    driverkit.Driver
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
func (r *runner) spec(cmd ...string) driverkit.ContainerSpec {
	r.n++
	return driverkit.ContainerSpec{
		Name:  fmt.Sprintf("armada-conformance-%s-%d", r.run, r.n),
		Image: r.opts.Image,
		Cmd:   cmd,
		// Not armada.managed: an agent on the same node would remove
		// containers it does not know.
		Labels:      map[string]string{labelRun: r.run},
		MemoryBytes: max(64<<20, r.opts.Info.MinMemoryBytes),
		PidsLimit:   100,
		Security:    driverkit.Security{NoNewPrivileges: true, DropCapabilities: driverkit.RequiredDroppedCaps},
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
func (r *runner) wait(ctx context.Context, t *testing.T, id string) driverkit.Container {
	t.Helper()
	for {
		c, err := r.d.Inspect(ctx, id)
		if err != nil {
			t.Fatalf("Inspect: %v", err)
		}
		if c.State != driverkit.StateRunning && c.State != driverkit.StateCreated && c.State != driverkit.StateRestarting {
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
func (r *runner) output(t *testing.T, spec driverkit.ContainerSpec) (stdout, stderr string, exit int) {
	t.Helper()
	ctx, cancel := r.ctx()
	defer cancel()
	id, err := r.d.Run(ctx, spec)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	c := r.wait(ctx, t, id)
	ls, err := r.d.Logs(ctx, id, driverkit.LogOptions{})
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
		if f.Stream == driverkit.Stderr {
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
	spec.Files = []driverkit.FileMount{{Source: file, Target: "/run/secrets/s"}}
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
	// With VM isolation the container's kernel is its own, and the
	// VMIsolation subtest checks that instead (ADR 0016).
	vm := r.opts.Info.VMIsolation
	if fields["NoNewPrivs"] != "1" && !vm {
		t.Errorf("NoNewPrivs = %q, want 1", fields["NoNewPrivs"])
	}
	capEff, err := strconv.ParseUint(fields["CapEff"], 16, 64)
	if err != nil {
		t.Errorf("CapEff %q: %v", fields["CapEff"], err)
	}
	for _, c := range driverkit.RequiredDroppedCaps {
		if bit, ok := capBits[c]; ok && capEff&(1<<bit) != 0 {
			t.Errorf("capability %s not dropped (CapEff %s)", c, fields["CapEff"])
		}
	}
	if fields["memory"] != strconv.FormatInt(spec.MemoryBytes, 10) {
		t.Errorf("memory limit %q, want %d", fields["memory"], spec.MemoryBytes)
	}
	if fields["pids"] != strconv.FormatInt(spec.PidsLimit, 10) && !vm {
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

// vmIsolation checks a driver's VM isolation claim: two containers, and
// this machine when it runs Linux, report different kernel boot IDs.
func (r *runner) vmIsolation(t *testing.T) {
	const cmd = "cat /proc/sys/kernel/random/boot_id"
	seen := map[string]string{}
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		seen[strings.TrimSpace(string(b))] = "this machine"
	}
	for i := range 2 {
		out, errOut, code := r.output(t, r.spec("sh", "-c", cmd))
		id := strings.TrimSpace(out)
		if code != 0 || id == "" {
			t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
		}
		who := fmt.Sprintf("container %d", i+1)
		if prev, ok := seen[id]; ok {
			t.Fatalf("%s shares a kernel with %s (boot ID %s)", who, prev, id)
		}
		seen[id] = who
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
	if c.State != driverkit.StateRunning || c.Name != spec.Name || c.StartedAt.IsZero() {
		t.Errorf("after Run: state %q, name %q, started %v", c.State, c.Name, c.StartedAt)
	}
	if err := r.d.Stop(ctx, id, 2*time.Second); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if c := r.wait(ctx, t, id); c.State != driverkit.StateExited && c.State != driverkit.StateDead {
		t.Errorf("after Stop: state %q", c.State)
	}
	if err := r.d.Remove(ctx, id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := r.d.Inspect(ctx, id); !errors.Is(err, driverkit.ErrNotFound) {
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
	found := map[string]driverkit.Container{}
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
	if _, err := r.d.Inspect(ctx, id); !errors.Is(err, driverkit.ErrNotFound) {
		t.Errorf("Inspect = %v", err)
	}
	if err := r.d.Remove(ctx, id); !errors.Is(err, driverkit.ErrNotFound) {
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

func (r *runner) system(t *testing.T, sys driverkit.SystemRunner) {
	ctx, cancel := r.ctx()
	defer cancel()
	id, err := sys.RunSystem(ctx, driverkit.SystemSpec{
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

func (r *runner) bridge(t *testing.T, bi driverkit.BridgeInspector) {
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
