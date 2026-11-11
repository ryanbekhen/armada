package conformance

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// members checks init containers and sidecars (ADR 0038): an init container
// runs to its end before anything else, a sidecar shares the replica's
// network namespace (the replica reaches it on 127.0.0.1), the replica's
// container stops before its sidecars, a failed init container leaves the
// replica unstarted with its output readable, and Remove takes them all.
func (r *runner) members(t *testing.T) {
	ctx, cancel := r.ctx()
	defer cancel()
	member := func(name string, cmd ...string) runtime.MemberSpec {
		return runtime.MemberSpec{Name: name, Image: r.opts.Image, Cmd: cmd, MemoryBytes: 32 << 20, PidsLimit: 100}
	}
	s := r.spec("sh", "-c", `for i in $(seq 50); do wget -q -O - http://127.0.0.1:8081/hostname && exit 0; sleep 0.2; done; exit 1`)
	s.Init = []runtime.MemberSpec{member("prep", "sh", "-c", "echo init-ran")}
	s.Sidecars = []runtime.MemberSpec{member("web", "httpd", "-f", "-p", "127.0.0.1:8081", "-h", "/etc")}
	id, err := r.d.Run(ctx, s)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	c := r.wait(ctx, t, id)
	if c.State != runtime.StateExited || c.ExitCode != 0 {
		t.Errorf("the container did not reach its sidecar on 127.0.0.1: %s, exit %d", c.State, c.ExitCode)
	}
	prep, ok := c.Member("prep")
	if !ok || prep.Role != runtime.RoleInit || prep.State != runtime.StateExited || prep.ExitCode != 0 {
		t.Errorf("init container %+v (members %+v)", prep, c.Members)
	}
	web, ok := c.Member("web")
	if !ok || web.Role != runtime.RoleSidecar || web.State != runtime.StateRunning {
		t.Errorf("sidecar %+v", web)
	}
	if out := r.logsOf(t, prep.ID); !strings.Contains(out, "init-ran") {
		t.Errorf("init container output %q", out)
	}
	if err := r.d.Stop(ctx, id, 5*time.Second); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if c, _ := r.d.Inspect(ctx, id); c.Members != nil {
		if web, _ := c.Member("web"); web.State == runtime.StateRunning {
			t.Error("the sidecar runs after Stop")
		}
	}
	if err := r.d.Remove(ctx, id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	for _, m := range c.Members {
		if _, err := r.d.Inspect(ctx, m.ID); !errors.Is(err, runtime.ErrNotFound) {
			t.Errorf("%s left after Remove: %v", m.Name, err)
		}
	}

	// A failed init container: nothing else starts, and its output stays.
	s = r.spec("sh", "-c", "echo must-not-run")
	s.Init = []runtime.MemberSpec{member("fail", "sh", "-c", "echo init-failed; exit 7")}
	s.Sidecars = []runtime.MemberSpec{member("web", "sleep", "300")}
	id, err = r.d.Run(ctx, s)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	c = r.wait(ctx, t, id)
	failed, ok := c.FailedInit()
	if !ok || failed.Name != "fail" || failed.ExitCode != 7 || c.State != runtime.StateExited {
		t.Errorf("failed init: %s %+v", c.State, c.Members)
	}
	if _, ok := c.Member("web"); ok {
		t.Error("a sidecar started after a failed init container")
	}
	if out := r.logsOf(t, failed.ID); !strings.Contains(out, "init-failed") {
		t.Errorf("failed init container output %q", out)
	}
	if out := r.logsOf(t, id); strings.Contains(out, "must-not-run") {
		t.Error("the container ran after a failed init container")
	}
	if err := r.d.Remove(ctx, id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
}

// logsOf returns what container id wrote, both streams.
func (r *runner) logsOf(t *testing.T, id string) string {
	t.Helper()
	ctx, cancel := r.ctx()
	defer cancel()
	ls, err := r.d.Logs(ctx, id, runtime.LogOptions{})
	if err != nil {
		return ""
	}
	defer ls.Close()
	var b strings.Builder
	for {
		f, err := ls.Next()
		if errors.Is(err, io.EOF) || err != nil {
			return b.String()
		}
		b.Write(f.Data)
	}
}
