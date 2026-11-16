package supervisor

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/errdefs"
)

// fakeShim answers requests on a socket the way armada-shim does.
func fakeShim(t *testing.T, sock string, answer func(req string) string) {
	t.Helper()
	l, err := net.Listen("unix", sock)
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
			_, _ = c.Write([]byte(answer(strings.TrimSpace(line)) + "\n"))
			_ = c.Close()
		}
	}()
}

func TestShimsStartOnce(t *testing.T) {
	dir := t.TempDir()
	var launched []string
	s := &Shims{Dir: dir, Bin: "/bin/armada-shim", Runc: "/bin/runc", Logger: "/bin/armada-log",
		Launch: func(_ context.Context, unit string, argv []string) error {
			launched = append(launched, unit+" "+strings.Join(argv, " "))
			fakeShim(t, argv[2], func(string) string { return "ok" })
			return nil
		}}
	ctx := context.Background()
	sh, err := s.For(ctx, "web@pack1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.For(ctx, "web@pack1"); err != nil {
		t.Fatal(err)
	}
	if len(launched) != 1 {
		t.Fatalf("launched %d shims: %q", len(launched), launched)
	}
	name := shimName("web@pack1")
	want := "armada-shim-" + name + " /bin/armada-shim serve " + filepath.Join(dir, name+".sock") + " " + filepath.Join(dir, name) + " /bin/runc /bin/armada-log"
	if launched[0] != want {
		t.Errorf("launched %q\nwant     %q", launched[0], want)
	}
	if sh.Root != filepath.Join(dir, name, "runc") {
		t.Errorf("root %s", sh.Root)
	}
	if shimName("web@pack2") == name {
		t.Error("groups share a name")
	}
}

func TestShimRequests(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s.sock")
	var got []string
	fakeShim(t, sock, func(req string) string {
		got = append(got, req)
		switch req {
		case "create c1 /b /l":
			return "ok 42"
		case "state c1":
			return "ok exited 137"
		case "state nope":
			return "err nope not found"
		case "list":
			return "ok c1 running:42 c2 exited:0 c3 created:7"
		}
		return "ok"
	})
	sh := &Shim{Socket: sock}
	ctx := context.Background()
	if pid, err := sh.Create(ctx, "c1", "/b", "/l"); err != nil || pid != 42 {
		t.Fatalf("create: %d %v", pid, err)
	}
	if st, err := sh.State(ctx, "c1"); err != nil || st != (TaskState{Status: "exited", Exit: 137}) {
		t.Fatalf("state: %+v %v", st, err)
	}
	if _, err := sh.State(ctx, "nope"); !NotFound(err) {
		t.Fatalf("state nope: %v", err)
	}
	all, err := sh.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]TaskState{
		"c1": {Status: "running", Pid: 42},
		"c2": {Status: "exited"},
		"c3": {Status: "created", Pid: 7},
	}
	if len(all) != len(want) {
		t.Fatalf("list %+v", all)
	}
	for id, st := range want {
		if all[id] != st {
			t.Errorf("%s: %+v, want %+v", id, all[id], st)
		}
	}
	if err := sh.Kill(ctx, "c1", 15); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.call(ctx, "kill", "c1 x"); err == nil {
		t.Error("a word with a space was sent")
	}
	if got[len(got)-1] != "kill c1 15" {
		t.Errorf("last request %q", got[len(got)-1])
	}
}

// mutedShim accepts requests on sock and closes each connection without an
// answer, as a busy shim's connection can end (EOF).
func mutedShim(t *testing.T, sock string) {
	t.Helper()
	l, err := net.Listen("unix", sock)
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
			_, _ = bufio.NewReader(c).ReadString('\n')
			_ = c.Close()
		}
	}()
}

// abandonShims returns shims whose runc records each call, with group's
// runc root in place and container c1 left in it.
func abandonShims(t *testing.T, group string, active func() (bool, error)) (*Shims, func() string) {
	t.Helper()
	// Unix socket paths are short: keep the directory near the root.
	dir, err := os.MkdirTemp("", "armada-shim")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	calls := filepath.Join(dir, "calls")
	runc := filepath.Join(dir, "runc")
	script := "#!/bin/sh\necho \"$*\" >>" + calls + "\ncase \"$*\" in *' list -q') echo c1;; esac\n"
	if err := os.WriteFile(runc, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	s := &Shims{Dir: dir, Runc: runc, Active: func(_ context.Context, unit string) (bool, error) {
		if unit != unitName(group) {
			t.Errorf("asked about unit %s", unit)
		}
		return active()
	}}
	if err := os.MkdirAll(s.Get(group).Root, 0o700); err != nil {
		t.Fatal(err)
	}
	return s, func() string {
		b, _ := os.ReadFile(calls)
		return string(b)
	}
}

// TestTaskKeepsSlowShim: a shim whose unit is active keeps its containers
// when a call to it fails, by timeout or a closed connection; the task is
// not reported missing, and the shim is not replaced.
func TestTaskKeepsSlowShim(t *testing.T) {
	const group = "web@pack"
	t.Run("closed connection", func(t *testing.T) {
		s, calls := abandonShims(t, group, func() (bool, error) { return true, nil })
		mutedShim(t, s.Get(group).Socket)
		c := &container{s: &Store{Shims: s}, rec: Record{ID: "c1", Group: group}}
		if _, err := c.Task(context.Background(), nil); err == nil || errdefs.IsNotFound(err) {
			t.Fatalf("task of a live shim: %v", err)
		}
		launched := false
		s.Launch = func(context.Context, string, []string) error { launched = true; return nil }
		if _, err := s.For(context.Background(), group); err == nil || launched {
			t.Fatalf("for a live shim: %v, launched %v", err, launched)
		}
		if got := calls(); got != "" {
			t.Fatalf("runc ran for a live shim:\n%s", got)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		s, calls := abandonShims(t, group, func() (bool, error) { return true, nil })
		sock := s.Get(group).Socket
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		// Never accepted: connections wait in the backlog, unanswered.
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		c := &container{s: &Store{Shims: s}, rec: Record{ID: "c1", Group: group}}
		if _, err := c.Task(ctx, nil); err == nil || errdefs.IsNotFound(err) {
			t.Fatalf("task of a slow shim: %v", err)
		}
		if got := calls(); got != "" {
			t.Fatalf("runc ran for a slow shim:\n%s", got)
		}
	})
}

// TestTaskAbandonsGoneShim: a shim whose unit is no longer active, or
// whose socket is gone, left containers that are ended.
func TestTaskAbandonsGoneShim(t *testing.T) {
	const group = "web@pack"
	for _, tc := range []struct {
		name   string
		listen bool
		active bool
	}{
		{"unit inactive", true, false},
		{"no socket", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, calls := abandonShims(t, group, func() (bool, error) { return tc.active, nil })
			if tc.listen {
				mutedShim(t, s.Get(group).Socket)
			}
			c := &container{s: &Store{Shims: s}, rec: Record{ID: "c1", Group: group}}
			if _, err := c.Task(context.Background(), nil); !errdefs.IsNotFound(err) {
				t.Fatalf("task of a gone shim: %v", err)
			}
			if got := calls(); !strings.Contains(got, "kill --all c1 KILL") || !strings.Contains(got, "delete --force c1") {
				t.Fatalf("runc calls:\n%s", got)
			}
		})
	}
}

// TestTaskActiveCheckFails: when the unit's state cannot be read, nothing
// is abandoned.
func TestTaskActiveCheckFails(t *testing.T) {
	const group = "web@pack"
	s, calls := abandonShims(t, group, func() (bool, error) { return false, errors.New("no systemd") })
	mutedShim(t, s.Get(group).Socket)
	c := &container{s: &Store{Shims: s}, rec: Record{ID: "c1", Group: group}}
	if _, err := c.Task(context.Background(), nil); err == nil || errdefs.IsNotFound(err) {
		t.Fatalf("task: %v", err)
	}
	if got := calls(); got != "" {
		t.Fatalf("runc ran:\n%s", got)
	}
}

// TestShimsForSerialized: concurrent callers for one group start one shim,
// and a group that is starting holds up no other.
func TestShimsForSerialized(t *testing.T) {
	dir, err := os.MkdirTemp("", "armada-shim")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	var mu sync.Mutex
	launched := map[string]int{}
	release := make(chan struct{})
	s := &Shims{Dir: dir, Runc: "/bin/false",
		Launch: func(_ context.Context, unit string, argv []string) error {
			mu.Lock()
			launched[unit]++
			mu.Unlock()
			if unit == unitName("slow@pack") {
				<-release
			}
			// Answer a moment later, as a shim that is starting does.
			time.Sleep(50 * time.Millisecond)
			fakeShim(t, argv[2], func(string) string { return "ok" })
			return nil
		},
		Active: func(context.Context, string) (bool, error) { return false, nil },
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			_, err := s.For(ctx, "slow@pack")
			errs <- err
		})
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.For(ctx, "fast@pack")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a starting group held up another")
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	n := launched[unitName("slow@pack")]
	mu.Unlock()
	if n != 1 {
		t.Fatalf("launched %d shims for one group", n)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.groups) != 0 {
		t.Errorf("group locks left: %d", len(s.groups))
	}
}

// TestShimsLockHonoursContext: a caller waiting for a group's lock gives
// up when its context ends.
func TestShimsLockHonoursContext(t *testing.T) {
	s := &Shims{}
	unlock, err := s.lock(context.Background(), "g")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := s.lock(ctx, "g"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second lock: %v", err)
	}
	unlock()
	if len(s.groups) != 0 {
		t.Errorf("group locks left: %d", len(s.groups))
	}
}
