package supervisor

import (
	"bufio"
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
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
