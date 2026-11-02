package server

import (
	"errors"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
)

type execResult struct {
	replica, stdout, stderr string
	exit                    int32
	err                     error
}

// execCmd runs a command through AdminService.Exec, sending stdin and then
// closing it.
func execCmd(c *cluster, admin armadav1.AdminServiceClient, start *armadav1.ExecStart, stdin string) execResult {
	c.t.Helper()
	stream, err := admin.Exec(c.ctx)
	if err != nil {
		return execResult{err: err}
	}
	if err := stream.Send(&armadav1.ExecClientMessage{Msg: &armadav1.ExecClientMessage_Start{Start: start}}); err != nil {
		return execResult{err: err}
	}
	if start.GetStdin() {
		_ = stream.Send(&armadav1.ExecClientMessage{Msg: &armadav1.ExecClientMessage_Input{Input: &armadav1.ExecInput{Input: &armadav1.ExecInput_Stdin{Stdin: []byte(stdin)}}}})
		_ = stream.Send(&armadav1.ExecClientMessage{Msg: &armadav1.ExecClientMessage_Input{Input: &armadav1.ExecInput{Input: &armadav1.ExecInput_CloseStdin{CloseStdin: true}}}})
	}
	_ = stream.CloseSend()
	var r execResult
	for {
		m, err := stream.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				r.err = err
			}
			return r
		}
		switch o := m.GetMsg().(type) {
		case *armadav1.ExecServerMessage_Replica:
			r.replica = o.Replica
		case *armadav1.ExecServerMessage_Stdout:
			r.stdout += string(o.Stdout)
		case *armadav1.ExecServerMessage_Stderr:
			r.stderr += string(o.Stderr)
		case *armadav1.ExecServerMessage_ExitCode:
			r.exit = o.ExitCode
		}
	}
}

func TestExec(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	c.addNode("n1", "127.0.0.1")
	c.addNode("n2", "127.0.0.2")
	c.deploy(webSpec("nginx:1", 2))
	c.eventually("2 ready", func() bool {
		n := 0
		for _, r := range c.running("web") {
			if r.Ready {
				n++
			}
		}
		return n == 2
	})

	r := execCmd(c, c.admin, &armadav1.ExecStart{App: "web", Cmd: []string{"cat", "-", "--secret=hunter2"}, Stdin: true}, "hello")
	if r.err != nil || r.stdout != "hello" || r.stderr != "cat" || r.exit != 2 || r.replica == "" {
		t.Errorf("exec = %+v", r)
	}
	// A terminal sends everything as stdout.
	r = execCmd(c, c.admin, &armadav1.ExecStart{App: "web", Cmd: []string{"sh"}, Tty: true, Size: &armadav1.TermSize{Rows: 24, Cols: 80}}, "")
	if r.err != nil || r.stdout != "sh" || r.stderr != "" || r.exit != 0 {
		t.Errorf("tty exec = %+v", r)
	}
	// A named replica.
	rs := c.running("web")
	for _, rep := range rs {
		r := execCmd(c, c.admin, &armadav1.ExecStart{App: "web", Replica: rep.Id, Cmd: []string{"true"}}, "")
		if r.err != nil || r.replica != rep.Id {
			t.Errorf("exec in %s = %+v", rep.Id, r)
		}
	}

	// The audit log names the command, never its arguments.
	events, err := c.store.ListAudit(c.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Action != "app.exec" {
			continue
		}
		n++
		if e.Actor != "admin:ryan" {
			t.Errorf("audit actor = %q", e.Actor)
		}
		if strings.Contains(e.Detail, "hunter2") || strings.Contains(e.Detail, "--secret") {
			t.Errorf("audit detail holds arguments: %q", e.Detail)
		}
	}
	if n != 2+len(rs) {
		t.Errorf("%d app.exec audit events, want %d", n, 2+len(rs))
	}

	for name, tc := range map[string]struct {
		start *armadav1.ExecStart
		code  codes.Code
	}{
		"unknown app":     {&armadav1.ExecStart{App: "ghost", Cmd: []string{"sh"}}, codes.NotFound},
		"unknown replica": {&armadav1.ExecStart{App: "web", Replica: "ghost", Cmd: []string{"sh"}}, codes.NotFound},
		"empty command":   {&armadav1.ExecStart{App: "web"}, codes.InvalidArgument},
		"NUL byte":        {&armadav1.ExecStart{App: "web", Cmd: []string{"sh", "a\x00b"}}, codes.InvalidArgument},
		"too many args":   {&armadav1.ExecStart{App: "web", Cmd: make([]string, 65)}, codes.InvalidArgument},
	} {
		if r := execCmd(c, c.admin, tc.start, ""); status.Code(r.err) != tc.code {
			t.Errorf("%s: %v, want %s", name, r.err, tc.code)
		} else if strings.Contains(r.err.Error(), "a\x00b") {
			t.Errorf("%s: error repeats the argument: %v", name, r.err)
		}
	}

	// A second start ends the session with a clear error.
	stream2, err := c.admin.Exec(c.ctx)
	if err != nil {
		t.Fatal(err)
	}
	start := &armadav1.ExecClientMessage{Msg: &armadav1.ExecClientMessage_Start{Start: &armadav1.ExecStart{App: "web", Cmd: []string{"sh"}, Stdin: true}}}
	_ = stream2.Send(start)
	if m, err := stream2.Recv(); err != nil || m.GetReplica() == "" {
		t.Fatalf("first message = %v, %v", m, err)
	}
	_ = stream2.Send(start)
	for {
		if _, err := stream2.Recv(); err != nil {
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("second start: %v, want InvalidArgument", err)
			}
			break
		}
	}

	// Input before start is refused.
	stream, err := c.admin.Exec(c.ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Send(&armadav1.ExecClientMessage{Msg: &armadav1.ExecClientMessage_Input{Input: &armadav1.ExecInput{}}})
	if _, err := stream.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Errorf("input first: %v", err)
	}
}

func TestExecAuthorization(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	c.addNode("n1", "127.0.0.1")
	c.addNode("n2", "127.0.0.2")

	t.Run("node cannot call Exec", func(t *testing.T) {
		admin := armadav1.NewAdminServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: "n1"}))
		r := execCmd(c, admin, &armadav1.ExecStart{App: "web", Cmd: []string{"sh"}}, "")
		if status.Code(r.err) != codes.PermissionDenied {
			t.Errorf("err = %v, want PermissionDenied", r.err)
		}
	})

	t.Run("admin cannot open an exec session", func(t *testing.T) {
		ag := armadav1.NewAgentServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindAdmin, Name: "ryan"}))
		stream, err := ag.ExecSession(c.ctx)
		if err == nil {
			_ = stream.Send(&armadav1.ExecSessionOutput{RequestId: "x"})
			_, err = stream.Recv()
		}
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("err = %v, want PermissionDenied", err)
		}
	})

	t.Run("node cannot attach to another node's exec request", func(t *testing.T) {
		id, p := c.srv.execs.register("n1")
		defer c.srv.execs.cancel(id, p)
		for _, tc := range []struct{ node, req string }{{"n2", id}, {"n1", "unknown"}} {
			ag := armadav1.NewAgentServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: tc.node}))
			stream, err := ag.ExecSession(c.ctx)
			if err != nil {
				t.Fatal(err)
			}
			_ = stream.Send(&armadav1.ExecSessionOutput{RequestId: tc.req})
			if _, err := stream.Recv(); status.Code(err) != codes.PermissionDenied {
				t.Errorf("%s attaching %s: err = %v, want PermissionDenied", tc.node, tc.req, err)
			}
		}
		select {
		case <-p.attached:
			t.Error("request attached by the wrong node")
		default:
		}
	})

	t.Run("a request attaches once", func(t *testing.T) {
		id, p := c.srv.execs.register("n1")
		defer c.srv.execs.cancel(id, p)
		ag := armadav1.NewAgentServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: "n1"}))
		first, err := ag.ExecSession(c.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = first.Send(&armadav1.ExecSessionOutput{RequestId: id})
		<-p.attached
		second, err := ag.ExecSession(c.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = second.Send(&armadav1.ExecSessionOutput{RequestId: id})
		if _, err := second.Recv(); status.Code(err) != codes.PermissionDenied {
			t.Errorf("second attach: err = %v, want PermissionDenied", err)
		}
	})
}
