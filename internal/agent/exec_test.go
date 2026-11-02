package agent

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// execClient serves ExecSession with an in-memory stream.
type execClient struct {
	armadav1.AgentServiceClient
	stream *execStream
}

func (c execClient) ExecSession(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[armadav1.ExecSessionOutput, armadav1.ExecInput], error) {
	return c.stream, nil
}

type execStream struct {
	grpc.ClientStream
	in  chan *armadav1.ExecInput // closed: the server ended the session
	out chan *armadav1.ExecSessionOutput
}

func newExecStream() *execStream {
	return &execStream{in: make(chan *armadav1.ExecInput, 8), out: make(chan *armadav1.ExecSessionOutput, 64)}
}

func (s *execStream) Send(m *armadav1.ExecSessionOutput) error { s.out <- m; return nil }
func (s *execStream) CloseSend() error                         { return nil }

func (s *execStream) Recv() (*armadav1.ExecInput, error) {
	m, ok := <-s.in
	if !ok {
		return nil, io.EOF
	}
	return m, nil
}

func (s *execStream) next(t *testing.T) *armadav1.ExecSessionOutput {
	t.Helper()
	select {
	case m := <-s.out:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no message from the agent")
		return nil
	}
}

// appOnlyDriver hides the fake runtime's ExecApp.
type appOnlyDriver struct{ runtime.Driver }

func TestServeExec(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	newExecAgent := func(t *testing.T) (*Agent, *execStream) {
		a, d := newAgent(t)
		s := newExecStream()
		a.cfg.Client = execClient{stream: s}
		d.Add(runtime.Container{ID: "c1", State: runtime.StateRunning, Labels: map[string]string{runtime.LabelManaged: "true", runtime.LabelReplica: "web-1"}})
		d.Add(runtime.Container{ID: "c2", State: runtime.StateExited, Labels: map[string]string{runtime.LabelManaged: "true", runtime.LabelReplica: "web-2"}})
		a.setDesired([]*armadav1.ReplicaSpec{replica("web-1", "nginx", 80), replica("web-2", "nginx", 80)}, nil)
		return a, s
	}
	refused := func(t *testing.T, a *Agent, s *execStream, req *armadav1.ExecRequest, want string) {
		t.Helper()
		close(s.in)
		a.serveExec(ctx, req)
		m := s.next(t)
		if m.GetRequestId() != req.GetRequestId() || !strings.Contains(m.GetError(), want) {
			t.Errorf("first message = %v, want an error with %q", m, want)
		}
	}

	t.Run("replica of another node", func(t *testing.T) {
		a, s := newExecAgent(t)
		refused(t, a, s, &armadav1.ExecRequest{RequestId: "r", ReplicaId: "other-1", Cmd: []string{"sh"}}, "not assigned to this node")
	})
	t.Run("no running container", func(t *testing.T) {
		a, s := newExecAgent(t)
		refused(t, a, s, &armadav1.ExecRequest{RequestId: "r", ReplicaId: "web-2", Cmd: []string{"sh"}}, "no running container")
	})
	t.Run("bad command", func(t *testing.T) {
		a, s := newExecAgent(t)
		refused(t, a, s, &armadav1.ExecRequest{RequestId: "r", ReplicaId: "web-1", Cmd: []string{"sh", "x\x00"}}, "NUL")
	})
	t.Run("runtime without exec", func(t *testing.T) {
		a, s := newExecAgent(t)
		a.cfg.Driver = appOnlyDriver{a.cfg.Driver}
		refused(t, a, s, &armadav1.ExecRequest{RequestId: "r", ReplicaId: "web-1", Cmd: []string{"sh"}}, "does not run commands")
	})
	t.Run("too many sessions", func(t *testing.T) {
		a, s := newExecAgent(t)
		a.execs.Store(maxExecSessions)
		refused(t, a, s, &armadav1.ExecRequest{RequestId: "r", ReplicaId: "web-1", Cmd: []string{"sh"}}, "most exec sessions")
		if a.execs.Load() != maxExecSessions {
			t.Errorf("session count = %d", a.execs.Load())
		}
	})

	t.Run("runs the command", func(t *testing.T) {
		a, s := newExecAgent(t)
		done := make(chan struct{})
		go func() {
			defer close(done)
			a.serveExec(ctx, &armadav1.ExecRequest{RequestId: "r", ReplicaId: "web-1", Cmd: []string{"cat", "-"}, Stdin: true})
		}()
		if m := s.next(t); m.GetRequestId() != "r" || m.GetOutput() != nil {
			t.Fatalf("first message = %v", m)
		}
		s.in <- &armadav1.ExecInput{Input: &armadav1.ExecInput_Stdin{Stdin: []byte("hi")}}
		s.in <- &armadav1.ExecInput{Input: &armadav1.ExecInput_CloseStdin{CloseStdin: true}}
		var stdout, stderr string
		for {
			m := s.next(t)
			if m.GetOutput() == nil {
				t.Fatalf("message without output: %v", m)
			}
			if _, ok := m.GetOutput().(*armadav1.ExecSessionOutput_ExitCode); ok {
				if m.GetExitCode() != 1 {
					t.Errorf("exit code = %d", m.GetExitCode())
				}
				break
			}
			stdout += string(m.GetStdout())
			stderr += string(m.GetStderr())
		}
		if stdout != "hi" || stderr != "cat" {
			t.Errorf("stdout %q, stderr %q", stdout, stderr)
		}
		close(s.in)
		<-done
		if a.execs.Load() != 0 {
			t.Errorf("session count = %d after the session", a.execs.Load())
		}
	})
}
