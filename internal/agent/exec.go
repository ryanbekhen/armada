package agent

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"sync"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// maxExecSessions bounds the exec sessions an agent runs at once (ADR 0015).
const maxExecSessions = 8

// serveExec runs one exec request: it opens the session stream, checks the
// replica is this node's and has a running container, and relays the
// command's input and output. It never logs the command's arguments.
func (a *Agent) serveExec(ctx context.Context, req *armadav1.ExecRequest) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := a.cfg.Client.ExecSession(ctx)
	if err != nil {
		a.log.Warn("open exec stream failed", "err", err)
		return
	}
	var mu sync.Mutex // serializes sends
	send := func(m *armadav1.ExecSessionOutput) error {
		mu.Lock()
		defer mu.Unlock()
		return stream.Send(m)
	}
	// recvDone is closed once the stream has no more input; before the
	// command starts nothing reads it, so finish drains it itself.
	var recvDone chan struct{}
	finish := func(m *armadav1.ExecSessionOutput) {
		_ = send(m)
		_ = stream.CloseSend()
		// Wait for the server to end the session, so the last message is
		// delivered before the stream is cancelled.
		if recvDone != nil {
			<-recvDone
			return
		}
		for {
			if _, err := stream.Recv(); err != nil {
				return
			}
		}
	}
	fail := func(msg string) {
		finish(&armadav1.ExecSessionOutput{RequestId: req.GetRequestId(), Output: &armadav1.ExecSessionOutput_Error{Error: msg}})
	}

	if n := a.execs.Add(1); n > maxExecSessions {
		a.execs.Add(-1)
		fail("this node already runs the most exec sessions it allows")
		return
	}
	defer a.execs.Add(-1)
	if err := runtime.CheckExecCommand(req.GetCmd()); err != nil {
		fail(err.Error())
		return
	}
	ex, ok := a.cfg.Driver.(runtime.Execer)
	if !ok || !runtime.CanExec(a.cfg.Driver) {
		fail("this node's container runtime does not run commands in containers")
		return
	}
	a.mu.Lock()
	_, assigned := a.desired[req.GetReplicaId()]
	a.mu.Unlock()
	if !assigned {
		fail("replica " + req.GetReplicaId() + " is not assigned to this node")
		return
	}
	cs, err := a.cfg.Driver.List(ctx, map[string]string{runtime.LabelManaged: "true", runtime.LabelReplica: req.GetReplicaId()})
	if err != nil {
		fail("list containers: " + err.Error())
		return
	}
	var id string
	for _, c := range cs {
		if c.State == runtime.StateRunning {
			id = c.ID
		}
	}
	if id == "" {
		fail("replica " + req.GetReplicaId() + " has no running container on this node")
		return
	}
	if err := send(&armadav1.ExecSessionOutput{RequestId: req.GetRequestId()}); err != nil {
		return
	}

	opts := runtime.ExecOptions{
		Cmd: req.GetCmd(), TTY: req.GetTty(), Size: termSize(req.GetSize()),
		Stdout: execWriter(send, true), Stderr: execWriter(send, false),
	}
	resize := make(chan runtime.TermSize, 4)
	opts.Resize = resize
	var stdinW *io.PipeWriter
	if req.GetStdin() {
		var r *io.PipeReader
		r, stdinW = io.Pipe()
		opts.Stdin = r
		defer func() { _ = r.Close() }()
	}
	recvDone = make(chan struct{})
	go func() {
		defer close(recvDone)
		// The server ending the stream ends the command.
		defer cancel()
		defer func() {
			if stdinW != nil {
				_ = stdinW.Close()
			}
		}()
		for {
			in, err := stream.Recv()
			if err != nil {
				return
			}
			switch {
			case in.GetResize() != nil:
				select {
				case resize <- termSize(in.GetResize()):
				default:
				}
			case in.GetCloseStdin():
				if stdinW != nil {
					_ = stdinW.Close()
				}
			case len(in.GetStdin()) > 0 && stdinW != nil:
				if _, err := stdinW.Write(in.GetStdin()); err != nil {
					stdinW = nil
				}
			}
		}
	}()

	a.log.Info("exec session", "replica", req.GetReplicaId(), "command", filepath.Base(req.GetCmd()[0]), "tty", req.GetTty())
	code, err := ex.ExecApp(ctx, id, opts)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		fail(err.Error())
		return
	}
	finish(&armadav1.ExecSessionOutput{Output: &armadav1.ExecSessionOutput_ExitCode{ExitCode: int32(code)}}) //nolint:gosec // exit codes fit
}

func termSize(t *armadav1.TermSize) runtime.TermSize {
	return runtime.TermSize{Rows: uint16(min(t.GetRows(), 0xffff)), Cols: uint16(min(t.GetCols(), 0xffff))}
}

// execWriter sends what is written as stdout or stderr messages of at most
// runtime.MaxExecChunk bytes.
func execWriter(send func(*armadav1.ExecSessionOutput) error, stdout bool) io.Writer {
	return writerFunc(func(p []byte) (int, error) {
		for off := 0; off < len(p); off += runtime.MaxExecChunk {
			chunk := append([]byte(nil), p[off:min(off+runtime.MaxExecChunk, len(p))]...)
			m := &armadav1.ExecSessionOutput{Output: &armadav1.ExecSessionOutput_Stderr{Stderr: chunk}}
			if stdout {
				m = &armadav1.ExecSessionOutput{Output: &armadav1.ExecSessionOutput_Stdout{Stdout: chunk}}
			}
			if err := send(m); err != nil {
				return off, io.ErrClosedPipe
			}
		}
		return len(p), nil
	})
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
