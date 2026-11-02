package driverkit

import (
	"context"
	"errors"
	"io"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	driverv1 "github.com/ryanbekhen/armada/api/armada/driver/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// Exec limits (ADR 0017): arguments per command, bytes per argument, and
// bytes of data per message.
const (
	MaxExecArgs   = runtime.MaxExecArgs
	MaxExecArgLen = runtime.MaxExecArgLen
	MaxExecChunk  = runtime.MaxExecChunk
)

// CheckExecCommand checks a command for ExecApp: one to MaxExecArgs
// arguments of at most MaxExecArgLen bytes, without NUL bytes. Its errors
// never repeat the arguments.
func CheckExecCommand(cmd []string) error { return runtime.CheckExecCommand(cmd) }

func (s *server) ExecApp(stream driverv1.Driver_ExecAppServer) error {
	ex, ok := s.d.(Execer)
	if !ok {
		return status.Error(codes.Unimplemented, "driver does not run commands in app containers")
	}
	ctx := stream.Context()
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	start := first.GetStart()
	if start == nil {
		return status.Error(codes.InvalidArgument, "the first message must be start")
	}
	if err := checkID(start.GetId()); err != nil {
		return err
	}
	if err := CheckExecCommand(start.GetCmd()); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	// Only Armada's running app containers: never a system container or
	// one Armada did not create.
	c, err := s.d.Inspect(ctx, start.GetId())
	if err != nil {
		return toStatus(err)
	}
	if c.Labels[runtime.LabelManaged] != "true" || c.Labels[runtime.LabelSystem] != "" {
		return status.Error(codes.PermissionDenied, "not an app container")
	}
	if c.State != StateRunning {
		return status.Error(codes.FailedPrecondition, "container is not running")
	}

	out := &execSender{stream: stream}
	opts := ExecOptions{
		Cmd: start.GetCmd(), TTY: start.GetTty(), Size: termSize(start.GetSize()),
		Stdout: out.writer(true), Stderr: out.writer(false),
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	resize := make(chan TermSize, 4)
	opts.Resize = resize
	var stdinW *io.PipeWriter
	if start.GetStdin() {
		var r *io.PipeReader
		r, stdinW = io.Pipe()
		opts.Stdin = r
		defer func() { _ = r.Close() }()
	}
	go func() {
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
				default: // drop sizes the command has not caught up with
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
			if ctx.Err() != nil {
				return
			}
		}
	}()
	code, err := ex.ExecApp(ctx, start.GetId(), opts)
	if err != nil {
		return toStatus(err)
	}
	return out.send(&driverv1.ExecAppOutput{Output: &driverv1.ExecAppOutput_ExitCode{ExitCode: int32(code)}}) //nolint:gosec // exit codes fit
}

func termSize(t *driverv1.TermSize) TermSize {
	return TermSize{Rows: uint16(min(t.GetRows(), 0xffff)), Cols: uint16(min(t.GetCols(), 0xffff))}
}

// execSender serializes output messages, split into MaxExecChunk pieces.
type execSender struct {
	mu     sync.Mutex
	stream driverv1.Driver_ExecAppServer
}

func (e *execSender) send(m *driverv1.ExecAppOutput) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stream.Send(m)
}

func (e *execSender) writer(stdout bool) io.Writer {
	return writerFunc(func(p []byte) (int, error) {
		for off := 0; off < len(p); off += MaxExecChunk {
			chunk := append([]byte(nil), p[off:min(off+MaxExecChunk, len(p))]...)
			m := &driverv1.ExecAppOutput{Output: &driverv1.ExecAppOutput_Stderr{Stderr: chunk}}
			if stdout {
				m = &driverv1.ExecAppOutput{Output: &driverv1.ExecAppOutput_Stdout{Stdout: chunk}}
			}
			if err := e.send(m); err != nil {
				return off, errors.Join(io.ErrClosedPipe, err)
			}
		}
		return len(p), nil
	})
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
