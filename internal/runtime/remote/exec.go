package remote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	driverv1 "github.com/ryanbekhen/armada/api/armada/driver/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

var _ runtime.Execer = (*Driver)(nil)

// CanExec reports whether the driver runs commands in app containers.
func (d *Driver) CanExec() bool { return d.has(driverv1.Capability_CAPABILITY_EXEC) }

// ExecApp runs a command in an app container through the driver.
func (d *Driver) ExecApp(ctx context.Context, id string, opts runtime.ExecOptions) (int, error) {
	if !d.CanExec() {
		return 0, errors.New("the node's runtime driver does not run commands in app containers")
	}
	if err := runtime.CheckExecCommand(opts.Cmd); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := d.client.ExecApp(ctx)
	if err != nil {
		return 0, wrap(err)
	}
	var mu sync.Mutex // serializes sends
	send := func(in *driverv1.ExecAppInput) error {
		mu.Lock()
		defer mu.Unlock()
		return stream.Send(in)
	}
	if err := send(&driverv1.ExecAppInput{Input: &driverv1.ExecAppInput_Start{Start: &driverv1.ExecAppStart{
		Id: id, Cmd: opts.Cmd, Tty: opts.TTY, Stdin: opts.Stdin != nil,
		Size: &driverv1.TermSize{Rows: uint32(opts.Size.Rows), Cols: uint32(opts.Size.Cols)},
	}}}); err != nil {
		return 0, wrap(err)
	}
	if opts.Stdin != nil {
		go func() {
			buf := make([]byte, runtime.MaxExecChunk)
			for {
				n, err := opts.Stdin.Read(buf)
				if n > 0 {
					if send(&driverv1.ExecAppInput{Input: &driverv1.ExecAppInput_Stdin{Stdin: append([]byte(nil), buf[:n]...)}}) != nil {
						return
					}
				}
				if err != nil {
					if errors.Is(err, io.EOF) {
						_ = send(&driverv1.ExecAppInput{Input: &driverv1.ExecAppInput_CloseStdin{CloseStdin: true}})
					}
					return
				}
			}
		}()
	}
	if opts.Resize != nil {
		go func() {
			for {
				select {
				case sz, ok := <-opts.Resize:
					if !ok {
						return
					}
					if send(&driverv1.ExecAppInput{Input: &driverv1.ExecAppInput_Resize{Resize: &driverv1.TermSize{Rows: uint32(sz.Rows), Cols: uint32(sz.Cols)}}}) != nil {
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	for {
		out, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, errors.New("driver ended the command without an exit code")
			}
			return 0, wrap(err)
		}
		switch o := out.GetOutput().(type) {
		case *driverv1.ExecAppOutput_Stdout:
			if opts.Stdout != nil {
				if _, err := opts.Stdout.Write(o.Stdout); err != nil {
					return 0, fmt.Errorf("write output: %w", err)
				}
			}
		case *driverv1.ExecAppOutput_Stderr:
			if opts.Stderr != nil {
				if _, err := opts.Stderr.Write(o.Stderr); err != nil {
					return 0, fmt.Errorf("write output: %w", err)
				}
			}
		case *driverv1.ExecAppOutput_ExitCode:
			return int(o.ExitCode), nil
		}
	}
}
