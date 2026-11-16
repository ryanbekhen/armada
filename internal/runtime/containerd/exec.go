package containerd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/ryanbekhen/armada/internal/runtime"
)

var _ runtime.Execer = (*Driver)(nil)

// ExecApp runs a command in a running app container (ADR 0015). The process
// is the container's own process spec with other arguments, so it keeps the
// container's user, capabilities, no-new-privileges, seccomp profile,
// SELinux label, and namespaces.
func (d *Driver) ExecApp(ctx context.Context, id string, opts runtime.ExecOptions) (int, error) {
	if err := runtime.CheckExecCommand(opts.Cmd); err != nil {
		return 0, err
	}
	ctx = d.ctx(ctx)
	c, err := d.ctr.LoadContainer(ctx, id)
	if err != nil {
		return 0, notFound(err)
	}
	labels, err := c.Labels(ctx)
	if err != nil {
		return 0, notFound(err)
	}
	// The agent only passes its replicas' containers; never run a command
	// in an infrastructure container through this path.
	if labels[runtime.LabelSystem] != "" {
		return 0, fmt.Errorf("container %s is a system container", id)
	}
	t, err := c.Task(ctx, nil)
	if err != nil {
		return 0, notFound(err)
	}
	spec, err := c.Spec(ctx)
	if err != nil {
		return 0, err
	}
	p := *spec.Process
	p.Args = opts.Cmd
	p.Terminal = opts.TTY
	p.ConsoleSize = nil
	if opts.TTY && opts.Size.Rows > 0 && opts.Size.Cols > 0 {
		// The terminal has its size before the command starts.
		p.ConsoleSize = &specs.Box{Height: uint(opts.Size.Rows), Width: uint(opts.Size.Cols)}
	}

	// Standard input: EOF from opts.Stdin closes the process's input, which
	// the fifo alone does not.
	var stdin io.Reader
	stdinDone := make(chan struct{})
	if opts.Stdin != nil {
		stdin = &eofReader{r: opts.Stdin, eof: stdinDone}
	}
	// Output moving after the process exited is still copied (drainIO).
	var activity runtime.OutputActivity
	stdout, stderr := activity.Wrap(opts.Stdout), activity.Wrap(opts.Stderr)
	streams := []cio.Opt{cio.WithStreams(stdin, stdout, stderr), cio.WithFIFODir(d.paths.FIFO())}
	if opts.TTY {
		streams = []cio.Opt{cio.WithStreams(stdin, stdout, nil), cio.WithTerminal, cio.WithFIFODir(d.paths.FIFO())}
	}
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	proc, err := t.Exec(ctx, "exec-"+hex.EncodeToString(b), &p, cio.NewCreator(streams...))
	if err != nil {
		return 0, fmt.Errorf("exec: %w", err)
	}
	cleanup := context.WithoutCancel(ctx)
	defer func() {
		// Bounded: a process the runtime cannot end at once must not
		// hold the caller past its deadline (a command that left a child
		// holding its output, for one).
		dctx, cancel := context.WithTimeout(cleanup, execCleanupTimeout)
		defer cancel()
		_, _ = proc.Delete(dctx, client.WithProcessKill)
		// Delete closes the streams unless it gave up early; either way
		// nothing writes to the caller's writers once ExecApp returns.
		pio := proc.IO()
		pio.Cancel()
		pio.Wait()
		_ = pio.Close()
	}()
	exited, err := proc.Wait(ctx)
	if err != nil {
		return 0, err
	}
	if err := proc.Start(ctx); err != nil {
		return 0, fmt.Errorf("exec: %w", err)
	}
	// The first size is also sent as a resize, so the shell sees it at once.
	if opts.TTY && opts.Size.Rows > 0 && opts.Size.Cols > 0 {
		_ = proc.Resize(ctx, uint32(opts.Size.Cols), uint32(opts.Size.Rows))
	}
	done := make(chan struct{})
	defer close(done)
	if opts.Stdin != nil {
		go func() {
			select {
			case <-stdinDone:
				_ = proc.CloseIO(cleanup, client.WithStdinCloser)
			case <-done:
			}
		}()
	}
	if opts.TTY && opts.Resize != nil {
		go func() {
			for {
				select {
				case sz, ok := <-opts.Resize:
					if !ok {
						return
					}
					if sz.Rows > 0 && sz.Cols > 0 {
						_ = proc.Resize(ctx, uint32(sz.Cols), uint32(sz.Rows))
					}
				case <-done:
					return
				}
			}
		}()
	}
	select {
	case st := <-exited:
		code, _, err := st.Result()
		if err != nil {
			return 0, err
		}
		if err := drainIO(ctx, proc.IO(), &activity); err != nil {
			return int(code), fmt.Errorf("exec output cut short: %w", err)
		}
		return int(code), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// ioDrainGrace is how long ExecApp keeps copying output after the
// process exited once no output has moved: a child the process left in
// the background can hold the output open for as long as it lives. Output
// that keeps moving is copied until it ends or the caller's context does.
// A variable for tests.
var ioDrainGrace = 2 * time.Second

// execCleanupTimeout bounds killing and removing the process once ExecApp
// is done with it.
const execCleanupTimeout = 5 * time.Second

// drainIO copies the output still on its way after the process exited:
// until its end, or until no output has moved for ioDrainGrace, never past
// ctx. It returns once nothing writes to the caller's writers anymore, with
// ctx's error when ctx ended first, since output may then have been cut.
func drainIO(ctx context.Context, pio cio.IO, activity *runtime.OutputActivity) error {
	copied := make(chan struct{})
	go func() {
		pio.Wait()
		close(copied)
	}()
	err := activity.WaitQuiet(ctx, copied, ioDrainGrace)
	pio.Cancel()
	<-copied
	return err
}

// eofReader closes eof once r has returned io.EOF.
type eofReader struct {
	r    io.Reader
	eof  chan struct{}
	once sync.Once
}

func (e *eofReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if errors.Is(err, io.EOF) {
		e.once.Do(func() { close(e.eof) })
	}
	return n, err
}
