package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/console"
	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/errdefs"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// execProcess is a process run in a container with `runc exec` in the
// foreground (client.Process): runc waits for it and exits with its code.
// It belongs to the agent, so it ends with the agent's session, as exec
// sessions do anyway.
//
// Its standard streams are the FIFOs the caller's cio.Creator made. With
// a terminal, runc's own standard streams are a pseudo-terminal the agent
// holds: runc copies between it and the container's terminal, and passes
// on size changes, which the agent makes on its side.
type execProcess struct {
	t    *taskProc
	id   string
	spec specs.Process
	io   cio.IO
	dir  string // the process spec and pid file

	mu      sync.Mutex
	started bool
	runc    *os.Process // the runc exec process, once started
	pty     console.Console
	endCopy context.CancelFunc // stops copying the terminal's output
	done    chan struct{}
	code    int
	err     error
}

var _ client.Process = (*execProcess)(nil)

func newExecProcess(_ context.Context, t *taskProc, id string, p *specs.Process, creator cio.Creator) (*execProcess, error) {
	if strings.ContainsAny(id, "/\x00") || id == "" || id == "." || id == ".." {
		return nil, fmt.Errorf("exec id %q: %w", id, errdefs.ErrInvalidArgument)
	}
	pio, err := creator(id)
	if err != nil {
		return nil, err
	}
	return &execProcess{
		t: t, id: id, spec: *p, io: pio,
		dir:  filepath.Join(filepath.Dir(t.sh.Root), "exec-"+t.c.rec.ID+"-"+id),
		done: make(chan struct{}),
	}, nil
}

func (p *execProcess) ID() string { return p.id }
func (p *execProcess) IO() cio.IO { return p.io }

// Pid is the process's ID once runc wrote it, else 0.
func (p *execProcess) Pid() uint32 {
	b, err := os.ReadFile(filepath.Join(p.dir, "pid"))
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// Start starts runc exec and returns once it runs.
func (p *execProcess) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return fmt.Errorf("exec %s: %w", p.id, errdefs.ErrAlreadyExists)
	}
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return err
	}
	// The process spec holds the container's environment: written 0600
	// on tmpfs and removed when the process ends.
	b, err := json.Marshal(p.spec)
	if err != nil {
		return err
	}
	spec := filepath.Join(p.dir, "process.json")
	if err := os.WriteFile(spec, b, 0o600); err != nil {
		return err
	}
	args := []string{"--root", p.t.sh.Root, "exec", "--process", spec, "--pid-file", filepath.Join(p.dir, "pid")}
	if p.spec.Terminal {
		args = append(args, "--tty")
	}
	cmd := exec.Command(p.t.c.s.Shims.Runc, append(args, p.t.c.rec.ID)...) //nolint:gosec // the pack's runc
	var closeAfter []io.Closer
	cfg := p.io.Config()
	if p.spec.Terminal {
		pty, slavePath, err := console.NewPty()
		if err != nil {
			return err
		}
		slave, err := os.OpenFile(slavePath, os.O_RDWR|syscall.O_NOCTTY, 0) //nolint:gosec // the pty just made
		if err != nil {
			_ = pty.Close()
			return err
		}
		if s := p.spec.ConsoleSize; s != nil {
			_ = pty.Resize(console.WinSize{Height: uint16(min(s.Height, 1<<16-1)), Width: uint16(min(s.Width, 1<<16-1))})
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		// runc's controlling terminal, so a size change reaches it.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
		closeAfter = append(closeAfter, slave)
		p.pty = pty
	} else {
		for _, s := range []struct {
			path string
			set  func(*os.File)
			out  bool
		}{
			{cfg.Stdin, func(f *os.File) { cmd.Stdin = f }, false},
			{cfg.Stdout, func(f *os.File) { cmd.Stdout = f }, true},
			{cfg.Stderr, func(f *os.File) { cmd.Stderr = f }, true},
		} {
			if s.path == "" {
				continue
			}
			f, err := openFifo(s.path, s.out)
			if err != nil {
				closeAll(closeAfter)
				return err
			}
			s.set(f)
			closeAfter = append(closeAfter, f)
		}
	}
	if err := cmd.Start(); err != nil {
		closeAll(closeAfter)
		if p.pty != nil {
			_ = p.pty.Close()
		}
		return fmt.Errorf("runc exec: %w", err)
	}
	// Only runc holds the streams now, so they end when it does.
	closeAll(closeAfter)
	p.started = true
	p.runc = cmd.Process
	var copies sync.WaitGroup
	var activity runtime.OutputActivity
	copyCtx, endCopy := context.WithCancel(context.Background())
	p.endCopy = endCopy
	if p.pty != nil {
		copies.Add(1)
		go p.copyTerminal(cfg, &copies, &activity)
	}
	go func() {
		err := cmd.Wait()
		code := 0
		var exitErr *exec.ExitError
		switch {
		case errors.As(err, &exitErr):
			code, err = exitCode(exitErr.ProcessState), nil
		case err == nil:
		}
		if p.pty != nil {
			// What runc wrote to the terminal before it exited may still
			// be on its way to a slow reader: copy it until its end, which
			// comes once nothing else holds the terminal, until no output
			// has moved for terminalDrainGrace (something runc left
			// behind holds the terminal), or until the caller stops
			// waiting (killRunc).
			copied := make(chan struct{})
			go func() {
				copies.Wait()
				close(copied)
			}()
			_ = activity.WaitQuiet(copyCtx, copied, terminalDrainGrace)
			_ = p.pty.Close()
		}
		copies.Wait()
		endCopy()
		p.mu.Lock()
		p.code, p.err = code, err
		p.mu.Unlock()
		_ = os.RemoveAll(p.dir)
		close(p.done)
	}()
	// Return once the process runs, as containerd's Start does.
	deadline := time.Now().Add(10 * time.Second)
	for p.Pid() == 0 {
		select {
		case <-p.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.New("runc exec did not start the process")
		}
	}
	return nil
}

// terminalDrainGrace is how long the terminal's output is still copied
// after runc exited once no output has moved. A variable for tests.
var terminalDrainGrace = 2 * time.Second

// copyTerminal copies between the terminal and the caller's FIFOs.
func (p *execProcess) copyTerminal(cfg cio.Config, wg *sync.WaitGroup, activity *runtime.OutputActivity) {
	defer wg.Done()
	if cfg.Stdin != "" {
		go func() {
			in, err := openFifo(cfg.Stdin, false)
			if err != nil {
				return
			}
			defer in.Close()
			_, _ = io.Copy(p.pty, in)
			// End of input: an end-of-transmission character, as a
			// terminal sends for Ctrl-D.
			_, _ = p.pty.Write([]byte{4})
		}()
	}
	if cfg.Stdout != "" {
		out, err := openFifo(cfg.Stdout, true)
		if err != nil {
			return
		}
		defer out.Close()
		_, _ = io.Copy(activity.Wrap(out), p.pty)
	}
}

// openFifo opens a FIFO the caller's cio made: for writing (its reader is
// open), or for reading without waiting for the writer.
func openFifo(path string, write bool) (*os.File, error) {
	if write {
		return os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // a FIFO the caller made
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // a FIFO the caller made
	if err != nil {
		return nil, err
	}
	if err := syscall.SetNonblock(int(f.Fd()), false); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func closeAll(cs []io.Closer) {
	for _, c := range cs {
		_ = c.Close()
	}
}

func exitCode(st *os.ProcessState) int {
	if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return st.ExitCode()
}

func (p *execProcess) Wait(ctx context.Context) (<-chan client.ExitStatus, error) {
	ch := make(chan client.ExitStatus, 1)
	go func() {
		select {
		case <-p.done:
			p.mu.Lock()
			code, err := p.code, p.err
			p.mu.Unlock()
			ch <- *client.NewExitStatus(uint32(max(code, 0)), time.Now(), err) //nolint:gosec // an exit code
		case <-ctx.Done():
			ch <- *client.NewExitStatus(client.UnknownExitStatus, time.Time{}, ctx.Err())
		}
	}()
	return ch, nil
}

// Kill signals the process. SIGKILL also ends runc: runc copies the
// process's output until its end, which a child the process left in the
// background can hold open for as long as it lives.
func (p *execProcess) Kill(_ context.Context, sig syscall.Signal, _ ...client.KillOpts) error {
	pid := p.Pid()
	if pid == 0 {
		return fmt.Errorf("exec %s: %w", p.id, errdefs.ErrNotFound)
	}
	select {
	case <-p.done:
		return fmt.Errorf("exec %s: %w", p.id, errdefs.ErrNotFound)
	default:
	}
	err := syscall.Kill(int(pid), sig)
	if sig == syscall.SIGKILL {
		p.killRunc()
	}
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("exec %s: %w", p.id, errdefs.ErrNotFound)
		}
		return err
	}
	return nil
}

// killRunc ends the runc exec process, which closes its end of the
// streams and lets Wait and Delete return, and stops copying the
// terminal's output.
func (p *execProcess) killRunc() {
	p.mu.Lock()
	runc, endCopy := p.runc, p.endCopy
	p.mu.Unlock()
	if endCopy != nil {
		endCopy()
	}
	if runc != nil {
		// Once cmd.Wait reaped it this does nothing, and never reaches
		// another process.
		_ = runc.Kill()
	}
}

// CloseIO needs nothing: the caller's cio closes the input FIFO at the end
// of its input, which runc and the process then see.
func (p *execProcess) CloseIO(context.Context, ...client.IOCloserOpts) error { return nil }

func (p *execProcess) Resize(_ context.Context, w, h uint32) error {
	if p.pty == nil {
		return fmt.Errorf("exec %s has no terminal: %w", p.id, errdefs.ErrFailedPrecondition)
	}
	return p.pty.Resize(console.WinSize{Height: uint16(min(h, 1<<16-1)), Width: uint16(min(w, 1<<16-1))})
}

func (p *execProcess) Status(context.Context) (client.Status, error) {
	p.mu.Lock()
	started := p.started
	p.mu.Unlock()
	select {
	case <-p.done:
		p.mu.Lock()
		defer p.mu.Unlock()
		return client.Status{Status: client.Stopped, ExitStatus: uint32(max(p.code, 0))}, nil //nolint:gosec // an exit code
	default:
	}
	if !started {
		return client.Status{Status: client.Created}, nil
	}
	return client.Status{Status: client.Running}, nil
}

// Delete waits for the process (opts such as WithProcessKill end it) and
// closes its streams. When ctx ends first, it ends runc and closes the
// streams anyway, so nothing is left copying for the caller.
func (p *execProcess) Delete(ctx context.Context, opts ...client.ProcessDeleteOpts) (*client.ExitStatus, error) {
	var optErr error
	for _, o := range opts {
		if optErr = o(ctx, p); optErr != nil {
			break
		}
	}
	p.mu.Lock()
	started := p.started
	p.mu.Unlock()
	if optErr != nil {
		if started {
			p.abandon()
		}
		return nil, optErr
	}
	if started {
		select {
		case <-p.done:
		case <-ctx.Done():
			p.abandon()
			return nil, ctx.Err()
		}
	}
	if p.io != nil {
		p.io.Cancel()
		p.io.Wait()
		_ = p.io.Close()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return client.NewExitStatus(uint32(max(p.code, 0)), time.Now(), nil), nil //nolint:gosec // an exit code
}

// abandonWait bounds how long abandon waits for runc to be reaped.
const abandonWait = time.Second

// abandon ends runc and stops copying to the caller's streams once the
// caller stopped waiting for the process.
func (p *execProcess) abandon() {
	p.killRunc()
	if p.io != nil {
		p.io.Cancel()
	}
	t := time.NewTimer(abandonWait)
	defer t.Stop()
	select {
	case <-p.done:
	case <-t.C:
	}
	if p.io != nil {
		p.io.Wait()
		_ = p.io.Close()
	}
}
