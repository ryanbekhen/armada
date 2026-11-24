package supervisor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/containerd/v2/client"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"github.com/ryanbekhen/armada/internal/nodeprog"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// ExecSession is an exec armada-node runs whole (ADR 0054 step 5, last
// part): what the driver's ExecApp and Exec do with a client.Process of
// this package (execProcess) and its cio.
type ExecSession struct {
	// ID is the exec's ID within the container.
	ID string
	// Process is the container's process with the exec's arguments,
	// terminal, and console size.
	Process *specs.Process
	// The caller's streams; nil ones are not passed. Stderr is not used
	// with a terminal.
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	// Size is sent as a resize once the process runs (with a terminal,
	// when both sides are set); Resize brings later sizes.
	Size   runtime.TermSize
	Resize <-chan runtime.TermSize
	// DrainGrace is ExecApp's ioDrainGrace: after the process exited its
	// output is copied while it moves, never past the caller's context
	// ("exec output cut short"). 0 copies it to its end whatever the
	// context, as the driver's Exec does.
	DrainGrace time.Duration
	// CleanupTimeout bounds the kill (client.WithProcessKill) of a
	// process the call left running before the session is abandoned. 0
	// kills nothing and waits for the process, as the driver's Exec
	// does.
	CleanupTimeout time.Duration
}

// nativeExec is what `runtime exec` reads on descriptor 3: the
// container's bundle (its config.json holds the process spec), the
// directory for process.json and the pid file, runc and its root, what
// the exec changes in the container's process spec, which of the
// caller's streams it gets, and the drains' graces.
type nativeExec struct {
	Bundle               string     `json:"bundle"`
	Dir                  string     `json:"dir"`
	Root                 string     `json:"root"`
	Runc                 string     `json:"runc"`
	ID                   string     `json:"id"`
	Args                 []string   `json:"args"`
	Terminal             bool       `json:"terminal"`
	ConsoleSize          *specs.Box `json:"consoleSize"`
	Stdin                bool       `json:"stdin"`
	Stdout               bool       `json:"stdout"`
	Stderr               bool       `json:"stderr"`
	DrainGraceMs         int64      `json:"drainGraceMs"`
	TerminalDrainGraceMs int64      `json:"terminalDrainGraceMs"`
}

// sessionAnswer is one line armada-node writes on the control socket.
type sessionAnswer struct {
	Spawned    bool    `json:"spawned"`
	ExecErrno  *int    `json:"execErrno"`
	Redo       *string `json:"redo"`
	Error      *string `json:"error"`
	Started    bool    `json:"started"`
	NotStarted bool    `json:"notStarted"`
	Exit       *int    `json:"exit"`
	Drained    bool    `json:"drained"`

	raw []byte // the line, for an unreadable one
	ok  bool   // it was a JSON object
}

// sessionEnded is armada-node ending a session it had started.
var sessionEnded = programError{errors.New("ended the exec session")}

// NativeExec runs an exec's session through armada-node (`runtime exec`):
// armada-node starts runc exec, copies between its streams and the
// caller's, waits for it, drains its output, and removes its directory,
// as execProcess and ExecApp's drain do; the call here keeps the
// caller's context, its timers, and the cleanup's, and answers with
// ExecApp's texts. handled is false when Go must run the session
// itself: the node is not on armada-node, or armada-node failed before
// runc ran (logged once per distinct failure), before any byte of the
// caller's moved. After that, a failure is the call's.
func (s *Store) NativeExec(ctx context.Context, task client.Task, x ExecSession) (code int, handled bool, err error) {
	n := s.Native
	t, ok := task.(*taskProc)
	if n == nil || !ok || x.Process == nil {
		return 0, false, nil
	}
	p := x.Process
	req := nativeExec{
		Bundle: s.Bundles.Path(t.c.rec.ID),
		Dir:    filepath.Join(filepath.Dir(t.sh.Root), "exec-"+t.c.rec.ID+"-"+x.ID),
		Root:   t.sh.Root, Runc: s.Shims.Runc, ID: t.c.rec.ID,
		Args: p.Args, Terminal: p.Terminal, ConsoleSize: p.ConsoleSize,
		Stdin: x.Stdin != nil, Stdout: x.Stdout != nil, Stderr: x.Stderr != nil && !p.Terminal,
		DrainGraceMs:         x.DrainGrace.Milliseconds(),
		TerminalDrainGraceMs: terminalDrainGrace.Milliseconds(),
	}
	if x.DrainGrace > 0 && req.DrainGraceMs == 0 {
		req.DrainGraceMs = 1
	}
	if req.TerminalDrainGraceMs == 0 {
		req.TerminalDrainGraceMs = 1
	}
	return n.session(ctx, req, x)
}

// session is the agent's side of `runtime exec`.
type session struct {
	ctl     *os.File
	ctlMu   sync.Mutex
	answers chan sessionAnswer
	exited  chan struct{} // armada-node ended
	in      *os.File      // the caller's input, written here
	outs    []*os.File    // the output's pipes, read here
	copies  sync.WaitGroup
	once    sync.Once
}

// send writes one control line; after close it does nothing.
func (s *session) send(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	s.ctlMu.Lock()
	defer s.ctlMu.Unlock()
	if s.ctl != nil {
		_, _ = s.ctl.Write(append(b, '\n'))
	}
}

// close ends the session from here: armada-node reads the control
// socket's end as abandon (runc killed, nothing more copied), and no copy
// to the caller's writers goes on past the write in progress.
func (s *session) close() {
	s.once.Do(func() {
		s.ctlMu.Lock()
		if s.ctl != nil {
			_ = s.ctl.Close()
			s.ctl = nil
		}
		s.ctlMu.Unlock()
		if s.in != nil {
			_ = s.in.Close()
		}
		for _, f := range s.outs {
			_ = f.Close()
		}
	})
	s.copies.Wait()
}

// next waits for the next answer; ok is false once the socket ended.
func (s *session) next(ctx context.Context) (a sessionAnswer, ok bool, err error) {
	select {
	case a, ok = <-s.answers:
		return a, ok, nil
	case <-ctx.Done():
		return sessionAnswer{}, false, ctx.Err()
	}
}

// waitFor waits for an answer that has want, an end of the socket, or
// done.
func (s *session) waitFor(done <-chan struct{}, want func(sessionAnswer) bool) {
	for {
		select {
		case a, ok := <-s.answers:
			if !ok || want(a) {
				return
			}
		case <-done:
			return
		}
	}
}

func (n *Native) session(ctx context.Context, req nativeExec, x ExecSession) (code int, handled bool, err error) {
	b, err := json.Marshal(req)
	if err != nil {
		return 0, false, nil
	}
	var parent, child []*os.File // closed here: what we keep on failure, what armada-node got
	fail := func(err error) (int, bool, error) {
		closeFiles(parent)
		closeFiles(child)
		n.fallback("exec", programError{err})
		return 0, false, nil
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fail(fmt.Errorf("socketpair: %w", err))
	}
	// Non-blocking, so the runtime's poller holds it and closing it ends a
	// read in progress at once (armada-node then reads the socket's end).
	if err := unix.SetNonblock(fds[0], true); err != nil {
		_, _ = unix.Close(fds[0]), unix.Close(fds[1])
		return fail(fmt.Errorf("socketpair: %w", err))
	}
	ctl, peer := os.NewFile(uintptr(fds[0]), "exec-control"), os.NewFile(uintptr(fds[1]), "exec-control")
	parent, child = append(parent, ctl), append(child, peer)
	reqR, reqW, err := os.Pipe()
	if err != nil {
		return fail(fmt.Errorf("pipe: %w", err))
	}
	parent, child = append(parent, reqW), append(child, reqR)
	// Descriptors 3 to 7: request, control, input, output, error output.
	extra := []*os.File{reqR, peer, nil, nil, nil}
	s := &session{ctl: ctl, answers: make(chan sessionAnswer, 8), exited: make(chan struct{})}
	pipe := func(on bool, slot int, write bool) error {
		if !on {
			return nil
		}
		r, w, err := os.Pipe()
		if err != nil {
			return fmt.Errorf("pipe: %w", err)
		}
		if write {
			// The caller's input: armada-node reads.
			extra[slot], s.in = r, w
			parent, child = append(parent, w), append(child, r)
		} else {
			extra[slot] = w
			s.outs = append(s.outs, r)
			parent, child = append(parent, r), append(child, w)
		}
		return nil
	}
	for _, p := range []struct {
		on    bool
		slot  int
		write bool
	}{{req.Stdin, 2, true}, {req.Stdout, 3, false}, {req.Stderr, 4, false}} {
		if err := pipe(p.on, p.slot, p.write); err != nil {
			return fail(err)
		}
	}
	cmd := exec.Command(n.Bin, "runtime", "exec") //nolint:gosec // the runtime pack's armada-node
	cmd.ExtraFiles = extra
	cmd.Env = nodeprog.Env()
	if err := cmd.Start(); err != nil {
		return fail(err)
	}
	closeFiles(child)
	go func() {
		_ = cmd.Wait()
		close(s.exited)
	}()
	go func() {
		// The request carries the command's arguments: never logged.
		_, _ = reqW.Write(b)
		_ = reqW.Close()
	}()
	go s.read(ctl)

	first, ok, cerr := s.next(ctx)
	if cerr != nil {
		// What execProcess.Start returns once the caller stops waiting.
		// The socket's end abandons whatever armada-node started.
		s.close()
		return 0, true, fmt.Errorf("exec: %w", cerr)
	}
	switch {
	case ok && first.Spawned:
		n.ran1()
	case ok && first.ExecErrno != nil:
		s.close()
		n.ran1()
		// What os.StartProcess returns for a failed exec.
		return 0, true, fmt.Errorf("exec: runc exec: %w", &os.PathError{Op: "fork/exec", Path: req.Runc, Err: syscall.Errno(*first.ExecErrno)})
	case ok && first.Redo != nil:
		// A failure Go words itself, on the caller's untouched streams.
		s.close()
		n.fallback("exec", nil)
		n.mu.Lock()
		n.standIn("exec")
		n.mu.Unlock()
		return 0, false, nil
	case ok && first.Error != nil:
		s.close()
		n.fallback("exec", programError{errors.New(*first.Error)})
		return 0, false, nil
	default:
		s.close()
		select {
		case <-s.exited:
		case <-time.After(programGrace):
			_ = cmd.Process.Kill()
			<-s.exited
		}
		msg := fmt.Sprintf("unreadable answer %q", first.raw)
		if !ok {
			msg = "no answer"
		}
		if st := cmd.ProcessState; st != nil && !st.Success() {
			msg += " (" + st.String() + ")"
		}
		n.fallback("exec", programError{errors.New(msg)})
		return 0, false, nil
	}
	return s.run(ctx, x)
}

// ran1 counts an exec armada-node ran runc for.
func (n *Native) ran1() {
	n.fallback("exec", nil)
	n.mu.Lock()
	n.count("exec")
	n.mu.Unlock()
}

// read turns control lines into answers until the socket ends.
func (s *session) read(ctl *os.File) {
	defer close(s.answers)
	r := bufio.NewReader(ctl)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			a := sessionAnswer{raw: line}
			a.ok = json.Unmarshal(line, &a) == nil
			s.answers <- a
		}
		if err != nil {
			return
		}
	}
}

// run is ExecApp's flow once runc runs: the caller's streams copied, the
// start, the first size and later ones, the exit, the drain, and the
// cleanup.
func (s *session) run(ctx context.Context, x ExecSession) (code int, handled bool, err error) {
	if s.in != nil {
		go func() {
			_, _ = io.Copy(s.in, x.Stdin)
			// The input's end, as the caller's cio closes its FIFO.
			_ = s.in.Close()
		}()
	}
	outs := []io.Writer{x.Stdout}
	if x.Stderr != nil && !x.Process.Terminal {
		outs = append(outs, x.Stderr)
	}
	i := 0
	for _, w := range outs {
		if w == nil {
			continue
		}
		f := s.outs[i]
		i++
		s.copies.Add(1)
		go func() {
			defer s.copies.Done()
			_, _ = io.Copy(w, f)
		}()
	}
	exited := false
	defer func() {
		if !exited {
			s.cleanup(ctx, x)
		}
		s.close()
	}()

	// execProcess.Start.
	for started := false; !started; {
		a, ok, cerr := s.next(ctx)
		switch {
		case cerr != nil:
			return 0, true, fmt.Errorf("exec: %w", cerr)
		case !ok:
			return 0, true, fmt.Errorf("exec: %w", sessionEnded)
		case a.NotStarted:
			return 0, true, errors.New("exec: runc exec did not start the process")
		case a.Started:
			started = true
		}
	}
	if x.Process.Terminal {
		if x.Size.Rows > 0 && x.Size.Cols > 0 {
			s.resize(x.Size)
		}
		if x.Resize != nil {
			done := make(chan struct{})
			defer close(done)
			go func() {
				for {
					select {
					case sz, ok := <-x.Resize:
						if !ok {
							return
						}
						if sz.Rows > 0 && sz.Cols > 0 {
							s.resize(sz)
						}
					case <-done:
						return
					}
				}
			}()
		}
	}
	// The exit.
	for !exited {
		a, ok, cerr := s.next(ctx)
		switch {
		case cerr != nil:
			return 0, true, cerr
		case !ok:
			return 0, true, sessionEnded
		case a.Exit != nil:
			code, exited = *a.Exit, true
		}
	}
	// The drain, done by armada-node; then the copies to the caller's
	// writers reach the end armada-node closes.
	drainCtx := ctx
	if x.DrainGrace <= 0 {
		drainCtx = context.WithoutCancel(ctx)
	}
	for {
		a, ok, cerr := s.next(drainCtx)
		if cerr != nil {
			s.close()
			return code, true, fmt.Errorf("exec output cut short: %w", cerr)
		}
		if !ok || a.Drained {
			break
		}
	}
	copied := make(chan struct{})
	go func() {
		s.copies.Wait()
		close(copied)
	}()
	select {
	case <-copied:
	case <-drainCtx.Done():
		s.close()
		return code, true, fmt.Errorf("exec output cut short: %w", drainCtx.Err())
	}
	return code, true, nil
}

// resize asks for a size change of the terminal.
func (s *session) resize(sz runtime.TermSize) {
	s.send(map[string]any{"resize": map[string]uint32{"width": uint32(sz.Cols), "height": uint32(sz.Rows)}})
}

// cleanup is ExecApp's deferred Delete with WithProcessKill, bounded by
// CleanupTimeout, for a process still running when the call ended: the
// kill, then the wait for its end, then abandon (close). With no timeout
// (the driver's Exec), it waits for the end without killing.
func (s *session) cleanup(ctx context.Context, x ExecSession) {
	isExit := func(a sessionAnswer) bool { return a.Exit != nil }
	if x.CleanupTimeout <= 0 {
		s.waitFor(nil, isExit)
		return
	}
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), x.CleanupTimeout)
	defer cancel()
	s.send(map[string]bool{"kill": true})
	s.waitFor(dctx.Done(), isExit)
}

func closeFiles(fs []*os.File) {
	for _, f := range fs {
		if f != nil {
			_ = f.Close()
		}
	}
}
