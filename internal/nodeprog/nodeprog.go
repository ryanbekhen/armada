// Package nodeprog runs the runtime pack's armada-node for the node's
// readings (ADR 0054 step 5): the connection tracking table, NFS mounts,
// and whatever else the agent hands it outside the container runtime. Each
// call sends JSON on stdin and reads JSON from stdout; a call the program
// fails (it does not run, or its answer cannot be read) is done by Go's
// code instead, and each distinct failure is logged once.
//
// The container runtime's calls (supervisor.Native) run armada-node the
// same way: Run and Tally are what both share.
package nodeprog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Program is armada-node, with what it failed and what Go did instead.
type Program struct {
	// Bin is the runtime pack's armada-node.
	Bin string

	Tally
}

// New returns the program at bin, or nil when bin is empty (Go's code
// does everything).
func New(bin string) *Program {
	if bin == "" {
		return nil
	}
	return &Program{Bin: bin}
}

// Error is armada-node failing to do a call: it did not run, or its
// answer could not be read. Errors it answered with are plain.
type Error struct{ Err error }

func (e Error) Error() string { return "armada-node: " + e.Err.Error() }
func (e Error) Unwrap() error { return e.Err }

// Limit bounds a call that has no deadline of its own.
const Limit = time.Minute

// Grace is how long armada-node may run past the caller's deadline: the
// deadline travels in the request, and the program answers with Go's
// texts once its time is up rather than being killed first.
const Grace = 2 * time.Second

// TimeoutMs is ctx's time left in milliseconds for a request, 0 without
// a deadline.
func TimeoutMs(ctx context.Context) int64 {
	dl, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	return max(time.Until(dl).Milliseconds(), 1)
}

// RunOptions are how Run runs one call.
type RunOptions struct {
	// Limit bounds the call whatever the caller's deadline; 0 for none.
	Limit time.Duration
	// ExtraFiles are handed to the program from descriptor 3 on.
	ExtraFiles []*os.File
	// WaitDelay, when set, stops waiting that long after the program was
	// killed or its output closed; an answer it wrote by then counts (a
	// mount the kernel never returns from may keep it from exiting).
	WaitDelay time.Duration
	// LimitFails makes running out of Limit (with the caller still
	// waiting) a failure of the program, which the caller's Go code then
	// does; otherwise it is the plain context error.
	LimitFails bool
	// Fail makes the error a failure of the program is returned as; nil
	// for Error.
	Fail func(error) error
}

func (o RunOptions) fail(err error) error {
	if o.Fail != nil {
		return o.Fail(err)
	}
	return Error{err}
}

// Run runs bin with args and stdin (JSON), returning its output. A
// cancelled caller kills it at once and gets the context's error; one
// whose deadline passes, after Grace. A program that does not start, ends
// badly, or is killed by o.Limit (with o.LimitFails) is a failure (o.Fail,
// else an Error), with its stderr.
func Run(ctx context.Context, bin string, o RunOptions, stdin any, args ...string) ([]byte, error) {
	in, err := json.Marshal(stdin)
	if err != nil {
		return nil, err
	}
	run, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	if dl, ok := ctx.Deadline(); ok {
		var stop context.CancelFunc
		run, stop = context.WithDeadline(run, dl.Add(Grace))
		defer stop()
	}
	after := context.AfterFunc(ctx, func() {
		if errors.Is(ctx.Err(), context.Canceled) {
			cancel()
		}
	})
	defer after()
	if o.Limit > 0 {
		var stop context.CancelFunc
		run, stop = context.WithTimeout(run, o.Limit)
		defer stop()
	}
	cmd := exec.CommandContext(run, bin, args...) //nolint:gosec // the runtime pack's armada-node
	cmd.Stdin = bytes.NewReader(in)
	cmd.ExtraFiles = o.ExtraFiles
	cmd.WaitDelay = o.WaitDelay
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if run.Err() != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			if o.LimitFails {
				return nil, o.fail(run.Err())
			}
			return nil, run.Err()
		}
		if o.WaitDelay > 0 && errors.Is(err, exec.ErrWaitDelay) && len(out) > 0 {
			return out, nil
		}
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			err = fmt.Errorf("%w: %s", err, msg)
		}
		return nil, o.fail(err)
	}
	return out, nil
}

// Answer reads a call's output into out: {"error": TEXT} is that error,
// returned as errors.New(TEXT); output it cannot read is a failure of the
// program (fail, else an Error).
func Answer(b []byte, out any, fail func(error) error) error {
	if fail == nil {
		fail = func(err error) error { return Error{err} }
	}
	var answer struct {
		Error *string `json:"error"`
	}
	if err := json.Unmarshal(b, &answer); err != nil {
		return fail(fmt.Errorf("unreadable answer: %w", err))
	}
	if answer.Error != nil {
		return errors.New(*answer.Error)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fail(fmt.Errorf("unreadable answer: %w", err))
		}
	}
	return nil
}

// Exec runs armada-node with args and stdin (JSON), returning its output.
// A cancelled caller kills it at once and gets the context's error; one
// whose deadline passes, after Grace.
func (p *Program) Exec(ctx context.Context, stdin any, args ...string) ([]byte, error) {
	return Run(ctx, p.Bin, RunOptions{Limit: Limit, WaitDelay: Grace, LimitFails: true}, stdin, args...)
}

// Call runs a call and reads its answer into out: {"error": TEXT} is that
// error, returned as errors.New(TEXT).
func (p *Program) Call(ctx context.Context, stdin, out any, args ...string) error {
	b, err := p.Exec(ctx, stdin, args...)
	if err != nil {
		return err
	}
	return Answer(b, out, nil)
}

// StoodIn is how many times Go did op instead of armada-node.
func (p *Program) StoodIn(op string) int {
	if p == nil {
		return 0
	}
	return p.Tally.StoodIn(op)
}

// Tally keeps what armada-node failed, what Go did instead, and what
// armada-node did, per call ("op"), so each distinct failure is logged
// once. The zero Tally is ready.
type Tally struct {
	mu    sync.Mutex
	errs  map[string]string
	stood map[string]int
	ran   map[string]int
}

// Fallback reports whether Go must do a call armada-node failed (op names
// it; err is an Error then), logging each distinct failure once and when
// it works again.
func (t *Tally) Fallback(op string, err error) bool {
	var perr Error
	failed := errors.As(err, &perr)
	msg := ""
	if failed {
		msg = err.Error()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.errs == nil {
		t.errs = map[string]string{}
	}
	prev, seen := t.errs[op]
	t.errs[op] = msg
	if failed {
		t.standIn(op)
	}
	switch {
	case !failed && seen && prev != "":
		slog.Info("armada-node works again", "op", op)
	case failed && (!seen || prev != msg):
		slog.Warn("armada-node failed; Go did it instead", "op", op, "err", err)
	}
	return failed
}

// Note logs a failure (an Error) of a call Go cannot do instead, once per
// distinct failure.
func (t *Tally) Note(op string, err error) {
	var perr Error
	if !errors.As(err, &perr) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.errs == nil {
		t.errs = map[string]string{}
	}
	if t.errs[op] != err.Error() {
		slog.Warn("armada-node failed", "op", op, "err", err)
	}
	t.errs[op] = err.Error()
}

// StandIn counts a call Go did itself although armada-node answered: one
// it left to Go.
func (t *Tally) StandIn(op string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.standIn(op)
}

func (t *Tally) standIn(op string) {
	if t.stood == nil {
		t.stood = map[string]int{}
	}
	t.stood[op]++
}

// StoodIn is how many times Go did op instead of armada-node.
func (t *Tally) StoodIn(op string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stood[op]
}

// Count counts a call armada-node did.
func (t *Tally) Count(op string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ran == nil {
		t.ran = map[string]int{}
	}
	t.ran[op]++
}

// Ran is how many times armada-node did op.
func (t *Tally) Ran(op string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ran[op]
}
