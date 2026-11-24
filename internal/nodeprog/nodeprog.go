// Package nodeprog runs the runtime pack's armada-node for the node's
// readings (ADR 0054 step 5): the connection tracking table, NFS mounts,
// and whatever else the agent hands it outside the container runtime. Each
// call sends JSON on stdin and reads JSON from stdout; a call the program
// fails (it does not run, or its answer cannot be read) is done by Go's
// code instead, and each distinct failure is logged once.
package nodeprog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Program is armada-node, with what it failed and what Go did instead.
type Program struct {
	// Bin is the runtime pack's armada-node.
	Bin string

	mu    sync.Mutex
	errs  map[string]string
	stood map[string]int
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

// Exec runs armada-node with args and stdin (JSON), returning its output.
// A cancelled caller kills it at once and gets the context's error; one
// whose deadline passes, after Grace.
func (p *Program) Exec(ctx context.Context, stdin any, args ...string) ([]byte, error) {
	in, err := json.Marshal(stdin)
	if err != nil {
		return nil, err
	}
	run, cancel := context.WithTimeout(context.WithoutCancel(ctx), Limit)
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
	cmd := exec.CommandContext(run, p.Bin, args...) //nolint:gosec // the runtime pack's armada-node
	cmd.Stdin = bytes.NewReader(in)
	// A mount the kernel never returns from may keep the program from
	// exiting; its answer is out by then, or the caller gives up.
	cmd.WaitDelay = Grace
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if run.Err() != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			return nil, Error{run.Err()}
		}
		if errors.Is(err, exec.ErrWaitDelay) && len(out) > 0 {
			return out, nil
		}
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			err = fmt.Errorf("%w: %s", err, msg)
		}
		return nil, Error{err}
	}
	return out, nil
}

// Call runs a call and reads its answer into out: {"error": TEXT} is that
// error, returned as errors.New(TEXT).
func (p *Program) Call(ctx context.Context, stdin, out any, args ...string) error {
	b, err := p.Exec(ctx, stdin, args...)
	if err != nil {
		return err
	}
	var answer struct {
		Error *string `json:"error"`
	}
	if err := json.Unmarshal(b, &answer); err != nil {
		return Error{fmt.Errorf("unreadable answer: %w", err)}
	}
	if answer.Error != nil {
		return errors.New(*answer.Error)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return Error{fmt.Errorf("unreadable answer: %w", err)}
		}
	}
	return nil
}

// Fallback reports whether Go must do a call armada-node failed (op names
// it), logging each distinct failure once and when it works again.
func (p *Program) Fallback(op string, err error) bool {
	var perr Error
	failed := errors.As(err, &perr)
	msg := ""
	if failed {
		msg = err.Error()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.errs == nil {
		p.errs = map[string]string{}
	}
	prev, seen := p.errs[op]
	p.errs[op] = msg
	if failed {
		p.standIn(op)
	}
	switch {
	case !failed && seen && prev != "":
		slog.Info("armada-node works again", "op", op)
	case failed && (!seen || prev != msg):
		slog.Warn("armada-node failed; Go did it instead", "op", op, "err", err)
	}
	return failed
}

// StandIn counts a call Go did itself although armada-node answered: one
// it left to Go.
func (p *Program) StandIn(op string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.standIn(op)
}

func (p *Program) standIn(op string) {
	if p.stood == nil {
		p.stood = map[string]int{}
	}
	p.stood[op]++
}

// StoodIn is how many times Go did op instead of armada-node.
func (p *Program) StoodIn(op string) int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stood[op]
}
