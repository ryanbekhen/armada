package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// nativeExec is what `runtime exec` reads on descriptor 3: the
// container's bundle (its config.json holds the process spec), the
// directory for process.json and the pid file, runc and its root, and
// what ExecApp changes in the container's process spec.
type nativeExec struct {
	Bundle      string     `json:"bundle"`
	Dir         string     `json:"dir"`
	Root        string     `json:"root"`
	Runc        string     `json:"runc"`
	ID          string     `json:"id"`
	Args        []string   `json:"args"`
	Terminal    bool       `json:"terminal"`
	ConsoleSize *specs.Box `json:"consoleSize"`
}

// execReady is what armada-node writes on descriptor 4 just before it
// becomes runc; the descriptor closes on exec, so a successful start
// reads as exactly this.
const execReady = "exec\n"

// startExec starts runc exec through armada-node (ADR 0054 step 4, sixth
// part): armada-node, started with the standard streams and terminal
// wire gives it, writes the process spec Go writes (the container's own
// with req's arguments, terminal, and size) and the same directory, then
// replaces itself with runc exec and the arguments Go gives it. The
// process cmd started is runc from then on, so everything after the
// start (waiting, exit codes, signals, the terminal, draining) is Go's
// code on the same process.
//
// handled is false when Go must start runc itself: armada-node did not
// run, failed before it became runc (logged once per distinct failure),
// or left the start to Go (an error Go words itself). A failed exec of
// runc is the error Go's start gives.
func (n *Native) startExec(ctx context.Context, req nativeExec, wire func(*exec.Cmd)) (*exec.Cmd, bool, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nil, false, nil
	}
	reqR, reqW, err := os.Pipe()
	if err != nil {
		n.fallback("exec", programError{fmt.Errorf("pipe: %w", err)})
		return nil, false, nil
	}
	ansR, ansW, err := os.Pipe()
	if err != nil {
		_, _ = reqR.Close(), reqW.Close()
		n.fallback("exec", programError{fmt.Errorf("pipe: %w", err)})
		return nil, false, nil
	}
	cmd := exec.Command(n.Bin, "runtime", "exec") //nolint:gosec // the runtime pack's armada-node
	wire(cmd)
	cmd.ExtraFiles = []*os.File{reqR, ansW}
	err = cmd.Start()
	_, _ = reqR.Close(), ansW.Close()
	if err != nil {
		_, _ = reqW.Close(), ansR.Close()
		n.fallback("exec", programError{err})
		return nil, false, nil
	}
	go func() {
		// The request carries the command's arguments: never logged.
		_, _ = reqW.Write(b)
		_ = reqW.Close()
	}()
	answer := make(chan []byte, 1)
	go func() {
		a, _ := io.ReadAll(ansR)
		_ = ansR.Close()
		answer <- a
	}()
	var a []byte
	select {
	case a = <-answer:
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, true, ctx.Err()
	}
	if string(a) == execReady {
		n.fallback("exec", nil)
		n.mu.Lock()
		n.count("exec")
		n.mu.Unlock()
		return cmd, true, nil
	}
	// armada-node ended without becoming runc.
	werr := cmd.Wait()
	if rest, ok := strings.CutPrefix(string(a), execReady); ok {
		var e struct {
			ExecErrno *int `json:"execErrno"`
		}
		if json.Unmarshal([]byte(rest), &e) == nil && e.ExecErrno != nil {
			n.fallback("exec", nil)
			n.mu.Lock()
			n.count("exec")
			n.mu.Unlock()
			// What os.StartProcess returns for a failed exec.
			return nil, true, fmt.Errorf("runc exec: %w", &os.PathError{Op: "fork/exec", Path: req.Runc, Err: syscall.Errno(*e.ExecErrno)})
		}
	}
	var r struct {
		Redo  *string `json:"redo"`
		Error *string `json:"error"`
	}
	switch {
	case json.Unmarshal(a, &r) != nil || (r.Redo == nil && r.Error == nil):
		msg := fmt.Sprintf("unreadable answer %q", a)
		if len(a) == 0 {
			msg = "no answer"
		}
		if werr != nil {
			msg += " (" + werr.Error() + ")"
		}
		n.fallback("exec", programError{errors.New(msg)})
	case r.Error != nil:
		n.fallback("exec", programError{errors.New(*r.Error)})
	default:
		// An error Go words itself, on the same files.
		n.fallback("exec", nil)
		n.mu.Lock()
		n.standIn("exec")
		n.mu.Unlock()
	}
	return nil, false, nil
}
