package supervisor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Shims starts and reaches armada-shim processes, one per group (an app
// and runtime pack on this node, ADR 0046). Each runs as a transient
// systemd service of its own, so restarting the agent's service leaves
// it, and the containers it supervises, alone.
type Shims struct {
	// Dir holds each shim's socket and state (tmpfs: nothing in it
	// outlives a reboot, like the containers).
	Dir string
	// Bin, Runc, and Logger are the programs a shim runs.
	Bin, Runc, Logger string
	// Launch starts a shim; nil runs it with systemd-run.
	Launch func(ctx context.Context, unit string, argv []string) error
}

// Shim is one running armada-shim.
type Shim struct {
	Group  string
	Socket string
	// Root is runc's state directory for the shim's containers.
	Root string
}

// TaskState is what a shim reports about a container.
type TaskState struct {
	Status string // "created", "running", or "exited"
	Pid    int
	Exit   int
}

// shimName turns a group into a short name safe in paths and unit names.
func shimName(group string) string {
	sum := sha256.Sum256([]byte(group))
	return "s" + hex.EncodeToString(sum[:8])
}

// Get returns group's shim without starting it; its calls fail when it
// does not run.
func (s *Shims) Get(group string) *Shim {
	name := shimName(group)
	return &Shim{
		Group:  group,
		Socket: filepath.Join(s.Dir, name+".sock"),
		Root:   filepath.Join(s.Dir, name, "runc"),
	}
}

// Abandon ends the containers a shim that no longer answers left behind.
func (s *Shims) Abandon(ctx context.Context, sh *Shim) error { return s.abandon(ctx, sh.Root) }

// For returns group's shim, starting it when it does not answer.
func (s *Shims) For(ctx context.Context, group string) (*Shim, error) {
	name := shimName(group)
	sh := s.Get(group)
	if _, err := sh.call(ctx, "list"); err == nil {
		return sh, nil
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	// Containers an earlier shim of the group left behind lost their
	// supervisor and their exit code: end them, as containerd does when a
	// shim dies, so the agent starts them again.
	if err := s.abandon(ctx, sh.Root); err != nil {
		return nil, fmt.Errorf("containers of a stopped shim for %s: %w", group, err)
	}
	argv := []string{s.Bin, "serve", sh.Socket, filepath.Join(s.Dir, name), s.Runc, s.Logger}
	launch := s.Launch
	if launch == nil {
		launch = systemdRun
	}
	if err := launch(ctx, "armada-shim-"+name, argv); err != nil {
		return nil, fmt.Errorf("start shim for %s: %w", group, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := sh.call(ctx, "list")
		if err == nil {
			return sh, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("shim for %s does not answer: %w", group, err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// abandon kills and deletes every container in runc's state under root.
func (s *Shims) abandon(ctx context.Context, root string) error {
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	out, err := exec.CommandContext(ctx, s.Runc, "--root", root, "list", "-q").Output() //nolint:gosec // the pack's runc
	if err != nil {
		return fmt.Errorf("runc list: %w", err)
	}
	for _, id := range strings.Fields(string(out)) {
		_ = exec.CommandContext(ctx, s.Runc, "--root", root, "kill", "--all", id, "KILL").Run()                                 //nolint:gosec // the pack's runc
		if out, err := exec.CommandContext(ctx, s.Runc, "--root", root, "delete", "--force", id).CombinedOutput(); err != nil { //nolint:gosec // the pack's runc
			return fmt.Errorf("runc delete %s: %w: %s", id, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// systemdRun starts argv as a transient service. Stopping the unit ends
// the shim and the log writers it started; containers live in cgroups of
// their own under /armada.
func systemdRun(ctx context.Context, unit string, argv []string) error {
	args := append([]string{
		"--unit=" + unit, "--collect", "--quiet",
		"--property=OOMScoreAdjust=-999",
		"--property=LimitNOFILE=infinity",
		"--property=TasksMax=infinity",
		"--",
	}, argv...)
	out, err := exec.CommandContext(ctx, "systemd-run", args...).CombinedOutput() //nolint:gosec // argv names the pack's programs and paths the agent built
	if err != nil {
		return fmt.Errorf("systemd-run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// errShim is an error the shim answered with.
type errShim string

func (e errShim) Error() string { return string(e) }

// call sends one request and reads the answer's words after "ok".
func (sh *Shim) call(ctx context.Context, words ...string) (string, error) {
	for _, w := range words {
		if w == "" || strings.ContainsAny(w, " \t\r\n") {
			return "", fmt.Errorf("invalid shim argument %q", w)
		}
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", sh.Socket)
	if err != nil {
		return "", err
	}
	defer c.Close()
	// A wait lasts as long as the container; anything else answers soon.
	if words[0] != "wait" {
		deadline := time.Now().Add(2 * time.Minute)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		_ = c.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if _, err := fmt.Fprintln(c, strings.Join(words, " ")); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("shim: %w", err)
	}
	line = strings.TrimSuffix(line, "\n")
	switch {
	case line == "ok":
		return "", nil
	case strings.HasPrefix(line, "ok "):
		return line[3:], nil
	case strings.HasPrefix(line, "err "):
		return "", errShim(line[4:])
	}
	return "", fmt.Errorf("shim: unexpected answer %q", line)
}

// Create creates container id from bundle (not started); its output goes
// to armada-log in logDir. It returns the container's process ID.
func (sh *Shim) Create(ctx context.Context, id, bundle, logDir string) (int, error) {
	out, err := sh.call(ctx, "create", id, bundle, logDir)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(out)
}

// Start starts a created container.
func (sh *Shim) Start(ctx context.Context, id string) error {
	_, err := sh.call(ctx, "start", id)
	return err
}

// Wait blocks until the container exits and returns its exit code.
func (sh *Shim) Wait(ctx context.Context, id string) (int, error) {
	out, err := sh.call(ctx, "wait", id)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(out)
}

// KillAll sends sig to every process in the container.
func (sh *Shim) KillAll(ctx context.Context, id string, sig int) error {
	_, err := sh.call(ctx, "kill", id, strconv.Itoa(sig), "all")
	return err
}

// Kill sends sig to the container's process.
func (sh *Shim) Kill(ctx context.Context, id string, sig int) error {
	_, err := sh.call(ctx, "kill", id, strconv.Itoa(sig))
	return err
}

// Delete removes the container, killing it first if it runs.
func (sh *Shim) Delete(ctx context.Context, id string) error {
	_, err := sh.call(ctx, "delete", id)
	return err
}

// State reports one container.
func (sh *Shim) State(ctx context.Context, id string) (TaskState, error) {
	out, err := sh.call(ctx, "state", id)
	if err != nil {
		return TaskState{}, err
	}
	return parseState(strings.Fields(out))
}

// List reports every container of the shim.
func (sh *Shim) List(ctx context.Context) (map[string]TaskState, error) {
	out, err := sh.call(ctx, "list")
	if err != nil {
		return nil, err
	}
	// Pairs of "ID STATUS:N".
	fields := strings.Fields(out)
	if len(fields)%2 != 0 {
		return nil, fmt.Errorf("shim: unexpected list %q", out)
	}
	states := make(map[string]TaskState, len(fields)/2)
	for i := 0; i < len(fields); i += 2 {
		status, n, _ := strings.Cut(fields[i+1], ":")
		st, err := parseState([]string{status, n})
		if err != nil {
			return nil, err
		}
		states[fields[i]] = st
	}
	return states, nil
}

func parseState(w []string) (TaskState, error) {
	if len(w) != 2 {
		return TaskState{}, fmt.Errorf("shim: unexpected state %q", strings.Join(w, " "))
	}
	n, err := strconv.Atoi(w[1])
	if err != nil {
		return TaskState{}, fmt.Errorf("shim: unexpected state %q", strings.Join(w, " "))
	}
	switch w[0] {
	case "created", "running":
		return TaskState{Status: w[0], Pid: n}, nil
	case "exited":
		return TaskState{Status: w[0], Exit: n}, nil
	}
	return TaskState{}, fmt.Errorf("shim: unexpected state %q", strings.Join(w, " "))
}

// NotFound reports whether err says the shim does not know the container.
func NotFound(err error) bool {
	var e errShim
	return errors.As(err, &e) && strings.HasSuffix(string(e), " not found")
}
