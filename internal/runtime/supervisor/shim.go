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
	"sync"
	"syscall"
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
	// Active reports whether a shim's unit still runs; nil asks systemd.
	Active func(ctx context.Context, unit string) (bool, error)
	// SystemdRun and Systemctl name the programs systemd is reached
	// through, "systemd-run" and "systemctl" when empty (tests name
	// stand-ins; armada-node is handed the same).
	SystemdRun, Systemctl string
	// Native, when set, sends every request through armada-node (ADR
	// 0054), Go's code doing a call it fails.
	Native *Native

	mu     sync.Mutex
	groups map[string]*groupLock
}

// groupLock serializes starting and abandoning one group's shim; n counts
// its holders and waiters, and it is dropped when none is left.
type groupLock struct {
	ch chan struct{}
	n  int
}

// lock takes group's lock, or fails when ctx ends first. Other groups are
// not held up.
func (s *Shims) lock(ctx context.Context, group string) (func(), error) {
	s.mu.Lock()
	if s.groups == nil {
		s.groups = map[string]*groupLock{}
	}
	l := s.groups[group]
	if l == nil {
		l = &groupLock{ch: make(chan struct{}, 1)}
		s.groups[group] = l
	}
	l.n++
	s.mu.Unlock()
	release := func() {
		s.mu.Lock()
		if l.n--; l.n == 0 {
			delete(s.groups, group)
		}
		s.mu.Unlock()
	}
	select {
	case l.ch <- struct{}{}:
		return func() { <-l.ch; release() }, nil
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	}
}

// Shim is one running armada-shim.
type Shim struct {
	Group  string
	Socket string
	// Root is runc's state directory for the shim's containers.
	Root string

	shims *Shims
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
		shims:  s,
	}
}

// unitName is the transient systemd unit a group's shim runs as.
func unitName(group string) string { return "armada-shim-" + shimName(group) }

// Abandon ends the containers a shim left behind once it is really gone,
// and reports whether it was. A shim that is slow or busy is not gone: its
// containers keep running, and the caller tries again later.
func (s *Shims) Abandon(ctx context.Context, sh *Shim) (bool, error) {
	unlock, err := s.lock(ctx, sh.Group)
	if err != nil {
		return false, err
	}
	defer unlock()
	if s.Native != nil {
		gone, err := s.Native.abandon(ctx, s.request(ctx, sh.Group, nil))
		if !s.Native.fallback("shim abandon", err) {
			return gone, err
		}
	}
	// Ask again under the lock: a shim may have been started meanwhile.
	err = sh.probe(ctx)
	if err == nil {
		return false, nil
	}
	if gone, gerr := s.gone(ctx, sh, err); gerr != nil || !gone {
		return false, gerr
	}
	return true, s.abandon(ctx, sh.Root)
}

// gone reports whether the shim a call failed to reach no longer runs:
// nothing listens on its socket, or its unit is not active. A timeout or a
// closed connection says nothing about the shim's containers.
func (s *Shims) gone(ctx context.Context, sh *Shim, callErr error) (bool, error) {
	var shimErr errShim
	if errors.As(callErr, &shimErr) {
		return false, nil
	}
	if errors.Is(callErr, syscall.ENOENT) || errors.Is(callErr, syscall.ECONNREFUSED) {
		return true, nil
	}
	active := s.Active
	if active == nil {
		active = func(ctx context.Context, unit string) (bool, error) {
			return systemdActive(ctx, s.Systemctl, unit)
		}
	}
	running, err := active(ctx, unitName(sh.Group))
	if err != nil {
		return false, fmt.Errorf("state of shim for %s: %w", sh.Group, err)
	}
	return !running, nil
}

// For returns group's shim, starting it when none runs. A shim that runs
// but does not answer is an error, never replaced.
func (s *Shims) For(ctx context.Context, group string) (*Shim, error) {
	unlock, err := s.lock(ctx, group)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if s.Native != nil {
		err := s.Native.run(ctx, s.request(ctx, group, nil), nil, "runtime", "shim", "start")
		if !s.Native.fallback("shim start", err) {
			if err != nil {
				return nil, err
			}
			return s.Get(group), nil
		}
	}
	name := shimName(group)
	sh := s.Get(group)
	err = sh.probe(ctx)
	if err == nil {
		return sh, nil
	}
	gone, gerr := s.gone(ctx, sh, err)
	if gerr != nil {
		return nil, fmt.Errorf("shim for %s does not answer: %w; %w", group, err, gerr)
	}
	if !gone {
		return nil, fmt.Errorf("shim for %s runs but does not answer: %w", group, err)
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
		launch = func(ctx context.Context, unit string, argv []string) error {
			return systemdRun(ctx, s.SystemdRun, unit, argv)
		}
	}
	if err := launch(ctx, unitName(group), argv); err != nil {
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
func systemdRun(ctx context.Context, prog, unit string, argv []string) error {
	if prog == "" {
		prog = "systemd-run"
	}
	args := append([]string{
		"--unit=" + unit, "--collect", "--quiet",
		"--property=OOMScoreAdjust=-999",
		"--property=LimitNOFILE=infinity",
		"--property=LimitNPROC=infinity",
		"--property=LimitCORE=infinity",
		"--property=TasksMax=infinity",
		"--",
	}, argv...)
	out, err := exec.CommandContext(ctx, prog, args...).CombinedOutput() //nolint:gosec // argv names the pack's programs and paths the agent built
	if err != nil {
		return fmt.Errorf("systemd-run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// systemdActive reports whether unit is active (or starting, reloading, or
// stopping): only a unit that is inactive, failed, or unknown has no shim.
func systemdActive(ctx context.Context, prog, unit string) (bool, error) {
	if prog == "" {
		prog = "systemctl"
	}
	out, err := exec.CommandContext(ctx, prog, "show", "--property=ActiveState", "--value", "--", unit).Output() //nolint:gosec // the unit name is built from a hash
	if err != nil {
		return false, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	switch strings.TrimSpace(string(out)) {
	case "", "inactive", "failed":
		return false, nil
	}
	return true, nil
}

// probeTimeout bounds the list request that checks a shim answers before
// it is started or abandoned.
const probeTimeout = 10 * time.Second

// probe checks the shim answers.
func (sh *Shim) probe(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	_, err := sh.call(ctx, "list")
	return err
}

// errShim is an error the shim answered with.
type errShim string

func (e errShim) Error() string { return string(e) }

// request is what armada-node's shim commands read for group.
func (s *Shims) request(ctx context.Context, group string, words []string) shimRequest {
	return shimRequest{
		Dir: s.Dir, Bin: s.Bin, Runc: s.Runc, Logger: s.Logger, Group: group,
		SystemdRun: s.SystemdRun, Systemctl: s.Systemctl, TimeoutMs: timeoutMs(ctx), Words: words,
	}
}

// call sends one request and reads the answer's words after "ok", through
// armada-node when the shims use it.
func (sh *Shim) call(ctx context.Context, words ...string) (string, error) {
	if sh.shims != nil && sh.shims.Native != nil && len(words) > 0 {
		n := sh.shims.Native
		out, err := n.shimCall(ctx, sh.shims.request(ctx, sh.Group, words))
		if !n.fallback("shim call", err) {
			return out, err
		}
	}
	return sh.callGo(ctx, words...)
}

// callGo is call in Go.
func (sh *Shim) callGo(ctx context.Context, words ...string) (string, error) {
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
