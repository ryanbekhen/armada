// Package fake provides an in-memory runtime.Driver for tests.
package fake

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// Driver is a concurrency-safe in-memory container engine.
type Driver struct {
	mu         sync.Mutex
	containers map[string]*runtime.Container
	specs      map[string]runtime.ContainerSpec
	seq        int
	nextPort   int

	// PullErr, if set, is returned by Pull for matching images.
	PullErr map[string]error
	// RunErr, if set, is returned by Run.
	RunErr error
	// RunHook, if set, is called by every Run, without the driver's lock.
	RunHook func(ctx context.Context, s runtime.ContainerSpec)
	// Digests maps image references to the digest Pull returns.
	Digests map[string]string
	// Platforms maps image references to the platforms Pull returns.
	Platforms map[string][]string
	// LogLines is returned by Logs for every container.
	LogLines []runtime.LogFrame
	// BridgeIPs, if set, gives each new container the address BridgeIPs
	// followed by its sequence number, such as "10.120.0." for 10.120.0.1.
	BridgeIPs string

	Pulls []string
	// PullAuths records the credentials of each pull (nil for none).
	PullAuths []*runtime.RegistryAuth
	// Prunes records the keep list of each PruneImages call, sorted.
	Prunes [][]string

	// ExecFunc, if set, answers Exec calls.
	ExecFunc func(id string, cmd []string) (string, int, error)
	Execs    [][]string
	Signals  []string
	Systems  []runtime.SystemSpec
	// SystemExits makes system containers exit immediately with this code.
	SystemExits int
	// BridgeNet is returned by Bridge; the zero value means "no bridge".
	BridgeNet runtime.Bridge
	// PingErr is returned by Ping.
	PingErr error
	// ExecAppFunc, if set, answers ExecApp calls for running containers.
	// Without it ExecApp copies standard input to stdout, writes the command
	// name to stderr (stdout with a terminal), and exits with the number of
	// arguments after the command.
	ExecAppFunc func(ctx context.Context, id string, opts runtime.ExecOptions) (int, error)
	// AppExecs records the commands of ExecApp calls.
	AppExecs [][]string
	// Usage is what Stats returns for running containers, keyed by replica
	// ID; without an entry a running container used nothing.
	Usage map[string]runtime.Stats
	// Released counts ReleaseNetwork calls per container.
	Released map[string]int
	// NoStats makes the driver report that it cannot sample containers.
	NoStats bool
	// NoVolumes makes the driver report that it cannot mount volumes.
	NoVolumes bool
	// NoExec makes the driver report that it cannot run commands in
	// containers or dial from them.
	NoExec bool
	// Dials records the addresses DialContainer was asked for.
	Dials []string

	// sandboxes are the network sandboxes, by ID; sandboxSeq numbers them.
	sandboxes  map[string]runtime.Sandbox
	sandboxSeq int
	// NoSandboxes makes the driver report that it keeps no network
	// sandboxes.
	NoSandboxes bool
	// SandboxDials records the sandbox and address of each DialSandbox.
	SandboxDials []string
	// SandboxCreates counts the sandboxes EnsureSandbox created.
	SandboxCreates int
}

var _ runtime.NetworkSandboxer = (*Driver)(nil)

// CanSandbox reports whether sandboxes are offered (not NoSandboxes).
func (d *Driver) CanSandbox() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.NoSandboxes
}

// EnsureSandbox creates a sandbox with the address BridgeIPs followed by
// 200 and up, or returns the existing one.
func (d *Driver) EnsureSandbox(_ context.Context, id string) (runtime.Sandbox, error) {
	if err := runtime.CheckSandboxID(id); err != nil {
		return runtime.Sandbox{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if s, ok := d.sandboxes[id]; ok {
		return s, nil
	}
	if d.sandboxes == nil {
		d.sandboxes = map[string]runtime.Sandbox{}
	}
	d.sandboxSeq++
	d.SandboxCreates++
	s := runtime.Sandbox{ID: id}
	if d.BridgeIPs != "" {
		s.IP = d.BridgeIPs + strconv.Itoa(200+d.sandboxSeq%50)
	}
	d.sandboxes[id] = s
	return s, nil
}

// RemoveSandbox removes a sandbox; a missing one is not an error.
func (d *Driver) RemoveSandbox(_ context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.sandboxes, id)
	return nil
}

// ListSandboxes returns the sandboxes, sorted by ID.
func (d *Driver) ListSandboxes(context.Context) ([]runtime.Sandbox, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := slices.Collect(maps.Values(d.sandboxes))
	slices.SortFunc(out, func(a, b runtime.Sandbox) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// Sandboxes returns the IDs of the sandboxes, sorted.
func (d *Driver) Sandboxes() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Sorted(maps.Keys(d.sandboxes))
}

// DialSandbox dials from the host, like DialContainer, from a sandbox that
// exists.
func (d *Driver) DialSandbox(ctx context.Context, id, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return nil, fmt.Errorf("%q is not an IP address", host)
	}
	d.mu.Lock()
	_, ok := d.sandboxes[id]
	d.SandboxDials = append(d.SandboxDials, id+" "+address)
	d.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("sandbox %s does not exist", id)
	}
	var dl net.Dialer
	return dl.DialContext(ctx, network, address)
}

// DialContainer dials from the host: the fake has no network namespaces.
// It refuses names, like the real runtime, and containers that do not run.
func (d *Driver) DialContainer(ctx context.Context, id, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return nil, fmt.Errorf("%q is not an IP address", host)
	}
	d.mu.Lock()
	c, ok := d.containers[id]
	running := ok && c.State == runtime.StateRunning
	d.Dials = append(d.Dials, address)
	d.mu.Unlock()
	if !running {
		return nil, fmt.Errorf("container %s is not running", id)
	}
	var dl net.Dialer
	return dl.DialContext(ctx, network, address)
}

// CanDial reports whether DialContainer is offered (not NoExec).
func (d *Driver) CanDial() bool { return d.CanExec() }

// CanExec reports whether ExecApp is offered (not NoExec).
func (d *Driver) CanExec() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.NoExec
}

// CanMountVolumes reports whether volumes are offered (not NoVolumes).
func (d *Driver) CanMountVolumes() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.NoVolumes
}

// ReleaseNetwork records that a container's network was freed.
func (d *Driver) ReleaseNetwork(_ context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Released == nil {
		d.Released = map[string]int{}
	}
	d.Released[id]++
	return nil
}

// Stats returns d.Usage for a running container.
func (d *Driver) Stats(_ context.Context, id string) (runtime.Stats, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.containers[id]
	if !ok {
		return runtime.Stats{}, runtime.ErrNotFound
	}
	u := d.Usage[c.Labels[runtime.LabelReplica]]
	// Like the real runtime, an exited container still has its OOM counter.
	if c.State != runtime.StateRunning && u.OOMKills == 0 {
		return runtime.Stats{}, fmt.Errorf("container %s is not running", id)
	}
	return u, nil
}

// CanStats reports whether Stats is offered (not NoStats).
func (d *Driver) CanStats() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.NoStats
}

// SetUsage sets what Stats returns for a replica's container.
func (d *Driver) SetUsage(replica string, s runtime.Stats) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Usage == nil {
		d.Usage = map[string]runtime.Stats{}
	}
	d.Usage[replica] = s
}

// ExecApp runs a fake command in a running container.
func (d *Driver) ExecApp(ctx context.Context, id string, opts runtime.ExecOptions) (int, error) {
	if err := runtime.CheckExecCommand(opts.Cmd); err != nil {
		return 0, err
	}
	d.mu.Lock()
	c, ok := d.containers[id]
	running := ok && c.State == runtime.StateRunning
	d.AppExecs = append(d.AppExecs, slices.Clone(opts.Cmd))
	fn := d.ExecAppFunc
	d.mu.Unlock()
	if !ok {
		return 0, runtime.ErrNotFound
	}
	if !running {
		return 0, fmt.Errorf("container %s is not running", id)
	}
	if fn != nil {
		return fn(ctx, id, opts)
	}
	if opts.Stdin != nil && opts.Stdout != nil {
		if _, err := io.Copy(opts.Stdout, opts.Stdin); err != nil {
			return 0, err
		}
	}
	errOut := opts.Stderr
	if opts.TTY {
		errOut = opts.Stdout
	}
	if errOut != nil {
		if _, err := io.WriteString(errOut, opts.Cmd[0]); err != nil {
			return 0, err
		}
	}
	return len(opts.Cmd) - 1, nil
}

var (
	_ runtime.SystemRunner    = (*Driver)(nil)
	_ runtime.BridgeInspector = (*Driver)(nil)
)

// Bridge implements runtime.BridgeInspector.
func (d *Driver) Bridge(context.Context) (runtime.Bridge, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.BridgeNet.Gateway.IsValid() {
		return runtime.Bridge{}, fmt.Errorf("no bridge network")
	}
	return d.BridgeNet, nil
}

// RunSystem creates a running system container.
func (d *Driver) RunSystem(_ context.Context, s runtime.SystemSpec) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seq++
	id := fmt.Sprintf("sys%04d", d.seq)
	state := runtime.StateRunning
	if d.SystemExits != 0 {
		state = runtime.StateExited
	}
	d.containers[id] = &runtime.Container{ID: id, Name: s.Name, Image: s.Image, Labels: maps.Clone(s.Labels), State: state, ExitCode: d.SystemExits}
	d.Systems = append(d.Systems, s)
	return id, nil
}

// SystemSpecs returns the system containers started so far.
func (d *Driver) SystemSpecs() []runtime.SystemSpec {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.Systems)
}

// Exec records the command and returns ExecFunc's answer (success by default).
func (d *Driver) Exec(_ context.Context, id string, cmd []string) (string, int, error) {
	d.mu.Lock()
	d.Execs = append(d.Execs, cmd)
	f := d.ExecFunc
	d.mu.Unlock()
	if f != nil {
		return f(id, cmd)
	}
	return "", 0, nil
}

// Signal records the signal.
func (d *Driver) Signal(_ context.Context, id, signal string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.containers[id]; !ok {
		return runtime.ErrNotFound
	}
	d.Signals = append(d.Signals, signal)
	return nil
}

var _ runtime.Driver = (*Driver)(nil)

// New returns an empty engine.
func New() *Driver {
	return &Driver{
		containers: map[string]*runtime.Container{},
		specs:      map[string]runtime.ContainerSpec{},
		nextPort:   32768,
	}
}

// Ping always succeeds.
func (d *Driver) Ping(context.Context) error { return d.PingErr }

// Pull records the pull and returns the configured digest and platforms.
func (d *Driver) Pull(_ context.Context, image string, auth *runtime.RegistryAuth) (runtime.Image, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Pulls = append(d.Pulls, image)
	d.PullAuths = append(d.PullAuths, auth)
	if err := d.PullErr[image]; err != nil {
		return runtime.Image{}, err
	}
	return runtime.Image{Ref: d.Digests[image], Platforms: d.Platforms[image]}, nil
}

// Run creates a running container.
func (d *Driver) Run(ctx context.Context, s runtime.ContainerSpec) (string, error) {
	if d.RunHook != nil {
		d.RunHook(ctx, s)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.RunErr != nil {
		return "", d.RunErr
	}
	for _, c := range d.containers {
		if c.Name == s.Name {
			return "", fmt.Errorf("container name %q already in use", s.Name)
		}
	}
	d.seq++
	id := fmt.Sprintf("c%04d", d.seq)
	labels := maps.Clone(s.Labels)
	c := &runtime.Container{ID: id, Name: s.Name, Image: s.Image, Labels: labels, State: runtime.StateRunning, StartedAt: time.Now()}
	if s.Port != 0 {
		c.HostIP, c.HostPort = s.HostIP, d.nextPort
		d.nextPort++
	}
	if d.BridgeIPs != "" {
		c.IP = d.BridgeIPs + strconv.Itoa(d.seq)
	}
	d.containers[id] = c
	d.specs[id] = s
	return id, nil
}

// Stop marks a container exited.
func (d *Driver) Stop(_ context.Context, id string, _ time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.containers[id]
	if !ok {
		return runtime.ErrNotFound
	}
	c.State = runtime.StateExited
	return nil
}

// Remove deletes a container.
func (d *Driver) Remove(_ context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.containers[id]; !ok {
		return runtime.ErrNotFound
	}
	delete(d.containers, id)
	delete(d.specs, id)
	return nil
}

// List returns containers matching all labels, sorted by name.
func (d *Driver) List(_ context.Context, labels map[string]string) ([]runtime.Container, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []runtime.Container
outer:
	for _, c := range d.containers {
		for k, v := range labels {
			if c.Labels[k] != v {
				continue outer
			}
		}
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Inspect returns one container.
func (d *Driver) Inspect(_ context.Context, id string) (runtime.Container, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.containers[id]
	if !ok {
		return runtime.Container{}, runtime.ErrNotFound
	}
	return *c, nil
}

// Logs returns LogLines.
func (d *Driver) Logs(_ context.Context, id string, _ runtime.LogOptions) (runtime.LogStream, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.containers[id]; !ok {
		return nil, runtime.ErrNotFound
	}
	return &stream{frames: append([]runtime.LogFrame(nil), d.LogLines...)}, nil
}

// SetState changes a container's state, e.g. to simulate a crash.
func (d *Driver) SetState(id, state string, exitCode int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c, ok := d.containers[id]; ok {
		c.State, c.ExitCode = state, exitCode
	}
}

// Spec returns the spec a container was created with.
func (d *Driver) Spec(id string) (runtime.ContainerSpec, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.specs[id]
	return s, ok
}

// Add inserts an existing container, e.g. one left over from a previous run.
func (d *Driver) Add(c runtime.Container) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cp := c
	d.containers[c.ID] = &cp
}

type stream struct {
	frames []runtime.LogFrame
}

func (s *stream) Next() (runtime.LogFrame, error) {
	if len(s.frames) == 0 {
		return runtime.LogFrame{}, io.EOF
	}
	f := s.frames[0]
	s.frames = s.frames[1:]
	return f, nil
}

func (s *stream) Close() error { return nil }

// PruneImages records what it was asked to keep and removes nothing.
func (d *Driver) PruneImages(_ context.Context, keep []string, _ time.Duration) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Prunes = append(d.Prunes, slices.Sorted(slices.Values(keep)))
	return nil, nil
}
