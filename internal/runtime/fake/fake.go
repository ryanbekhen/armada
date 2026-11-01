// Package fake provides an in-memory runtime.Driver for tests.
package fake

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"
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
	// Digests maps image references to the digest Pull returns.
	Digests map[string]string
	// Platforms maps image references to the platforms Pull returns.
	Platforms map[string][]string
	// LogLines is returned by Logs for every container.
	LogLines []runtime.LogFrame

	Pulls []string
	// PullAuths records the credentials of each pull (nil for none).
	PullAuths []*runtime.RegistryAuth

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
func (d *Driver) Run(_ context.Context, s runtime.ContainerSpec) (string, error) {
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
