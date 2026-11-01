package haproxy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// Image is the HAProxy image, pinned by digest (3.2 LTS, Alpine). Update it
// through a reviewed PR; never use a mutable tag.
const Image = "haproxy:3.2-alpine@sha256:5893840576071e6217cd52ebdcc14f454c6f7a631056fa6f4e0f40d3cac4215b"

const (
	containerName = "armada-haproxy"
	systemLabel   = "haproxy"
	// imageLabel records the configured image reference, which the
	// runtime may report in another form (digest-pinned, normalized).
	imageLabel = "armada.image"
	// dirLabel records the host directory mounted into the container, so an
	// agent started with another data directory replaces it.
	dirLabel = "armada.dir"
)

// ContainerEngine runs HAProxy as a host-network system container.
type ContainerEngine struct {
	Runtime runtime.Driver
	System  runtime.SystemRunner
	// Dir is the same host directory given to the Driver.
	Dir   string
	Image string
	// StartWait is how long Start waits to confirm HAProxy stays up.
	StartWait time.Duration
}

var _ Engine = (*ContainerEngine)(nil)

func (e *ContainerEngine) image() string {
	if e.Image != "" {
		return e.Image
	}
	return Image
}

func (e *ContainerEngine) find(ctx context.Context) ([]runtime.Container, error) {
	return e.Runtime.List(ctx, map[string]string{runtime.LabelSystem: systemLabel})
}

// Running reports whether the HAProxy container is up with the pinned image
// and this engine's directory.
func (e *ContainerEngine) Running(ctx context.Context) (bool, error) {
	cs, err := e.find(ctx)
	if err != nil {
		return false, err
	}
	for _, c := range cs {
		if c.State == runtime.StateRunning && c.Labels[imageLabel] == e.image() && c.Labels[dirLabel] == e.Dir {
			return true, nil
		}
	}
	return false, nil
}

func (e *ContainerEngine) running(ctx context.Context) (string, error) {
	cs, err := e.find(ctx)
	if err != nil {
		return "", err
	}
	for _, c := range cs {
		if c.State == runtime.StateRunning {
			return c.ID, nil
		}
	}
	return "", errors.New("haproxy container is not running")
}

// Start replaces any existing HAProxy container with a fresh one.
func (e *ContainerEngine) Start(ctx context.Context) error {
	cs, err := e.find(ctx)
	if err != nil {
		return err
	}
	for _, c := range cs {
		_ = e.Runtime.Stop(ctx, c.ID, 5*time.Second)
		if err := e.Runtime.Remove(ctx, c.ID); err != nil && !errors.Is(err, runtime.ErrNotFound) {
			return err
		}
	}
	if _, err := e.Runtime.Pull(ctx, e.image(), nil); err != nil {
		return err
	}
	id, err := e.System.RunSystem(ctx, runtime.SystemSpec{
		Name:   containerName,
		Image:  e.image(),
		Labels: map[string]string{runtime.LabelSystem: systemLabel, imageLabel: e.image(), dirLabel: e.Dir},
		Mounts: []runtime.Mount{
			{Source: etcDir(e.Dir), Target: containerConfDir, ReadOnly: true},
			{Source: runDir(e.Dir), Target: containerRunDir},
		},
		// Root inside the container is needed to use the 0700 host
		// directories; every capability except binding :80/:443 is dropped.
		User:   "0:0",
		CapAdd: []string{"NET_BIND_SERVICE"},
	})
	if err != nil {
		return err
	}

	wait := e.StartWait
	if wait == 0 {
		wait = 2 * time.Second
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(wait):
	}
	c, err := e.Runtime.Inspect(ctx, id)
	if err != nil {
		return err
	}
	if c.State != runtime.StateRunning {
		return fmt.Errorf("haproxy exited (code %d): %s", c.ExitCode, e.tail(ctx, id))
	}
	return nil
}

func (e *ContainerEngine) tail(ctx context.Context, id string) string {
	ls, err := e.Runtime.Logs(ctx, id, runtime.LogOptions{Tail: 20})
	if err != nil {
		return "no logs"
	}
	defer ls.Close()
	var b strings.Builder
	for {
		f, err := ls.Next()
		if err != nil {
			break
		}
		b.Write(f.Data)
	}
	return strings.TrimSpace(b.String())
}

// Validate runs `haproxy -c -f file` inside the running container.
func (e *ContainerEngine) Validate(ctx context.Context, file string) error {
	id, err := e.running(ctx)
	if err != nil {
		return err
	}
	out, code, err := e.System.Exec(ctx, id, []string{"haproxy", "-c", "-f", file})
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("haproxy -c: %s", strings.TrimSpace(out))
	}
	return nil
}

// Reload sends SIGUSR2 to the HAProxy master process.
func (e *ContainerEngine) Reload(ctx context.Context) error {
	id, err := e.running(ctx)
	if err != nil {
		return err
	}
	return e.System.Signal(ctx, id, "SIGUSR2")
}
