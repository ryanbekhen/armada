package containerd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"sync"
	"syscall"

	"github.com/containerd/containerd/v2/pkg/cio"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// RunSystem creates and starts an infrastructure container.
func (d *Driver) RunSystem(ctx context.Context, s runtime.SystemSpec) (_ string, err error) {
	for _, m := range s.Mounts {
		if err := runtime.CheckSystemMount(m); err != nil {
			return "", err
		}
	}
	id, err := newID(s.Name)
	if err != nil {
		return "", err
	}
	ctx = d.ctx(ctx)
	img, err := d.image(ctx, s.Image)
	if err != nil {
		return "", err
	}
	labels := maps.Clone(s.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels[labelKind] = "system"
	labels[labelName] = s.Name
	var undo []func()
	defer func() {
		if err != nil {
			for i := len(undo) - 1; i >= 0; i-- {
				undo[i]()
			}
		}
	}()
	opts := argsOpts(img, runtime.ContainerSpec{Cmd: s.Cmd})
	opts = append(opts, systemOpts(s, cgroupParent+"/"+id, seccompOpt())...)
	return d.create(ctx, id, img, labels, opts, &undo)
}

// lockedBuffer collects output written from two goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Exec runs cmd in a running container and returns its combined output.
func (d *Driver) Exec(ctx context.Context, id string, cmd []string) (string, int, error) {
	ctx = d.ctx(ctx)
	c, err := d.client.LoadContainer(ctx, id)
	if err != nil {
		return "", 0, notFound(err)
	}
	t, err := c.Task(ctx, nil)
	if err != nil {
		return "", 0, notFound(err)
	}
	spec, err := c.Spec(ctx)
	if err != nil {
		return "", 0, err
	}
	p := *spec.Process
	p.Args = cmd
	p.Terminal = false
	var buf lockedBuffer
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", 0, err
	}
	proc, err := t.Exec(ctx, "exec-"+hex.EncodeToString(b), &p,
		cio.NewCreator(cio.WithStreams(nil, &buf, &buf), cio.WithFIFODir(d.paths.FIFO())))
	if err != nil {
		return "", 0, fmt.Errorf("exec: %w", err)
	}
	defer func() { _, _ = proc.Delete(context.WithoutCancel(ctx)) }()
	exited, err := proc.Wait(ctx)
	if err != nil {
		return "", 0, err
	}
	if err := proc.Start(ctx); err != nil {
		return "", 0, fmt.Errorf("exec: %w", err)
	}
	var code uint32
	select {
	case st := <-exited:
		code, _, err = st.Result()
		if err != nil {
			return "", 0, err
		}
	case <-ctx.Done():
		return "", 0, ctx.Err()
	}
	proc.IO().Wait()
	return buf.String(), int(code), nil
}

var signals = map[string]syscall.Signal{
	"SIGHUP": syscall.SIGHUP, "SIGINT": syscall.SIGINT, "SIGQUIT": syscall.SIGQUIT,
	"SIGKILL": syscall.SIGKILL, "SIGTERM": syscall.SIGTERM,
	"SIGUSR1": syscall.SIGUSR1, "SIGUSR2": syscall.SIGUSR2,
}

// Signal sends a signal to the container's main process.
func (d *Driver) Signal(ctx context.Context, id, signal string) error {
	sig, ok := signals[signal]
	if !ok {
		return fmt.Errorf("unsupported signal %q", signal)
	}
	ctx = d.ctx(ctx)
	c, err := d.client.LoadContainer(ctx, id)
	if err != nil {
		return notFound(err)
	}
	t, err := c.Task(ctx, nil)
	if err != nil {
		return notFound(err)
	}
	return t.Kill(ctx, sig)
}
