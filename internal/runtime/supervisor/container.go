package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"syscall"
	"time"

	"github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// container is a recorded container (client.Container).
type container struct {
	s   *Store
	rec Record
}

var _ client.Container = (*container)(nil)

func (c *container) ID() string { return c.rec.ID }

func (c *container) Info(context.Context, ...client.InfoOpts) (containers.Container, error) {
	return containers.Container{
		ID: c.rec.ID, Labels: maps.Clone(c.rec.Labels), Image: c.rec.Image,
		SnapshotKey: c.rec.ID, Snapshotter: snapshotterName,
		Runtime:   containers.RuntimeInfo{Name: "armada-shim"},
		CreatedAt: c.rec.Created, UpdatedAt: c.rec.Created,
	}, nil
}

func (c *container) Labels(context.Context) (map[string]string, error) {
	return maps.Clone(c.rec.Labels), nil
}

// SetLabels merges labels into the record.
func (c *container) SetLabels(_ context.Context, labels map[string]string) (map[string]string, error) {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	if c.rec.Labels == nil {
		c.rec.Labels = map[string]string{}
	}
	maps.Copy(c.rec.Labels, labels)
	if err := writeJSON(c.s.Bundles.Path(c.rec.ID)+"/"+bundleRecord, c.rec); err != nil {
		return nil, err
	}
	return maps.Clone(c.rec.Labels), nil
}

func (c *container) Spec(context.Context) (*oci.Spec, error) { return c.s.Bundles.Spec(c.rec.ID) }

func (c *container) Image(ctx context.Context) (client.Image, error) {
	return c.s.GetImage(ctx, c.rec.Image)
}

// NewTask creates the container's process in its shim, not started. Its
// output goes to armada-log; the creator is not used.
func (c *container) NewTask(ctx context.Context, _ cio.Creator, _ ...client.NewTaskOpts) (client.Task, error) {
	sh, err := c.s.Shims.For(ctx, c.rec.Group)
	if err != nil {
		return nil, err
	}
	pid, err := sh.Create(ctx, c.rec.ID, c.s.Bundles.Path(c.rec.ID), c.s.Logs)
	if err != nil {
		return nil, fmt.Errorf("create task: %w", err)
	}
	return &taskProc{c: c, sh: sh, pid: pid}, nil
}

// Task returns the container's task. A shim that does not answer took its
// containers with it: they are ended, and the task is not found, as on
// containerd when a shim dies.
func (c *container) Task(ctx context.Context, _ cio.Attach) (client.Task, error) {
	sh := c.s.Shims.Get(c.rec.Group)
	st, err := sh.State(ctx, c.rec.ID)
	switch {
	case err == nil:
		return &taskProc{c: c, sh: sh, pid: st.Pid}, nil
	case NotFound(err):
		return nil, fmt.Errorf("task %s: %w", c.rec.ID, errdefs.ErrNotFound)
	}
	var shimErr errShim
	if errors.As(err, &shimErr) {
		return nil, err
	}
	if aerr := c.s.Shims.Abandon(ctx, sh); aerr != nil {
		return nil, fmt.Errorf("shim of %s: %w; ending its containers: %w", c.rec.ID, err, aerr)
	}
	return nil, fmt.Errorf("task %s (shim gone): %w", c.rec.ID, errdefs.ErrNotFound)
}

// Delete removes the record, the bundle, and the root filesystem. The
// task must be gone; opts (containerd's) are not used: the snapshot always
// goes.
func (c *container) Delete(ctx context.Context, _ ...client.DeleteOpts) error {
	if err := c.s.Bundles.Remove(c.rec.ID); err != nil {
		return err
	}
	return c.s.Images.Release(context.WithoutCancel(ctx), c.rec.ID)
}

func (c *container) Extensions(context.Context) (map[string]typeurl.Any, error) {
	return nil, nil
}

func (c *container) Update(context.Context, ...client.UpdateContainerOpts) error {
	return errdefs.ErrNotImplemented
}

func (c *container) Checkpoint(context.Context, string, ...client.CheckpointOpts) (client.Image, error) {
	return nil, errdefs.ErrNotImplemented
}

func (c *container) Restore(context.Context, cio.Creator, string) (int, error) {
	return 0, errdefs.ErrNotImplemented
}

// taskProc is a container's process in its shim (client.Task).
type taskProc struct {
	c   *container
	sh  *Shim
	pid int
}

var _ client.Task = (*taskProc)(nil)

func (t *taskProc) ID() string  { return t.c.rec.ID }
func (t *taskProc) Pid() uint32 { return uint32(max(t.pid, 0)) } //nolint:gosec // a process ID

func (t *taskProc) Start(ctx context.Context) error { return t.sh.Start(ctx, t.c.rec.ID) }

func (t *taskProc) Status(ctx context.Context) (client.Status, error) {
	st, err := t.sh.State(ctx, t.c.rec.ID)
	if err != nil {
		if NotFound(err) {
			return client.Status{}, fmt.Errorf("task %s: %w", t.c.rec.ID, errdefs.ErrNotFound)
		}
		return client.Status{}, err
	}
	switch st.Status {
	case "running":
		return client.Status{Status: client.Running}, nil
	case "created":
		return client.Status{Status: client.Created}, nil
	}
	return client.Status{Status: client.Stopped, ExitStatus: uint32(max(st.Exit, 0)), ExitTime: time.Now()}, nil //nolint:gosec // an exit code
}

// Wait returns a channel that gets the exit status once the process exits.
func (t *taskProc) Wait(ctx context.Context) (<-chan client.ExitStatus, error) {
	ch := make(chan client.ExitStatus, 1)
	go func() {
		code, err := t.sh.Wait(ctx, t.c.rec.ID)
		ch <- *client.NewExitStatus(uint32(max(code, 0)), time.Now(), err) //nolint:gosec // an exit code
	}()
	return ch, nil
}

func (t *taskProc) Kill(ctx context.Context, sig syscall.Signal, opts ...client.KillOpts) error {
	var info client.KillInfo
	for _, o := range opts {
		if err := o(ctx, &info); err != nil {
			return err
		}
	}
	var err error
	if info.All {
		err = t.sh.KillAll(ctx, t.c.rec.ID, int(sig))
	} else {
		err = t.sh.Kill(ctx, t.c.rec.ID, int(sig))
	}
	if NotFound(err) {
		return fmt.Errorf("task %s: %w", t.c.rec.ID, errdefs.ErrNotFound)
	}
	var shimErr errShim
	if errors.As(err, &shimErr) {
		// "is not running": nothing to signal.
		return fmt.Errorf("%w: %w", err, errdefs.ErrFailedPrecondition)
	}
	return err
}

// Delete removes the process from its shim (killing it if it runs; opts
// such as containerd's WithProcessKill run first).
func (t *taskProc) Delete(ctx context.Context, opts ...client.ProcessDeleteOpts) (*client.ExitStatus, error) {
	for _, o := range opts {
		if err := o(ctx, t); err != nil {
			return nil, err
		}
	}
	code := 0
	if st, err := t.sh.State(ctx, t.c.rec.ID); err == nil && st.Status == "exited" {
		code = st.Exit
	}
	if err := t.sh.Delete(ctx, t.c.rec.ID); err != nil {
		if NotFound(err) {
			return nil, fmt.Errorf("task %s: %w", t.c.rec.ID, errdefs.ErrNotFound)
		}
		return nil, err
	}
	return client.NewExitStatus(uint32(max(code, 0)), time.Now(), nil), nil
}

func (t *taskProc) CloseIO(context.Context, ...client.IOCloserOpts) error { return nil }
func (t *taskProc) Resize(context.Context, uint32, uint32) error          { return errdefs.ErrNotImplemented }
func (t *taskProc) IO() cio.IO                                            { return nil }
func (t *taskProc) Pause(context.Context) error                           { return errdefs.ErrNotImplemented }
func (t *taskProc) Resume(context.Context) error                          { return errdefs.ErrNotImplemented }

func (t *taskProc) Pids(context.Context) ([]client.ProcessInfo, error) {
	return []client.ProcessInfo{{Pid: t.Pid()}}, nil
}

func (t *taskProc) Checkpoint(context.Context, ...client.CheckpointTaskOpts) (client.Image, error) {
	return nil, errdefs.ErrNotImplemented
}

func (t *taskProc) Update(context.Context, ...client.UpdateTaskOpts) error {
	return errdefs.ErrNotImplemented
}

func (t *taskProc) LoadProcess(context.Context, string, cio.Attach) (client.Process, error) {
	return nil, errdefs.ErrNotImplemented
}

func (t *taskProc) Spec(ctx context.Context) (*oci.Spec, error) { return t.c.Spec(ctx) }

// Metrics reads the container's cgroup (v2) the way containerd's shim
// reports it.
func (t *taskProc) Metrics(ctx context.Context) (*types.Metric, error) {
	spec, err := t.c.Spec(ctx)
	if err != nil {
		return nil, err
	}
	if spec.Linux == nil || spec.Linux.CgroupsPath == "" {
		return nil, errors.New("the container has no cgroup")
	}
	st, err := readCgroup(filepath.Join(cgroupRoot, filepath.Clean("/"+spec.Linux.CgroupsPath)))
	if err != nil {
		return nil, err
	}
	data, err := typeurl.MarshalAnyToProto(st)
	if err != nil {
		return nil, err
	}
	return &types.Metric{ID: t.c.rec.ID, Data: data}, nil
}

// Exec runs a process in the container with runc exec (exec.go).
func (t *taskProc) Exec(ctx context.Context, id string, p *specs.Process, creator cio.Creator) (client.Process, error) {
	return newExecProcess(ctx, t, id, p, creator)
}

// image is a pulled image (client.Image).
type image struct {
	s   *Store
	rec Image
}

var _ client.Image = (*image)(nil)

func (i *image) Name() string                                              { return i.rec.Name }
func (i *image) Target() ocispec.Descriptor                                { return i.rec.Target }
func (i *image) Labels() map[string]string                                 { return maps.Clone(i.rec.Labels) }
func (i *image) Unpack(context.Context, string, ...client.UnpackOpt) error { return nil }
func (i *image) IsUnpacked(context.Context, string) (bool, error)          { return true, nil }
func (i *image) Config(context.Context) (ocispec.Descriptor, error) {
	return i.rec.Config, nil
}
func (i *image) ContentStore() content.Store       { return i.s.Images.content }
func (i *image) Metadata() images.Image            { return i.rec.metadata() }
func (i *image) Platform() platforms.MatchComparer { return i.s.Images.platform }

func (i *image) RootFS(ctx context.Context) ([]digest.Digest, error) {
	return images.RootFS(ctx, i.s.Images.content, i.rec.Config)
}

func (i *image) Size(ctx context.Context) (int64, error) {
	img := images.Image{Target: i.rec.Target}
	return img.Size(ctx, i.s.Images.content, i.s.Images.platform)
}

func (i *image) Usage(ctx context.Context, _ ...client.UsageOpt) (int64, error) { return i.Size(ctx) }

func (i *image) Spec(ctx context.Context) (ocispec.Image, error) {
	var out ocispec.Image
	b, err := content.ReadBlob(ctx, i.s.Images.content, i.rec.Config)
	if err != nil {
		return out, err
	}
	return out, json.Unmarshal(b, &out)
}
