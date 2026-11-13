package containerd

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/errdefs"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// Init containers and sidecars (ADR 0038). A replica's own container is
// created first, with its network namespace, its host files, and its task
// (created, not started), so the agent adopts the replica by it whatever
// happens next. A goroutine of the driver then runs the init containers in
// order, each to its end, starts the sidecars, and starts the replica's
// task. Each of them is a container of its own: its own cgroup and limits,
// the same security defaults, and the replica's network namespace, host
// files, and SELinux label, so they reach each other on 127.0.0.1 and share
// the files and volumes they mount but nothing of other replicas.

// Labels of init containers and sidecars, for the driver's bookkeeping.
const (
	kindMember = "member"
	// labelPod names the replica's container an init container or sidecar
	// belongs to.
	labelPod = labelPrefix + "pod"
	// labelFailed on a replica's container says why its start was given up.
	labelFailed = labelPrefix + "failed"
)

// startup is a replica's bring-up in progress.
type startup struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// podEnv is what the replica's containers share.
type podEnv struct {
	spec    runtime.ContainerSpec
	netns   string
	files   containerFiles
	tini    string
	selinux selinuxLabels
	images  map[string]client.Image
}

// starting reports whether the driver is still bringing up id.
func (d *Driver) starting(id string) bool {
	d.startsMu.Lock()
	defer d.startsMu.Unlock()
	_, ok := d.starts[id]
	return ok
}

// endStart stops bringing up id, if that is still going on, and waits for
// it to have stopped.
func (d *Driver) endStart(id string) {
	d.startsMu.Lock()
	s := d.starts[id]
	d.startsMu.Unlock()
	if s != nil {
		s.cancel()
		<-s.done
	}
}

// runPod creates the replica's container and its task, unstarted, and
// leaves the rest to bringUp. unlock releases the lock on host ports once
// the container records its port.
func (d *Driver) runPod(ctx context.Context, id string, img client.Image, labels map[string]string, opts []oci.SpecOpts, env podEnv, undo *[]func(), unlock func()) (string, error) {
	labels[labelStarted] = time.Now().UTC().Format(time.RFC3339Nano)
	c, err := d.client.NewContainer(ctx, id,
		client.WithImage(img),
		client.WithNewSnapshot(id, img),
		client.WithRuntime(plugins.RuntimeRuncV2, d.runcOpts()),
		client.WithContainerLabels(labels),
		client.WithNewSpec(opts...),
	)
	if err != nil {
		return "", fmt.Errorf("create container: %w", err)
	}
	*undo = append(*undo, func() { _ = c.Delete(context.WithoutCancel(ctx), client.WithSnapshotCleanup) })
	unlock()
	d.logMeta(id, labels)
	t, err := c.NewTask(ctx, d.logIO())
	if err != nil {
		return "", fmt.Errorf("create task: %w", err)
	}
	*undo = append(*undo, func() { _, _ = t.Delete(context.WithoutCancel(ctx), client.WithProcessKill) })

	// The bring-up outlives Run: it ends with the driver's process, or
	// when Stop or Remove ends it.
	bctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	s := &startup{cancel: cancel, done: make(chan struct{})}
	d.startsMu.Lock()
	if d.starts == nil {
		d.starts = map[string]*startup{}
	}
	d.starts[id] = s
	d.startsMu.Unlock()
	go func() {
		defer close(s.done)
		defer cancel()
		defer func() {
			d.startsMu.Lock()
			delete(d.starts, id)
			d.startsMu.Unlock()
		}()
		why, gaveUp := d.bringUp(bctx, id, t, env)
		if gaveUp && bctx.Err() == nil {
			// Never started: the task goes, so the container lists as
			// exited, and the reason, unless a failed init container tells
			// it, stays on it.
			dctx := context.WithoutCancel(bctx)
			_, _ = t.Delete(dctx, client.WithProcessKill)
			if why != "" {
				_, _ = c.SetLabels(dctx, map[string]string{labelFailed: truncate(why, maxFailed)})
			}
		}
	}()
	return id, nil
}

// maxFailed bounds the reason a start was given up, kept in a label.
const maxFailed = 512

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// bringUp runs the init containers, starts the sidecars, then the replica's
// task. It reports whether it gave up, and why unless a failed init
// container tells it. When ctx ends it stops without giving up: Stop or
// Remove take over.
func (d *Driver) bringUp(ctx context.Context, id string, t client.Task, env podEnv) (string, bool) {
	for _, m := range env.spec.Init {
		mt, exited, err := d.startMember(ctx, id, m, runtime.RoleInit, env)
		if err != nil {
			return "init container " + m.Name + ": " + err.Error(), true
		}
		select {
		case st := <-exited:
			if st.ExitCode() != 0 {
				return "", true
			}
		case <-ctx.Done():
			_ = mt.Kill(context.WithoutCancel(ctx), syscall.SIGKILL, client.WithKillAll)
			return "", false
		}
	}
	for _, m := range env.spec.Sidecars {
		if _, _, err := d.startMember(ctx, id, m, runtime.RoleSidecar, env); err != nil {
			return "sidecar " + m.Name + ": " + err.Error(), true
		}
	}
	if err := t.Start(ctx); err != nil {
		return "start container: " + err.Error(), true
	}
	_ = d.setStarted(ctx, id)
	return "", false
}

// CanRunMembers implements runtime support for init containers and
// sidecars (ADR 0038).
func (d *Driver) CanRunMembers() bool { return true }

// setStarted records when the replica's own container started.
func (d *Driver) setStarted(ctx context.Context, id string) error {
	c, err := d.client.LoadContainer(ctx, id)
	if err != nil {
		return err
	}
	_, err = c.SetLabels(ctx, map[string]string{labelStarted: time.Now().UTC().Format(time.RFC3339Nano)})
	return err
}

// startMember creates and starts an init container or sidecar of the
// replica's container pod, in its network namespace, and returns its task
// with the channel its exit arrives on.
func (d *Driver) startMember(ctx context.Context, pod string, m runtime.MemberSpec, role string, env podEnv) (_ client.Task, _ <-chan client.ExitStatus, err error) {
	mid, err := newID("armada-" + m.Name)
	if err != nil {
		return nil, nil, err
	}
	img := env.images[m.Image]
	if img == nil {
		return nil, nil, fmt.Errorf("image %s was not resolved", m.Image)
	}
	labels := maps.Clone(env.spec.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels[runtime.LabelRole] = role
	labels[runtime.LabelContainer] = m.Name
	labels[labelKind] = kindMember
	labels[labelName] = m.Name
	labels[labelPod] = pod
	labels[labelStarted] = time.Now().UTC().Format(time.RFC3339Nano)
	// The replica's host name: they are one machine on the network.
	ms := runtime.ContainerSpec{
		Name: env.spec.Name, Image: m.Image, Entrypoint: m.Entrypoint, Cmd: m.Cmd, Env: m.Env,
		MemoryBytes: m.MemoryBytes, NanoCPUs: m.NanoCPUs, CPUReserveMillis: m.CPUReserveMillis, PidsLimit: m.PidsLimit,
		Files: m.Files, Volumes: m.Volumes,
	}
	opts := argsOpts(img, ms)
	opts = append(opts, appOpts(appSpec{
		spec: ms, netns: env.netns, files: env.files, tini: env.tini,
		cgroup:   cgroupParent + "/" + mid,
		seccomp:  seccompOpt(),
		apparmor: apparmorOpt(),
		selinux:  env.selinux,
	})...)
	var undo []func()
	defer func() {
		if err != nil {
			for i := len(undo) - 1; i >= 0; i-- {
				undo[i]()
			}
		}
	}()
	c, err := d.client.NewContainer(ctx, mid,
		client.WithImage(img),
		client.WithNewSnapshot(mid, img),
		client.WithRuntime(plugins.RuntimeRuncV2, d.runcOpts()),
		client.WithContainerLabels(labels),
		client.WithNewSpec(opts...),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create container: %w", err)
	}
	undo = append(undo, func() { _ = c.Delete(context.WithoutCancel(ctx), client.WithSnapshotCleanup) })
	d.logMeta(mid, labels)
	t, err := c.NewTask(ctx, d.logIO())
	if err != nil {
		return nil, nil, fmt.Errorf("create task: %w", err)
	}
	undo = append(undo, func() { _, _ = t.Delete(context.WithoutCancel(ctx), client.WithProcessKill) })
	exited, err := t.Wait(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := t.Start(ctx); err != nil {
		return nil, nil, fmt.Errorf("start: %w", err)
	}
	return t, exited, nil
}

// members returns the init containers and sidecars of the replica's
// container pod.
func (d *Driver) members(ctx context.Context, pod string) ([]client.Container, error) {
	return d.client.Containers(ctx, "labels."+strconv.Quote(labelPod)+"=="+strconv.Quote(pod))
}

// describeMembers fills c.Members from the init containers and sidecars of
// c, oldest first.
func (d *Driver) describeMembers(ctx context.Context, c *runtime.Container) error {
	ms, err := d.members(ctx, c.ID)
	if err != nil {
		return err
	}
	for _, m := range ms {
		rc, _, err := d.describeWith(ctx, m, nil)
		if errdefs.IsNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		c.Members = append(c.Members, memberOf(rc))
	}
	sortMembers(c.Members)
	return nil
}

func memberOf(rc runtime.Container) runtime.Member {
	return runtime.Member{
		ID: rc.ID, Name: rc.Labels[runtime.LabelContainer], Role: rc.Labels[runtime.LabelRole],
		State: rc.State, ExitCode: rc.ExitCode, StartedAt: rc.StartedAt,
	}
}

// sortMembers orders members by role (init containers first), then by when
// they started.
func sortMembers(ms []runtime.Member) {
	rank := func(m runtime.Member) int {
		if m.Role == runtime.RoleInit {
			return 0
		}
		return 1
	}
	for i := 1; i < len(ms); i++ {
		for j := i; j > 0; j-- {
			a, b := ms[j-1], ms[j]
			if rank(a) < rank(b) || (rank(a) == rank(b) && !b.StartedAt.Before(a.StartedAt)) {
				break
			}
			ms[j-1], ms[j] = b, a
		}
	}
}

// stopSidecars stops the running sidecars of pod, at once, each with grace.
func (d *Driver) stopSidecars(ctx context.Context, pod string, grace time.Duration) error {
	ms, err := d.members(ctx, pod)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	errs := make([]error, len(ms))
	for i, m := range ms {
		l, err := m.Labels(ctx)
		if err != nil || l[runtime.LabelRole] != runtime.RoleSidecar {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = d.stopContainer(ctx, m, grace)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// removeMembers removes the init containers and sidecars of pod.
func (d *Driver) removeMembers(ctx context.Context, pod string) error {
	ms, err := d.members(ctx, pod)
	if err != nil {
		return err
	}
	var errs []error
	for _, m := range ms {
		if err := d.removeContainer(ctx, m); err != nil && !errors.Is(err, runtime.ErrNotFound) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// memberStats adds what pod's running init containers and sidecars use to
// st. The network counters are the replica's already: they share it.
func (d *Driver) memberStats(ctx context.Context, pod string, st *runtime.Stats) {
	ms, err := d.members(ctx, pod)
	if err != nil {
		return
	}
	for _, m := range ms {
		one, err := d.taskStats(ctx, m)
		if err != nil {
			continue
		}
		st.CPU += one.CPU
		st.MemoryBytes += one.MemoryBytes
		st.OOMKills += one.OOMKills
	}
}
