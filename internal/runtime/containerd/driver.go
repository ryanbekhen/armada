// Package containerd implements runtime.Driver on the containerd instance
// that Armada embeds (ADR 0011).
package containerd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types/runc/options"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/core/remotes/docker/config"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/errdefs"
	"github.com/distribution/reference"

	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// Labels the driver keeps on containers for its own bookkeeping.
const (
	labelPrefix   = "armada.runtime/"
	labelKind     = labelPrefix + "kind" // "app" or "system"
	labelName     = labelPrefix + "name"
	labelHostIP   = labelPrefix + "host-ip"
	labelHostPort = labelPrefix + "host-port"
	labelPort     = labelPrefix + "port"
	labelIP       = labelPrefix + "ip"
	labelNetNS    = labelPrefix + "netns"
	labelStarted  = labelPrefix + "started"
)

// cgroupParent groups Armada's containers in the cgroup v2 hierarchy.
const cgroupParent = "/armada"

// network attaches app containers to the node's bridge.
type network interface {
	// Ensure creates the bridge with the gateway address if needed.
	Ensure(ctx context.Context) error
	// Setup creates a network namespace for id, attaches it, publishes the
	// port if any, and returns the namespace path and the container IP.
	Setup(ctx context.Context, id string, pm *portMapping) (netns, ip string, err error)
	// Teardown undoes Setup; it tolerates a namespace that is already gone.
	Teardown(ctx context.Context, id, netns string, pm *portMapping) error
	// SetupAt attaches a namespace the caller made at path as id, with no
	// port, and returns its IP; Address returns that IP again later.
	SetupAt(ctx context.Context, id, path string) (ip string, err error)
	Address(id, path string) (ip string, err error)
	Bridge() runtime.Bridge
}

type portMapping struct {
	HostIP        string
	HostPort      int
	ContainerPort int
}

// Config configures the driver.
type Config struct {
	Paths  embedded.Paths
	Subnet netip.Prefix // container bridge subnet; zero means DefaultSubnet
	// MTU of the bridge and container interfaces; 0 leaves the kernel's
	// default (1500). The cluster network sets it from the uplink
	// (ADR 0025).
	MTU int
	// Self is the armada binary the shim runs to store container output;
	// empty means the running executable.
	Self string
}

// Driver runs containers on the embedded containerd.
type Driver struct {
	client *client.Client
	paths  embedded.Paths
	net    network
	self   string

	mu sync.Mutex // serializes Run so host ports are not handed out twice
	// sandboxMu serializes changes to network sandboxes (ADR 0040).
	sandboxMu sync.Mutex

	labelsMu       sync.Mutex
	labelsReserved bool // SELinux categories of existing containers are reserved

	startsMu sync.Mutex
	starts   map[string]*startup // replicas whose init containers or sidecars are starting (ADR 0038)
}

var (
	_ runtime.Driver          = (*Driver)(nil)
	_ runtime.SystemRunner    = (*Driver)(nil)
	_ runtime.BridgeInspector = (*Driver)(nil)
)

// New connects to the embedded containerd. It does not wait for it to be
// up; Ping does.
func New(cfg Config) (*Driver, error) {
	subnet := cfg.Subnet
	if !subnet.IsValid() {
		subnet = embedded.DefaultSubnet
	}
	n, err := newNetwork(cfg.Paths, subnet, cfg.MTU)
	if err != nil {
		return nil, err
	}
	self := cfg.Self
	if self == "" {
		if self, err = os.Executable(); err != nil {
			return nil, err
		}
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return nil, err
	}
	c, err := client.New(cfg.Paths.Socket(), client.WithDefaultNamespace(embedded.Namespace), client.WithTimeout(5*time.Second))
	if err != nil {
		return nil, fmt.Errorf("connect to containerd: %w", err)
	}
	return &Driver{client: c, paths: cfg.Paths, net: n, self: self}, nil
}

// Close releases the connection.
func (d *Driver) Close() error { return d.client.Close() }

// CanMountVolumes implements runtime volume support (ADR 0023).
func (d *Driver) CanMountVolumes() bool { return true }

func (d *Driver) ctx(ctx context.Context) context.Context {
	return namespaces.WithNamespace(ctx, embedded.Namespace)
}

// Ping verifies containerd answers and the bridge exists.
func (d *Driver) Ping(ctx context.Context) error {
	if _, err := d.client.Version(d.ctx(ctx)); err != nil {
		return fmt.Errorf("containerd at %s: %w", d.paths.Socket(), err)
	}
	return d.net.Ensure(ctx)
}

// Bridge reports the container network.
func (d *Driver) Bridge(ctx context.Context) (runtime.Bridge, error) {
	if err := d.net.Ensure(ctx); err != nil {
		return runtime.Bridge{}, err
	}
	return d.net.Bridge(), nil
}

// normalize returns the fully qualified reference containerd stores images
// under, and the familiar name used in digest-pinned references.
func normalize(image string) (ref, familiar string, digested bool, err error) {
	named, err := reference.ParseDockerRef(image)
	if err != nil {
		return "", "", false, fmt.Errorf("invalid image reference %q: %w", image, err)
	}
	_, digested = named.(reference.Digested)
	return named.String(), reference.FamiliarName(named), digested, nil
}

// Pull fetches an image and returns its digest-pinned reference. A
// digest-pinned image already on the node is used without contacting the
// registry.
func (d *Driver) Pull(ctx context.Context, image string, auth *runtime.RegistryAuth) (runtime.Image, error) {
	ctx = d.ctx(ctx)
	ref, familiar, digested, err := normalize(image)
	if err != nil {
		return runtime.Image{}, err
	}
	if digested {
		if img, err := d.client.GetImage(ctx, ref); err == nil {
			if err := unpack(ctx, img); err != nil {
				return runtime.Image{}, err
			}
			return runtime.Image{Ref: image, Platforms: d.localPlatforms(ctx, img)}, nil
		}
	}
	resolver := docker.NewResolver(docker.ResolverOptions{
		Hosts: config.ConfigureHosts(ctx, config.HostOptions{
			// Always TLS, also for registries on localhost.
			DefaultScheme: "https",
			Credentials:   credentials(auth),
		}),
	})
	img, err := d.client.Pull(ctx, ref, client.WithPullUnpack, client.WithResolver(resolver))
	if err != nil {
		// Tell an image built for other platforms from other failures.
		want := nodePlatform()
		if have, perr := remotePlatforms(ctx, resolver, ref); perr == nil && len(have) > 0 && !slices.Contains(have, want) {
			return runtime.Image{}, &runtime.PlatformError{Image: image, Want: want, Have: have}
		}
		return runtime.Image{}, pullError(image, auth != nil, err)
	}
	return runtime.Image{Ref: familiar + "@" + img.Target().Digest.String(), Platforms: d.localPlatforms(ctx, img)}, nil
}

func unpack(ctx context.Context, img client.Image) error {
	ok, err := img.IsUnpacked(ctx, "")
	if err != nil || ok {
		return err
	}
	return img.Unpack(ctx, "")
}

// credentials answers the resolver for the registry auth was given for.
func credentials(auth *runtime.RegistryAuth) func(string) (string, string, error) {
	if auth == nil {
		return nil
	}
	want := registryHost(auth.ServerAddress)
	return func(host string) (string, string, error) {
		if registryHost(host) == want {
			return auth.Username, auth.Password, nil
		}
		return "", "", nil
	}
}

// registryHost reduces a registry address to its host, with Docker Hub's
// aliases folded into the host the resolver uses.
func registryHost(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	s, _, _ = strings.Cut(s, "/")
	s = strings.ToLower(s)
	switch s {
	case "", "docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com":
		return "registry-1.docker.io"
	}
	return s
}

func (d *Driver) image(ctx context.Context, image string) (client.Image, error) {
	ref, _, _, err := normalize(image)
	if err != nil {
		return nil, err
	}
	img, err := d.client.GetImage(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("image %s: %w", image, err)
	}
	return img, unpack(ctx, img)
}

// newID returns a fresh container ID for name. IDs are unique per
// creation: a recreated replica must not look like the
// container it replaces (the agent ties probes to the ID).
func newID(name string) (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := name + "-" + hex.EncodeToString(b)
	if _, err := embedded.LogPath("/", id); err != nil {
		return "", fmt.Errorf("invalid container name %q", name)
	}
	return id, nil
}

func (d *Driver) runcOpts() *options.Options {
	return &options.Options{BinaryName: filepath.Join(d.paths.Bin(), embedded.BinRunc)}
}

// logIO makes the shim pipe the container's output to `armadad runtime-log`.
func (d *Driver) logIO() cio.Creator {
	return cio.BinaryIO(d.self, map[string]string{"runtime-log": d.paths.Logs()})
}

// Run creates and starts an app container with Armada's security defaults.
func (d *Driver) Run(ctx context.Context, s runtime.ContainerSpec) (_ string, err error) {
	if err := runtime.CheckContainerSpec(s); err != nil {
		return "", err
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
	images := map[string]client.Image{}
	for _, m := range slices.Concat(s.Init, s.Sidecars) {
		if images[m.Image] == nil {
			if images[m.Image], err = d.image(ctx, m.Image); err != nil {
				return "", fmt.Errorf("container %s: %w", m.Name, err)
			}
		}
	}
	tini, err := filepath.EvalSymlinks(filepath.Join(d.paths.Bin(), embedded.BinTini))
	if err != nil {
		return "", fmt.Errorf("tini: %w", err)
	}

	// Picking a host port and taking it must not interleave. Without a port,
	// containers start at once: the network plugins and containerd take care
	// of their own state.
	unlock := func() {}
	if s.Port != 0 {
		d.mu.Lock()
		var once sync.Once
		unlock = func() { once.Do(d.mu.Unlock) }
		defer unlock()
	}
	sl, err := d.newLabels(ctx)
	if err != nil {
		return "", err
	}
	var undo []func()
	defer func() {
		if err != nil {
			for i := len(undo) - 1; i >= 0; i-- {
				undo[i]()
			}
		}
	}()
	undo = append(undo, func() { releaseLabel(sl.process) })

	labels := maps.Clone(s.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels[labelKind] = "app"
	labels[labelName] = s.Name
	var pm *portMapping
	if s.Port != 0 {
		used, err := d.usedPorts(ctx)
		if err != nil {
			return "", err
		}
		hp, err := pickPort(s.HostIP, used, portFree)
		if err != nil {
			return "", err
		}
		pm = &portMapping{HostIP: s.HostIP, HostPort: hp, ContainerPort: s.Port}
		labels[labelHostIP] = s.HostIP
		labels[labelHostPort] = strconv.Itoa(hp)
		labels[labelPort] = strconv.Itoa(s.Port)
	}
	if err := d.net.Ensure(ctx); err != nil {
		return "", err
	}
	netns, ip, err := d.net.Setup(ctx, id, pm)
	if err != nil {
		return "", fmt.Errorf("container network: %w", err)
	}
	undo = append(undo, func() { _ = d.net.Teardown(context.WithoutCancel(ctx), id, netns, pm) })
	labels[labelNetNS] = netns
	labels[labelIP] = ip

	files, err := writeFiles(d.paths.Containers(), id, s.Name, ip, s.DNS, s.DNSSearch)
	if err != nil {
		return "", err
	}
	undo = append(undo, func() { _ = os.RemoveAll(filepath.Join(d.paths.Containers(), id)) })
	if err := relabel(filepath.Join(d.paths.Containers(), id), sl); err != nil {
		return "", fmt.Errorf("label container files: %w", err)
	}
	for _, f := range s.Files {
		if err := relabel(f.Source, sl); err != nil {
			return "", fmt.Errorf("label %s: %w", f.Target, err)
		}
	}
	// A volume gets this container's categories each time: only one
	// container uses it at a time, and a new one gets new categories.
	for _, v := range s.Volumes {
		if v.Shared {
			continue // mounted with a label every container may use (ADR 0042)
		}
		if err := relabel(v.Source, sl); err != nil {
			return "", fmt.Errorf("label volume %s: %w", v.Target, err)
		}
	}
	if err := relabelShared(tini, sl); err != nil {
		return "", fmt.Errorf("label tini: %w", err)
	}

	opts := argsOpts(img, s)
	opts = append(opts, appOpts(appSpec{
		spec: s, netns: netns, files: files, tini: tini,
		cgroup:   cgroupParent + "/" + id,
		seccomp:  seccompOpt(),
		apparmor: apparmorOpt(),
		selinux:  sl,
	})...)
	if len(s.Init) > 0 || len(s.Sidecars) > 0 {
		// Its init containers and sidecars share its network namespace,
		// host files, and SELinux label (ADR 0038).
		return d.runPod(ctx, id, img, labels, opts, podEnv{
			spec: s, netns: netns, files: files, tini: tini, selinux: sl, images: images,
		}, &undo, unlock)
	}
	labels[labelStarted] = time.Now().UTC().Format(time.RFC3339Nano)
	return d.create(ctx, id, img, labels, opts, d.runcOpts(), &undo)
}

// newLabels returns fresh SELinux labels for a container (empty where
// containers are not confined). The first call reserves the categories of
// the containers that already exist, which an agent adopts after a
// restart.
func (d *Driver) newLabels(ctx context.Context) (selinuxLabels, error) {
	if SELinux() != SELinuxConfined {
		return selinuxLabels{}, nil
	}
	d.labelsMu.Lock()
	defer d.labelsMu.Unlock()
	if !d.labelsReserved {
		cs, err := d.client.Containers(ctx)
		if err != nil {
			return selinuxLabels{}, fmt.Errorf("list containers: %w", err)
		}
		for _, c := range cs {
			if s, err := c.Spec(ctx); err == nil {
				reserveLabel(processLabel(s))
			}
		}
		d.labelsReserved = true
	}
	return newLabels()
}

// create makes the container and starts its task; undo collects cleanups.
func (d *Driver) create(ctx context.Context, id string, img client.Image, labels map[string]string, opts []oci.SpecOpts, rt *options.Options, undo *[]func()) (string, error) {
	c, err := d.client.NewContainer(ctx, id,
		client.WithImage(img),
		client.WithNewSnapshot(id, img),
		client.WithRuntime(plugins.RuntimeRuncV2, rt),
		client.WithContainerLabels(labels),
		client.WithNewSpec(opts...),
	)
	if err != nil {
		return "", fmt.Errorf("create container: %w", err)
	}
	*undo = append(*undo, func() {
		_ = c.Delete(context.WithoutCancel(ctx), client.WithSnapshotCleanup)
	})
	t, err := c.NewTask(ctx, d.logIO())
	if err != nil {
		return "", fmt.Errorf("create task: %w", err)
	}
	*undo = append(*undo, func() {
		_, _ = t.Delete(context.WithoutCancel(ctx), client.WithProcessKill)
	})
	if err := t.Start(ctx); err != nil {
		return "", fmt.Errorf("start container: %w", err)
	}
	return id, nil
}

func (d *Driver) usedPorts(ctx context.Context) (map[int]bool, error) {
	cs, err := d.client.Containers(ctx)
	if err != nil {
		return nil, err
	}
	used := map[int]bool{}
	for _, c := range cs {
		l, err := c.Labels(ctx)
		if err != nil {
			continue
		}
		if p, err := strconv.Atoi(l[labelHostPort]); err == nil {
			used[p] = true
		}
	}
	return used, nil
}

func notFound(err error) error {
	if errdefs.IsNotFound(err) {
		return runtime.ErrNotFound
	}
	return err
}

// Stop sends SIGTERM to the container's init and SIGKILL after grace. The
// stopped task is kept so its exit code stays visible until Remove.
// A replica's sidecars stop after its own container (ADR 0038), so a proxy
// or log shipper in front of it outlives it.
func (d *Driver) Stop(ctx context.Context, id string, grace time.Duration) error {
	ctx = d.ctx(ctx)
	c, err := d.client.LoadContainer(ctx, id)
	if err != nil {
		return notFound(err)
	}
	d.endStart(id)
	if err := d.stopContainer(ctx, c, grace); err != nil {
		return err
	}
	labels, err := c.Labels(ctx)
	if err != nil || labels[labelKind] != "app" {
		return nil //nolint:nilerr // gone meanwhile, or no sidecars to stop
	}
	return d.stopSidecars(ctx, id, grace)
}

// stopContainer stops one container's task, like Stop. A task that was
// created but never started is deleted: there is nothing to end.
func (d *Driver) stopContainer(ctx context.Context, c client.Container, grace time.Duration) error {
	t, err := c.Task(ctx, nil)
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	st, err := t.Status(ctx)
	if err != nil {
		return err
	}
	switch st.Status {
	case client.Stopped:
		return nil
	case client.Created:
		if _, err := t.Delete(ctx, client.WithProcessKill); err != nil && !errdefs.IsNotFound(err) {
			return err
		}
		return nil
	}
	exited, err := t.Wait(ctx)
	if err != nil {
		return err
	}
	if err := t.Kill(ctx, syscall.SIGTERM); err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	select {
	case <-exited:
		return nil
	case <-time.After(grace):
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := t.Kill(ctx, syscall.SIGKILL, client.WithKillAll); err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	select {
	case <-exited:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Remove kills and deletes a container with its network, files, and logs,
// and a replica's container with its init containers and sidecars first:
// they live in its network namespace.
func (d *Driver) Remove(ctx context.Context, id string) error {
	ctx = d.ctx(ctx)
	c, err := d.client.LoadContainer(ctx, id)
	if err != nil {
		return notFound(err)
	}
	d.endStart(id)
	if l, err := c.Labels(ctx); err == nil && l[labelKind] == "app" {
		if err := d.removeMembers(ctx, id); err != nil {
			return fmt.Errorf("init containers and sidecars: %w", err)
		}
	}
	return d.removeContainer(ctx, c)
}

// removeContainer removes one container, like Remove.
func (d *Driver) removeContainer(ctx context.Context, c client.Container) error {
	id := c.ID()
	labels, err := c.Labels(ctx)
	if err != nil {
		return notFound(err)
	}
	if t, err := c.Task(ctx, nil); err == nil {
		// A stopped task is deleted without a kill.
		var opts []client.ProcessDeleteOpts
		if st, err := t.Status(ctx); err != nil || st.Status != client.Stopped {
			opts = append(opts, client.WithProcessKill)
		}
		_, err := t.Delete(ctx, opts...)
		if err != nil && len(opts) > 0 {
			// It may have stopped in between.
			if st, serr := t.Status(ctx); serr == nil && st.Status == client.Stopped {
				_, err = t.Delete(ctx)
			}
		}
		if err != nil && !errdefs.IsNotFound(err) {
			return fmt.Errorf("delete task: %w", err)
		}
	} else if !errdefs.IsNotFound(err) {
		return err
	}
	if labels[labelKind] == "app" {
		if err := d.net.Teardown(ctx, id, labels[labelNetNS], mappingFromLabels(labels)); err != nil {
			return fmt.Errorf("container network: %w", err)
		}
	}
	spec, _ := c.Spec(ctx)
	if err := c.Delete(ctx, client.WithSnapshotCleanup); err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	// An init container or sidecar has its replica's label, which the
	// replica's container gives back.
	if labels[labelKind] != kindMember {
		releaseLabel(processLabel(spec))
	}
	return errors.Join(
		os.RemoveAll(filepath.Join(d.paths.Containers(), id)),
		embedded.RemoveLogs(d.paths.Logs(), id),
	)
}

// ReleaseNetwork frees the address of a stopped container kept for its logs.
// Its network namespace is the mark: once that is gone nothing is left to free,
// and Remove releasing again is harmless.
func (d *Driver) ReleaseNetwork(ctx context.Context, id string) error {
	ctx = d.ctx(ctx)
	c, err := d.client.LoadContainer(ctx, id)
	if err != nil {
		return notFound(err)
	}
	labels, err := c.Labels(ctx)
	if err != nil {
		return err
	}
	if labels[labelKind] != "app" {
		return nil
	}
	if _, err := os.Stat(labels[labelNetNS]); err != nil {
		return nil //nolint:nilerr // already released, or gone with a reboot
	}
	return d.net.Teardown(ctx, id, labels[labelNetNS], mappingFromLabels(labels))
}

func mappingFromLabels(l map[string]string) *portMapping {
	hp, err1 := strconv.Atoi(l[labelHostPort])
	cp, err2 := strconv.Atoi(l[labelPort])
	if err1 != nil || err2 != nil {
		return nil
	}
	return &portMapping{HostIP: l[labelHostIP], HostPort: hp, ContainerPort: cp}
}

// List returns containers carrying all given labels.
func (d *Driver) List(ctx context.Context, labels map[string]string) ([]runtime.Container, error) {
	ctx = d.ctx(ctx)
	cs, err := d.client.Containers(ctx)
	if err != nil {
		return nil, err
	}
	// One request for the state of every task, rather than two for each. A
	// task the answer leaves out, as containerd does when it cannot reach its
	// shim, is asked for by itself: only that can say it is gone.
	known := map[string]*task.Process{}
	if resp, err := d.client.TaskService().List(ctx, &tasks.ListTasksRequest{}); err == nil {
		for _, t := range resp.GetTasks() {
			known[t.GetID()] = t
		}
	}
	var out []runtime.Container
	// Init containers and sidecars are listed with their replica's
	// container (ADR 0038), or by themselves if it is gone.
	members := map[string][]runtime.Container{}
	ids := map[string]bool{}
	for _, c := range cs {
		ids[c.ID()] = true
	}
	for _, c := range cs {
		rc, pod, err := d.describeWith(ctx, c, known[c.ID()])
		if errdefs.IsNotFound(err) {
			continue // removed meanwhile
		}
		if err != nil {
			return nil, err
		}
		if pod != "" && ids[pod] {
			members[pod] = append(members[pod], rc)
			continue
		}
		if matches(rc.Labels, labels) {
			out = append(out, rc)
		}
	}
	for i := range out {
		for _, m := range members[out[i].ID] {
			out[i].Members = append(out[i].Members, memberOf(m))
		}
		sortMembers(out[i].Members)
	}
	return out, nil
}

func matches(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// Inspect returns one container's state.
func (d *Driver) Inspect(ctx context.Context, id string) (runtime.Container, error) {
	ctx = d.ctx(ctx)
	c, err := d.client.LoadContainer(ctx, id)
	if err != nil {
		return runtime.Container{}, notFound(err)
	}
	rc, pod, err := d.describeWith(ctx, c, nil)
	if err != nil {
		return runtime.Container{}, notFound(err)
	}
	if pod == "" {
		if err := d.describeMembers(ctx, &rc); err != nil {
			return runtime.Container{}, notFound(err)
		}
	}
	return rc, nil
}

// describeWith describes c, using its task's state if it is known already,
// and returns the replica's container it belongs to if it is an init
// container or a sidecar.
func (d *Driver) describeWith(ctx context.Context, c client.Container, known *task.Process) (_ runtime.Container, pod string, _ error) {
	rc, pod, err := d.describeTask(ctx, c, known)
	if err == nil && pod == "" && d.starting(rc.ID) {
		rc.State = runtime.StateStarting
	}
	return rc, pod, err
}

func (d *Driver) describeTask(ctx context.Context, c client.Container, known *task.Process) (runtime.Container, string, error) {
	info, err := c.Info(ctx, client.WithoutRefreshedMetadata)
	if err != nil {
		return runtime.Container{}, "", err
	}
	pod := ""
	if info.Labels[labelKind] == kindMember {
		pod = info.Labels[labelPod]
	}
	rc := runtime.Container{ID: c.ID(), Name: info.Labels[labelName], Image: info.Image, Labels: map[string]string{}, StartError: info.Labels[labelFailed]}
	if rc.Name == "" {
		rc.Name = c.ID()
	}
	for k, v := range info.Labels {
		if !strings.HasPrefix(k, labelPrefix) {
			rc.Labels[k] = v
		}
	}
	rc.IP = info.Labels[labelIP]
	if p, err := strconv.Atoi(info.Labels[labelHostPort]); err == nil {
		if _, err := netutil.CheckPrivateIP(info.Labels[labelHostIP]); err == nil {
			rc.HostIP, rc.HostPort = info.Labels[labelHostIP], p
		}
	}
	rc.StartedAt, _ = time.Parse(time.RFC3339Nano, info.Labels[labelStarted])

	if known != nil {
		switch known.GetStatus() {
		case task.Status_RUNNING:
			rc.State = runtime.StateRunning
		case task.Status_CREATED:
			rc.State = runtime.StateCreated
		case task.Status_PAUSED, task.Status_PAUSING:
			rc.State = runtime.StatePaused
		case task.Status_STOPPED:
			rc.State, rc.ExitCode = runtime.StateExited, int(known.GetExitStatus())
		default:
			rc.State = runtime.StateDead
		}
		return rc, pod, nil
	}
	t, err := c.Task(ctx, nil)
	if errdefs.IsNotFound(err) {
		// No task: the node rebooted or containerd lost the shim. The
		// agent recreates the container.
		rc.State, rc.ExitCode = runtime.StateExited, 255
		return rc, pod, nil
	}
	if err != nil {
		return runtime.Container{}, "", err
	}
	st, err := t.Status(ctx)
	if err != nil {
		return runtime.Container{}, "", err
	}
	switch st.Status {
	case client.Running:
		rc.State = runtime.StateRunning
	case client.Created:
		rc.State = runtime.StateCreated
	case client.Paused, client.Pausing:
		rc.State = runtime.StatePaused
	case client.Stopped:
		rc.State, rc.ExitCode = runtime.StateExited, int(st.ExitStatus)
	default:
		rc.State = runtime.StateDead
	}
	return rc, pod, nil
}

// Logs returns the container's stored output.
func (d *Driver) Logs(ctx context.Context, id string, opts runtime.LogOptions) (runtime.LogStream, error) {
	return embedded.ReadLogs(ctx, d.paths.Logs(), id, opts)
}

// PruneImages removes images no container of this namespace uses (Armada's
// own containers included), that keep does not name, and that were neither
// pulled nor updated within grace. Images that share a digest with a kept or
// used image stay too: a tag and its digest name the same content.
func (d *Driver) PruneImages(ctx context.Context, keep []string, grace time.Duration) ([]string, error) {
	ctx = d.ctx(ctx)
	names := map[string]bool{}
	digests := map[string]bool{}
	for _, k := range keep {
		named, err := reference.ParseDockerRef(k)
		if err != nil {
			continue
		}
		names[named.String()] = true
		if dg, ok := named.(reference.Digested); ok {
			digests[dg.Digest().String()] = true
		}
	}
	cs, err := d.client.Containers(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		info, err := c.Info(ctx, client.WithoutRefreshedMetadata)
		if errdefs.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		names[info.Image] = true
	}
	is := d.client.ImageService()
	imgs, err := is.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, img := range imgs {
		if names[img.Name] {
			digests[img.Target.Digest.String()] = true
		}
	}
	cutoff := time.Now().Add(-grace)
	var unused []string
	for _, img := range imgs {
		if !names[img.Name] && !digests[img.Target.Digest.String()] && !img.CreatedAt.After(cutoff) && !img.UpdatedAt.After(cutoff) {
			unused = append(unused, img.Name)
		}
	}
	var removed []string
	for i, name := range unused {
		var opts []images.DeleteOpt
		if i == len(unused)-1 {
			// Content and snapshots go with containerd's garbage
			// collection; the last removal waits for it to free them.
			opts = append(opts, images.SynchronousDelete())
		}
		if err := is.Delete(ctx, name, opts...); err != nil && !errdefs.IsNotFound(err) {
			return removed, fmt.Errorf("remove image %s: %w", name, err)
		}
		removed = append(removed, name)
	}
	return removed, nil
}

// pullError says what a failed pull most likely means before the registry's
// own words: an image that does not exist and one the registry will not
// show without credentials look the same from outside.
func pullError(image string, withAuth bool, err error) error {
	msg := err.Error()
	denied := strings.Contains(msg, "403 Forbidden") || strings.Contains(msg, "401 Unauthorized") ||
		strings.Contains(msg, "insufficient_scope") || strings.Contains(msg, "pull access denied") ||
		strings.Contains(msg, "authorization failed")
	switch {
	case errdefs.IsNotFound(err) || strings.Contains(msg, "not found"):
		return fmt.Errorf("pull %s: no such image or tag in the registry: %w", image, err)
	case denied && withAuth:
		return fmt.Errorf("pull %s: the registry refused the app's credentials, or the image does not exist: %w", image, err)
	case denied:
		return fmt.Errorf("pull %s: the image does not exist, or it is private and the app has no registry credentials (spec registry, --registry-user/--registry-secret): %w", image, err)
	}
	return fmt.Errorf("pull %s: %w", image, err)
}
