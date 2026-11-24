package supervisor

import (
	"context"
	"fmt"
	"maps"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
)

// GroupAnnotation names the shim a container shares; the driver sets it
// in the spec. A container without it gets a shim of its own.
const GroupAnnotation = "io.containerd.runc.v2.group"

// snapshotterName is what container records name as their snapshotter.
const snapshotterName = "overlayfs"

// Store is the agent's own container runtime (ADR 0046): images, bundles,
// and armada-shim processes. It offers containers, tasks, and images
// through containerd's client interfaces, so the driver's logic is the
// same on either runtime.
type Store struct {
	// Images is Go's image store. With Native it may be nil, and is used
	// only to release the root filesystems of containers Go made; once
	// Moved records it converted, it goes with the last of them
	// (CollectGo).
	Images  *Images
	Bundles Bundles
	Shims   *Shims
	// Logs is the directory armada-log writes container output to.
	Logs string
	// Native, when set, hands images, root filesystems, bundles, and shim
	// requests to armada-node (ADR 0054); Shims.Native is the same.
	Native *Native
	// NodeImages is armada-node's image store, whose root filesystems of
	// containers armada-node made Go removes with them (a node that went
	// back to Go's code).
	NodeImages string
	// Moved, with Native, is the record (MovedFile) that Go's image store
	// was converted into armada-node's; MoveErr is why the conversion at
	// the agent's start failed, if it did.
	Moved   string
	MoveErr error
	// CgroupRoot is where cgroup v2 is mounted; empty is /sys/fs/cgroup
	// (tests name a fixture).
	CgroupRoot string

	mu sync.Mutex // serializes record changes
	// goMu guards Images while armada-node runs the store, which
	// CollectGo closes and clears.
	goMu sync.Mutex
}

// cgroupRoot is where the containers' cgroups are read.
func (s *Store) cgroupRoot() string {
	if s.CgroupRoot != "" {
		return s.CgroupRoot
	}
	return cgroupRoot
}

// Close releases the image store.
func (s *Store) Close() error {
	s.goMu.Lock()
	defer s.goMu.Unlock()
	if s.Images == nil {
		return nil
	}
	return s.Images.Close()
}

// Ping checks the store is usable.
func (s *Store) Ping(context.Context) error {
	if _, err := os.Stat(s.Shims.Bin); err != nil {
		return fmt.Errorf("armada-shim: %w", err)
	}
	if s.Native != nil {
		if _, err := os.Stat(s.Native.Bin); err != nil {
			return fmt.Errorf("armada-node: %w", err)
		}
	}
	return nil
}

// NewContainer records a container from img with labels and the spec opts
// make, and prepares its root filesystem. Its task is created by NewTask.
func (s *Store) NewContainer(ctx context.Context, id string, img client.Image, labels map[string]string, opts []oci.SpecOpts) (client.Container, error) {
	im, ok := img.(*image)
	if !ok {
		return nil, fmt.Errorf("image %s is not from this store", img.Name())
	}
	if _, err := os.Stat(s.Bundles.Path(id)); err == nil {
		return nil, fmt.Errorf("container %s: %w", id, errdefs.ErrAlreadyExists)
	}
	cc := &containers.Container{ID: id, Image: im.rec.Name, Labels: maps.Clone(labels), SnapshotKey: id, Snapshotter: snapshotterName}
	if s.Native != nil {
		return s.newNativeContainer(ctx, cc, opts)
	}
	// The root filesystem first, as on containerd: spec opts read the
	// image's users and groups from it. Opts that read the image's
	// configuration get it from the caller, which passes this store's image.
	rootfs, err := s.Images.Prepare(ctx, id, im.rec)
	if err != nil {
		return nil, fmt.Errorf("root filesystem: %w", err)
	}
	_, oclient := s.Images.OCI(im.rec)
	spec, err := oci.GenerateSpec(ctx, oclient, cc, opts...)
	if err != nil {
		_ = s.Images.Release(context.WithoutCancel(ctx), id)
		return nil, err
	}
	group := spec.Annotations[GroupAnnotation]
	if group == "" {
		group = id
	}
	rec := Record{ID: id, Image: im.rec.Name, Labels: cc.Labels, Group: group, Created: time.Now().UTC()}
	if _, err := s.Bundles.Create(rec, spec, rootfs); err != nil {
		// The root filesystem goes only once its bundle is unmounted.
		if s.Bundles.Remove(id) == nil {
			_ = s.Images.Release(context.WithoutCancel(ctx), id)
		}
		return nil, err
	}
	return &container{s: s, rec: rec}, nil
}

// newNativeContainer is NewContainer on armada-node: the root filesystem
// it prepares, the spec built here from opts, and the bundle it writes.
func (s *Store) newNativeContainer(ctx context.Context, cc *containers.Container, opts []oci.SpecOpts) (client.Container, error) {
	id := cc.ID
	rootfs, err := s.Native.Prepare(ctx, id, cc.Image)
	if err != nil {
		return nil, fmt.Errorf("root filesystem: %w", err)
	}
	spec, err := oci.GenerateSpec(ctx, mountsClient{rootfs}, cc, opts...)
	if err != nil {
		_ = s.Native.Release(context.WithoutCancel(ctx), id)
		return nil, err
	}
	rec, err := s.Native.CreateBundle(ctx, s.Bundles.Dir, id, cc.Image, cc.Labels, spec, rootfs)
	if s.Native.fallback("bundle create", err) {
		group := spec.Annotations[GroupAnnotation]
		if group == "" {
			group = id
		}
		rec = Record{ID: id, Image: cc.Image, Labels: cc.Labels, Group: group, Created: time.Now().UTC()}
		_, err = s.Bundles.Create(rec, spec, rootfs)
	}
	if err != nil {
		// The root filesystem goes only once its bundle is unmounted.
		if s.removeBundle(context.WithoutCancel(ctx), id) == nil {
			_ = s.Native.Release(context.WithoutCancel(ctx), id)
		}
		return nil, err
	}
	return &container{s: s, rec: rec}, nil
}

// records lists the finished bundles' records.
func (s *Store) records(ctx context.Context) ([]Record, error) {
	if s.Native != nil {
		recs, err := s.Native.Records(ctx, s.Bundles.Dir)
		if !s.Native.fallback("bundle records", err) {
			return recs, err
		}
	}
	return s.Bundles.Records()
}

// removeBundle unmounts and removes container id's bundle.
func (s *Store) removeBundle(ctx context.Context, id string) error {
	if s.Native != nil {
		err := s.Native.RemoveBundle(ctx, s.Bundles.Dir, id)
		if !s.Native.fallback("bundle remove", err) {
			return err
		}
	}
	return s.Bundles.Remove(id)
}

// release removes container id's root filesystem, from whichever store
// made it.
func (s *Store) release(ctx context.Context, id string) error {
	if s.Native != nil {
		if err := s.Native.Release(ctx, id); err != nil {
			return err
		}
	} else if s.NodeImages != "" {
		if err := removeNodeSnapshot(s.NodeImages, id); err != nil {
			return err
		}
	}
	s.goMu.Lock()
	defer s.goMu.Unlock()
	if s.Images == nil {
		return nil
	}
	if err := s.Images.Release(ctx, id); err != nil {
		return err
	}
	// The last container on Go's converted store takes it along.
	s.collectGoLocked(ctx)
	return nil
}

// contentStore holds the images' blobs.
func (s *Store) contentStore() content.Store {
	if s.Native != nil {
		return s.Native.content
	}
	return s.Images.content
}

// platform is what images are pulled for: this node's platform.
func (s *Store) platform() platforms.MatchComparer {
	if s.Native != nil {
		return platforms.Default()
	}
	return s.Images.platform
}

// LoadContainer returns a recorded container.
func (s *Store) LoadContainer(ctx context.Context, id string) (client.Container, error) {
	recs, err := s.records(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		if r.ID == id {
			return &container{s: s, rec: r}, nil
		}
	}
	return nil, fmt.Errorf("container %s: %w", id, errdefs.ErrNotFound)
}

// filterRE is the one filter the driver uses: labels."KEY"=="VALUE".
var filterRE = regexp.MustCompile(`^labels\.("(?:[^"\\]|\\.)*")==("(?:[^"\\]|\\.)*")$`)

// Containers returns recorded containers matching every filter.
func (s *Store) Containers(ctx context.Context, filters ...string) ([]client.Container, error) {
	want := map[string]string{}
	for _, f := range filters {
		m := filterRE.FindStringSubmatch(f)
		if m == nil {
			return nil, fmt.Errorf("unsupported filter %q: %w", f, errdefs.ErrNotImplemented)
		}
		k, err1 := strconv.Unquote(m[1])
		v, err2 := strconv.Unquote(m[2])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("filter %q: %w", f, errdefs.ErrInvalidArgument)
		}
		want[k] = v
	}
	recs, err := s.records(ctx)
	if err != nil {
		return nil, err
	}
	var out []client.Container
	for _, r := range recs {
		ok := true
		for k, v := range want {
			if r.Labels[k] != v {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, &container{s: s, rec: r})
		}
	}
	return out, nil
}

// Tasks returns the state of every container's task by container ID, asking
// each shim once. Containers of a shim that does not answer are left out.
func (s *Store) Tasks(ctx context.Context) (map[string]*task.Process, error) {
	recs, err := s.records(ctx)
	if err != nil {
		return nil, err
	}
	groups := map[string]bool{}
	for _, r := range recs {
		groups[r.Group] = true
	}
	out := map[string]*task.Process{}
	for g := range groups {
		states, err := s.Shims.Get(g).List(ctx)
		if err != nil {
			continue
		}
		for id, st := range states {
			out[id] = processInfo(id, st)
		}
	}
	return out, nil
}

func processInfo(id string, st TaskState) *task.Process {
	p := &task.Process{ID: id, Pid: uint32(max(st.Pid, 0))} //nolint:gosec // a process ID
	switch st.Status {
	case "running":
		p.Status = task.Status_RUNNING
	case "created":
		p.Status = task.Status_CREATED
	default:
		p.Status, p.ExitStatus = task.Status_STOPPED, uint32(max(st.Exit, 0)) //nolint:gosec // an exit code
	}
	return p
}

// GetImage returns a pulled image by name.
func (s *Store) GetImage(_ context.Context, name string) (client.Image, error) {
	if s.Native != nil {
		rec, err := s.Native.image(name)
		if err != nil {
			return nil, err
		}
		return &image{s: s, rec: rec}, nil
	}
	rec, ok := s.Images.Get(name)
	if !ok {
		return nil, fmt.Errorf("image %s: %w", name, errdefs.ErrNotFound)
	}
	return &image{s: s, rec: rec}, nil
}

// Pull pulls and unpacks ref; wrap, when set, wraps the handler that
// fetches each descriptor.
func (s *Store) Pull(ctx context.Context, ref string, resolver remotes.Resolver, wrap func(images.Handler) images.Handler) (client.Image, error) {
	if s.Native != nil {
		return nil, errNativeImages
	}
	rec, err := s.Images.Pull(ctx, ref, resolver, wrap)
	if err != nil {
		return nil, err
	}
	return &image{s: s, rec: rec}, nil
}

// SetImageLabel sets one label of a pulled image.
func (s *Store) SetImageLabel(_ context.Context, name, key, value string) error {
	if s.Native != nil {
		return errNativeImages
	}
	return s.Images.SetLabel(name, key, value)
}

// CheckLayers reports nil: Images.Pull records an image only once its
// layers were checked.
func (s *Store) CheckLayers(context.Context, client.Image) error { return nil }

// ContentStore holds the images' blobs.
func (s *Store) ContentStore() content.Store { return s.contentStore() }

// ListImages lists pulled images.
func (s *Store) ListImages(context.Context) ([]images.Image, error) {
	if s.Native != nil {
		return s.Native.list()
	}
	var out []images.Image
	for _, r := range s.Images.List() {
		out = append(out, r.metadata())
	}
	return out, nil
}

// DeleteImage forgets an image and removes what no other image or
// container uses, always at once.
func (s *Store) DeleteImage(ctx context.Context, name string, _ bool) error {
	if s.Native != nil {
		return errNativeImages
	}
	return s.Images.Delete(ctx, name)
}

// errNativeImages: with Native, images are pulled and removed by
// armada-node (the driver's Pull and PruneImages call it).
var errNativeImages = fmt.Errorf("armada-node's image store changes only through armada-node runtime pull and prune: %w", errdefs.ErrNotImplemented)
