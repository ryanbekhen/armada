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
	Images  *Images
	Bundles Bundles
	Shims   *Shims
	// Logs is the directory armada-log writes container output to.
	Logs string

	mu sync.Mutex // serializes record changes
}

// Close releases the image store.
func (s *Store) Close() error { return s.Images.Close() }

// Ping checks the store is usable.
func (s *Store) Ping(context.Context) error {
	if _, err := os.Stat(s.Shims.Bin); err != nil {
		return fmt.Errorf("armada-shim: %w", err)
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
		_ = s.Bundles.Remove(id)
		_ = s.Images.Release(context.WithoutCancel(ctx), id)
		return nil, err
	}
	return &container{s: s, rec: rec}, nil
}

// LoadContainer returns a recorded container.
func (s *Store) LoadContainer(_ context.Context, id string) (client.Container, error) {
	recs, err := s.Bundles.Records()
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
func (s *Store) Containers(_ context.Context, filters ...string) ([]client.Container, error) {
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
	recs, err := s.Bundles.Records()
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
	recs, err := s.Bundles.Records()
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
	rec, ok := s.Images.Get(name)
	if !ok {
		return nil, fmt.Errorf("image %s: %w", name, errdefs.ErrNotFound)
	}
	return &image{s: s, rec: rec}, nil
}

// Pull pulls and unpacks ref; wrap, when set, wraps the handler that
// fetches each descriptor.
func (s *Store) Pull(ctx context.Context, ref string, resolver remotes.Resolver, wrap func(images.Handler) images.Handler) (client.Image, error) {
	rec, err := s.Images.Pull(ctx, ref, resolver, wrap)
	if err != nil {
		return nil, err
	}
	return &image{s: s, rec: rec}, nil
}

// SetImageLabel sets one label of a pulled image.
func (s *Store) SetImageLabel(_ context.Context, name, key, value string) error {
	return s.Images.SetLabel(name, key, value)
}

// CheckLayers reports nil: Images.Pull records an image only once its
// layers were checked.
func (s *Store) CheckLayers(context.Context, client.Image) error { return nil }

// ContentStore holds the images' blobs.
func (s *Store) ContentStore() content.Store { return s.Images.content }

// ListImages lists pulled images.
func (s *Store) ListImages(context.Context) ([]images.Image, error) {
	var out []images.Image
	for _, r := range s.Images.List() {
		out = append(out, r.metadata())
	}
	return out, nil
}

// DeleteImage forgets an image and removes what no other image or
// container uses, always at once.
func (s *Store) DeleteImage(ctx context.Context, name string, _ bool) error {
	return s.Images.Delete(ctx, name)
}
