package containerd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types/runc/options"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/containerd/v2/plugins"

	"github.com/ryanbekhen/armada/internal/runtime/embedded"
	"github.com/ryanbekhen/armada/internal/runtime/imagecheck"
	"github.com/ryanbekhen/armada/internal/runtime/supervisor"
)

// backend is where the driver's containers, tasks, and images live:
// Armada's embedded containerd (ADR 0011), or the agent's own store with
// armada-shim (supervisor.Store, ADR 0046). Both hand out containerd's
// client types, so everything else in the driver is the same on either.
type backend interface {
	Close() error
	Ping(ctx context.Context) error
	LoadContainer(ctx context.Context, id string) (client.Container, error)
	// Containers filters like containerd: only labels."KEY"=="VALUE".
	Containers(ctx context.Context, filters ...string) ([]client.Container, error)
	// NewContainer records a container from img with labels and the spec
	// opts make, with its root filesystem; NewTask creates its process.
	NewContainer(ctx context.Context, id string, img client.Image, labels map[string]string, opts []oci.SpecOpts) (client.Container, error)
	// Tasks returns every task's state in one request, by container ID.
	Tasks(ctx context.Context) (map[string]*task.Process, error)

	GetImage(ctx context.Context, name string) (client.Image, error)
	// Pull fetches and unpacks ref for this node's platform; wrap, when
	// set, wraps the handler that fetches each descriptor. It fetches
	// every layer blob, also of layers already unpacked, and returns an
	// image only once each blob was shown to match its diff ID
	// (imagecheck), since unpacked layers are found by diff IDs alone.
	Pull(ctx context.Context, ref string, resolver remotes.Resolver, wrap func(images.Handler) images.Handler) (client.Image, error)
	// CheckLayers reports whether a pulled image's layer blobs are known
	// to match its diff IDs.
	CheckLayers(ctx context.Context, img client.Image) error
	SetImageLabel(ctx context.Context, name, key, value string) error
	ListImages(ctx context.Context) ([]images.Image, error)
	// DeleteImage removes an image; what only it used goes with it, at
	// once when wait is set.
	DeleteImage(ctx context.Context, name string, wait bool) error
	ContentStore() content.Store
}

// containerdBackend is the embedded containerd.
type containerdBackend struct {
	c    *client.Client
	runc string
}

func newContainerdBackend(paths embedded.Paths, c *client.Client) *containerdBackend {
	return &containerdBackend{c: c, runc: filepath.Join(paths.Bin(), embedded.BinRunc)}
}

func (b *containerdBackend) Close() error { return b.c.Close() }

func (b *containerdBackend) Ping(ctx context.Context) error {
	_, err := b.c.Version(ctx)
	return err
}

func (b *containerdBackend) LoadContainer(ctx context.Context, id string) (client.Container, error) {
	return b.c.LoadContainer(ctx, id)
}

func (b *containerdBackend) Containers(ctx context.Context, filters ...string) ([]client.Container, error) {
	return b.c.Containers(ctx, filters...)
}

func (b *containerdBackend) NewContainer(ctx context.Context, id string, img client.Image, labels map[string]string, opts []oci.SpecOpts) (client.Container, error) {
	return b.c.NewContainer(ctx, id,
		client.WithImage(img),
		client.WithNewSnapshot(id, img),
		client.WithRuntime(plugins.RuntimeRuncV2, &options.Options{BinaryName: b.runc}),
		client.WithContainerLabels(labels),
		client.WithNewSpec(opts...),
	)
}

func (b *containerdBackend) Tasks(ctx context.Context) (map[string]*task.Process, error) {
	resp, err := b.c.TaskService().List(ctx, &tasks.ListTasksRequest{})
	if err != nil {
		return nil, err
	}
	out := map[string]*task.Process{}
	for _, t := range resp.GetTasks() {
		out[t.GetID()] = t
	}
	return out, nil
}

func (b *containerdBackend) GetImage(ctx context.Context, name string) (client.Image, error) {
	return b.c.GetImage(ctx, name)
}

func (b *containerdBackend) Pull(ctx context.Context, ref string, resolver remotes.Resolver, wrap func(images.Handler) images.Handler) (client.Image, error) {
	opts := []client.RemoteOpt{
		client.WithPullUnpack, client.WithResolver(resolver),
		client.WithUnpackOpts([]client.UnpackOpt{client.WithUnpackFetchAllContent()}),
	}
	if wrap != nil {
		opts = append(opts, client.WithImageHandlerWrapper(wrap))
	}
	img, err := b.c.Pull(ctx, ref, opts...)
	if err != nil {
		return nil, err
	}
	if err := b.CheckLayers(ctx, img); err != nil {
		// Nothing may use what the unpacker found under these diff IDs.
		if derr := b.DeleteImage(ctx, img.Name(), false); derr != nil {
			return nil, errors.Join(err, fmt.Errorf("remove the image: %w", derr))
		}
		return nil, err
	}
	return img, nil
}

// CheckLayers checks img's layer blobs against its diff IDs; the
// unpacker labels each blob it extracted, so only layers it found
// already unpacked are read.
func (b *containerdBackend) CheckLayers(ctx context.Context, img client.Image) error {
	cs := b.c.ContentStore()
	manifest, err := images.Manifest(ctx, cs, img.Target(), img.Platform())
	if err != nil {
		return err
	}
	diffIDs, err := images.RootFS(ctx, cs, manifest.Config)
	if err != nil {
		return err
	}
	return imagecheck.Layers(ctx, cs, manifest.Layers, diffIDs)
}

func (b *containerdBackend) SetImageLabel(ctx context.Context, name, key, value string) error {
	_, err := b.c.ImageService().Update(ctx, images.Image{Name: name, Labels: map[string]string{key: value}}, "labels."+key)
	return err
}

func (b *containerdBackend) ListImages(ctx context.Context) ([]images.Image, error) {
	return b.c.ImageService().List(ctx)
}

// DeleteImage leaves content and snapshots to containerd's garbage
// collection, and with wait returns once it freed them.
func (b *containerdBackend) DeleteImage(ctx context.Context, name string, wait bool) error {
	var opts []images.DeleteOpt
	if wait {
		opts = append(opts, images.SynchronousDelete())
	}
	return b.c.ImageService().Delete(ctx, name, opts...)
}

func (b *containerdBackend) ContentStore() content.Store { return b.c.ContentStore() }

// NodeDir is armada-node's directory under the data directory: its image
// store (images) and supervisor.MovedFile.
const NodeDir = "node"

// newSupervisorBackend opens the agent's own store (ADR 0046): images and
// container bundles under <data dir>/supervisor, shims under <run
// dir>/shim, all programs from the runtime pack. With cfg.NodeBin, images
// live in armada-node's store (<data dir>/node/images) and armada-node
// does the store's work (ADR 0054); Go's image store is opened only when
// it exists, to release the root filesystems of containers Go made. When
// cfg.NodeBin names no program, the node stays on Go's code.
//
// For the agent (cfg.Agent) it also moves the images between the stores
// before opening them (ADR 0054, "The runtime's move"): with armada-node,
// Go's store is converted into armada-node's once, and removed as soon as
// no container uses it; with Go's code on a node armada-node ran, the
// layers the conversion moved go back to Go's store.
func newSupervisorBackend(cfg Config, logger string) (*supervisor.Store, error) {
	root := filepath.Join(cfg.Paths.DataDir, "supervisor")
	goImages := filepath.Join(root, "images")
	moved := filepath.Join(cfg.Paths.DataDir, NodeDir, supervisor.MovedFile)
	shim := cfg.ShimBin
	if shim == "" {
		shim = filepath.Join(cfg.Paths.Bin(), embedded.BinArmadaShim)
	}
	st := &supervisor.Store{
		Bundles: supervisor.Bundles{Dir: filepath.Join(root, "containers")},
		Shims: &supervisor.Shims{
			Dir: filepath.Join(cfg.Paths.RunDir, "shim"), Bin: shim,
			Runc: filepath.Join(cfg.Paths.Bin(), embedded.BinRunc), Logger: logger,
		},
		Logs:       cfg.Paths.Logs(),
		NodeImages: filepath.Join(cfg.Paths.DataDir, NodeDir, "images"),
	}
	if cfg.NodeBin != "" {
		n, err := openNative(cfg.NodeBin, st.NodeImages)
		if err == nil {
			st.Native, st.Shims.Native, st.Moved = n, n, moved
			if cfg.Agent {
				st.MoveErr = moveImages(goImages, st.NodeImages, st.Bundles.Dir, moved)
			}
			if _, err := os.Stat(goImages); err == nil {
				if st.Images, err = supervisor.OpenImages(goImages); err != nil {
					slog.Warn("Go's image store: containers Go made keep their root filesystems until it opens", "err", err)
				} else if cfg.Agent {
					st.CollectGo(context.Background())
				}
			}
			return st, nil
		}
		slog.Warn("armada-node cannot run containers; Go runs them", "err", err)
	}
	if cfg.Agent {
		if _, err := os.Stat(st.NodeImages); err == nil {
			switch back, err := supervisor.RevertImages(context.Background(), goImages, st.NodeImages, moved); {
			case err != nil:
				slog.Warn("Go's image store could not take its layers back from armada-node's; Go pulls the images it misses again", "err", err)
			case back > 0:
				slog.Info("Go's image store took its layers back from armada-node's", "layers", back)
			}
		}
	}
	imgs, err := supervisor.OpenImages(goImages)
	if err != nil {
		return nil, err
	}
	st.Images = imgs
	return st, nil
}

// moveImages converts Go's image store into armada-node's at the agent's
// start, once, and logs what it did. Images it leaves out are pulled
// again when a replica needs them.
func moveImages(goImages, nodeImages, bundles, moved string) error {
	before, had, _ := supervisor.ReadMoveState(moved)
	st, sum, err := supervisor.MoveImages(context.Background(), goImages, nodeImages, bundles, moved)
	if err != nil {
		slog.Warn("Go's image store could not be converted into armada-node's; armada-node pulls the images it needs, and the next start tries again", "err", err)
		return err
	}
	if sum != nil {
		slog.Info("converted Go's image store into armada-node's", "converted", len(sum.Converted), "kept", len(sum.Kept), "skipped", len(st.Skipped),
			"layers", st.Layers, "containers", st.Containers, "containersLeft", len(st.ContainersLeft))
		for _, name := range slices.Sorted(maps.Keys(st.Skipped)) {
			slog.Warn("image left out of the conversion; armada-node pulls it again when a replica needs it", "image", name, "reason", st.Skipped[name])
		}
	}
	for _, id := range slices.Sorted(maps.Keys(st.ContainersLeft)) {
		slog.Warn("container's root filesystem stays in Go's image store until the container goes", "container", id, "reason", st.ContainersLeft[id])
	}
	if st.Collected && !before.Collected && (had || sum != nil) {
		slog.Info("Go's image store removed: no container's root filesystem is left in it", "containers", st.Containers)
	}
	return nil
}

// openNative opens armada-node's store when bin is a program.
func openNative(bin, images string) (*supervisor.Native, error) {
	fi, err := os.Stat(bin)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a program", bin)
	}
	return supervisor.OpenNative(bin, images)
}
