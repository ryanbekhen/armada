// Package supervisor is the container runtime of ADR 0046: images and
// container records kept by the agent itself, containers supervised by
// armada-shim. Work in progress; nothing uses it yet.
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/diff/apply"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/rootfs"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/containerd/v2/plugins/snapshots/overlay"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/semaphore"
)

// Images keeps a node's images without a daemon: blobs in a content store
// under <root>/content, unpacked layers as overlay snapshots under
// <root>/snapshots, and one record per image name in <root>/images.json.
type Images struct {
	root     string
	content  content.Store
	snap     snapshots.Snapshotter
	applier  diff.Applier
	platform platforms.MatchComparer

	mu   sync.Mutex
	recs map[string]Image
}

// Image is what the store records about a pulled image name.
type Image struct {
	Name    string             `json:"name"`
	Target  ocispec.Descriptor `json:"target"`
	Config  ocispec.Descriptor `json:"config"`
	ChainID digest.Digest      `json:"chainID"`
	// Platforms the image offers, as "os/arch".
	Platforms []string          `json:"platforms,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

const recordsFile = "images.json"

// pullParallel bounds the blobs one pull fetches at once, which bounds
// the memory a pull takes (each fetch holds its buffers).
const pullParallel = 2

// OpenImages opens (creating) the store under root for this node's platform.
func OpenImages(root string) (*Images, error) {
	if err := os.MkdirAll(root, 0o700); err != nil { //nolint:gosec // root is the agent's data directory
		return nil, err
	}
	cs, err := local.NewStore(filepath.Join(root, "content"))
	if err != nil {
		return nil, fmt.Errorf("content store: %w", err)
	}
	sn, err := overlay.NewSnapshotter(filepath.Join(root, "snapshots"))
	if err != nil {
		return nil, fmt.Errorf("snapshots: %w", err)
	}
	s := &Images{
		root:     root,
		content:  cs,
		snap:     sn,
		applier:  apply.NewFileSystemApplier(cs),
		platform: platforms.Default(),
		recs:     map[string]Image{},
	}
	b, err := os.ReadFile(filepath.Join(root, recordsFile)) //nolint:gosec // under the agent's data directory
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, &s.recs); err != nil {
			return nil, fmt.Errorf("%s: %w", recordsFile, err)
		}
	}
	return s, nil
}

// Close releases the snapshotter's metadata.
func (s *Images) Close() error { return s.snap.Close() }

// Get returns the record of an image name.
func (s *Images) Get(name string) (Image, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	img, ok := s.recs[name]
	return img, ok
}

// Pull resolves ref with resolver, fetches the manifest for this node's
// platform with its config and layers, unpacks the layers, and records the
// image under ref with labels.
func (s *Images) Pull(ctx context.Context, ref string, resolver remotes.Resolver, labels map[string]string) (Image, error) {
	name, desc, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return Image{}, err
	}
	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		return Image{}, err
	}
	children := images.LimitManifests(images.FilterPlatforms(images.ChildrenHandler(s.content), s.platform), s.platform, 1)
	if err := images.Dispatch(ctx, images.Handlers(remotes.FetchHandler(s.content, fetcher), children), semaphore.NewWeighted(pullParallel), desc); err != nil {
		return Image{}, fmt.Errorf("fetch: %w", err)
	}
	return s.unpack(ctx, ref, desc, labels)
}

func (s *Images) unpack(ctx context.Context, name string, desc ocispec.Descriptor, labels map[string]string) (Image, error) {
	manifest, err := images.Manifest(ctx, s.content, desc, s.platform)
	if err != nil {
		return Image{}, err
	}
	diffs, err := images.RootFS(ctx, s.content, manifest.Config)
	if err != nil {
		return Image{}, err
	}
	if len(diffs) != len(manifest.Layers) {
		return Image{}, fmt.Errorf("image has %d layers and %d diff IDs", len(manifest.Layers), len(diffs))
	}
	layers := make([]rootfs.Layer, len(diffs))
	for i := range diffs {
		layers[i] = rootfs.Layer{
			Diff: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: diffs[i]},
			Blob: manifest.Layers[i],
		}
	}
	chain, err := rootfs.ApplyLayers(ctx, layers, s.snap, s.applier)
	if err != nil {
		return Image{}, fmt.Errorf("unpack: %w", err)
	}
	img := Image{Name: name, Target: desc, Config: manifest.Config, ChainID: chain, Labels: labels}
	if ps, err := images.Platforms(ctx, s.content, desc); err == nil {
		for _, p := range ps {
			img.Platforms = append(img.Platforms, p.OS+"/"+p.Architecture)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs[name] = img
	return img, s.saveLocked()
}

// saveLocked writes the records atomically.
func (s *Images) saveLocked() error {
	b, err := json.Marshal(s.recs)
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.root, recordsFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil { //nolint:gosec // under the agent's data directory
		return err
	}
	return os.Rename(tmp, filepath.Join(s.root, recordsFile)) //nolint:gosec // under the agent's data directory
}

// Prepare makes a writable root filesystem for container key on top of
// img's layers and returns its mounts.
func (s *Images) Prepare(ctx context.Context, key string, img Image) ([]mount.Mount, error) {
	m, err := s.snap.Prepare(ctx, key, img.ChainID.String())
	if errdefs.IsAlreadyExists(err) {
		return s.snap.Mounts(ctx, key)
	}
	return m, err
}

// Release removes container key's root filesystem.
func (s *Images) Release(ctx context.Context, key string) error {
	if err := s.snap.Remove(ctx, key); err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	return nil
}
