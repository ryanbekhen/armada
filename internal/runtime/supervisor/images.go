// Package supervisor is the container runtime of ADR 0046: images and
// container records kept by the agent itself, containers supervised by
// armada-shim. Work in progress; nothing uses it yet.
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

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
	clog "github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/semaphore"

	"github.com/ryanbekhen/armada/internal/runtime/imagecheck"
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

	// pulls is held shared by every pull from its first fetch until its
	// record is written, and exclusively while unused layers and blobs
	// are collected, so a collection never takes what a pull is using.
	// A collection that would wait is left to the last pull to end
	// (uncollected).
	pulls       sync.RWMutex
	uncollected bool

	mu   sync.Mutex
	recs map[string]Image
	// verified holds layer blobs shown to decompress to a diff ID since
	// the store was opened (the content store keeps no labels).
	verified map[digest.Digest]digest.Digest
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
	Created   time.Time         `json:"created"`
	Updated   time.Time         `json:"updated"`
}

const recordsFile = "images.json"

// pullParallel bounds the blobs one pull fetches at once, which bounds
// the memory a pull takes (each fetch holds its buffers).
const pullParallel = 2

// OpenImages opens (creating) the store under root for this node's platform.
func OpenImages(root string) (*Images, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	// The store warns when the file system has no fsverity, which it uses
	// only when present: keep that out of the agent's log.
	level := clog.GetLevel()
	_ = clog.SetLevel(clog.ErrorLevel)
	cs, err := local.NewStore(filepath.Join(root, "content"))
	_ = clog.SetLevel(level)
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
		verified: map[digest.Digest]digest.Digest{},
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
// image under ref. The record keeps the labels of the record it replaces
// only when both name the same target. wrap, when set, wraps the handler
// that fetches each descriptor and finds its children.
func (s *Images) Pull(ctx context.Context, ref string, resolver remotes.Resolver, wrap func(images.Handler) images.Handler) (Image, error) {
	s.pulls.RLock()
	defer func() {
		s.pulls.RUnlock()
		if err := s.collectIdle(context.WithoutCancel(ctx)); err != nil {
			slog.Warn("collect unused image layers", "err", err)
		}
	}()
	name, desc, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return Image{}, err
	}
	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		return Image{}, err
	}
	children := images.LimitManifests(images.FilterPlatforms(images.ChildrenHandler(s.content), s.platform), s.platform, 1)
	var handler images.Handler = images.Handlers(remotes.FetchHandler(s.content, fetcher), children)
	if wrap != nil {
		handler = wrap(handler)
	}
	if err := images.Dispatch(ctx, handler, semaphore.NewWeighted(pullParallel), desc); err != nil {
		return Image{}, fmt.Errorf("fetch: %w", err)
	}
	return s.unpack(ctx, ref, desc)
}

func (s *Images) unpack(ctx context.Context, name string, desc ocispec.Descriptor) (Image, error) {
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
	// Unpacked layers are found by chain ID, from the config's diff IDs
	// alone, and ApplyLayers skips one already there without reading its
	// blob: first show that each such blob really is that layer.
	chainIDs := identity.ChainIDs(slices.Clone(diffs))
	for i := range layers {
		if _, err := s.snap.Stat(ctx, chainIDs[i].String()); err != nil {
			continue
		}
		if err := s.checkLayer(ctx, layers[i]); err != nil {
			return Image{}, err
		}
	}
	var chain digest.Digest
	err = withImageUmask(func() (err error) {
		chain, err = rootfs.ApplyLayers(ctx, layers, s.snap, s.applier)
		return err
	})
	if err != nil {
		return Image{}, fmt.Errorf("unpack: %w", err)
	}
	s.mu.Lock()
	for _, l := range layers {
		// Applied layers were checked by the applier, the rest above.
		s.verified[l.Blob.Digest] = l.Diff.Digest
	}
	s.mu.Unlock()
	now := time.Now().UTC()
	img := Image{Name: name, Target: desc, Config: manifest.Config, ChainID: chain, Created: now, Updated: now}
	if ps, err := images.Platforms(ctx, s.content, desc); err == nil {
		for _, p := range ps {
			img.Platforms = append(img.Platforms, p.OS+"/"+p.Architecture)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.recs[name]; ok && old.Target.Digest == desc.Digest {
		// The labels record who may use this target (pulled-with).
		img.Created, img.Labels = old.Created, maps.Clone(old.Labels)
	}
	s.recs[name] = img
	return img, s.saveLocked()
}

// checkLayer checks that l's blob decompresses to its diff ID.
func (s *Images) checkLayer(ctx context.Context, l rootfs.Layer) error {
	s.mu.Lock()
	ok := s.verified[l.Blob.Digest] == l.Diff.Digest
	s.mu.Unlock()
	if ok {
		return nil
	}
	if err := imagecheck.Layer(ctx, s.content, l.Blob, l.Diff.Digest); err != nil {
		return err
	}
	s.mu.Lock()
	s.verified[l.Blob.Digest] = l.Diff.Digest
	s.mu.Unlock()
	return nil
}

// saveLocked writes the records atomically.
func (s *Images) saveLocked() error {
	b, err := json.Marshal(s.recs)
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.root, recordsFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.root, recordsFile))
}

// Prepare makes a writable root filesystem for container key on top of
// img's layers and returns its mounts.
func (s *Images) Prepare(ctx context.Context, key string, img Image) ([]mount.Mount, error) {
	var m []mount.Mount
	err := withImageUmask(func() (err error) {
		m, err = s.snap.Prepare(ctx, key, img.ChainID.String())
		return err
	})
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

// List returns every image record.
func (s *Images) List() []Image {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Image, 0, len(s.recs))
	for _, r := range s.recs {
		out = append(out, r)
	}
	return out
}

// SetLabel sets one label of an image record.
func (s *Images) SetLabel(name, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[name]
	if !ok {
		return fmt.Errorf("image %s: %w", name, errdefs.ErrNotFound)
	}
	r.Labels = maps.Clone(r.Labels)
	if r.Labels == nil {
		r.Labels = map[string]string{}
	}
	r.Labels[key] = value
	r.Updated = time.Now().UTC()
	s.recs[name] = r
	return s.saveLocked()
}

// metadata describes a record the way containerd's image service does.
func (r Image) metadata() images.Image {
	return images.Image{Name: r.Name, Target: r.Target, Labels: maps.Clone(r.Labels), CreatedAt: r.Created, UpdatedAt: r.Updated}
}

// Delete forgets an image, then removes layers and blobs no remaining
// image needs. Layers under a container's root filesystem stay: the
// snapshotter refuses to remove a parent.
func (s *Images) Delete(ctx context.Context, name string) error {
	s.mu.Lock()
	if _, ok := s.recs[name]; !ok {
		s.mu.Unlock()
		return fmt.Errorf("image %s: %w", name, errdefs.ErrNotFound)
	}
	delete(s.recs, name)
	err := s.saveLocked()
	s.uncollected = true
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.collectIdle(ctx)
}

// collectIdle collects unused layers and blobs when a deletion left some
// and no pull is running; otherwise the last running pull does it.
func (s *Images) collectIdle(ctx context.Context) error {
	if !s.pulls.TryLock() {
		return nil
	}
	defer s.pulls.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.uncollected {
		return nil
	}
	s.uncollected = false
	return s.collectLocked(ctx)
}

// collectLocked removes committed snapshots and blobs no record uses.
func (s *Images) collectLocked(ctx context.Context) error {
	keepChains := map[string]bool{}
	keepBlobs := map[digest.Digest]bool{}
	for _, r := range s.recs {
		keepChains[r.ChainID.String()] = true
		_ = images.Walk(ctx, images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			keepBlobs[desc.Digest] = true
			if _, err := s.content.Info(ctx, desc.Digest); err != nil {
				return nil, images.ErrSkipDesc // not fetched: another platform's
			}
			return images.Children(ctx, s.content, desc)
		}), r.Target)
	}
	// A kept chain keeps its parents.
	parents := map[string]string{}
	var committed []string
	_ = s.snap.Walk(ctx, func(_ context.Context, info snapshots.Info) error {
		parents[info.Name] = info.Parent
		if info.Kind == snapshots.KindCommitted {
			committed = append(committed, info.Name)
		}
		return nil
	})
	for c := range maps.Clone(keepChains) {
		for p := parents[c]; p != ""; p = parents[p] {
			keepChains[p] = true
		}
	}
	// Remove leaves first: a parent goes once its children went.
	for progress := true; progress; {
		progress = false
		for i, name := range committed {
			if name == "" || keepChains[name] {
				continue
			}
			if err := s.snap.Remove(ctx, name); err == nil {
				committed[i], progress = "", true
			}
		}
	}
	return s.content.Walk(ctx, func(info content.Info) error {
		if !keepBlobs[info.Digest] {
			if err := s.content.Delete(ctx, info.Digest); err != nil && !errdefs.IsNotFound(err) {
				return err
			}
		}
		return nil
	})
}
