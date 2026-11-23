package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"syscall"
	"time"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/storage"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

// The conversion of a node's images from the supervisor runtime's store
// to the store armada-node keeps (ADR 0054, "The runtime's move"). It is
// not called yet: the release that makes armada-node a node's runtime
// runs it before the runtime starts.

// nodeIndexVersion is the version of armada-node's index.json written.
const nodeIndexVersion = 1

// ConvertSummary says what ConvertImages did.
type ConvertSummary struct {
	// Converted lists the image names now in armada-node's store.
	Converted []string
	// Skipped names each image left out, and why; it is pulled again
	// when a replica needs it.
	Skipped map[string]string
	// Layers counts the unpacked layers moved.
	Layers int
}

// nodeImage is armada-node's record of an image (node/src/runtime/image/
// store.rs, ImageRecord).
type nodeImage struct {
	Name      string               `json:"name"`
	Target    ocispec.Descriptor   `json:"target"`
	Manifest  ocispec.Descriptor   `json:"manifest"`
	Config    ocispec.Descriptor   `json:"config"`
	Layers    []ocispec.Descriptor `json:"layers"`
	DiffIDs   []digest.Digest      `json:"diffIDs"`
	ChainID   string               `json:"chainID"`
	Platforms []string             `json:"platforms,omitempty"`
	Labels    map[string]string    `json:"labels,omitempty"`
	Created   string               `json:"created"`
	Updated   string               `json:"updated"`
}

// nodeIndex is armada-node's index.json.
type nodeIndex struct {
	Version     int                      `json:"version"`
	Images      map[string]nodeImage     `json:"images"`
	Verified    map[string]digest.Digest `json:"verified"`
	Uncollected bool                     `json:"uncollected,omitempty"`
}

// ConvertImages writes the images of the supervisor store under src
// (<data dir>/supervisor/images: the content store, the overlay
// snapshotter's metadata.db, and images.json) into armada-node's store
// under dst (<data dir>/node/images): blobs hard-linked into
// content/blobs, each record converted with its labels, committed
// snapshots renamed to layers/<chain ID hex>, and index.json written
// last. Active snapshots (containers' root filesystems) are left where
// they are. Every converted image is verified (its blobs' digests, its
// manifest, config, and layers present, every chain's directory present);
// an image that cannot be converted is left out and named in the
// summary. Records already in dst's index are kept as they are. Both
// directories must be on one file system, and neither store may be in
// use: src's snapshotter closed, no armada-node running on dst.
func ConvertImages(ctx context.Context, src, dst string) (ConvertSummary, error) {
	sum := ConvertSummary{Skipped: map[string]string{}}
	var recs map[string]Image
	b, err := os.ReadFile(filepath.Join(src, recordsFile)) //nolint:gosec // under the agent's data directory
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return sum, err
	default:
		if err := json.Unmarshal(b, &recs); err != nil {
			return sum, fmt.Errorf("%s: %w", recordsFile, err)
		}
	}
	committed, err := committedSnapshots(ctx, filepath.Join(src, "snapshots"))
	if err != nil {
		return sum, err
	}
	for _, d := range []string{dst, filepath.Join(dst, "content", "blobs"), filepath.Join(dst, "content", "ingest"), filepath.Join(dst, "layers")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return sum, err
		}
	}
	// armada-node's locks: no pull and no other change while converting.
	for _, name := range []string{"pull.lock", "index.lock"} {
		unlock, err := lockFile(filepath.Join(dst, name))
		if err != nil {
			return sum, err
		}
		defer unlock()
	}
	idx := nodeIndex{Version: nodeIndexVersion, Images: map[string]nodeImage{}, Verified: map[string]digest.Digest{}}
	switch b, err := os.ReadFile(filepath.Join(dst, "index.json")); { //nolint:gosec // under the agent's data directory
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return sum, err
	default:
		if err := json.Unmarshal(b, &idx); err != nil {
			return sum, fmt.Errorf("index.json: %w", err)
		}
		if idx.Version > nodeIndexVersion {
			return sum, fmt.Errorf("index.json: version %d is newer than %d", idx.Version, nodeIndexVersion)
		}
		if idx.Images == nil {
			idx.Images = map[string]nodeImage{}
		}
		if idx.Verified == nil {
			idx.Verified = map[string]digest.Digest{}
		}
	}
	c := converter{src: src, dst: dst, committed: committed, checked: map[digest.Digest]error{}}
	names := make([]string, 0, len(recs))
	for n := range recs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := idx.Images[name]; ok {
			sum.Skipped[name] = "armada-node's store already records it"
			continue
		}
		rec, moved, err := c.convert(recs[name])
		sum.Layers += moved
		if err == nil {
			err = c.verify(rec)
		}
		if err != nil {
			sum.Skipped[name] = err.Error()
			// Blobs and layers it brought along go with armada-node's
			// next collection.
			idx.Uncollected = true
			continue
		}
		idx.Images[name] = rec
		sum.Converted = append(sum.Converted, name)
	}
	idx.Version = nodeIndexVersion
	out, err := json.Marshal(idx)
	if err != nil {
		return sum, err
	}
	tmp := filepath.Join(dst, "index.json.tmp")
	if err := writeSynced(tmp, out); err != nil {
		return sum, err
	}
	return sum, os.Rename(tmp, filepath.Join(dst, "index.json"))
}

func writeSynced(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // under the agent's data directory
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// lockFile takes an exclusive flock as armada-node's Store does.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600) //nolint:gosec // under the agent's data directory
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

// committedSnapshots maps each committed snapshot's name (a chain ID) to
// its directory, read from the overlay snapshotter's metadata.
func committedSnapshots(ctx context.Context, root string) (map[string]string, error) {
	db := filepath.Join(root, "metadata.db")
	if _, err := os.Stat(db); errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	ms, err := storage.NewMetaStore(db, func(o *bolt.Options) error {
		o.ReadOnly = true
		o.Timeout = 5 * time.Second
		return nil
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = ms.Close() }()
	out := map[string]string{}
	err = ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		var names []string
		if err := storage.WalkInfo(ctx, func(_ context.Context, info snapshots.Info) error {
			if info.Kind == snapshots.KindCommitted {
				names = append(names, info.Name)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, n := range names {
			id, _, _, err := storage.GetInfo(ctx, n)
			if err != nil {
				return err
			}
			out[n] = filepath.Join(root, "snapshots", id, "fs")
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("snapshots: %w", err)
	}
	return out, nil
}

type converter struct {
	src, dst  string
	committed map[string]string
	// checked holds each blob's digest check in dst.
	checked map[digest.Digest]error
}

func blobPath(root string, d digest.Digest) string {
	return filepath.Join(root, "content", "blobs", d.Algorithm().String(), d.Encoded())
}

// readBlob reads a manifest, index, or config of at most 4 MiB from src.
func (c *converter) readBlob(d ocispec.Descriptor) ([]byte, error) {
	if err := d.Digest.Validate(); err != nil {
		return nil, err
	}
	f, err := os.Open(blobPath(c.src, d.Digest))
	if err != nil {
		return nil, fmt.Errorf("blob %s: %w", d.Digest, err)
	}
	defer func() { _ = f.Close() }()
	const maxBlob = 4 << 20
	b, err := io.ReadAll(io.LimitReader(f, maxBlob+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBlob {
		return nil, fmt.Errorf("blob %s is larger than %d bytes", d.Digest, maxBlob)
	}
	return b, nil
}

// chooseManifest is images.Manifest, also returning the manifest's
// descriptor: the one armada-node records for the image.
func (c *converter) chooseManifest(target ocispec.Descriptor, m platforms.MatchComparer) (ocispec.Descriptor, ocispec.Manifest, error) {
	var (
		found    []ocispec.Descriptor
		manifest []ocispec.Manifest
		wasIndex bool
	)
	var walk func(ds []ocispec.Descriptor) error
	walk = func(ds []ocispec.Descriptor) error {
		for _, d := range ds {
			switch {
			case images.IsManifestType(d.MediaType):
				b, err := c.readBlob(d)
				if err != nil {
					return err
				}
				if err := validateMediaType(b, d.MediaType); err != nil {
					return fmt.Errorf("manifest: invalid desc %s: %w", d.Digest, err)
				}
				var mf ocispec.Manifest
				if err := json.Unmarshal(b, &mf); err != nil {
					return err
				}
				if d.Digest != target.Digest {
					if d.Platform != nil && !m.Match(*d.Platform) {
						continue
					}
					if d.Platform == nil {
						cb, err := c.readBlob(mf.Config)
						if err != nil {
							return err
						}
						var cfg ocispec.Image
						if err := json.Unmarshal(cb, &cfg); err != nil {
							return err
						}
						if !m.Match(platforms.Normalize(cfg.Platform)) {
							continue
						}
					}
				}
				found = append(found, d)
				manifest = append(manifest, mf)
			case images.IsIndexType(d.MediaType):
				b, err := c.readBlob(d)
				if err != nil {
					return err
				}
				if err := validateMediaType(b, d.MediaType); err != nil {
					return fmt.Errorf("manifest: invalid desc %s: %w", d.Digest, err)
				}
				var ix ocispec.Index
				if err := json.Unmarshal(b, &ix); err != nil {
					return err
				}
				var ds []ocispec.Descriptor
				for _, x := range ix.Manifests {
					if x.Platform == nil || m.Match(*x.Platform) {
						ds = append(ds, x)
					}
				}
				sort.SliceStable(ds, func(i, j int) bool {
					if ds[i].Platform == nil {
						return false
					}
					if ds[j].Platform == nil {
						return true
					}
					return m.Less(*ds[i].Platform, *ds[j].Platform)
				})
				wasIndex = true
				if len(ds) > 1 {
					ds = ds[:1]
				}
				if err := walk(ds); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unexpected media type %v for %v: not found", d.MediaType, d.Digest)
			}
		}
		return nil
	}
	if err := walk([]ocispec.Descriptor{target}); err != nil {
		return ocispec.Descriptor{}, ocispec.Manifest{}, err
	}
	if len(found) == 0 {
		if wasIndex {
			return ocispec.Descriptor{}, ocispec.Manifest{}, fmt.Errorf("no match for platform in manifest %v: not found", target.Digest)
		}
		return ocispec.Descriptor{}, ocispec.Manifest{}, fmt.Errorf("manifest %v: not found", target.Digest)
	}
	d := found[0]
	d.Platform = nil
	return d, manifest[0], nil
}

// validateMediaType is containerd's: a document must be what its
// descriptor says.
func validateMediaType(b []byte, mt string) error {
	var doc struct {
		Manifests json.RawMessage `json:"manifests,omitempty"`
		Config    json.RawMessage `json:"config,omitempty"`
		Layers    json.RawMessage `json:"layers,omitempty"`
		FSLayers  json.RawMessage `json:"fsLayers,omitempty"`
		MediaType string          `json:"mediaType,omitempty"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return err
	}
	if len(doc.FSLayers) != 0 {
		return fmt.Errorf("media-type: schema 1 not supported")
	}
	if images.IsManifestType(mt) && (len(doc.Manifests) != 0 || images.IsIndexType(doc.MediaType)) {
		return fmt.Errorf("media-type: expected manifest but found index (%s)", mt)
	} else if images.IsIndexType(mt) && (len(doc.Config) != 0 || len(doc.Layers) != 0 || images.IsManifestType(doc.MediaType)) {
		return fmt.Errorf("media-type: expected index but found manifest (%s)", mt)
	}
	return nil
}

// convert builds armada-node's record of one image, links its blobs, and
// moves its unpacked layers; it returns how many layers it moved.
func (c *converter) convert(img Image) (nodeImage, int, error) {
	if err := img.Target.Digest.Validate(); err != nil {
		return nodeImage{}, 0, fmt.Errorf("target: %w", err)
	}
	mdesc, mf, err := c.chooseManifest(img.Target, platforms.Default())
	if err != nil {
		return nodeImage{}, 0, err
	}
	if mf.Config.Digest != img.Config.Digest {
		return nodeImage{}, 0, fmt.Errorf("manifest %s names config %s, the record %s", mdesc.Digest, mf.Config.Digest, img.Config.Digest)
	}
	cb, err := c.readBlob(mf.Config)
	if err != nil {
		return nodeImage{}, 0, err
	}
	var cfg ocispec.Image
	if err := json.Unmarshal(cb, &cfg); err != nil {
		return nodeImage{}, 0, fmt.Errorf("config: %w", err)
	}
	diffs := cfg.RootFS.DiffIDs
	if len(diffs) != len(mf.Layers) {
		return nodeImage{}, 0, fmt.Errorf("image has %d layers and %d diff IDs", len(mf.Layers), len(diffs))
	}
	for _, d := range diffs {
		if err := d.Validate(); err != nil {
			return nodeImage{}, 0, fmt.Errorf("diff ID: %w", err)
		}
	}
	chains := identity.ChainIDs(slices.Clone(diffs))
	var top digest.Digest
	if len(chains) > 0 {
		top = chains[len(chains)-1]
	}
	if top != img.ChainID {
		return nodeImage{}, 0, fmt.Errorf("chain ID %s, the record %s", top, img.ChainID)
	}
	// Every blob the record keeps: the target and what it reaches that is
	// in the store, which must include the manifest, config, and layers.
	blobs, err := c.reachable(img.Target)
	if err != nil {
		return nodeImage{}, 0, err
	}
	for _, d := range append([]ocispec.Descriptor{mdesc, mf.Config}, mf.Layers...) {
		if !slices.Contains(blobs, d.Digest) {
			return nodeImage{}, 0, fmt.Errorf("blob %s is missing", d.Digest)
		}
	}
	for _, d := range blobs {
		if err := c.link(d); err != nil {
			return nodeImage{}, 0, err
		}
	}
	moved := 0
	for _, ch := range chains {
		dir := filepath.Join(c.dst, "layers", ch.Encoded())
		if _, err := os.Lstat(dir); err == nil {
			continue
		}
		from, ok := c.committed[ch.String()]
		if !ok {
			return nodeImage{}, moved, fmt.Errorf("layer %s is not unpacked", ch)
		}
		if err := os.Rename(from, dir); err != nil {
			return nodeImage{}, moved, fmt.Errorf("layer %s: %w", ch, err)
		}
		moved++
	}
	rec := nodeImage{
		Name: img.Name, Target: img.Target, Manifest: mdesc, Config: mf.Config,
		Layers: mf.Layers, DiffIDs: diffs, ChainID: top.String(),
		Platforms: img.Platforms, Labels: img.Labels,
		Created: img.Created.UTC().Format(time.RFC3339Nano), Updated: img.Updated.UTC().Format(time.RFC3339Nano),
	}
	if rec.Layers == nil {
		rec.Layers = []ocispec.Descriptor{}
	}
	if rec.DiffIDs == nil {
		rec.DiffIDs = []digest.Digest{}
	}
	return rec, moved, nil
}

// reachable lists target and every blob in src it reaches: an index's
// manifests that are there, a manifest's config and layers.
func (c *converter) reachable(target ocispec.Descriptor) ([]digest.Digest, error) {
	var out []digest.Digest
	var walk func(d ocispec.Descriptor) error
	walk = func(d ocispec.Descriptor) error {
		if d.Digest.Validate() != nil || slices.Contains(out, d.Digest) {
			return nil
		}
		if _, err := os.Stat(blobPath(c.src, d.Digest)); err != nil {
			return nil
		}
		out = append(out, d.Digest)
		if !images.IsManifestType(d.MediaType) && !images.IsIndexType(d.MediaType) {
			return nil
		}
		b, err := c.readBlob(d)
		if err != nil {
			return err
		}
		var doc struct {
			Config    *ocispec.Descriptor  `json:"config"`
			Layers    []ocispec.Descriptor `json:"layers"`
			Manifests []ocispec.Descriptor `json:"manifests"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return fmt.Errorf("%s: %w", d.Digest, err)
		}
		if doc.Config != nil {
			if err := walk(*doc.Config); err != nil {
				return err
			}
		}
		for _, x := range append(doc.Layers, doc.Manifests...) {
			if err := walk(x); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(target); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("blob %s is missing", target.Digest)
	}
	return out, nil
}

// link hard-links a blob into dst (copying it when the stores are on
// different file systems), read-only as armada-node writes blobs.
func (c *converter) link(d digest.Digest) error {
	to := blobPath(c.dst, d)
	if _, err := os.Lstat(to); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return err
	}
	from := blobPath(c.src, d)
	err := os.Link(from, to)
	if errors.Is(err, syscall.EXDEV) {
		err = copyBlob(from, to)
	}
	if err != nil {
		return fmt.Errorf("blob %s: %w", d, err)
	}
	return nil
}

func copyBlob(from, to string) error {
	in, err := os.Open(from) //nolint:gosec // under the store
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	tmp := to + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o400) //nolint:gosec // under the store
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, to)
}

// verify checks a converted record against dst: every blob it keeps is
// there with its digest, and every chain has its directory. A blob whose
// digest does not match is removed from dst.
func (c *converter) verify(rec nodeImage) error {
	ds := []digest.Digest{rec.Target.Digest, rec.Manifest.Digest, rec.Config.Digest}
	for _, l := range rec.Layers {
		ds = append(ds, l.Digest)
	}
	for _, d := range ds {
		err, ok := c.checked[d]
		if !ok {
			err = checkBlob(blobPath(c.dst, d), d)
			c.checked[d] = err
			if err != nil {
				_ = os.Remove(blobPath(c.dst, d))
			}
		}
		if err != nil {
			return err
		}
	}
	for _, ch := range identity.ChainIDs(slices.Clone(rec.DiffIDs)) {
		fi, err := os.Lstat(filepath.Join(c.dst, "layers", ch.Encoded()))
		if err != nil || !fi.IsDir() {
			return fmt.Errorf("layer %s is missing", ch)
		}
	}
	return nil
}

func checkBlob(path string, d digest.Digest) error {
	f, err := os.Open(path) //nolint:gosec // a validated digest under the store
	if err != nil {
		return fmt.Errorf("blob %s: %w", d, err)
	}
	defer func() { _ = f.Close() }()
	v := d.Verifier()
	if _, err := io.Copy(v, f); err != nil {
		return fmt.Errorf("blob %s: %w", d, err)
	}
	if !v.Verified() {
		return fmt.Errorf("blob %s does not match its digest", d)
	}
	return nil
}
