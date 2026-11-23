package supervisor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// markApplier "applies" a layer by reading its blob and writing it as a
// file named "layer" into the snapshot's directory, which mounts name
// without mounting anything.
type markApplier struct{ cs content.Store }

func (a markApplier) Apply(ctx context.Context, desc ocispec.Descriptor, mounts []mount.Mount, _ ...diff.ApplyOpt) (ocispec.Descriptor, error) {
	b, err := content.ReadBlob(ctx, a.cs, desc)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	dir := mounts[0].Source
	for _, o := range mounts[0].Options {
		if v, ok := strings.CutPrefix(o, "upperdir="); ok {
			dir = v
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "layer"), b, 0o644); err != nil {
		return ocispec.Descriptor{}, err
	}
	return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: digest.FromBytes(b), Size: int64(len(b))}, nil
}

func inode(t *testing.T, p string) uint64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// The supervisor store converts into armada-node's layout: blobs linked,
// records with the chosen manifest, layers, and diff IDs, committed
// snapshots moved to layers/<chain>, active ones left alone; an image
// with a blob missing is left out and named.
func TestConvertImages(t *testing.T) {
	ctx := context.Background()
	src := filepath.Join(t.TempDir(), "supervisor", "images")
	s, err := OpenImages(src)
	if err != nil {
		t.Fatal(err)
	}
	s.applier = markApplier{s.content}
	one, two := []byte("layer one"), []byte("layer two")
	a, err := s.Pull(ctx, "registry.example/a:1", oneLayer(t, one, digest.FromBytes(one)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetLabel(a.Name, "armada.pulled-with/k", "1"); err != nil {
		t.Fatal(err)
	}
	b, err := s.Pull(ctx, "registry.example/b:1", oneLayer(t, two, digest.FromBytes(two)), nil)
	if err != nil {
		t.Fatal(err)
	}
	// A container's root filesystem on a: an active snapshot.
	if _, err := s.Prepare(ctx, "container-1", a); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// b loses its layer blob.
	if err := os.Remove(filepath.Join(src, "content", "blobs", "sha256", digest.FromBytes(two).Encoded())); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(filepath.Dir(filepath.Dir(src)), "node", "images")
	sum, err := ConvertImages(ctx, src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sum.Converted, []string{a.Name}) || sum.Skipped[b.Name] == "" || sum.Layers != 1 {
		t.Fatalf("summary %+v", sum)
	}
	var idx nodeIndex
	raw, err := os.ReadFile(filepath.Join(dst, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	rec := idx.Images[a.Name]
	if rec.Target.Digest != a.Target.Digest || rec.Manifest.Digest != a.Target.Digest || rec.Config.Digest != a.Config.Digest ||
		rec.ChainID != a.ChainID.String() || len(rec.Layers) != 1 || len(rec.DiffIDs) != 1 ||
		rec.Labels["armada.pulled-with/k"] != "1" || rec.Created == "" || !idx.Uncollected {
		t.Fatalf("record %+v (uncollected %v)", rec, idx.Uncollected)
	}
	got, err := os.ReadFile(filepath.Join(dst, "layers", a.ChainID.Encoded(), "layer"))
	if err != nil || string(got) != string(one) {
		t.Fatalf("layer: %q %v", got, err)
	}
	for _, d := range []digest.Digest{a.Target.Digest, a.Config.Digest, digest.FromBytes(one)} {
		if inode(t, blobPath(src, d)) != inode(t, blobPath(dst, d)) {
			t.Errorf("blob %s was not linked", d)
		}
	}
	// The container's snapshot (active) and b's (not converted) stay
	// where the snapshotter keeps them.
	left, err := filepath.Glob(filepath.Join(src, "snapshots", "snapshots", "*", "fs"))
	if err != nil || len(left) != 2 {
		t.Errorf("snapshots left %v %v", left, err)
	}

	// Again: nothing new, the record kept.
	sum, err = ConvertImages(ctx, src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Converted) != 0 || sum.Skipped[a.Name] == "" {
		t.Errorf("second conversion %+v", sum)
	}
}

// No supervisor store: an empty index.
func TestConvertImagesEmpty(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "node", "images")
	sum, err := ConvertImages(context.Background(), filepath.Join(t.TempDir(), "none"), dst)
	if err != nil || len(sum.Converted) != 0 || len(sum.Skipped) != 0 {
		t.Fatalf("%+v %v", sum, err)
	}
	if _, err := os.Stat(filepath.Join(dst, "index.json")); err != nil {
		t.Fatal(err)
	}
}
