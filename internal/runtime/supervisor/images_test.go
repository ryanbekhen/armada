package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// readApplier "applies" a layer by reading its blob, as an uncompressed
// tar would be: the real applier needs mounts.
type readApplier struct{ cs content.Store }

func (a readApplier) Apply(ctx context.Context, desc ocispec.Descriptor, _ []mount.Mount, _ ...diff.ApplyOpt) (ocispec.Descriptor, error) {
	b, err := content.ReadBlob(ctx, a.cs, desc)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: digest.FromBytes(b), Size: int64(len(b))}, nil
}

// memRegistry resolves to root and serves blobs.
type memRegistry struct {
	root  ocispec.Descriptor
	blobs map[digest.Digest][]byte
}

func (r memRegistry) Resolve(context.Context, string) (string, ocispec.Descriptor, error) {
	return "registry.example/x", r.root, nil
}
func (r memRegistry) Fetcher(context.Context, string) (remotes.Fetcher, error) { return r, nil }
func (r memRegistry) Pusher(context.Context, string) (remotes.Pusher, error) {
	return nil, errors.New("no push")
}
func (r memRegistry) Fetch(_ context.Context, d ocispec.Descriptor) (io.ReadCloser, error) {
	b, ok := r.blobs[d.Digest]
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// oneLayer returns a one-layer image whose config names diffID.
func oneLayer(t *testing.T, layer []byte, diffID digest.Digest) memRegistry {
	t.Helper()
	desc := func(mt string, b []byte) ocispec.Descriptor {
		return ocispec.Descriptor{MediaType: mt, Digest: digest.FromBytes(b), Size: int64(len(b))}
	}
	ld := desc(ocispec.MediaTypeImageLayer, layer)
	cfg, err := json.Marshal(ocispec.Image{Platform: platforms.DefaultSpec(),
		RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{diffID}}})
	if err != nil {
		t.Fatal(err)
	}
	cd := desc(ocispec.MediaTypeImageConfig, cfg)
	man, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: cd, Layers: []ocispec.Descriptor{ld}})
	if err != nil {
		t.Fatal(err)
	}
	md := desc(ocispec.MediaTypeImageManifest, man)
	return memRegistry{root: md, blobs: map[digest.Digest][]byte{ld.Digest: layer, cd.Digest: cfg, md.Digest: man}}
}

// An image whose config names another image's diff IDs does not get that
// image's unpacked layer: its own blob must decompress to the diff ID.
func TestPullChecksReusedLayers(t *testing.T) {
	ctx := context.Background()
	s, err := OpenImages(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	s.applier = readApplier{s.content}

	secret := []byte("SECRET FILES OF SPACE A")
	a, err := s.Pull(ctx, "a", oneLayer(t, secret, digest.FromBytes(secret)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pull(ctx, "b", oneLayer(t, []byte("my own layer"), digest.FromBytes(secret)), nil); err == nil {
		t.Fatal("an image naming another image's diff ID got its layer")
	}
	if _, ok := s.Get("b"); ok {
		t.Fatal("the refused image was recorded")
	}
	// The same layer under another name is reused, checked once.
	b, err := s.Pull(ctx, "c", oneLayer(t, secret, digest.FromBytes(secret)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if b.ChainID != a.ChainID {
		t.Errorf("chains %s and %s", a.ChainID, b.ChainID)
	}
}

// A name pulled again to another target keeps no pulled-with labels.
func TestPullDropsLabelsOfOldTarget(t *testing.T) {
	ctx := context.Background()
	s, err := OpenImages(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	s.applier = readApplier{s.content}
	one := []byte("v1")
	if _, err := s.Pull(ctx, "app:latest", oneLayer(t, one, digest.FromBytes(one)), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLabel("app:latest", "armada.pulled-with/k", "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pull(ctx, "app:latest", oneLayer(t, one, digest.FromBytes(one)), nil); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Get("app:latest"); r.Labels["armada.pulled-with/k"] == "" {
		t.Error("the same target lost its labels")
	}
	two := []byte("v2")
	if _, err := s.Pull(ctx, "app:latest", oneLayer(t, two, digest.FromBytes(two)), nil); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Get("app:latest"); len(r.Labels) != 0 {
		t.Errorf("a new target kept %v", r.Labels)
	}
}
