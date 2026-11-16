package containerd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/semaphore"
)

// proofBackend is a node's content and image records; nothing else.
type proofBackend struct {
	backend
	cs   content.Store
	imgs []images.Image
}

func (b *proofBackend) ContentStore() content.Store { return b.cs }
func (b *proofBackend) ListImages(context.Context) ([]images.Image, error) {
	return b.imgs, nil
}

// registry answers Resolve with root and serves blobs; fetches counts
// every Fetch.
type registry struct {
	root    ocispec.Descriptor
	blobs   map[digest.Digest][]byte
	fetches atomic.Int32
}

func (r *registry) Resolve(context.Context, string) (string, ocispec.Descriptor, error) {
	return "registry.example/x", r.root, nil
}
func (r *registry) Fetcher(context.Context, string) (remotes.Fetcher, error) { return r, nil }
func (r *registry) Pusher(context.Context, string) (remotes.Pusher, error) {
	return nil, errors.New("no push")
}
func (r *registry) Fetch(_ context.Context, d ocispec.Descriptor) (io.ReadCloser, error) {
	r.fetches.Add(1)
	b, ok := r.blobs[d.Digest]
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func blob(mt string, b []byte) ocispec.Descriptor {
	return ocispec.Descriptor{MediaType: mt, Digest: digest.FromBytes(b), Size: int64(len(b))}
}

// manifest returns a one-layer image's manifest descriptor and blobs.
func manifest(t *testing.T, layer []byte) (ocispec.Descriptor, map[digest.Digest][]byte) {
	t.Helper()
	ld := blob(ocispec.MediaTypeImageLayer, layer)
	cfg, err := json.Marshal(ocispec.Image{Platform: ocispec.Platform{OS: "linux", Architecture: "amd64"},
		RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{ld.Digest}}})
	if err != nil {
		t.Fatal(err)
	}
	cd := blob(ocispec.MediaTypeImageConfig, cfg)
	man, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: cd, Layers: []ocispec.Descriptor{ld}})
	if err != nil {
		t.Fatal(err)
	}
	md := blob(ocispec.MediaTypeImageManifest, man)
	return md, map[digest.Digest][]byte{ld.Digest: layer, cd.Digest: cfg, md.Digest: man}
}

// A pull under a new name may use blobs already on the node only when
// images pulled with the same credentials (or none) hold them; otherwise
// its own registry must serve them, so another space's private image
// cannot be taken by naming its digest on a registry the spec author runs.
func TestPullProvesExistingContent(t *testing.T) {
	ctx := context.Background()
	cs, err := local.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	private, blobs := manifest(t, []byte("private layer of space A"))
	for _, b := range blobs {
		if err := content.WriteBlob(ctx, cs, digest.FromBytes(b).String(), bytes.NewReader(b), blob("", b)); err != nil {
			t.Fatal(err)
		}
	}
	keyA := pullKey("private.example/a/app", nil) + "-a"
	be := &proofBackend{cs: cs, imgs: []images.Image{{
		Name: "private.example/a/app@" + private.Digest.String(), Target: private,
		Labels: map[string]string{pullLabel + keyA: "1"},
	}}}
	d := &Driver{ctr: be}

	pull := func(key string, r *registry) error {
		wrap, err := d.proveContent(ctx, "registry.example/x", key, r)
		if err != nil {
			return err
		}
		fetcher, _ := r.Fetcher(ctx, "")
		h := wrap(images.Handlers(remotes.FetchHandler(cs, fetcher), images.ChildrenHandler(cs)))
		return images.Dispatch(ctx, h, semaphore.NewWeighted(2), r.root)
	}

	// The spec author's registry knows only the digest.
	headOnly := &registry{root: private}
	if err := pull(pullAnyone, headOnly); err == nil {
		t.Fatal("a registry that serves nothing got another space's private image")
	}
	// Nor does a manifest of its own help, pointing at A's config and layer.
	var m ocispec.Manifest
	if err := json.Unmarshal(blobs[private.Digest], &m); err != nil {
		t.Fatal(err)
	}
	own, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: m.Config, Layers: m.Layers, Annotations: map[string]string{"x": "y"}})
	if err != nil {
		t.Fatal(err)
	}
	ownDesc := blob(ocispec.MediaTypeImageManifest, own)
	if err := pull(pullAnyone, &registry{root: ownDesc, blobs: map[digest.Digest][]byte{ownDesc.Digest: own}}); err == nil {
		t.Fatal("a manifest naming another space's layers got them")
	}
	// A registry serving other bytes under the digests is refused too.
	forged := map[digest.Digest][]byte{}
	for dg := range blobs {
		forged[dg] = []byte("not it")
	}
	if err := pull("other", &registry{root: private, blobs: forged}); err == nil {
		t.Fatal("content that does not match its digest was accepted")
	}

	// The same credentials use what is on the node without the registry.
	same := &registry{root: private}
	if err := pull(keyA, same); err != nil {
		t.Fatal(err)
	}
	if n := same.fetches.Load(); n != 0 {
		t.Errorf("the credentials that pulled it fetched %d blobs again", n)
	}
	// Other credentials the registry serves fetch every blob once more.
	other := &registry{root: private, blobs: blobs}
	if err := pull("other", other); err != nil {
		t.Fatal(err)
	}
	if n := other.fetches.Load(); n != 3 {
		t.Errorf("other credentials fetched %d blobs, want 3", n)
	}
	// What anyone could pull is anyone's.
	be.imgs[0].Labels = map[string]string{pullLabel + pullAnyone: "1"}
	d = &Driver{ctr: be}
	public := &registry{root: private}
	if err := pull("someone", public); err != nil {
		t.Fatal(err)
	}
	if n := public.fetches.Load(); n != 0 {
		t.Errorf("a public image's blobs were fetched %d times", n)
	}
}
