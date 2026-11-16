package imagecheck

import (
	"bytes"
	"compress/gzip"
	"context"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/metadata"
	"github.com/containerd/containerd/v2/pkg/labels"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	bolt "go.etcd.io/bbolt"
)

func gzipped(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func put(ctx context.Context, t *testing.T, cs content.Store, b []byte) ocispec.Descriptor {
	t.Helper()
	d := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromBytes(b), Size: int64(len(b))}
	if err := content.WriteBlob(ctx, cs, d.Digest.String(), bytes.NewReader(b), d); err != nil {
		t.Fatal(err)
	}
	return d
}

// A layer blob passes only with the diff ID it really decompresses to,
// so an image cannot name another image's unpacked layers.
func TestLayers(t *testing.T) {
	ctx := context.Background()
	cs, err := local.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mine, theirs := []byte("my layer tar"), []byte("another space's layer tar")
	blob := put(ctx, t, cs, gzipped(t, mine))
	plain := put(ctx, t, cs, mine)
	if err := Layers(ctx, cs, []ocispec.Descriptor{blob, plain}, []digest.Digest{digest.FromBytes(mine), digest.FromBytes(mine)}); err != nil {
		t.Fatal(err)
	}
	if err := Layer(ctx, cs, blob, digest.FromBytes(theirs)); err == nil {
		t.Fatal("a blob passed with another layer's diff ID")
	}
	if err := Layers(ctx, cs, []ocispec.Descriptor{blob}, nil); err == nil {
		t.Fatal("layers and diff IDs of different counts passed")
	}
	missing := ocispec.Descriptor{Digest: digest.FromString("absent"), Size: 6}
	if err := Layer(ctx, cs, missing, digest.FromBytes(mine)); err == nil {
		t.Fatal("a blob not on the node passed")
	}
	if err := Layer(ctx, cs, blob, "sha256:short"); err == nil {
		t.Fatal("an invalid diff ID passed")
	}
}

// A blob checked once is labelled with its uncompressed digest, and the
// label (which only unpackers and this check set) answers later checks.
func TestLayerLabels(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "armada")
	dir := t.TempDir()
	base, err := local.NewStore(dir + "/content")
	if err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(dir+"/meta.db", 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	cs := metadata.NewDB(db, base, nil).ContentStore()
	tar := []byte("layer tar")
	blob := put(ctx, t, cs, gzipped(t, tar))
	if err := Layer(ctx, cs, blob, digest.FromBytes(tar)); err != nil {
		t.Fatal(err)
	}
	info, err := cs.Info(ctx, blob.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if info.Labels[labels.LabelUncompressed] != digest.FromBytes(tar).String() {
		t.Fatalf("labels after the check: %v", info.Labels)
	}
	if err := Layer(ctx, cs, blob, digest.FromBytes([]byte("other"))); err == nil {
		t.Fatal("a labelled blob passed with another diff ID")
	}
}
