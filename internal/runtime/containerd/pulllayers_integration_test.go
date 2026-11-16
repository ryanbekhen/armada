//go:build integration && linux

package containerd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// namedRegistry resolves to name and root and serves blobs.
type namedRegistry struct {
	name  string
	root  ocispec.Descriptor
	blobs map[digest.Digest][]byte
}

func (r *namedRegistry) Resolve(context.Context, string) (string, ocispec.Descriptor, error) {
	return r.name, r.root, nil
}
func (r *namedRegistry) Fetcher(context.Context, string) (remotes.Fetcher, error) { return r, nil }
func (r *namedRegistry) Pusher(context.Context, string) (remotes.Pusher, error) {
	return nil, errors.New("no push")
}
func (r *namedRegistry) Fetch(_ context.Context, d ocispec.Descriptor) (io.ReadCloser, error) {
	b, ok := r.blobs[d.Digest]
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// layerImage is a one-file image whose config names diffID, or its own
// layer's diff ID when diffID is empty.
func layerImage(t *testing.T, name, file string, diffID digest.Digest) (*namedRegistry, digest.Digest) {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	if err := tw.WriteHeader(&tar.Header{Name: "secret.txt", Mode: 0o644, Size: int64(len(file))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(file)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	own := digest.FromBytes(raw.Bytes())
	if diffID == "" {
		diffID = own
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw.Bytes())
	_ = zw.Close()
	desc := func(mt string, b []byte) ocispec.Descriptor {
		return ocispec.Descriptor{MediaType: mt, Digest: digest.FromBytes(b), Size: int64(len(b))}
	}
	ld := desc(ocispec.MediaTypeImageLayerGzip, gz.Bytes())
	cfg, _ := json.Marshal(ocispec.Image{Platform: platforms.DefaultSpec(), RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{diffID}}})
	cd := desc(ocispec.MediaTypeImageConfig, cfg)
	man, _ := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: cd, Layers: []ocispec.Descriptor{ld}})
	md := desc(ocispec.MediaTypeImageManifest, man)
	return &namedRegistry{name: name, root: md, blobs: map[digest.Digest][]byte{ld.Digest: gz.Bytes(), cd.Digest: cfg, md.Digest: man}}, own
}

// TestIntegrationPullLayerProof checks, on a node's own containerd, that an
// image whose config names another image's diff ID with a blob of its own
// is refused and removed, while the same layer under another name is
// reused (T82).
//
//	sudo ARMADA_BIN=/usr/local/bin/armadad \
//	  go test -tags integration -run PullLayerProof ./internal/runtime/containerd/
func TestIntegrationPullLayerProof(t *testing.T) {
	bin := os.Getenv("ARMADA_BIN")
	if bin == "" || os.Geteuid() != 0 {
		t.Skip("needs root and ARMADA_BIN")
	}
	d, err := New(nodeConfig(t, bin))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := d.ctx(context.Background())
	secret := "secret of space A " + t.Name()
	a, diffA := layerImage(t, "private.example/a/app:proof", secret, "")
	b, _ := layerImage(t, "attacker.example/b/app:proof", "my own files", diffA)
	c, _ := layerImage(t, "private.example/a/copy:proof", secret, "")
	t.Cleanup(func() {
		for _, r := range []*namedRegistry{a, b, c} {
			_ = d.ctr.DeleteImage(ctx, r.name, true)
		}
	})
	if _, err := d.ctr.Pull(ctx, a.name, a, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ctr.Pull(ctx, b.name, b, nil); err == nil {
		t.Fatal("an image naming another image's diff ID got its layer")
	} else {
		t.Logf("refused: %v", err)
	}
	if _, err := d.ctr.GetImage(ctx, b.name); err == nil {
		t.Fatal("the refused image is still recorded")
	}
	if _, err := d.ctr.Pull(ctx, c.name, c, nil); err != nil {
		t.Fatalf("the same layer under another name: %v", err)
	}
}
