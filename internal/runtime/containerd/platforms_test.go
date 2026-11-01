package containerd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestPlatformStrings(t *testing.T) {
	t.Parallel()
	got := platformStrings([]ocispec.Platform{
		{OS: "linux", Architecture: "arm64", Variant: "v8"},
		{OS: "linux", Architecture: "aarch64"},
		{OS: "linux", Architecture: "x86_64"},
		{OS: "linux", Architecture: "arm", Variant: "v7"},
		{OS: "unknown", Architecture: "unknown"}, // attestation manifest
		{OS: "", Architecture: "amd64"},
	})
	if want := []string{"linux/amd64", "linux/arm", "linux/arm64"}; !slices.Equal(got, want) {
		t.Errorf("platformStrings = %v, want %v", got, want)
	}
	many := make([]ocispec.Platform, 40)
	for i := range many {
		many[i] = ocispec.Platform{OS: "linux", Architecture: "a" + strings.Repeat("x", i)}
	}
	if n := len(platformStrings(many)); n != maxPlatforms {
		t.Errorf("%d platforms kept, want at most %d", n, maxPlatforms)
	}
}

// fakeRegistry serves blobs by digest; the reference resolves to top.
type fakeRegistry struct {
	top   ocispec.Descriptor
	blobs map[digest.Digest][]byte
}

func (r *fakeRegistry) add(t *testing.T, mediaType string, v any) ocispec.Descriptor {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	d := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(b), Size: int64(len(b))}
	r.blobs[d.Digest] = b
	return d
}

func (r *fakeRegistry) Resolve(context.Context, string) (string, ocispec.Descriptor, error) {
	return "example.org/app:1", r.top, nil
}

func (r *fakeRegistry) Fetcher(context.Context, string) (remotes.Fetcher, error) {
	return remotes.FetcherFunc(func(_ context.Context, d ocispec.Descriptor) (io.ReadCloser, error) {
		b, ok := r.blobs[d.Digest]
		if !ok {
			return nil, errors.New("not found")
		}
		return io.NopCloser(bytes.NewReader(b)), nil
	}), nil
}

func (r *fakeRegistry) Pusher(context.Context, string) (remotes.Pusher, error) {
	return nil, errors.New("read only")
}

func TestRemotePlatforms(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	idx := &fakeRegistry{blobs: map[digest.Digest][]byte{}}
	idx.top = idx.add(t, ocispec.MediaTypeImageIndex, ocispec.Index{Manifests: []ocispec.Descriptor{
		{MediaType: ocispec.MediaTypeImageManifest, Platform: &ocispec.Platform{OS: "linux", Architecture: "amd64"}},
		{MediaType: ocispec.MediaTypeImageManifest, Platform: &ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}},
		{MediaType: ocispec.MediaTypeImageManifest, Platform: &ocispec.Platform{OS: "unknown", Architecture: "unknown"}},
	}})
	if got, err := remotePlatforms(ctx, idx, "example.org/app:1"); err != nil || !slices.Equal(got, []string{"linux/amd64", "linux/arm64"}) {
		t.Errorf("index: %v, %v", got, err)
	}

	single := &fakeRegistry{blobs: map[digest.Digest][]byte{}}
	cfg := single.add(t, ocispec.MediaTypeImageConfig, ocispec.Image{Platform: ocispec.Platform{OS: "linux", Architecture: "amd64"}})
	single.top = single.add(t, images.MediaTypeDockerSchema2Manifest, ocispec.Manifest{Config: cfg})
	if got, err := remotePlatforms(ctx, single, "example.org/app:1"); err != nil || !slices.Equal(got, []string{"linux/amd64"}) {
		t.Errorf("single image: %v, %v", got, err)
	}

	// A registry announcing a huge manifest is not read.
	huge := &fakeRegistry{blobs: map[digest.Digest][]byte{}}
	huge.top = huge.add(t, ocispec.MediaTypeImageIndex, ocispec.Index{})
	huge.top.Size = maxManifest + 1
	if _, err := remotePlatforms(ctx, huge, "example.org/app:1"); err == nil {
		t.Error("oversized manifest read")
	}
	// Nor one that sends more than it announced.
	lying := &fakeRegistry{blobs: map[digest.Digest][]byte{}}
	lying.top = lying.add(t, ocispec.MediaTypeImageIndex, ocispec.Index{})
	lying.blobs[lying.top.Digest] = bytes.Repeat([]byte(" "), maxManifest+10)
	if _, err := remotePlatforms(ctx, lying, "example.org/app:1"); err == nil {
		t.Error("manifest larger than the limit read")
	}
	unknown := &fakeRegistry{blobs: map[digest.Digest][]byte{}}
	unknown.top = unknown.add(t, "application/x-unknown", struct{}{})
	if _, err := remotePlatforms(ctx, unknown, "example.org/app:1"); err == nil {
		t.Error("unknown media type accepted")
	}
}
