package containerd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// maxPlatforms bounds the platforms reported for one image, and
// maxManifest the size of a manifest or config read to find them.
const (
	maxPlatforms = 32
	maxManifest  = 4 << 20
)

// nodePlatform is this node's platform as "os/arch".
func nodePlatform() string {
	p := platforms.DefaultSpec()
	return p.OS + "/" + p.Architecture
}

// platformStrings turns image platforms into sorted, unique "os/arch"
// strings. Variants are dropped (nodes report only OS and architecture),
// and so are the "unknown" entries of attestation manifests.
func platformStrings(ps []ocispec.Platform) []string {
	var out []string
	for _, p := range ps {
		// Checked before normalizing, which fills in this host's values.
		if p.OS == "" || p.Architecture == "" || p.OS == "unknown" || p.Architecture == "unknown" {
			continue
		}
		p = platforms.Normalize(p)
		s := p.OS + "/" + p.Architecture
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	if len(out) > maxPlatforms {
		out = out[:maxPlatforms]
	}
	return out
}

// localPlatforms reads the platforms of a pulled image from the content
// store; nil if they cannot be read.
func (d *Driver) localPlatforms(ctx context.Context, img client.Image) []string {
	ps, err := images.Platforms(ctx, d.client.ContentStore(), img.Target())
	if err != nil {
		return nil
	}
	return platformStrings(ps)
}

// remotePlatforms reads the platforms of ref from its registry without
// pulling it: the platforms listed in an index, or the OS and architecture
// in a single image's config.
func remotePlatforms(ctx context.Context, resolver remotes.Resolver, ref string) ([]string, error) {
	name, desc, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		return nil, err
	}
	switch desc.MediaType {
	case images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
		var idx ocispec.Index
		if err := fetchJSON(ctx, fetcher, desc, &idx); err != nil {
			return nil, err
		}
		var ps []ocispec.Platform
		for _, m := range idx.Manifests {
			if m.Platform != nil {
				ps = append(ps, *m.Platform)
			}
		}
		return platformStrings(ps), nil
	case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
		var m ocispec.Manifest
		if err := fetchJSON(ctx, fetcher, desc, &m); err != nil {
			return nil, err
		}
		var cfg ocispec.Image
		if err := fetchJSON(ctx, fetcher, m.Config, &cfg); err != nil {
			return nil, err
		}
		return platformStrings([]ocispec.Platform{cfg.Platform}), nil
	}
	return nil, fmt.Errorf("unsupported media type %q", desc.MediaType)
}

func fetchJSON(ctx context.Context, f remotes.Fetcher, desc ocispec.Descriptor, v any) error {
	if desc.Size > maxManifest {
		return fmt.Errorf("%s is larger than %d bytes", desc.MediaType, maxManifest)
	}
	rc, err := f.Fetch(ctx, desc)
	if err != nil {
		return err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maxManifest+1))
	if err != nil {
		return err
	}
	if len(b) > maxManifest {
		return fmt.Errorf("%s is larger than %d bytes", desc.MediaType, maxManifest)
	}
	return json.Unmarshal(b, v)
}
