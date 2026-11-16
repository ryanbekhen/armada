package containerd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// proveContent returns the resolver and the handler wrapper a pull of ref
// with key's credentials runs. Content on a node is shared by digest
// across every image name, and the fetch skips a blob that is already
// there (or that another pull is fetching at the same time), so without
// this a pull under a new name, from a registry its spec author runs,
// could take another space's private manifests and layers just by naming
// their digests. A blob this pull's own fetcher did not download is used
// only when an image pulled with the same credentials, or with none,
// holds it (pulledWith); any other is fetched again from this pull's
// registry and checked against its digest, so the registry must really
// serve it to these credentials. The pull must use the returned resolver:
// it records what its fetcher downloads.
func (d *Driver) proveContent(ctx context.Context, ref, key string, resolver remotes.Resolver) (remotes.Resolver, func(images.Handler) images.Handler, error) {
	fetcher, err := resolver.Fetcher(ctx, ref)
	if err != nil {
		return nil, nil, err
	}
	cs := d.ctr.ContentStore()
	rec := &recordingResolver{Resolver: resolver}
	var (
		once   sync.Once
		proven map[digest.Digest]bool
		perr   error
	)
	return rec, func(next images.Handler) images.Handler {
		return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			children, err := next.Handle(ctx, desc)
			if err != nil || rec.fetched(desc.Digest) {
				return children, err
			}
			once.Do(func() { proven, perr = d.provenContent(ctx, cs, key) })
			if perr != nil {
				return nil, perr
			}
			if !proven[desc.Digest] {
				if err := fetchVerified(ctx, fetcher, desc); err != nil {
					return nil, fmt.Errorf("%s is on this node but its registry did not serve it to these credentials: %w", desc.Digest, err)
				}
			}
			return children, nil
		})
	}, nil
}

// recordingResolver records every blob its fetchers start to download.
type recordingResolver struct {
	remotes.Resolver
	seen sync.Map
}

func (r *recordingResolver) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	f, err := r.Resolver.Fetcher(ctx, ref)
	if err != nil {
		return nil, err
	}
	return recordingFetcher{f, r}, nil
}

func (r *recordingResolver) fetched(d digest.Digest) bool {
	_, ok := r.seen.Load(d)
	return ok
}

// recordingFetcher hides every other interface of the fetcher it wraps,
// so every download goes through Fetch.
type recordingFetcher struct {
	f   remotes.Fetcher
	rec *recordingResolver
}

func (f recordingFetcher) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	rc, err := f.f.Fetch(ctx, desc)
	if err == nil {
		// The store checks the digest of what it commits.
		f.rec.seen.Store(desc.Digest, true)
	}
	return rc, err
}

// provenContent returns every blob that images pulled with key's
// credentials, or with none, reference: indexes, manifests, configs, and
// layers that are on the node.
func (d *Driver) provenContent(ctx context.Context, cs content.Provider, key string) (map[digest.Digest]bool, error) {
	imgs, err := d.ctr.ListImages(ctx)
	if err != nil {
		return nil, err
	}
	proven := map[digest.Digest]bool{}
	walk := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if proven[desc.Digest] {
			return nil, nil
		}
		proven[desc.Digest] = true
		children, err := images.Children(ctx, cs, desc)
		if errdefs.IsNotFound(err) {
			// Manifests of other platforms are not fetched.
			return nil, nil
		}
		return children, err
	})
	for _, img := range imgs {
		if !pulledWith(img.Labels, key) {
			continue
		}
		if err := images.Walk(ctx, walk, img.Target); err != nil {
			return nil, fmt.Errorf("image %s: %w", img.Name, err)
		}
	}
	return proven, nil
}

// fetchVerified reads desc from fetcher and checks that it is exactly
// desc's content; what it reads is dropped.
func fetchVerified(ctx context.Context, fetcher remotes.Fetcher, desc ocispec.Descriptor) error {
	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	verifier := desc.Digest.Verifier()
	n, err := io.Copy(verifier, io.LimitReader(rc, desc.Size+1))
	if err != nil {
		return err
	}
	if n != desc.Size || !verifier.Verified() {
		return errors.New("content does not match its digest")
	}
	return nil
}
