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

// proveContent returns the handler wrapper a pull of ref with key's
// credentials runs before fetching each descriptor. Content on a node is
// shared by digest across every image name, and the fetch skips a blob
// that is already there, so without this a pull under a new name, from a
// registry its spec author runs, could take another space's private
// manifests and layers just by naming their digests. A blob already on
// the node is used as is only when an image pulled with the same
// credentials, or with none, holds it (pulledWith); any other is fetched
// again from this pull's registry and checked against its digest, so the
// registry must really serve it to these credentials.
func (d *Driver) proveContent(ctx context.Context, ref, key string, resolver remotes.Resolver) (func(images.Handler) images.Handler, error) {
	fetcher, err := resolver.Fetcher(ctx, ref)
	if err != nil {
		return nil, err
	}
	cs := d.ctr.ContentStore()
	var (
		once   sync.Once
		proven map[digest.Digest]bool
		perr   error
	)
	return func(next images.Handler) images.Handler {
		return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			if _, err := cs.Info(ctx, desc.Digest); err == nil {
				once.Do(func() { proven, perr = d.provenContent(ctx, cs, key) })
				if perr != nil {
					return nil, perr
				}
				if !proven[desc.Digest] {
					if err := fetchVerified(ctx, fetcher, desc); err != nil {
						return nil, fmt.Errorf("%s is on this node but its registry did not serve it to these credentials: %w", desc.Digest, err)
					}
				}
			}
			return next.Handle(ctx, desc)
		})
	}, nil
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
