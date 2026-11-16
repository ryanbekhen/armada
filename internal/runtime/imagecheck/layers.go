// Package imagecheck checks that an image's layers are what its config
// says they are before a runtime reuses an unpacked layer for it.
//
// Unpacked layers are shared on a node by chain ID, which is computed
// from the diff IDs in an image's config, not from the layer blobs its
// manifest names. An unpacker that finds a chain already unpacked skips
// that layer's blob, so without a check an image whose config names
// another image's diff IDs would get that image's file system while
// serving blobs of its own. Layers checks that every layer blob really
// decompresses to its diff ID.
package imagecheck

import (
	"context"
	"fmt"
	"io"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/containerd/v2/pkg/labels"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Layers checks that each of blobs, read from cs, decompresses to the
// diff ID at the same index. A blob labelled with its uncompressed digest
// (set only after an unpacker verified it, or by this check) is not read
// again; one checked here gets the label when cs can keep labels.
func Layers(ctx context.Context, cs content.Store, blobs []ocispec.Descriptor, diffIDs []digest.Digest) error {
	if len(blobs) != len(diffIDs) {
		return fmt.Errorf("image has %d layers and %d diff IDs", len(blobs), len(diffIDs))
	}
	for i := range blobs {
		if err := Layer(ctx, cs, blobs[i], diffIDs[i]); err != nil {
			return err
		}
	}
	return nil
}

// Layer checks one layer blob against its diff ID.
func Layer(ctx context.Context, cs content.Store, blob ocispec.Descriptor, diffID digest.Digest) error {
	if err := diffID.Validate(); err != nil {
		return fmt.Errorf("layer %s: diff ID: %w", blob.Digest, err)
	}
	info, err := cs.Info(ctx, blob.Digest)
	if err != nil {
		return fmt.Errorf("layer %s: %w", blob.Digest, err)
	}
	if info.Labels[labels.LabelUncompressed] == diffID.String() {
		return nil
	}
	got, err := uncompressed(ctx, cs, blob, diffID.Algorithm())
	if err != nil {
		return fmt.Errorf("layer %s: %w", blob.Digest, err)
	}
	if got != diffID {
		return fmt.Errorf("layer %s does not match its diff ID %s in the image config", blob.Digest, diffID)
	}
	_, err = cs.Update(ctx, content.Info{Digest: blob.Digest, Labels: map[string]string{labels.LabelUncompressed: diffID.String()}},
		"labels."+labels.LabelUncompressed)
	if err != nil && !errdefs.IsFailedPrecondition(err) && !errdefs.IsNotImplemented(err) {
		return fmt.Errorf("layer %s: record its diff ID: %w", blob.Digest, err)
	}
	return nil
}

// uncompressed returns the digest of blob's decompressed content in alg.
func uncompressed(ctx context.Context, cs content.Provider, blob ocispec.Descriptor, alg digest.Algorithm) (digest.Digest, error) {
	if !alg.Available() {
		return "", fmt.Errorf("diff ID algorithm %q is not available", alg)
	}
	ra, err := cs.ReaderAt(ctx, blob)
	if err != nil {
		return "", err
	}
	defer func() { _ = ra.Close() }()
	r, err := compression.DecompressStream(content.NewReader(ra))
	if err != nil {
		return "", err
	}
	defer func() { _ = r.Close() }()
	d := alg.Digester()
	if _, err := io.Copy(d.Hash(), r); err != nil {
		return "", err
	}
	return d.Digest(), nil
}
