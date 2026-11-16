package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/oci"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// Record is what the agent keeps about a container it created, next to
// its OCI bundle: enough to list, adopt, and remove it after a restart.
type Record struct {
	ID      string            `json:"id"`
	Image   string            `json:"image"`
	Labels  map[string]string `json:"labels,omitempty"`
	Group   string            `json:"group"`
	Created time.Time         `json:"created"`
}

// Bundles keeps containers' OCI bundles under Dir/<id>: config.json, the
// root filesystem mounted at rootfs, and record.json.
type Bundles struct{ Dir string }

const (
	bundleConfig = "config.json"
	bundleRecord = "record.json"
	bundleRootfs = "rootfs"
)

// Path is the bundle directory of id.
func (b Bundles) Path(id string) string { return filepath.Join(b.Dir, id) }

// Create mounts the root filesystem, writes spec (its root set to the
// mounted rootfs), then the record last, so a bundle without a record is
// one that was never finished.
func (b Bundles) Create(rec Record, spec *specs.Spec, rootfs []mount.Mount) (string, error) {
	dir := b.Path(rec.ID)
	if err := os.MkdirAll(filepath.Join(dir, bundleRootfs), 0o700); err != nil {
		return "", err
	}
	if err := mount.All(rootfs, filepath.Join(dir, bundleRootfs)); err != nil {
		return "", fmt.Errorf("mount root filesystem: %w", err)
	}
	spec.Root = &specs.Root{Path: bundleRootfs, Readonly: spec.Root != nil && spec.Root.Readonly}
	if err := writeJSON(filepath.Join(dir, bundleConfig), spec); err != nil {
		return "", err
	}
	return dir, writeJSON(filepath.Join(dir, bundleRecord), rec)
}

// Remove unmounts the root filesystem and removes the bundle.
func (b Bundles) Remove(id string) error {
	dir := b.Path(id)
	if err := mount.UnmountAll(filepath.Join(dir, bundleRootfs), 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unmount root filesystem: %w", err)
	}
	return os.RemoveAll(dir)
}

// Records lists every finished bundle's record.
func (b Bundles) Records() ([]Record, error) {
	entries, err := os.ReadDir(b.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(b.Dir, e.Name(), bundleRecord))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var r Record
		if err := json.Unmarshal(data, &r); err != nil || r.ID != e.Name() {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// Spec reads a bundle's OCI spec.
func (b Bundles) Spec(id string) (*specs.Spec, error) {
	data, err := os.ReadFile(filepath.Join(b.Path(id), bundleConfig))
	if err != nil {
		return nil, err
	}
	var s specs.Spec
	return &s, json.Unmarshal(data, &s)
}

func writeJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil { //nolint:gosec // under the agent's data directory
		return err
	}
	return os.Rename(tmp, path)
}

// OCI returns what containerd's spec options read of an image and its
// snapshots (the image's configuration, its users and groups).
func (s *Images) OCI(img Image) (oci.Image, oci.Client) {
	return ociImage{s.content, img.Config}, ociClient{s.snap}
}

type ociImage struct {
	cs     content.Store
	config ocispec.Descriptor
}

func (i ociImage) Config(context.Context) (ocispec.Descriptor, error) { return i.config, nil }
func (i ociImage) ContentStore() content.Store                        { return i.cs }

type ociClient struct{ sn snapshots.Snapshotter }

func (c ociClient) SnapshotService(string) snapshots.Snapshotter { return c.sn }
