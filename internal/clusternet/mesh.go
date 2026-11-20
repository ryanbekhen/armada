package clusternet

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/fsutil"
)

// maxMeshCache bounds the mesh peer list read back from disk.
const maxMeshCache = 4 << 20

// meshCacheOf is what the mesh mode keeps of a network configuration: the
// ranges and the peers, enough to bring the tunnel up before the control
// plane answers; isolation waits for the control plane.
func meshCacheOf(cfg *armadav1.NetworkConfig) *armadav1.NetworkConfig {
	return &armadav1.NetworkConfig{
		Mode:        cfg.GetMode(),
		ClusterCidr: cfg.GetClusterCidr(),
		MeshCidr:    cfg.GetMeshCidr(),
		Peers:       cfg.GetPeers(),
	}
}

// saveMeshCache writes the peer list of cfg to path (0600), unless the file
// already holds it.
func saveMeshCache(path string, cfg *armadav1.NetworkConfig) error {
	keep := meshCacheOf(cfg)
	if old, err := loadMeshCache(path); err == nil && old != nil && proto.Equal(old, keep) {
		return nil
	}
	data, err := protojson.MarshalOptions{Multiline: true}.Marshal(keep)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, data, 0o600)
}

// loadMeshCache reads the peer list saveMeshCache wrote, or returns nil when
// there is none. The file must be private to root, like the node's key.
func loadMeshCache(path string) (*armadav1.NetworkConfig, error) {
	data, err := fsutil.ReadPrivateFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) > maxMeshCache {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxMeshCache)
	}
	cfg := &armadav1.NetworkConfig{}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// RemoveMeshCache deletes the mesh peer list, for a node that leaves.
func RemoveMeshCache(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
