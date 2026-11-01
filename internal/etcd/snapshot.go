package etcd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/etcdutl/v3/snapshot"
	"go.uber.org/zap"

	"github.com/ryanbekhen/armada/internal/fsutil"
)

// Dial connects to the running member described by cfg, authenticating with
// the member certificate in cfg.Dir. It fails if the member is not running.
func Dial(ctx context.Context, cfg Config) (*clientv3.Client, error) {
	cfg = withDefaults(cfg)
	tlsCfg, err := clientTLS(cfg.Dir)
	if err != nil {
		return nil, err
	}
	u := memberURL(cfg.Addr, cfg.ClientPort)
	c, err := clientv3.New(clientv3.Config{Endpoints: []string{u.String()}, TLS: tlsCfg, DialTimeout: 3 * time.Second, Logger: zap.NewNop()})
	if err != nil {
		return nil, err
	}
	sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := c.Status(sctx, u.Host); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("etcd at %s: %w", u.Host, err)
	}
	return c, nil
}

// Snapshot writes a consistent snapshot of the keyspace to w. The stream
// ends with a SHA-256 of its content, which Restore verifies.
func Snapshot(ctx context.Context, c *clientv3.Client, w io.Writer) error {
	rc, err := c.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("etcd snapshot: %w", err)
	}
	defer rc.Close()
	if _, err := io.Copy(w, rc); err != nil {
		return fmt.Errorf("etcd snapshot: %w", err)
	}
	return nil
}

// Restore turns the snapshot file into the data of a new single-member
// cluster for cfg. cfg.Dir must not hold data yet. The snapshot's checksum
// is verified; a truncated or altered snapshot is rejected.
func Restore(snapshotFile string, cfg Config) error {
	cfg = withDefaults(cfg)
	if cfg.Name == "" {
		return errors.New("etcd: Name is required")
	}
	if err := fsutil.MkdirPrivate(cfg.Dir); err != nil {
		return err
	}
	data := filepath.Join(cfg.Dir, dirData)
	if _, err := os.Stat(data); err == nil {
		return fmt.Errorf("%s already exists", data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	peer := memberURL(cfg.Addr, cfg.PeerPort)
	err := snapshot.NewV3(zap.NewNop()).Restore(snapshot.RestoreConfig{
		SnapshotPath:        snapshotFile,
		Name:                cfg.Name,
		OutputDataDir:       data,
		PeerURLs:            []string{peer.String()},
		InitialCluster:      cfg.Name + "=" + peer.String(),
		InitialClusterToken: clusterToken,
	})
	if err != nil {
		_ = os.RemoveAll(data)
		return fmt.Errorf("restore etcd snapshot: %w", err)
	}
	return os.Chmod(data, 0o700) //nolint:gosec // a directory: owner-only, needs the execute bit
}
