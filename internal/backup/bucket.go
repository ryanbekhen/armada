package backup

import (
	"context"
	"fmt"
	"io"

	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/volbackup"
)

// RestoreSnapshot restores snapshot id of the control plane's repository
// into dataDir, which must not exist or be empty, with the same checks as
// Restore: the snapshot holds the files Stage wrote.
func RestoreSnapshot(ctx context.Context, repo *volbackup.Repo, id, dataDir string, member etcd.Config) (Manifest, volbackup.Snapshot, error) {
	rs, err := NewRestorer(dataDir)
	if err != nil {
		return Manifest{}, volbackup.Snapshot{}, err
	}
	defer rs.Close()
	snap, err := repo.Restore(ctx, id, func(e volbackup.Entry, content io.Reader) error {
		switch {
		case e.Path == "." && e.Type == "d":
			return nil
		case e.Type != "f":
			return fmt.Errorf("unexpected entry %q in backup: only regular files are allowed", e.Path)
		}
		return rs.Add(e.Path, e.Size, content)
	})
	if err != nil {
		return Manifest{}, volbackup.Snapshot{}, err
	}
	m, err := rs.Finish(ctx, member)
	return m, snap, err
}
