package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/volbackup"
)

// keyedMutex holds one lock per key.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*sync.Mutex{}
	}
	l, ok := k.locks[key]
	if !ok {
		l = &sync.Mutex{}
		k.locks[key] = l
	}
	k.mu.Unlock()
	l.Lock()
	return l.Unlock
}

// openRepo opens the volume's backup repository in its bucket.
func (a *Agent) openRepo(ctx context.Context, req *armadav1.VolumeRequest) (*volbackup.Repo, error) {
	b := req.GetBackup()
	if b == nil {
		return nil, errors.New("the volume has no backup bucket")
	}
	t, err := volbackup.ParseTarget(b.GetUrl())
	if err != nil {
		return nil, err
	}
	open := a.cfg.Buckets
	if open == nil {
		open = volbackup.S3
	}
	obj, err := open(t)
	if err != nil {
		return nil, err
	}
	return volbackup.Open(ctx, obj, volbackup.Root(t, req.GetApp(), req.GetVolume()), b.GetKey())
}

// snapshotOp runs a backup, a listing, or a restore against the volume's
// bucket. A backup that worked but whose cleanup failed returns both its
// result and the error.
func (a *Agent) snapshotOp(ctx context.Context, req *armadav1.VolumeRequest, dir string) (*armadav1.VolumeData, error) {
	unlock := a.repos.lock(req.GetApp() + "/" + req.GetVolume())
	defer unlock()
	repo, err := a.openRepo(ctx, req)
	if err != nil {
		return nil, err
	}
	switch req.GetOp() {
	case armadav1.VolumeRequest_OP_SNAPSHOTS:
		snaps, err := repo.Snapshots(ctx)
		if err != nil {
			return nil, err
		}
		m := &armadav1.VolumeData{}
		for _, s := range snaps {
			m.Snapshots = append(m.Snapshots, &armadav1.VolumeSnapshot{Id: s.ID, Time: timestamppb.New(s.Time)})
		}
		return m, nil
	case armadav1.VolumeRequest_OP_SNAPSHOT:
		if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("volume %s of %s does not exist on this node", req.GetVolume(), req.GetApp())
		}
		if req.GetStop() {
			if err := a.pause(ctx, req.GetApp()); err != nil {
				return nil, err
			}
		}
		now := time.Now()
		snap, st, err := repo.Backup(ctx, dir, a.cfg.NodeID, now)
		if req.GetStop() {
			a.resume(req.GetApp())
		}
		if err != nil {
			return nil, err
		}
		a.log.Info("backed up volume", "app", req.GetApp(), "volume", req.GetVolume(), "backup", snap.ID, "new_bytes", st.NewBytes)
		res := &armadav1.CreateVolumeSnapshotResponse{
			Snapshot: &armadav1.VolumeSnapshot{Id: snap.ID, Time: timestamppb.New(snap.Time), Files: int64(snap.Files), Bytes: snap.Bytes},
			NewBytes: st.NewBytes,
		}
		k := req.GetBackup().GetKeep()
		keep := spec.BackupKeep{Last: int(k.GetLast()), Hourly: int(k.GetHourly()), Daily: int(k.GetDaily()), Weekly: int(k.GetWeekly()), Monthly: int(k.GetMonthly())}
		loc := time.UTC
		if z := req.GetBackup().GetTimeZone(); z != "" {
			if l, err := time.LoadLocation(z); err == nil {
				loc = l
			}
		}
		u, err := repo.Prune(ctx, keep, loc, time.Now())
		res.StoredBytes, res.Snapshots = u.Stored, int32(min(u.Snapshots, 1<<30)) //nolint:gosec // bounded above
		if err != nil {
			return &armadav1.VolumeData{Snapshot: res}, fmt.Errorf("backed up as %s, but removing old backups failed: %w", snap.ID, err)
		}
		return &armadav1.VolumeData{Snapshot: res}, nil
	case armadav1.VolumeRequest_OP_RESTORE_SNAPSHOT:
		id := req.GetSnapshot()
		if id == "latest" {
			if id, err = repo.Latest(ctx); err != nil {
				return nil, err
			}
		}
		if err := a.pause(ctx, req.GetApp()); err != nil {
			return nil, err
		}
		defer a.resume(req.GetApp())
		var snap volbackup.Snapshot
		err := replaceDir(dir, func(w *entryWriter) error {
			var err error
			snap, err = repo.Restore(ctx, id, func(e volbackup.Entry, content io.Reader) error {
				if _, err := volbackup.CleanPath(e.Path); err != nil {
					return err
				}
				re := restoreEntry{Name: e.Path, Mode: fs.FileMode(e.Mode) & (fs.ModePerm | fs.ModeSticky), UID: e.UID, GID: e.GID,
					ModTime: time.Unix(0, e.ModTime), Link: e.Target, Size: e.Size}
				if len(e.Type) == 1 {
					re.Type = e.Type[0]
				}
				if e.Type == "d" {
					re.Mode |= fs.ModeDir
				}
				if content == nil {
					content = strings.NewReader("")
				}
				return w.write(re, content)
			})
			return err
		})
		if err != nil {
			return nil, err
		}
		a.log.Info("restored volume from backup", "app", req.GetApp(), "volume", req.GetVolume(), "backup", id)
		return &armadav1.VolumeData{Snapshot: &armadav1.CreateVolumeSnapshotResponse{
			Snapshot: &armadav1.VolumeSnapshot{Id: snap.ID, Time: timestamppb.New(snap.Time), Files: int64(snap.Files), Bytes: snap.Bytes},
		}}, nil
	}
	return nil, errors.New("unknown volume operation")
}
