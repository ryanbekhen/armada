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
// result and the error. Each step goes through armada-node when the agent
// has it (nativesnapshot.go), else through Go's volbackup.
func (a *Agent) snapshotOp(ctx context.Context, req *armadav1.VolumeRequest, dir string) (*armadav1.VolumeData, error) {
	unlock := a.repos.lock(req.GetApp() + "/" + req.GetVolume())
	defer unlock()
	if req.GetBackup() == nil {
		return nil, errors.New("the volume has no backup bucket")
	}
	switch req.GetOp() {
	case armadav1.VolumeRequest_OP_SNAPSHOTS:
		snaps, err := a.listSnapshots(ctx, req)
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
		snap, st, err := a.backupSnapshot(ctx, req, dir, time.Now())
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
		u, err := a.pruneSnapshots(ctx, req, time.Now())
		res.StoredBytes, res.Snapshots = u.Stored, int32(min(u.Snapshots, 1<<30)) //nolint:gosec // bounded above
		if err != nil {
			return &armadav1.VolumeData{Snapshot: res}, fmt.Errorf("backed up as %s, but removing old backups failed: %w", snap.ID, err)
		}
		return &armadav1.VolumeData{Snapshot: res}, nil
	case armadav1.VolumeRequest_OP_RESTORE_SNAPSHOT:
		snap, err := a.restoreSnapshot(ctx, req, dir)
		if err != nil {
			return nil, err
		}
		a.log.Info("restored volume from backup", "app", req.GetApp(), "volume", req.GetVolume(), "backup", snap.ID)
		return &armadav1.VolumeData{Snapshot: &armadav1.CreateVolumeSnapshotResponse{
			Snapshot: &armadav1.VolumeSnapshot{Id: snap.ID, Time: timestamppb.New(snap.Time), Files: int64(snap.Files), Bytes: snap.Bytes},
		}}, nil
	}
	return nil, errors.New("unknown volume operation")
}

// backupKeep is the request's keep policy and the zone it counts in.
func backupKeep(req *armadav1.VolumeRequest) (spec.BackupKeep, *time.Location) {
	k := req.GetBackup().GetKeep()
	keep := spec.BackupKeep{Last: int(k.GetLast()), Hourly: int(k.GetHourly()), Daily: int(k.GetDaily()), Weekly: int(k.GetWeekly()), Monthly: int(k.GetMonthly())}
	loc := time.UTC
	if z := req.GetBackup().GetTimeZone(); z != "" {
		if l, err := time.LoadLocation(z); err == nil {
			loc = l
		}
	}
	return keep, loc
}

// goBackup is Backup with Go's volbackup.
func (a *Agent) goBackup(ctx context.Context, req *armadav1.VolumeRequest, dir string, now time.Time) (volbackup.Snapshot, volbackup.Stats, error) {
	repo, err := a.openRepo(ctx, req)
	if err != nil {
		return volbackup.Snapshot{}, volbackup.Stats{}, err
	}
	return repo.Backup(ctx, dir, a.cfg.NodeID, now)
}

// goPrune is Prune with Go's volbackup.
func (a *Agent) goPrune(ctx context.Context, req *armadav1.VolumeRequest, now time.Time) (volbackup.Usage, error) {
	repo, err := a.openRepo(ctx, req)
	if err != nil {
		return volbackup.Usage{}, err
	}
	keep, loc := backupKeep(req)
	return repo.Prune(ctx, keep, loc, now)
}

// goSnapshots is Snapshots with Go's volbackup.
func (a *Agent) goSnapshots(ctx context.Context, req *armadav1.VolumeRequest) ([]volbackup.Snapshot, error) {
	repo, err := a.openRepo(ctx, req)
	if err != nil {
		return nil, err
	}
	return repo.Snapshots(ctx)
}

// goRestore resolves latest, pauses the app, and restores with Go's
// volbackup.
func (a *Agent) goRestore(ctx context.Context, req *armadav1.VolumeRequest, dir string) (volbackup.Snapshot, error) {
	repo, err := a.openRepo(ctx, req)
	if err != nil {
		return volbackup.Snapshot{}, err
	}
	id := req.GetSnapshot()
	if id == "latest" {
		if id, err = repo.Latest(ctx); err != nil {
			return volbackup.Snapshot{}, err
		}
	}
	if err := a.pause(ctx, req.GetApp()); err != nil {
		return volbackup.Snapshot{}, err
	}
	defer a.resume(req.GetApp())
	return goRestoreInto(ctx, repo, dir, id)
}

// goRestoreInto replaces dir with snapshot id, the app paused.
func goRestoreInto(ctx context.Context, repo *volbackup.Repo, dir, id string) (volbackup.Snapshot, error) {
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
	return snap, err
}
