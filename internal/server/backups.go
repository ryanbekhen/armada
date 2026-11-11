package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/volbackup"
)

// Scheduled volume backups (ADR 0041).
const (
	defaultBackupInterval = 30 * time.Second
	// backupRetry is the longest wait after a failed backup.
	backupRetry = 5 * time.Minute
	// backupTimeout bounds one backup or restore.
	backupTimeout = 6 * time.Hour
)

// backupRuns tracks the backups in flight: one per volume, one per node.
type backupRuns struct {
	mu      sync.Mutex
	volumes map[string]bool
	nodes   map[string]bool
}

func newBackupRuns() *backupRuns {
	return &backupRuns{volumes: map[string]bool{}, nodes: map[string]bool{}}
}

// start claims the volume and, for scheduled backups, its node; false if
// either is busy.
func (b *backupRuns) start(volume, node string, scheduled bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.volumes[volume] || (scheduled && b.nodes[node]) {
		return false
	}
	b.volumes[volume] = true
	if scheduled {
		b.nodes[node] = true
	}
	return true
}

func (b *backupRuns) done(volume, node string, scheduled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.volumes, volume)
	if scheduled {
		delete(b.nodes, node)
	}
}

func (s *Server) backupLoop(ctx context.Context) {
	t := time.NewTicker(s.backupInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := s.scheduleBackups(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("volume backups", "err", err)
		}
	}
}

// backupDue is when a volume's next backup is due: on the schedule after
// the last success, and after a failure no later than backupRetry.
func backupDue(b *spec.VolumeBackup, st store.VolumeBackupState) time.Time {
	due := b.Next(st.LastAt)
	if st.FailedAt.After(st.LastAt) {
		retry := st.FailedAt.Add(backupRetry)
		if b.Every != 0 && b.Every.D() < backupRetry {
			retry = st.FailedAt.Add(b.Every.D())
		}
		if retry.After(due) {
			due = retry
		}
	}
	return due
}

// volumeBackupSpec returns the backup settings of a volume from the
// revision the app serves (or rolls out, before it serves any), with that
// revision.
func (s *Server) volumeBackupSpec(ctx context.Context, app, name string) (*spec.VolumeBackup, store.Revision, error) {
	a, err := s.store.GetApp(ctx, app)
	if err != nil {
		return nil, store.Revision{}, err
	}
	revName := a.ActiveRevision
	if revName == "" {
		revName = a.TargetRevision
	}
	if revName == "" {
		return nil, store.Revision{}, nil
	}
	rev, err := s.store.GetRevision(ctx, revName)
	if err != nil {
		return nil, store.Revision{}, err
	}
	for _, v := range rev.Spec.Volumes {
		if v.Name == name && v.Backup != nil {
			return v.Backup, rev, nil
		}
	}
	return nil, rev, nil
}

// scheduleBackups starts the backups that are due.
func (s *Server) scheduleBackups(ctx context.Context) error {
	vols, err := s.store.ListVolumes(ctx, "")
	if err != nil {
		return err
	}
	now := s.now()
	for _, v := range vols {
		b, rev, err := s.volumeBackupSpec(ctx, v.App, v.Name)
		if errors.Is(err, store.ErrNotFound) || (err == nil && b == nil) {
			continue // the app is gone, or the volume has no backups
		}
		if err != nil {
			return err
		}
		if backupDue(b, v.Backup).After(now) {
			continue
		}
		if _, measured := s.usage.volume(v.Node, v.App, v.Name, now); !measured {
			continue // its node has not reported the volume's directory yet
		}
		sess := s.session(v.Node)
		s.condition(ctx, "backup-agent:"+v.App+"/"+v.Name, sess != nil && !sess.backups, store.Event{Kind: eventApp, Object: v.App, App: v.App, Node: v.Node,
			Reason: "VolumeBackupUnsupported", Message: fmt.Sprintf("volume %s is not backed up: the agent on node %s is too old; upgrade it", v.Name, v.Node)})
		if sess == nil || !sess.backups {
			continue
		}
		key := v.App + "/" + v.Name
		if !s.backups.start(key, v.Node, true) {
			continue
		}
		go func() {
			defer s.backups.done(key, v.Node, true)
			_, _ = s.runSnapshot(ctx, v, b, rev)
		}()
	}
	return nil
}

// backupTarget builds the request's bucket and key from the revision's
// pinned secrets.
func (s *Server) backupTarget(ctx context.Context, b *spec.VolumeBackup, rev store.Revision) (*armadav1.BackupTarget, error) {
	revs := &revisionCache{store: s.store, keys: s.keys, m: map[string]store.Revision{}, opened: s.opened}
	vals, err := revs.secrets(ctx, rev)
	if err != nil {
		return nil, err
	}
	url, ok := vals[b.URLSecretRef]
	key, ok2 := vals[b.KeySecretRef]
	if !ok || !ok2 {
		return nil, errors.New("the backup's secrets are not set")
	}
	if _, err := volbackup.ParseTarget(string(url.Bytes())); err != nil {
		return nil, err
	}
	if len(key.Bytes()) < spec.MinBackupKeyLen {
		return nil, fmt.Errorf("secret %s must hold at least %d bytes to encrypt backups", b.KeySecretRef, spec.MinBackupKeyLen)
	}
	k := b.Keep
	return &armadav1.BackupTarget{
		Url: string(url.Bytes()), Key: key.Bytes(), TimeZone: b.TimeZone,
		Keep: &armadav1.BackupKeep{Last: int32(k.Last), Hourly: int32(k.Hourly), Daily: int32(k.Daily), Weekly: int32(k.Weekly), Monthly: int32(k.Monthly)}, //nolint:gosec // bounded by spec.MaxBackupKeep
	}, nil
}

// runSnapshot backs a volume up on its node and records how it went.
func (s *Server) runSnapshot(ctx context.Context, v store.Volume, b *spec.VolumeBackup, rev store.Revision) (*armadav1.CreateVolumeSnapshotResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, backupTimeout)
	defer cancel()
	var res *armadav1.CreateVolumeSnapshotResponse
	target, err := s.backupTarget(ctx, b, rev)
	if err == nil {
		var m *armadav1.VolumeData
		m, err = s.repoOp(ctx, v.Node, &armadav1.VolumeRequest{Op: armadav1.VolumeRequest_OP_SNAPSHOT, App: v.App, Volume: v.Name, Stop: b.Stop, Backup: target})
		if m != nil {
			res = m.GetSnapshot()
		}
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return res, err // the leader is stepping down, or the caller left
	}
	id, stored, snaps, msg := "", int64(0), 0, ""
	if res.GetSnapshot() != nil {
		id, stored, snaps = res.GetSnapshot().GetId(), res.GetStoredBytes(), int(res.GetSnapshots())
	}
	if err != nil {
		msg = status.Convert(err).Message()
	}
	if rerr := s.store.RecordVolumeBackup(context.WithoutCancel(ctx), v.App, v.Name, id, stored, snaps, msg); rerr != nil {
		s.log.Warn("record volume backup", "app", v.App, "volume", v.Name, "err", rerr)
	}
	s.condition(ctx, "backup-failed:"+v.App+"/"+v.Name, err != nil, store.Event{Kind: eventApp, Object: v.App, App: v.App, Node: v.Node,
		Reason: "VolumeBackupFailed", Message: fmt.Sprintf("volume %s: %s", v.Name, msg)})
	if err != nil {
		s.log.Warn("volume backup failed", "app", v.App, "volume", v.Name, "node", v.Node, "err", msg)
	} else {
		s.log.Info("volume backed up", "app", v.App, "volume", v.Name, "backup", id, "new_bytes", res.GetNewBytes())
	}
	return res, err
}

// repoOp runs a bucket operation on node and returns the agent's answer:
// its last message, which may carry a result and an error together.
func (s *Server) repoOp(ctx context.Context, node string, req *armadav1.VolumeRequest) (*armadav1.VolumeData, error) {
	sess, err := s.openVolumeSession(ctx, node, req)
	if err != nil {
		return nil, err
	}
	defer sess.close()
	type answer struct {
		m   *armadav1.VolumeData
		err error
	}
	got := make(chan answer, 1)
	go func() {
		for {
			m, err := sess.agent.Recv()
			switch {
			case err != nil:
				got <- answer{err: status.Errorf(codes.Unavailable, "node %s ended the volume operation", node)}
			case m.GetError() != "":
				got <- answer{m: m, err: status.Error(codes.FailedPrecondition, m.GetError())}
			case m.GetDone():
				got <- answer{m: m}
			default:
				continue
			}
			return
		}
	}()
	select {
	case a := <-got:
		return a.m, a.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// repoNode picks where a bucket operation runs: the volume's node, or,
// when it is not connected and the operation needs no data, any connected
// node that backs volumes up.
func (s *Server) repoNode(v store.Volume, needsData bool) (string, error) {
	if sess := s.session(v.Node); sess != nil {
		if !sess.backups {
			return "", status.Errorf(codes.FailedPrecondition, "the agent on node %s is too old to back volumes up; upgrade it", v.Node)
		}
		return v.Node, nil
	}
	if needsData {
		return "", status.Errorf(codes.Unavailable, "node %s, which holds the volume, is not connected", v.Node)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	best := ""
	for id, sess := range s.sessions {
		if sess.backups && (best == "" || id < best) {
			best = id
		}
	}
	if best == "" {
		return "", status.Error(codes.Unavailable, "no connected node backs volumes up")
	}
	return best, nil
}

// backupFor returns the volume and its backup settings for an RPC.
func (s *Server) backupFor(ctx context.Context, app, name string) (store.Volume, *spec.VolumeBackup, store.Revision, error) {
	if err := checkVolumeArgs(app, name); err != nil {
		return store.Volume{}, nil, store.Revision{}, err
	}
	v, err := s.store.GetVolume(ctx, app, name)
	if err != nil {
		return v, nil, store.Revision{}, storeErr(err)
	}
	b, rev, err := s.volumeBackupSpec(ctx, app, name)
	if err != nil {
		return v, nil, rev, storeErr(err)
	}
	if b == nil {
		return v, nil, rev, status.Errorf(codes.FailedPrecondition, "the spec of %s has no backup for volume %s (volumes[].backup)", app, name)
	}
	return v, b, rev, nil
}

// ListVolumeSnapshots lists the backups in a volume's bucket.
func (s *Server) ListVolumeSnapshots(ctx context.Context, req *armadav1.ListVolumeSnapshotsRequest) (*armadav1.ListVolumeSnapshotsResponse, error) {
	if err := accessFrom(ctx).app(req.GetApp()); err != nil {
		return nil, err
	}
	v, b, rev, err := s.backupFor(ctx, req.GetApp(), req.GetName())
	if err != nil {
		return nil, err
	}
	node, err := s.repoNode(v, false)
	if err != nil {
		return nil, err
	}
	target, err := s.backupTarget(ctx, b, rev)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	m, err := s.repoOp(ctx, node, &armadav1.VolumeRequest{Op: armadav1.VolumeRequest_OP_SNAPSHOTS, App: v.App, Volume: v.Name, Backup: target})
	if err != nil {
		return nil, err
	}
	return &armadav1.ListVolumeSnapshotsResponse{Snapshots: m.GetSnapshots()}, nil
}

// CreateVolumeSnapshot backs a volume up now.
func (s *Server) CreateVolumeSnapshot(ctx context.Context, req *armadav1.CreateVolumeSnapshotRequest) (*armadav1.CreateVolumeSnapshotResponse, error) {
	if err := accessFrom(ctx).app(req.GetApp()); err != nil {
		return nil, err
	}
	v, b, rev, err := s.backupFor(ctx, req.GetApp(), req.GetName())
	if err != nil {
		return nil, err
	}
	if _, err := s.repoNode(v, true); err != nil {
		return nil, err
	}
	key := v.App + "/" + v.Name
	if !s.backups.start(key, v.Node, false) {
		return nil, status.Errorf(codes.Aborted, "a backup of volume %s of %s is already running", v.Name, v.App)
	}
	defer s.backups.done(key, v.Node, false)
	if err := s.store.RecordAudit(ctx, actor(ctx), "volume.snapshot", v.App, "volume="+v.Name); err != nil {
		return nil, storeErr(err)
	}
	res, err := s.runSnapshot(ctx, v, b, rev)
	if _, ok := status.FromError(err); err != nil && !ok {
		err = status.Error(codes.FailedPrecondition, err.Error())
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

// RestoreVolumeSnapshot replaces a volume's contents with a backup from its
// bucket, on its node or, while that node is not connected, on another.
func (s *Server) RestoreVolumeSnapshot(ctx context.Context, req *armadav1.RestoreVolumeSnapshotRequest) (*armadav1.RestoreVolumeResponse, error) {
	acc := accessFrom(ctx)
	if err := acc.app(req.GetApp()); err != nil {
		return nil, err
	}
	if req.GetNode() != "" && !acc.admin() {
		return nil, status.Error(codes.PermissionDenied, "restoring a volume onto another node needs cluster-admin")
	}
	if req.GetSnapshot() == "" || len(req.GetSnapshot()) > 64 {
		return nil, status.Error(codes.InvalidArgument, "name a backup, or latest")
	}
	v, b, rev, err := s.backupFor(ctx, req.GetApp(), req.GetName())
	if err != nil {
		return nil, err
	}
	node := v.Node
	if req.GetNode() != "" && req.GetNode() != node {
		node = req.GetNode()
		if _, err := s.store.GetNode(ctx, node); err != nil {
			return nil, storeErr(err)
		}
		// Never leave two copies that could both be written.
		if s.session(v.Node) != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "node %s, which holds the volume, is connected; restore without --node", v.Node)
		}
	}
	if sess := s.session(node); sess == nil || !sess.backups {
		return nil, status.Errorf(codes.Unavailable, "node %s is not connected, or its agent is too old to restore backups", node)
	}
	target, err := s.backupTarget(ctx, b, rev)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	key := v.App + "/" + v.Name
	if !s.backups.start(key, node, false) {
		return nil, status.Errorf(codes.Aborted, "a backup of volume %s of %s is running; try again when it is done", v.Name, v.App)
	}
	defer s.backups.done(key, node, false)
	if err := s.store.RecordAudit(ctx, actor(ctx), "volume.restore", v.App, fmt.Sprintf("volume=%s node=%s backup=%s", v.Name, node, req.GetSnapshot())); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("volume restore from backup", "app", v.App, "volume", v.Name, "node", node, "backup", req.GetSnapshot(), "by", actor(ctx))
	ctx, cancel := context.WithTimeout(ctx, backupTimeout)
	defer cancel()
	m, err := s.repoOp(ctx, node, &armadav1.VolumeRequest{Op: armadav1.VolumeRequest_OP_RESTORE_SNAPSHOT, App: v.App, Volume: v.Name, Backup: target, Snapshot: req.GetSnapshot()})
	if err != nil {
		return nil, err
	}
	if node != v.Node {
		if err := s.store.BindVolume(ctx, v.App, v.Name, node, actor(ctx)); err != nil {
			return nil, storeErr(err)
		}
		s.Trigger()
	}
	id := m.GetSnapshot().GetSnapshot().GetId()
	s.record(ctx, store.Event{Kind: eventApp, Object: v.App, App: v.App, Node: node, Reason: "VolumeRestored", Message: "volume " + v.Name + " on " + node + " from backup " + id})
	return &armadav1.RestoreVolumeResponse{Node: node}, nil
}

// volumeBackupInfo fills a listed volume's backup fields.
func volumeBackupInfo(out *armadav1.Volume, b *spec.VolumeBackup, st store.VolumeBackupState, now time.Time) {
	if b == nil {
		return
	}
	out.Backup = true
	if !st.LastAt.IsZero() {
		out.LastBackupAt = timestamppb.New(st.LastAt)
	}
	if st.FailedAt.After(st.LastAt) {
		out.BackupFailedAt, out.BackupError = timestamppb.New(st.FailedAt), st.Error
	}
	out.BackupStoredBytes, out.BackupSnapshots = st.Stored, int32(min(st.Snapshots, 1<<30)) //nolint:gosec // bounded above
	next := backupDue(b, st)
	if next.Before(now) {
		next = now // due
	}
	out.NextBackupAt = timestamppb.New(next)
}
