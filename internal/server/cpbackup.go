package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/volbackup"
)

// Scheduled backups of the control plane to a bucket (ADR 0051).
const (
	// metaCPBackup holds the settings; metaCPBackupState how the backups
	// went, written by the leader after each one.
	metaCPBackup      = "control-plane-backup"
	metaCPBackupState = "control-plane-backup-state"
	// The bucket URL and the key are sealed like the DNS token.
	cpBackupURLName = "backup-url"
	cpBackupKeyName = "backup-key"
	// cpBackupCondition is the key of the failure condition.
	cpBackupCondition = "control-plane-backup"
	// cpBackupObject names the control plane in its events.
	cpBackupObject = "control-plane"
)

// ControlPlaneBackup writes the files of a backup of this server's control
// plane (what `armadad backup` writes) into a directory and calls fn with
// it, removing the directory afterwards.
type ControlPlaneBackup func(ctx context.Context, fn func(dir string) error) error

// cpBackupSettings is the meta record of the control plane's backups.
type cpBackupSettings struct {
	EverySeconds int64           `json:"everySeconds,omitempty"`
	Schedule     string          `json:"schedule,omitempty"`
	TimeZone     string          `json:"timeZone,omitempty"`
	Keep         spec.BackupKeep `json:"keep"`
	// Bucket names the endpoint, bucket, and prefix, without the keys.
	Bucket     string          `json:"bucket,omitempty"`
	URL        *secrets.Sealed `json:"url,omitempty"`
	URLVersion int             `json:"urlVersion,omitempty"`
	Key        *secrets.Sealed `json:"key,omitempty"`
	KeyVersion int             `json:"keyVersion,omitempty"`
}

// on reports whether backups run.
func (c cpBackupSettings) on() bool { return c.URL != nil && c.Key != nil }

// plan is when backups run and which stay, as a volume's backup says it.
func (c cpBackupSettings) plan() *spec.VolumeBackup {
	return &spec.VolumeBackup{Every: spec.Duration(time.Duration(c.EverySeconds) * time.Second), Schedule: c.Schedule, TimeZone: c.TimeZone, Keep: c.Keep}
}

// cpBackupState is how the control plane's backups went. It counts only
// while URLVersion and KeyVersion are the settings' own: a new bucket or
// key starts afresh.
type cpBackupState struct {
	URLVersion int       `json:"urlVersion"`
	KeyVersion int       `json:"keyVersion"`
	LastAt     time.Time `json:"lastAt,omitzero"`
	LastID     string    `json:"lastId,omitempty"`
	LastServer string    `json:"lastServer,omitempty"`
	LastBytes  int64     `json:"lastBytes,omitempty"`
	Stored     int64     `json:"stored,omitempty"`
	Snapshots  int       `json:"snapshots,omitempty"`
	FailedAt   time.Time `json:"failedAt,omitzero"`
	Error      string    `json:"error,omitempty"`
}

func (s *Server) readMeta(ctx context.Context, key string, v any) error {
	raw, err := s.store.GetMeta(ctx, key)
	if errors.Is(err, store.ErrNotFound) || (err == nil && raw == "") {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(raw), v); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	return nil
}

func (s *Server) writeMeta(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.store.SetMeta(ctx, key, string(b))
}

func (s *Server) cpBackupSettings(ctx context.Context) (cpBackupSettings, error) {
	var c cpBackupSettings
	return c, s.readMeta(ctx, metaCPBackup, &c)
}

// cpBackupState reads the state of the settings' bucket and key.
func (s *Server) cpBackupState(ctx context.Context, set cpBackupSettings) (cpBackupState, error) {
	var st cpBackupState
	if err := s.readMeta(ctx, metaCPBackupState, &st); err != nil {
		return cpBackupState{}, err
	}
	if st.URLVersion != set.URLVersion || st.KeyVersion != set.KeyVersion {
		return cpBackupState{URLVersion: set.URLVersion, KeyVersion: set.KeyVersion}, nil
	}
	return st, nil
}

// cpBackupDue is when the next backup is due: on the plan after the last
// success, and after a failure no later than backupRetry.
func cpBackupDue(set cpBackupSettings, st cpBackupState) time.Time {
	return backupDue(set.plan(), store.VolumeBackupState{LastAt: st.LastAt, FailedAt: st.FailedAt})
}

// setControlPlaneBackup stores the backup settings the request names. The
// URL and the key are sealed and never logged, audited, or returned.
func (s *Server) setControlPlaneBackup(ctx context.Context, req *armadav1.SetClusterConfigRequest) error {
	changes := req.GetSetBackupPlan() || req.GetSetBackupKeep() || req.GetSetBackupUrl() || req.GetSetBackupKey()
	if !changes && !req.GetSetBackupOff() {
		return nil
	}
	if changes && req.GetSetBackupOff() {
		return status.Error(codes.InvalidArgument, "--backup none turns control plane backups off: give no other backup setting with it")
	}
	set, err := s.cpBackupSettings(ctx)
	if err != nil {
		return storeErr(err)
	}
	var what []string
	if req.GetSetBackupOff() {
		// The versions stay, so a later URL or key never reuses one.
		set = cpBackupSettings{URLVersion: set.URLVersion, KeyVersion: set.KeyVersion}
		what = append(what, "off")
	}
	c := req.GetConfig()
	if req.GetSetBackupPlan() {
		set.EverySeconds, set.Schedule, set.TimeZone = c.GetBackupEverySeconds(), strings.TrimSpace(c.GetBackupSchedule()), strings.TrimSpace(c.GetBackupTimeZone())
		if set.EverySeconds < 0 {
			return status.Error(codes.InvalidArgument, "the backup interval must be positive")
		}
		if set.EverySeconds != 0 {
			what = append(what, "every="+(time.Duration(set.EverySeconds)*time.Second).String())
		} else {
			what = append(what, "schedule="+set.Schedule)
		}
		if set.TimeZone != "" {
			what = append(what, "time_zone="+set.TimeZone)
		}
	}
	if req.GetSetBackupKeep() {
		k := c.GetBackupKeep()
		set.Keep = spec.BackupKeep{Last: int(k.GetLast()), Hourly: int(k.GetHourly()), Daily: int(k.GetDaily()), Weekly: int(k.GetWeekly()), Monthly: int(k.GetMonthly())}
		what = append(what, fmt.Sprintf("keep=last:%d,hourly:%d,daily:%d,weekly:%d,monthly:%d", set.Keep.Last, set.Keep.Hourly, set.Keep.Daily, set.Keep.Weekly, set.Keep.Monthly))
	}
	if (req.GetSetBackupUrl() || req.GetSetBackupKey()) && s.keys == nil {
		return status.Error(codes.FailedPrecondition, "this server has no master key to encrypt the backup URL and key with")
	}
	if req.GetSetBackupUrl() {
		raw := strings.TrimSpace(string(req.GetBackupUrl()))
		if raw == "" {
			return status.Error(codes.InvalidArgument, "the backup URL is empty; --backup none turns backups off")
		}
		t, err := volbackup.ParseTarget(raw)
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error()) // never holds the URL
		}
		sealed, err := s.keys.Seal(tokenScope, cpBackupURLName, set.URLVersion+1, secrets.NewValue([]byte(raw)))
		if err != nil {
			return status.Error(codes.Internal, "seal the backup URL")
		}
		set.URLVersion++
		set.URL, set.Bucket = &sealed, t.Endpoint+"/"+t.String()
		what = append(what, "url")
	}
	if req.GetSetBackupKey() {
		key := []byte(strings.TrimSpace(string(req.GetBackupKey())))
		if len(key) < spec.MinBackupKeyLen {
			return status.Errorf(codes.InvalidArgument, "the backup key must hold at least %d bytes", spec.MinBackupKeyLen)
		}
		sealed, err := s.keys.Seal(tokenScope, cpBackupKeyName, set.KeyVersion+1, secrets.NewValue(key))
		if err != nil {
			return status.Error(codes.Internal, "seal the backup key")
		}
		set.KeyVersion++
		set.Key = &sealed
		what = append(what, "key")
	}
	if !req.GetSetBackupOff() {
		if set.URL == nil || set.Key == nil {
			return status.Error(codes.FailedPrecondition, "control plane backups need a bucket and a key: --backup-url FILE --backup-key FILE, with --backup-every D (or --backup-schedule CRON) and --backup-keep N")
		}
		if set.EverySeconds == 0 && set.Schedule == "" {
			return status.Error(codes.InvalidArgument, "control plane backups need --backup-every D or --backup-schedule CRON")
		}
		if err := spec.CheckBackupPlan(set.plan()); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
	}
	if err := s.writeMeta(ctx, metaCPBackup, set); err != nil {
		return storeErr(err)
	}
	detail := strings.Join(what, " ")
	if err := s.store.RecordAudit(ctx, actor(ctx), "cluster.backup", "cluster", detail); err != nil {
		return storeErr(err)
	}
	s.log.Info("control plane backups changed", "changed", detail, "by", actor(ctx))
	select {
	case s.cpWake <- struct{}{}:
	default:
	}
	return nil
}

// controlPlaneBackupLoop backs the control plane up whenever it is due,
// one backup at a time, while this server leads.
func (s *Server) controlPlaneBackupLoop(ctx context.Context) {
	if s.cpBackup == nil {
		return
	}
	t := time.NewTicker(s.backupInterval)
	defer t.Stop()
	for {
		if err := s.controlPlaneBackupPass(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("control plane backups", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.cpWake:
		}
	}
}

// controlPlaneBackupPass runs a backup when one is due.
func (s *Server) controlPlaneBackupPass(ctx context.Context) error {
	set, err := s.cpBackupSettings(ctx)
	if err != nil {
		return err
	}
	if !set.on() {
		s.condition(ctx, cpBackupCondition, false, store.Event{Kind: eventCluster, Object: cpBackupObject, Reason: "ControlPlaneBackupFailed"})
		return nil
	}
	st, err := s.cpBackupState(ctx, set)
	if err != nil {
		return err
	}
	if cpBackupDue(set, st).After(s.now()) {
		return nil
	}
	return s.runControlPlaneBackup(ctx, set)
}

// runControlPlaneBackup backs the control plane up, prunes the bucket, and
// records how it went.
func (s *Server) runControlPlaneBackup(ctx context.Context, set cpBackupSettings) error {
	bctx, cancel := context.WithTimeout(ctx, backupTimeout)
	defer cancel()
	snap, usage, err := s.backUpControlPlane(bctx, set)
	if ctx.Err() != nil {
		return ctx.Err() // the leader is stepping down
	}
	st, rerr := s.cpBackupState(ctx, set)
	if rerr != nil {
		return rerr
	}
	now := s.now()
	if snap.ID != "" {
		st.LastAt, st.LastID, st.LastServer, st.LastBytes = snap.Time, snap.ID, s.name, snap.Bytes
		st.Stored, st.Snapshots = usage.Stored, usage.Snapshots
		st.FailedAt, st.Error = time.Time{}, ""
	}
	msg := ""
	if err != nil {
		msg = cleanMessage(status.Convert(err).Message())
		st.FailedAt, st.Error = now, msg
		s.cpFailures.Inc()
	}
	if werr := s.writeMeta(ctx, metaCPBackupState, st); werr != nil {
		s.log.Warn("record control plane backup", "err", werr)
	}
	s.condition(ctx, cpBackupCondition, err != nil, store.Event{Kind: eventCluster, Object: cpBackupObject,
		Reason: "ControlPlaneBackupFailed", Message: fmt.Sprintf("backup of the control plane to %s failed: %s", set.Bucket, msg)})
	if err != nil {
		s.log.Warn("control plane backup failed", "bucket", set.Bucket, "err", msg)
		return nil
	}
	s.log.Info("control plane backed up", "bucket", set.Bucket, "backup", snap.ID, "bytes", snap.Bytes, "kept", usage.Snapshots,
		"deleted", usage.DeletedSnapshots)
	return nil
}

// backUpControlPlane writes a snapshot to the bucket and prunes it. A
// snapshot with an ID worked even when the error says the pruning failed.
func (s *Server) backUpControlPlane(ctx context.Context, set cpBackupSettings) (volbackup.Snapshot, volbackup.Usage, error) {
	var snap volbackup.Snapshot
	if s.keys == nil {
		return snap, volbackup.Usage{}, errors.New("this server has no master key to open the backup URL and key with")
	}
	url, err := s.keys.Open(*set.URL, tokenScope, cpBackupURLName, set.URLVersion)
	if err != nil {
		return snap, volbackup.Usage{}, errors.New("open the backup URL: the master key does not match")
	}
	key, err := s.keys.Open(*set.Key, tokenScope, cpBackupKeyName, set.KeyVersion)
	if err != nil {
		return snap, volbackup.Usage{}, errors.New("open the backup key: the master key does not match")
	}
	t, err := volbackup.ParseTarget(string(url.Bytes()))
	if err != nil {
		return snap, volbackup.Usage{}, err
	}
	obj, err := s.cpBuckets(t)
	if err != nil {
		return snap, volbackup.Usage{}, err
	}
	repo, err := volbackup.Open(ctx, obj, volbackup.ControlPlaneRoot(t), key.Bytes())
	if err != nil {
		return snap, volbackup.Usage{}, err
	}
	err = s.cpBackup(ctx, func(dir string) error {
		var berr error
		snap, _, berr = repo.Backup(ctx, dir, s.name, s.now())
		return berr
	})
	if err != nil {
		return volbackup.Snapshot{}, volbackup.Usage{}, err
	}
	plan := set.plan()
	usage, err := repo.Prune(ctx, plan.Keep, plan.Location(), s.now())
	if err != nil {
		return snap, usage, fmt.Errorf("backup %s worked, but removing old backups failed: %w", snap.ID, err)
	}
	return snap, usage, nil
}

// controlPlaneBackupStatus is what cluster status shows; nil while backups
// are off.
func (s *Server) controlPlaneBackupStatus(ctx context.Context) (*armadav1.ControlPlaneBackupStatus, error) {
	set, err := s.cpBackupSettings(ctx)
	if err != nil || !set.on() {
		return nil, err
	}
	st, err := s.cpBackupState(ctx, set)
	if err != nil {
		return nil, err
	}
	out := &armadav1.ControlPlaneBackupStatus{
		Bucket: set.Bucket, LastSnapshot: st.LastID, LastServer: st.LastServer, LastSizeBytes: st.LastBytes,
		StoredBytes: st.Stored, Snapshots: int32(st.Snapshots), //nolint:gosec // bounded by the keep policy
		NextAt: timestamppb.New(cpBackupDue(set, st)),
	}
	if !st.LastAt.IsZero() {
		out.LastAt = timestamppb.New(st.LastAt)
	}
	if st.Error != "" {
		out.FailedAt, out.Error = timestamppb.New(st.FailedAt), st.Error
	}
	return out, nil
}

// controlPlaneBackupConfig fills the backup settings of the cluster's
// configuration.
func (s *Server) controlPlaneBackupConfig(ctx context.Context, cc *armadav1.ClusterConfig) error {
	set, err := s.cpBackupSettings(ctx)
	if err != nil || !set.on() {
		return err
	}
	k := set.Keep
	cc.BackupEverySeconds, cc.BackupSchedule, cc.BackupTimeZone, cc.BackupBucket = set.EverySeconds, set.Schedule, set.TimeZone, set.Bucket
	cc.BackupKeep = &armadav1.BackupKeep{Last: int32(k.Last), Hourly: int32(k.Hourly), Daily: int32(k.Daily), Weekly: int32(k.Weekly), Monthly: int32(k.Monthly)} //nolint:gosec // bounded by spec.MaxBackupKeep
	return nil
}
