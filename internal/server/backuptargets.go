package server

import (
	"context"
	"errors"
	"net/netip"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/volbackup"
)

// checkBackupTargets lets only cluster-admins point an app's volume backups
// at a bucket on a private IP address (ADR 0041). Nodes reach the bucket
// from their own addresses, outside the space's network isolation, so a
// private address there would let a space reach the private network, the
// nodes, and other spaces' containers. A deploy, rollback, or secret change
// that keeps the private addresses of the revision the app is heading to is
// anyone's who may deploy it. value reads the URL secret sp would use; a
// secret that is not set yet is left to the backup itself to report.
func (s *Server) checkBackupTargets(ctx context.Context, acc access, appID string, sp *spec.App, value func(name string) ([]byte, bool, error)) error {
	if acc.admin() || sp == nil || !hasBackups(sp) {
		return nil
	}
	approved, err := s.approvedBackupIPs(ctx, appID)
	if err != nil {
		return err
	}
	for _, v := range sp.Volumes {
		if v.Backup == nil {
			continue
		}
		raw, ok, err := value(v.Backup.URLSecretRef)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		t, err := volbackup.ParseTarget(string(raw))
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "volume %s: %v", v.Name, err)
		}
		if ip, private := t.PrivateIP(); private && !approved[ip] {
			return status.Errorf(codes.PermissionDenied, "volume %s: a backup bucket on a private address (%s) needs cluster-admin, since nodes reach it from their own addresses; use an https:// bucket by name, or ask a cluster-admin to deploy it once", v.Name, ip)
		}
	}
	return nil
}

func hasBackups(sp *spec.App) bool {
	for _, v := range sp.Volumes {
		if v.Backup != nil {
			return true
		}
	}
	return false
}

// approvedBackupIPs returns the private bucket addresses of the revision
// the app is heading to (its target, else its active one).
func (s *Server) approvedBackupIPs(ctx context.Context, appID string) (map[netip.Addr]bool, error) {
	out := map[netip.Addr]bool{}
	a, err := s.store.GetApp(ctx, appID)
	if errors.Is(err, store.ErrNotFound) {
		return out, nil
	}
	if err != nil {
		return nil, storeErr(err)
	}
	rn := a.TargetRevision
	if rn == "" {
		rn = a.ActiveRevision
	}
	if rn == "" {
		return out, nil
	}
	rev, err := s.store.GetRevision(ctx, rn)
	if err != nil {
		return nil, storeErr(err)
	}
	if rev.Spec == nil || !hasBackups(rev.Spec) {
		return out, nil
	}
	vals, err := s.revisionSecrets(ctx, rev)
	if err != nil {
		return nil, err
	}
	for _, v := range rev.Spec.Volumes {
		if v.Backup == nil {
			continue
		}
		val, ok := vals[v.Backup.URLSecretRef]
		if !ok {
			continue
		}
		if t, err := volbackup.ParseTarget(string(val.Bytes())); err == nil {
			if ip, private := t.PrivateIP(); private {
				out[ip] = true
			}
		}
	}
	return out, nil
}

// revisionSecrets opens the secret versions rev pins.
func (s *Server) revisionSecrets(ctx context.Context, rev store.Revision) (map[string]secrets.Value, error) {
	revs := &revisionCache{store: s.store, keys: s.keys, m: map[string]store.Revision{}, opened: s.opened}
	vals, err := revs.secrets(ctx, rev)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "cannot read the app's backup secrets")
	}
	return vals, nil
}

// pinnedValue reads secrets from vals, the versions a revision pins.
func pinnedValue(vals map[string]secrets.Value) func(string) ([]byte, bool, error) {
	return func(name string) ([]byte, bool, error) {
		v, ok := vals[name]
		if !ok {
			return nil, false, nil
		}
		return v.Bytes(), true, nil
	}
}

// latestValue reads the latest version of an app's secret, the one a
// deploy pins.
func (s *Server) latestValue(ctx context.Context, appID string) func(string) ([]byte, bool, error) {
	var infos []store.SecretInfo
	listed := false
	return func(name string) ([]byte, bool, error) {
		if s.keys == nil {
			return nil, false, nil
		}
		if !listed {
			var err error
			if infos, err = s.store.ListSecrets(ctx, appID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, false, storeErr(err)
			}
			listed = true
		}
		for _, in := range infos {
			if in.Name != name {
				continue
			}
			sealed, err := s.store.GetSecret(ctx, appID, name, in.Version)
			if err != nil {
				return nil, false, storeErr(err)
			}
			v, err := s.keys.Open(sealed, appID, name, in.Version)
			if err != nil {
				return nil, false, status.Error(codes.FailedPrecondition, "cannot read the app's backup secrets")
			}
			return v.Bytes(), true, nil
		}
		return nil, false, nil
	}
}

// checkRollbackBackups runs checkBackupTargets on the revision a rollback
// restores, with the secret versions it pins.
func (s *Server) checkRollbackBackups(ctx context.Context, appID, target string) error {
	acc := accessFrom(ctx)
	if acc.admin() {
		return nil
	}
	rev, err := s.store.GetRevision(ctx, target)
	if err != nil {
		return storeErr(err)
	}
	if rev.App != appID || rev.Spec == nil || !hasBackups(rev.Spec) {
		return nil
	}
	vals, err := s.revisionSecrets(ctx, rev)
	if err != nil {
		return err
	}
	return s.checkBackupTargets(ctx, acc, appID, rev.Spec, pinnedValue(vals))
}

// checkSecretBackups runs checkBackupTargets when a secret change sets the
// bucket URL of the revision the app is heading to: a later deploy or
// rollout pins the new value.
func (s *Server) checkSecretBackups(ctx context.Context, appID, name string, value []byte) error {
	acc := accessFrom(ctx)
	if acc.admin() {
		return nil
	}
	a, err := s.store.GetApp(ctx, appID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return storeErr(err)
	}
	rn := a.TargetRevision
	if rn == "" {
		rn = a.ActiveRevision
	}
	if rn == "" {
		return nil
	}
	rev, err := s.store.GetRevision(ctx, rn)
	if err != nil {
		return storeErr(err)
	}
	if rev.Spec == nil {
		return nil
	}
	uses := false
	for _, v := range rev.Spec.Volumes {
		uses = uses || (v.Backup != nil && v.Backup.URLSecretRef == name)
	}
	if !uses {
		return nil
	}
	return s.checkBackupTargets(ctx, acc, appID, rev.Spec, func(n string) ([]byte, bool, error) {
		if n == name {
			return value, true, nil
		}
		return nil, false, nil
	})
}
