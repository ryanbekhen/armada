package store

import (
	"context"
	"fmt"
)

// MarkAppRemoving marks app for removal. See Store.
func (s *Etcd) MarkAppRemoving(ctx context.Context, app, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		a, ok, err := t.app(app)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("app %s", app)
		}
		if a.Removing {
			return nil
		}
		rev, err := t.revision(a.TargetRevision)
		if err != nil {
			return err
		}
		if rev.Spec.IsJob() {
			return fmt.Errorf("%s is a job; delete it with `armada job delete`: %w", app, ErrPrecondition)
		}
		a.Removing = true
		if err := t.put(pfxApps+app, a); err != nil {
			return err
		}
		return t.audit(now, actor, "app.remove", app, "")
	})
}

// DeleteApp removes an app marked for removal. See Store.
func (s *Etcd) DeleteApp(ctx context.Context, app string) error {
	return s.tx(ctx, func(t *etx) error {
		a, ok, err := t.app(app)
		if err != nil || !ok {
			return err
		}
		if !a.Removing {
			return fmt.Errorf("app %s is not being removed: %w", app, ErrPrecondition)
		}
		left := false
		err = appReplicas(t, app, func(string, replicaRec) error {
			left = true
			return nil
		})
		if err != nil {
			return err
		}
		if left {
			return fmt.Errorf("app %s still has replicas: %w", app, ErrPrecondition)
		}
		// One operation each, however many revisions and secret versions:
		// a transaction has a bounded number of them.
		t.delete(pfxApps + app)
		t.deletePrefix(pfxRevs + app + "/")
		t.deletePrefix(pfxSecrets + app + "/")
		t.deletePrefix(pfxSecretSeq + app + "/")
		return nil
	})
}
