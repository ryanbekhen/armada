package store

import (
	"context"
	"fmt"
	"time"
)

// Admin is an administrator the cluster knows by name (ADR 0028). Names it
// has no record of are accepted as before: certificates issued before
// administrators were recorded keep working until they are removed.
type Admin struct {
	Name string
	// Since refuses certificates of the name issued (NotBefore) before it;
	// zero accepts every one.
	Since time.Time
	// Removed refuses every certificate of the name.
	Removed bool
	AddedAt time.Time
	AddedBy string
}

type adminRec struct {
	Name    string `json:"name"`
	Since   int64  `json:"since,omitempty"`
	Removed bool   `json:"removed,omitempty"`
	AddedAt int64  `json:"addedAt,omitempty"`
	AddedBy string `json:"addedBy,omitempty"`
}

func (r adminRec) admin() Admin {
	a := Admin{Name: r.Name, Removed: r.Removed, AddedBy: r.AddedBy}
	if r.Since != 0 {
		a.Since = time.Unix(r.Since, 0)
	}
	if r.AddedAt != 0 {
		a.AddedAt = time.UnixMilli(r.AddedAt)
	}
	return a
}

const pfxAdmins = "admins/"

// AddAdmin records name as an administrator whose certificates issued
// before since are refused, so an earlier holder of the name loses access.
// It fails with ErrConflict while name is an administrator on record.
func (s *Etcd) AddAdmin(ctx context.Context, name string, since time.Time, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var r adminRec
		ok, err := t.get(pfxAdmins+name, &r)
		if err != nil {
			return err
		}
		if ok && !r.Removed {
			return fmt.Errorf("%s is already an administrator; remove it first to give the name a new certificate: %w", name, ErrConflict)
		}
		r = adminRec{Name: name, Since: since.Unix(), AddedAt: now.UnixMilli(), AddedBy: actor}
		if err := t.put(pfxAdmins+name, r); err != nil {
			return err
		}
		return t.audit(now, actor, "admin.add", name, "")
	})
}

// KnowAdmin records name, accepting all of its certificates, unless it is
// on record already; so administrators from before records show up in
// ListAdmins once they renew.
func (s *Etcd) KnowAdmin(ctx context.Context, name string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var r adminRec
		ok, err := t.get(pfxAdmins+name, &r)
		if err != nil || ok {
			return err
		}
		return t.put(pfxAdmins+name, adminRec{Name: name, AddedAt: now.UnixMilli()})
	})
}

// RemoveAdmin refuses every certificate of name from now on. The record
// stays, so the name is refused even when it was never on record.
func (s *Etcd) RemoveAdmin(ctx context.Context, name, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var r adminRec
		ok, err := t.get(pfxAdmins+name, &r)
		if err != nil {
			return err
		}
		if !ok {
			r = adminRec{Name: name}
		}
		r.Removed = true
		if err := t.put(pfxAdmins+name, r); err != nil {
			return err
		}
		return t.audit(now, actor, "admin.remove", name, "")
	})
}

// ListAdmins lists the administrators on record by name.
func (s *Etcd) ListAdmins(ctx context.Context) ([]Admin, error) {
	var out []Admin
	err := s.view(ctx, func(t *etx) error {
		out = nil
		return listInto(t, pfxAdmins, func(_ string, r adminRec) error {
			out = append(out, r.admin())
			return nil
		})
	})
	return out, err
}

// AdminAllowed reports whether an administrator certificate of name that
// starts at notBefore is accepted.
func (s *Etcd) AdminAllowed(ctx context.Context, name string, notBefore time.Time) (bool, error) {
	allowed := true
	err := s.view(ctx, func(t *etx) error {
		var r adminRec
		ok, err := t.get(pfxAdmins+name, &r)
		if err != nil || !ok {
			allowed = true
			return err
		}
		allowed = !r.Removed && notBefore.Unix() >= r.Since
		return nil
	})
	return allowed, err
}
