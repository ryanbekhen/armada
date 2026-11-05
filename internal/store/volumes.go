package store

import (
	"context"
	"fmt"
	"time"

	"github.com/ryanbekhen/armada/internal/spec"
)

// Volume is a persistent volume of an app, bound to the node that holds its
// data (ADR 0023). It is created with the first replica that mounts it and
// outlives the app's spec until it is removed.
type Volume struct {
	App       string
	Name      string
	Node      string
	CreatedAt time.Time
}

type volumeRec struct {
	App       string `json:"app"`
	Name      string `json:"name"`
	Node      string `json:"node"`
	CreatedAt int64  `json:"createdAt"`
}

func volumeKey(app, name string) string { return pfxVolumes + app + "/" + name }

func (r volumeRec) volume() Volume {
	return Volume{App: r.App, Name: r.Name, Node: r.Node, CreatedAt: fromMS(r.CreatedAt)}
}

// bindVolumes binds the volumes a replica of rev mounts to node: unbound
// ones are created there, and one bound to another node is an
// ErrPrecondition.
func (t *etx) bindVolumes(rev Revision, node string, now time.Time) error {
	for _, v := range rev.Spec.Volumes {
		var rec volumeRec
		ok, err := t.get(volumeKey(rev.App, v.Name), &rec)
		if err != nil {
			return err
		}
		if ok {
			if rec.Node != node {
				return fmt.Errorf("volume %s of %s is on node %s, not %s: %w", v.Name, rev.App, rec.Node, node, ErrPrecondition)
			}
			continue
		}
		if err := t.put(volumeKey(rev.App, v.Name), volumeRec{App: rev.App, Name: v.Name, Node: node, CreatedAt: ms(now)}); err != nil {
			return err
		}
	}
	return nil
}

// ListVolumes returns the volumes of app, or of every app if app is empty.
func (s *Etcd) ListVolumes(ctx context.Context, app string) ([]Volume, error) {
	prefix := pfxVolumes
	if app != "" {
		prefix += app + "/"
	}
	var out []Volume
	err := s.view(ctx, func(t *etx) error {
		out = nil
		return listInto(t, prefix, func(_ string, r volumeRec) error {
			out = append(out, r.volume())
			return nil
		})
	})
	return out, err
}

// GetVolume returns one volume.
func (s *Etcd) GetVolume(ctx context.Context, app, name string) (Volume, error) {
	var out Volume
	err := s.view(ctx, func(t *etx) error {
		var r volumeRec
		ok, err := t.get(volumeKey(app, name), &r)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("volume %s of app %s", name, app)
		}
		out = r.volume()
		return nil
	})
	return out, err
}

// volumeInUse reports whether app's serving or target revision mounts name.
func (t *etx) volumeInUse(app, name string) (bool, error) {
	a, ok, err := t.app(app)
	if err != nil || !ok {
		return false, err
	}
	for _, rn := range []string{a.ActiveRevision, a.TargetRevision} {
		if rn == "" {
			continue
		}
		rev, err := t.revision(rn)
		if err != nil {
			return false, err
		}
		for _, v := range rev.Spec.Volumes {
			if v.Name == name {
				return true, nil
			}
		}
	}
	return false, nil
}

// DeleteVolume removes a volume's record. It refuses one the app's spec
// still mounts; the caller removes the data on the node first.
func (s *Etcd) DeleteVolume(ctx context.Context, app, name, actor string) error {
	return s.tx(ctx, func(t *etx) error {
		if _, ok, err := t.getRaw(volumeKey(app, name)); err != nil {
			return err
		} else if !ok {
			return notFoundf("volume %s of app %s", name, app)
		}
		if used, err := t.volumeInUse(app, name); err != nil {
			return err
		} else if used {
			return fmt.Errorf("app %s still mounts volume %s; deploy it without the volume first: %w", app, name, ErrPrecondition)
		}
		t.delete(volumeKey(app, name))
		return t.audit(s.now(), actor, "volume.delete", app, name)
	})
}

// BindVolume binds a volume to node, creating its record if there is none,
// for a restore onto another node. The app's replicas on other nodes are
// replaced by the reconciler.
func (s *Etcd) BindVolume(ctx context.Context, app, name, node, actor string) error {
	if !spec.ValidAppID(app) || !spec.ValidName(name) {
		return fmt.Errorf("invalid volume name: %w", ErrPrecondition)
	}
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		if _, ok, err := t.node(node); err != nil {
			return err
		} else if !ok {
			return notFoundf("node %s", node)
		}
		rec := volumeRec{App: app, Name: name, Node: node, CreatedAt: ms(now)}
		var old volumeRec
		if ok, err := t.get(volumeKey(app, name), &old); err != nil {
			return err
		} else if ok {
			if old.Node == node {
				return nil
			}
			rec.CreatedAt = old.CreatedAt
		}
		if err := t.put(volumeKey(app, name), rec); err != nil {
			return err
		}
		return t.audit(now, actor, "volume.bind", app, name+" node="+node)
	})
}
