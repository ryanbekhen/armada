package store

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ryanbekhen/armada/internal/spec"
)

// Space holds apps, jobs, secrets, domains, and volumes (ADR 0026). The
// default space always exists and has no record.
type Space struct {
	Name      string
	CreatedAt time.Time
	CreatedBy string
}

type spaceRec struct {
	Name      string `json:"name"`
	CreatedAt int64  `json:"createdAt"`
	CreatedBy string `json:"createdBy,omitempty"`
}

const pfxSpaces = "spaces/"

// spaceExists returns ErrPrecondition unless space is the default one
// or has a record.
func (t *etx) spaceExists(space string) error {
	if space == "" || space == spec.DefaultSpace {
		return nil
	}
	var r spaceRec
	ok, err := t.get(pfxSpaces+space, &r)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("space %s does not exist (create it with `armada space create %s`): %w", space, space, ErrPrecondition)
	}
	return nil
}

// CreateSpace records a new space. See Store.
func (s *Etcd) CreateSpace(ctx context.Context, name, actor string, by *Principal) (Space, error) {
	if name == spec.DefaultSpace {
		return Space{}, fmt.Errorf("space %s always exists: %w", name, ErrConflict)
	}
	if !spec.ValidSpace(name) {
		return Space{}, fmt.Errorf("invalid space name %q: use lowercase letters, digits, and single hyphens, at most 30 characters", name)
	}
	now := s.now()
	p := Space{Name: name, CreatedAt: now.Truncate(time.Millisecond), CreatedBy: actor}
	err := s.tx(ctx, func(t *etx) error {
		var r spaceRec
		ok, err := t.get(pfxSpaces+name, &r)
		if err != nil {
			return err
		}
		if ok {
			return fmt.Errorf("space %s already exists: %w", name, ErrConflict)
		}
		if by != nil {
			if err := t.grantSpace(by.Kind, by.Name, name); err != nil {
				return err
			}
		}
		if err := t.put(pfxSpaces+name, spaceRec{Name: name, CreatedAt: now.UnixMilli(), CreatedBy: actor}); err != nil {
			return err
		}
		return t.audit(now, actor, "space.create", name, "")
	})
	return p, err
}

// GetSpace returns one space. See Store.
func (s *Etcd) GetSpace(ctx context.Context, name string) (Space, error) {
	var p Space
	err := s.view(ctx, func(t *etx) error {
		if name == spec.DefaultSpace {
			p = Space{Name: spec.DefaultSpace}
			return nil
		}
		var r spaceRec
		ok, err := t.get(pfxSpaces+name, &r)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("space %s", name)
		}
		p = r.space()
		return nil
	})
	return p, err
}

// ListSpaces lists every space, the default one first. See Store.
func (s *Etcd) ListSpaces(ctx context.Context) ([]Space, error) {
	var out []Space
	err := s.view(ctx, func(t *etx) error {
		out = []Space{{Name: spec.DefaultSpace}}
		return listInto(t, pfxSpaces, func(_ string, r spaceRec) error {
			out = append(out, r.space())
			return nil
		})
	})
	return out, err
}

// DeleteSpace removes an empty space. See Store.
func (s *Etcd) DeleteSpace(ctx context.Context, name, actor string) error {
	if name == spec.DefaultSpace {
		return fmt.Errorf("space %s cannot be removed: %w", name, ErrPrecondition)
	}
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var r spaceRec
		ok, err := t.get(pfxSpaces+name, &r)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("space %s", name)
		}
		left, err := t.spaceObjects(name)
		if err != nil {
			return err
		}
		if len(left) > 0 {
			return fmt.Errorf("space %s still holds %s; remove them first: %w", name, strings.Join(left, ", "), ErrPrecondition)
		}
		t.delete(pfxSpaces + name)
		if err := t.forgetSpace(name); err != nil {
			return err
		}
		return t.audit(now, actor, "space.delete", name, "")
	})
}

// spaceObjects describes what is still stored under space: every key
// whose app ID belongs to it.
func (t *etx) spaceObjects(space string) ([]string, error) {
	var left []string
	for _, c := range []struct{ prefix, what string }{
		{pfxApps, "apps"},
		{pfxSecrets, "secrets"},
		{pfxVolumes, "volumes"},
		{pfxRuns, "job runs"},
		{pfxReplicas, "replicas"},
	} {
		kvs, err := t.list(c.prefix)
		if err != nil {
			return nil, err
		}
		apps := map[string]bool{}
		for _, e := range kvs {
			id, _, _ := strings.Cut(strings.TrimPrefix(e.key, c.prefix), "/")
			if c.prefix == pfxReplicas {
				// Replica keys are replica IDs; the record names the app.
				var r replicaRec
				if err := json.Unmarshal(e.val, &r); err != nil {
					return nil, fmt.Errorf("decode %s: %w", e.key, err)
				}
				id = r.App
			}
			if p, _, ok := spec.SplitAppID(id); ok && p == space {
				apps[id] = true
			}
		}
		if len(apps) > 0 {
			names := make([]string, 0, len(apps))
			for id := range apps {
				names = append(names, id)
			}
			slices.Sort(names)
			left = append(left, fmt.Sprintf("%s (%s)", c.what, strings.Join(names, ", ")))
		}
	}
	return left, nil
}

func (r spaceRec) space() Space {
	return Space{Name: r.Name, CreatedAt: fromMS(r.CreatedAt), CreatedBy: r.CreatedBy}
}

// migrateSpaces moves records written while spaces were called projects
// to their current names (schema 10 to 11). Only records of spaces other
// than default carry the field, so the step writes few keys.
func migrateSpaces(t *etx) error {
	kvs, err := t.list("projects/")
	if err != nil {
		return err
	}
	for _, e := range kvs {
		if err := t.put(pfxSpaces+strings.TrimPrefix(e.key, "projects/"), json.RawMessage(e.val)); err != nil {
			return err
		}
	}
	t.deletePrefix("projects/")
	for _, pfx := range []string{pfxDomains, pfxRevs} {
		kvs, err := t.list(pfx)
		if err != nil {
			return err
		}
		for _, e := range kvs {
			b, changed, err := renameSpaceField(e.val, pfx == pfxRevs)
			if err != nil {
				return fmt.Errorf("decode %s: %w", e.key, err)
			}
			if changed {
				if err := t.put(e.key, json.RawMessage(b)); err != nil {
					return err
				}
			}
		}
	}
	for _, pfx := range []string{pfxUsers, pfxServices} {
		kvs, err := t.list(pfx)
		if err != nil {
			return err
		}
		for _, e := range kvs {
			b, changed, err := renameGrants(e.val)
			if err != nil {
				return fmt.Errorf("decode %s: %w", e.key, err)
			}
			if changed {
				if err := t.put(e.key, json.RawMessage(b)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// renameSpaceField renames a record's project field space; inSpec renames
// it in the record's spec (revisions) instead.
func renameSpaceField(b []byte, inSpec bool) ([]byte, bool, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, false, err
	}
	if inSpec {
		sp, changed, err := renameSpaceField(m["spec"], false)
		if err != nil || !changed {
			return b, false, err
		}
		m["spec"] = sp
		out, err := json.Marshal(m)
		return out, true, err
	}
	v, ok := m["project"]
	if !ok {
		return b, false, nil
	}
	delete(m, "project")
	m["space"] = v
	out, err := json.Marshal(m)
	return out, true, err
}

// renameGrants renames the project of a principal's grants space, and the
// project-creator role space-creator.
func renameGrants(b []byte) ([]byte, bool, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, false, err
	}
	if len(m["roles"]) == 0 {
		return b, false, nil
	}
	var roles []map[string]json.RawMessage
	if err := json.Unmarshal(m["roles"], &roles); err != nil {
		return nil, false, err
	}
	changed := false
	for _, g := range roles {
		if v, ok := g["project"]; ok {
			delete(g, "project")
			g["space"] = v
			changed = true
		}
		if string(g["role"]) == `"project-creator"` {
			g["role"] = json.RawMessage(`"` + RoleSpaceCreator + `"`)
			changed = true
		}
	}
	if !changed {
		return b, false, nil
	}
	r, err := json.Marshal(roles)
	if err != nil {
		return nil, false, err
	}
	m["roles"] = r
	out, err := json.Marshal(m)
	return out, true, err
}
