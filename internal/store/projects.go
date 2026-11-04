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

// Project holds apps, jobs, secrets, domains, and volumes (ADR 0029). The
// default project always exists and has no record.
type Project struct {
	Name      string
	CreatedAt time.Time
	CreatedBy string
}

type projectRec struct {
	Name      string `json:"name"`
	CreatedAt int64  `json:"createdAt"`
	CreatedBy string `json:"createdBy,omitempty"`
}

const pfxProjects = "projects/"

// projectExists returns ErrPrecondition unless project is the default one
// or has a record.
func (t *etx) projectExists(project string) error {
	if project == "" || project == spec.DefaultProject {
		return nil
	}
	var r projectRec
	ok, err := t.get(pfxProjects+project, &r)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("project %s does not exist (create it with `armada project create %s`): %w", project, project, ErrPrecondition)
	}
	return nil
}

// CreateProject records a new project. See Store.
func (s *Etcd) CreateProject(ctx context.Context, name, actor, automation string) (Project, error) {
	if name == spec.DefaultProject {
		return Project{}, fmt.Errorf("project %s always exists: %w", name, ErrConflict)
	}
	if !spec.ValidProject(name) {
		return Project{}, fmt.Errorf("invalid project name %q: use lowercase letters, digits, and single hyphens, at most 30 characters", name)
	}
	now := s.now()
	p := Project{Name: name, CreatedAt: now.Truncate(time.Millisecond), CreatedBy: actor}
	err := s.tx(ctx, func(t *etx) error {
		var r projectRec
		ok, err := t.get(pfxProjects+name, &r)
		if err != nil {
			return err
		}
		if ok {
			return fmt.Errorf("project %s already exists: %w", name, ErrConflict)
		}
		if err := t.put(pfxProjects+name, projectRec{Name: name, CreatedAt: now.UnixMilli(), CreatedBy: actor}); err != nil {
			return err
		}
		if automation != "" {
			if err := t.grantProject(automation, name); err != nil {
				return err
			}
		}
		return t.audit(now, actor, "project.create", name, "")
	})
	return p, err
}

// GetProject returns one project. See Store.
func (s *Etcd) GetProject(ctx context.Context, name string) (Project, error) {
	if name == spec.DefaultProject {
		return Project{Name: name}, nil
	}
	var p Project
	err := s.view(ctx, func(t *etx) error {
		var r projectRec
		ok, err := t.get(pfxProjects+name, &r)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("project %s", name)
		}
		p = r.project()
		return nil
	})
	return p, err
}

// ListProjects lists every project, the default one first. See Store.
func (s *Etcd) ListProjects(ctx context.Context) ([]Project, error) {
	var out []Project
	err := s.view(ctx, func(t *etx) error {
		out = []Project{{Name: spec.DefaultProject}}
		return listInto(t, pfxProjects, func(_ string, r projectRec) error {
			out = append(out, r.project())
			return nil
		})
	})
	return out, err
}

// DeleteProject removes an empty project. See Store.
func (s *Etcd) DeleteProject(ctx context.Context, name, actor string) error {
	if name == spec.DefaultProject {
		return fmt.Errorf("project %s cannot be removed: %w", name, ErrPrecondition)
	}
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var r projectRec
		ok, err := t.get(pfxProjects+name, &r)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("project %s", name)
		}
		left, err := t.projectObjects(name)
		if err != nil {
			return err
		}
		if len(left) > 0 {
			return fmt.Errorf("project %s still holds %s; remove them first: %w", name, strings.Join(left, ", "), ErrPrecondition)
		}
		t.delete(pfxProjects + name)
		if err := t.forgetProject(name); err != nil {
			return err
		}
		return t.audit(now, actor, "project.delete", name, "")
	})
}

// projectObjects describes what is still stored under project: every key
// whose app ID belongs to it.
func (t *etx) projectObjects(project string) ([]string, error) {
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
			if p, _, ok := spec.SplitAppID(id); ok && p == project {
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

func (r projectRec) project() Project {
	return Project{Name: r.Name, CreatedAt: fromMS(r.CreatedAt), CreatedBy: r.CreatedBy}
}
