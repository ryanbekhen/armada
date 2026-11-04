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
	// Isolation is the project's kernel isolation level (spec.Isolation*),
	// pinned into every revision deployed into it.
	Isolation string
	// Quota bounds what it may reserve; zero is unlimited.
	Quota spec.Quota
}

type projectRec struct {
	Name      string      `json:"name"`
	CreatedAt int64       `json:"createdAt"`
	CreatedBy string      `json:"createdBy,omitempty"`
	Isolation string      `json:"isolation,omitempty"`
	Quota     *spec.Quota `json:"quota,omitempty"`
}

// defaultProjectRec holds the settings of the default project, which has
// no record under projects/.
type defaultProjectRec struct {
	Isolation string      `json:"isolation,omitempty"`
	Quota     *spec.Quota `json:"quota,omitempty"`
}

const (
	pfxProjects       = "projects/"
	keyDefaultProject = "default-project"
)

// projectIsolation returns project's kernel isolation level; container for
// the default project until an administrator changes it.
func (t *etx) projectIsolation(project string) (string, error) {
	if project == "" || project == spec.DefaultProject {
		var r defaultProjectRec
		if _, err := t.get(keyDefaultProject, &r); err != nil {
			return "", err
		}
		return orContainer(r.Isolation), nil
	}
	var r projectRec
	ok, err := t.get(pfxProjects+project, &r)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", notFoundf("project %s", project)
	}
	return orContainer(r.Isolation), nil
}

func orContainer(level string) string {
	if level == "" {
		return spec.IsolationContainer
	}
	return level
}

// checkProjectLimits refuses to serve rev again when its project now
// requires a stronger kernel isolation level, or a lower egress limit, than
// rev was deployed with.
func (t *etx) checkProjectLimits(rev Revision) error {
	project, _, _ := spec.SplitAppID(rev.App)
	level, err := t.projectIsolation(project)
	if err != nil {
		return err
	}
	if spec.IsolationRank(rev.Isolation) < spec.IsolationRank(level) {
		return fmt.Errorf("%s ran with isolation %s, and project %s now requires %s; deploy its spec again: %w", rev.Name, orContainer(rev.Isolation), project, level, ErrPrecondition)
	}
	q, err := t.projectQuota(project)
	if err != nil {
		return err
	}
	if limit := q.EgressBits; limit > 0 && (rev.EgressBits == 0 || rev.EgressBits > limit) {
		ran := "no egress limit"
		if rev.EgressBits > 0 {
			ran = "egress " + spec.FormatBitRate(rev.EgressBits)
		}
		return fmt.Errorf("%s ran with %s, and project %s now limits egress to %s; deploy its spec again: %w", rev.Name, ran, project, spec.FormatBitRate(limit), ErrPrecondition)
	}
	return nil
}

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
func (s *Etcd) CreateProject(ctx context.Context, name, isolation, actor, automation string) (Project, error) {
	if name == spec.DefaultProject {
		return Project{}, fmt.Errorf("project %s always exists: %w", name, ErrConflict)
	}
	if !spec.ValidProject(name) {
		return Project{}, fmt.Errorf("invalid project name %q: use lowercase letters, digits, and single hyphens, at most 30 characters", name)
	}
	if isolation == "" {
		isolation = spec.DefaultIsolation
	}
	if err := spec.CheckIsolation(isolation); err != nil {
		return Project{}, fmt.Errorf("%w: %w", err, ErrPrecondition)
	}
	now := s.now()
	p := Project{Name: name, CreatedAt: now.Truncate(time.Millisecond), CreatedBy: actor, Isolation: isolation}
	err := s.tx(ctx, func(t *etx) error {
		var r projectRec
		ok, err := t.get(pfxProjects+name, &r)
		if err != nil {
			return err
		}
		if ok {
			return fmt.Errorf("project %s already exists: %w", name, ErrConflict)
		}
		// A project an automation identity creates gets the identity's
		// quota (ADR 0029), so the projects a tool makes stay bounded.
		var quota spec.Quota
		if automation != "" {
			if quota, err = t.grantProject(automation, name); err != nil {
				return err
			}
		}
		p.Quota = quota
		if err := t.put(pfxProjects+name, projectRec{Name: name, CreatedAt: now.UnixMilli(), CreatedBy: actor, Isolation: isolation, Quota: quotaPtr(quota)}); err != nil {
			return err
		}
		return t.audit(now, actor, "project.create", name, "isolation "+isolation)
	})
	return p, err
}

// SetProjectIsolation changes a project's kernel isolation level. See
// Store.
func (s *Etcd) SetProjectIsolation(ctx context.Context, name, isolation, actor string) error {
	if err := spec.CheckIsolation(isolation); err != nil {
		return fmt.Errorf("%w: %w", err, ErrPrecondition)
	}
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		cur, err := t.projectIsolation(name)
		if err != nil {
			return err
		}
		if cur == isolation {
			return nil
		}
		if name == spec.DefaultProject {
			var r defaultProjectRec
			if _, err := t.get(keyDefaultProject, &r); err != nil {
				return err
			}
			r.Isolation = isolation
			if err := t.put(keyDefaultProject, r); err != nil {
				return err
			}
		} else {
			var r projectRec
			if _, err := t.get(pfxProjects+name, &r); err != nil {
				return err
			}
			r.Isolation = isolation
			if err := t.put(pfxProjects+name, r); err != nil {
				return err
			}
		}
		return t.audit(now, actor, "project.set", name, "isolation "+isolation)
	})
}

// GetProject returns one project. See Store.
func (s *Etcd) GetProject(ctx context.Context, name string) (Project, error) {
	var p Project
	err := s.view(ctx, func(t *etx) error {
		if name == spec.DefaultProject {
			var err error
			p, err = t.defaultProject()
			return err
		}
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
		def, err := t.defaultProject()
		if err != nil {
			return err
		}
		out = []Project{def}
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
	return Project{Name: r.Name, CreatedAt: fromMS(r.CreatedAt), CreatedBy: r.CreatedBy, Isolation: orContainer(r.Isolation), Quota: r.quota()}
}

// defaultProject returns the default project with its settings.
func (t *etx) defaultProject() (Project, error) {
	var r defaultProjectRec
	_, err := t.get(keyDefaultProject, &r)
	return Project{Name: spec.DefaultProject, Isolation: orContainer(r.Isolation), Quota: r.quota()}, err
}
