package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ryanbekhen/armada/internal/spec"
)

// ErrQuota is returned when a change would take a project past its quota
// (ADR 0029). It is a precondition failure.
var ErrQuota = fmt.Errorf("over quota: %w", ErrPrecondition)

// appUse is what one app holds against its project's quota: its target
// spec and desired replica count.
type appUse struct {
	sp       *spec.App
	replicas int
}

// quotaChange describes a change to check: apps whose target or count it
// sets, a secret name it adds, and a job attempt it starts.
type quotaChange struct {
	apps    map[string]appUse
	secret  string // "<app>/<name>"
	attempt bool
}

// appQuota returns what an app counts: its replicas (an autoscaled app its
// scale.max) and their reservations, one attempt of a job, its volumes.
func appQuota(sp *spec.App, replicas int) spec.Quota {
	var q spec.Quota
	if sp.IsJob() {
		q.CPUMillis, q.MemoryBytes = sp.CPUMillis(), sp.MemoryBytes()
	} else {
		n := replicas
		if sp.Autoscaled() {
			_, hi := sp.ScaleBounds()
			n = max(n, hi)
		}
		q.Replicas, q.CPUMillis, q.MemoryBytes = n, int64(n)*sp.CPUMillis(), int64(n)*sp.MemoryBytes()
	}
	q.Volumes = len(sp.Volumes)
	return q
}

func addQuota(a, b spec.Quota) spec.Quota {
	a.CPUMillis += b.CPUMillis
	a.MemoryBytes += b.MemoryBytes
	a.Replicas += b.Replicas
	a.Volumes += b.Volumes
	a.Domains += b.Domains
	a.Secrets += b.Secrets
	a.Jobs += b.Jobs
	return a
}

// usage returns what every project uses, with change applied when it is
// not nil.
func (t *etx) usage(change *quotaChange) (map[string]spec.Quota, error) {
	out := map[string]spec.Quota{}
	domains := map[string]map[string]bool{}
	count := func(id string, u appUse) {
		p := projectOf(id)
		out[p] = addQuota(out[p], appQuota(u.sp, u.replicas))
		if u.sp.Ingress != nil && u.sp.Ingress.Type == spec.IngressExternal {
			for _, d := range u.sp.Ingress.Domains {
				if domains[p] == nil {
					domains[p] = map[string]bool{}
				}
				domains[p][d] = true
			}
		}
	}
	seen := map[string]bool{}
	err := listInto(t, pfxApps, func(_ string, a appRec) error {
		seen[a.Name] = true
		if change != nil {
			if u, ok := change.apps[a.Name]; ok {
				count(a.Name, u)
				return nil
			}
		}
		rev, err := t.revision(a.TargetRevision)
		if err != nil {
			return err
		}
		count(a.Name, appUse{sp: rev.Spec, replicas: a.Replicas})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if change != nil {
		for id, u := range change.apps {
			if !seen[id] {
				count(id, u)
			}
		}
	}
	for p, ds := range domains {
		q := out[p]
		q.Domains = len(ds)
		out[p] = q
	}

	names := map[string]bool{}
	kvs, err := t.list(pfxSecrets)
	if err != nil {
		return nil, err
	}
	for _, e := range kvs {
		rest := strings.TrimPrefix(e.key, pfxSecrets)
		if i := strings.LastIndex(rest, "/"); i > 0 {
			names[rest[:i]] = true
		}
	}
	if change != nil && change.secret != "" {
		names[change.secret] = true
	}
	for n := range names {
		app, _, _ := strings.Cut(n, "/")
		p := projectOf(app)
		q := out[p]
		q.Secrets++
		out[p] = q
	}

	reps, err := t.list(pfxReplicas)
	if err != nil {
		return nil, err
	}
	for _, e := range reps {
		var r replicaRec
		if err := json.Unmarshal(e.val, &r); err != nil {
			return nil, fmt.Errorf("decode %s: %w", e.key, err)
		}
		if r.Run != 0 && !r.Done {
			p := projectOf(r.App)
			q := out[p]
			q.Jobs++
			out[p] = q
		}
	}
	return out, nil
}

// checkQuota refuses change if it takes project past its quota where the
// project did not already use as much.
func (t *etx) checkQuota(project string, change quotaChange) error {
	q, err := t.projectQuota(project)
	if err != nil || q.IsZero() {
		return err
	}
	before, err := t.usage(nil)
	if err != nil {
		return err
	}
	after, err := t.usage(&change)
	if err != nil {
		return err
	}
	b, a := before[project], after[project]
	if change.attempt {
		a.Jobs++
	}
	if over := q.Exceeded(b, a); len(over) > 0 {
		return fmt.Errorf("project %s would use %s (armada project show %s): %w", project, strings.Join(over, ", "), project, ErrQuota)
	}
	return nil
}

// projectQuota returns project's quota; zero is unlimited.
func (t *etx) projectQuota(project string) (spec.Quota, error) {
	if project == "" || project == spec.DefaultProject {
		var r defaultProjectRec
		_, err := t.get(keyDefaultProject, &r)
		return r.quota(), err
	}
	var r projectRec
	ok, err := t.get(pfxProjects+project, &r)
	if err != nil {
		return spec.Quota{}, err
	}
	if !ok {
		return spec.Quota{}, notFoundf("project %s", project)
	}
	return r.quota(), nil
}

// SetProjectQuota replaces a project's quota. See Store.
func (s *Etcd) SetProjectQuota(ctx context.Context, name string, q spec.Quota, actor string) error {
	if err := spec.CheckQuota(q); err != nil {
		return fmt.Errorf("%w: %w", err, ErrPrecondition)
	}
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		if name == spec.DefaultProject {
			var r defaultProjectRec
			if _, err := t.get(keyDefaultProject, &r); err != nil {
				return err
			}
			r.Quota = quotaPtr(q)
			if err := t.put(keyDefaultProject, r); err != nil {
				return err
			}
		} else {
			var r projectRec
			ok, err := t.get(pfxProjects+name, &r)
			if err != nil {
				return err
			}
			if !ok {
				return notFoundf("project %s", name)
			}
			r.Quota = quotaPtr(q)
			if err := t.put(pfxProjects+name, r); err != nil {
				return err
			}
		}
		return t.audit(now, actor, "project.set", name, "quota "+q.String())
	})
}

// ProjectUsage returns what every project uses. See Store.
func (s *Etcd) ProjectUsage(ctx context.Context) (map[string]spec.Quota, error) {
	var out map[string]spec.Quota
	err := s.view(ctx, func(t *etx) error {
		var err error
		out, err = t.usage(nil)
		return err
	})
	return out, err
}

func quotaPtr(q spec.Quota) *spec.Quota {
	if q.IsZero() {
		return nil
	}
	return &q
}

func (r projectRec) quota() spec.Quota {
	if r.Quota == nil {
		return spec.Quota{}
	}
	return *r.Quota
}

func (r defaultProjectRec) quota() spec.Quota {
	if r.Quota == nil {
		return spec.Quota{}
	}
	return *r.Quota
}
