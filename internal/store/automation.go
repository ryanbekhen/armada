package store

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/ryanbekhen/armada/internal/spec"
)

// MaxAutomationCerts bounds the certificates recorded per automation
// identity; issuing more drops the oldest.
const MaxAutomationCerts = 8

// Automation is the scope of an automation identity (ADR 0029): a tool
// such as a CI system or a portal that manages projects for people,
// without administering the cluster. Only administrators change it.
type Automation struct {
	Name string
	// Projects it manages. The default project is never one of them.
	Projects []string
	// CreateProjects lets it create projects, which join Projects, and
	// remove the ones it manages.
	CreateProjects bool
	// Labels are the node label values its apps' placement.require may
	// name, per key; armada.* labels are always allowed.
	Labels map[string][]string
	// Quota is given to every project it creates; zero is unlimited.
	Quota     spec.Quota
	CreatedAt time.Time
	CreatedBy string
	// Certs are its valid certificates, newest last.
	Certs []NodeCert
}

// Manages reports whether a manages project.
func (a Automation) Manages(project string) bool {
	return project != spec.DefaultProject && slices.Contains(a.Projects, project)
}

type automationRec struct {
	Name           string              `json:"name"`
	Projects       []string            `json:"projects,omitempty"`
	CreateProjects bool                `json:"createProjects,omitempty"`
	Labels         map[string][]string `json:"labels,omitempty"`
	Quota          *spec.Quota         `json:"quota,omitempty"`
	CreatedAt      int64               `json:"createdAt"`
	CreatedBy      string              `json:"createdBy,omitempty"`
	Certs          []certRec           `json:"certs,omitempty"`
}

const pfxAutomation = "automation/"

// SetAutomation creates an automation identity or replaces its scope,
// keeping its certificates. Every project must exist.
func (s *Etcd) SetAutomation(ctx context.Context, a Automation, actor string) (Automation, error) {
	if err := CheckAutomation(a); err != nil {
		return Automation{}, err
	}
	now := s.now()
	var out Automation
	err := s.tx(ctx, func(t *etx) error {
		for _, p := range a.Projects {
			if err := t.projectExists(p); err != nil {
				return err
			}
		}
		var r automationRec
		ok, err := t.get(pfxAutomation+a.Name, &r)
		if err != nil {
			return err
		}
		action := "automation.update"
		if !ok {
			r = automationRec{Name: a.Name, CreatedAt: now.UnixMilli(), CreatedBy: actor}
			action = "automation.create"
		}
		r.Projects = slices.Compact(slices.Sorted(slices.Values(a.Projects)))
		r.CreateProjects = a.CreateProjects
		r.Labels = a.Labels
		r.Quota = quotaPtr(a.Quota)
		if err := t.put(pfxAutomation+a.Name, r); err != nil {
			return err
		}
		out = r.automation(now)
		detail := "projects=" + strings.Join(r.Projects, ",")
		if r.CreateProjects {
			detail += " create-projects"
		}
		if r.Quota != nil {
			detail += " quota=" + r.Quota.String()
		}
		return t.audit(now, actor, action, a.Name, detail)
	})
	return out, err
}

// CheckAutomation validates an automation scope's names and labels.
func CheckAutomation(a Automation) error {
	if !spec.ValidName(a.Name) {
		return fmt.Errorf("invalid automation name %q: use lowercase letters, digits, and single hyphens", a.Name)
	}
	if len(a.Projects) > 1000 {
		return fmt.Errorf("at most 1000 projects")
	}
	for _, p := range a.Projects {
		if p == spec.DefaultProject {
			return fmt.Errorf("automation identities cannot manage the default project: %w", ErrPrecondition)
		}
		if !spec.ValidProject(p) {
			return fmt.Errorf("invalid project %q", p)
		}
	}
	if len(a.Labels) > spec.MaxNodeLabels {
		return fmt.Errorf("at most %d label keys", spec.MaxNodeLabels)
	}
	if err := spec.CheckQuota(a.Quota); err != nil {
		return err
	}
	for k, vs := range a.Labels {
		if err := spec.CheckLabelKey(k); err != nil {
			return fmt.Errorf("label %q: %w", k, err)
		}
		if len(vs) == 0 || len(vs) > spec.MaxNodeLabels {
			return fmt.Errorf("label %s: give 1 to %d values", k, spec.MaxNodeLabels)
		}
		for _, v := range vs {
			if err := spec.CheckLabelValue(v); err != nil {
				return fmt.Errorf("label %s=%q: %w", k, v, err)
			}
		}
	}
	return nil
}

// GetAutomation returns an automation identity.
func (s *Etcd) GetAutomation(ctx context.Context, name string) (Automation, error) {
	var out Automation
	err := s.view(ctx, func(t *etx) error {
		var r automationRec
		ok, err := t.get(pfxAutomation+name, &r)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("automation %s", name)
		}
		out = r.automation(s.now())
		return nil
	})
	return out, err
}

// ListAutomations lists every automation identity by name.
func (s *Etcd) ListAutomations(ctx context.Context) ([]Automation, error) {
	var out []Automation
	err := s.view(ctx, func(t *etx) error {
		out = nil
		now := s.now()
		return listInto(t, pfxAutomation, func(_ string, r automationRec) error {
			out = append(out, r.automation(now))
			return nil
		})
	})
	return out, err
}

// DeleteAutomation removes an automation identity, which revokes every
// certificate it holds.
func (s *Etcd) DeleteAutomation(ctx context.Context, name, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var r automationRec
		ok, err := t.get(pfxAutomation+name, &r)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("automation %s", name)
		}
		t.delete(pfxAutomation + name)
		return t.audit(now, actor, "automation.delete", name, "")
	})
}

// RecordAutomationCert records a certificate issued to an existing
// automation identity and drops expired ones (and the oldest beyond
// MaxAutomationCerts). A non-empty keep (the serial of the certificate that
// asked for a renewal) revokes every other certificate.
func (s *Etcd) RecordAutomationCert(ctx context.Context, name string, c NodeCert, keep, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var r automationRec
		ok, err := t.get(pfxAutomation+name, &r)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("automation %s", name)
		}
		var certs []certRec
		for _, old := range r.Certs {
			if old.NotAfter > now.UnixMilli() && (keep == "" || old.Serial == keep) {
				certs = append(certs, old)
			}
		}
		certs = append(certs, certRec{Serial: c.Serial, NotAfter: c.NotAfter.UnixMilli()})
		if len(certs) > MaxAutomationCerts {
			certs = certs[len(certs)-MaxAutomationCerts:]
		}
		r.Certs = certs
		if err := t.put(pfxAutomation+name, r); err != nil {
			return err
		}
		return t.audit(now, actor, "automation.certificate", name, "serial="+c.Serial)
	})
}

// AutomationScope returns the identity's scope if serial is one of its
// valid certificates, and false otherwise (also when it does not exist).
func (s *Etcd) AutomationScope(ctx context.Context, name, serial string) (Automation, bool, error) {
	var out Automation
	allowed := false
	err := s.view(ctx, func(t *etx) error {
		var r automationRec
		ok, err := t.get(pfxAutomation+name, &r)
		if err != nil || !ok {
			allowed = false
			return err
		}
		out = r.automation(s.now())
		allowed = slices.ContainsFunc(out.Certs, func(c NodeCert) bool { return c.Serial == serial })
		return nil
	})
	return out, allowed, err
}

// grantProject adds project to automation's scope inside t; the identity
// must exist and be allowed to create projects.
func (t *etx) grantProject(automation, project string) (spec.Quota, error) {
	var r automationRec
	ok, err := t.get(pfxAutomation+automation, &r)
	if err != nil {
		return spec.Quota{}, err
	}
	if !ok || !r.CreateProjects {
		return spec.Quota{}, fmt.Errorf("automation %s may not create projects: %w", automation, ErrPrecondition)
	}
	if !slices.Contains(r.Projects, project) {
		r.Projects = append(r.Projects, project)
		slices.Sort(r.Projects)
	}
	var q spec.Quota
	if r.Quota != nil {
		q = *r.Quota
	}
	return q, t.put(pfxAutomation+automation, r)
}

// forgetProject removes a deleted project from every automation scope, so
// a project created later under the same name is not handed over.
func (t *etx) forgetProject(project string) error {
	kvs, err := t.list(pfxAutomation)
	if err != nil {
		return err
	}
	for _, e := range kvs {
		var r automationRec
		if err := json.Unmarshal(e.val, &r); err != nil {
			return fmt.Errorf("decode %s: %w", e.key, err)
		}
		if i := slices.Index(r.Projects, project); i >= 0 {
			r.Projects = slices.Delete(r.Projects, i, i+1)
			if err := t.put(e.key, r); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r automationRec) automation(now time.Time) Automation {
	a := Automation{Name: r.Name, Projects: slices.Clone(r.Projects), CreateProjects: r.CreateProjects,
		Labels: maps.Clone(r.Labels), CreatedAt: fromMS(r.CreatedAt), CreatedBy: r.CreatedBy}
	if r.Quota != nil {
		a.Quota = *r.Quota
	}
	for _, c := range r.Certs {
		if c.NotAfter > now.UnixMilli() {
			a.Certs = append(a.Certs, NodeCert{Serial: c.Serial, NotAfter: fromMS(c.NotAfter)})
		}
	}
	return a
}
