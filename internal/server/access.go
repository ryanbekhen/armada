package server

import (
	"context"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// need is what an AdminService method asks of a caller that is not
// cluster-admin (ADR 0033).
type need int

const (
	// needClusterAdmin is the zero value: methods missing from methodNeeds
	// are for cluster-admin only, including any added later.
	needClusterAdmin need = iota
	// needView, needDeploy, and needAdmin are the levels of the project
	// roles viewer, deployer, and admin, checked by each handler against
	// the project of what it touches.
	needView
	needDeploy
	needAdmin
	// needCreateProjects is the project-creator role.
	needCreateProjects
	// needSelf is any principal, acting on its own certificate.
	needSelf
)

const adminService = "/armada.v1.AdminService/"

// methodNeeds places every method a role other than cluster-admin may
// call. Handlers check the project of every app, job, volume, domain, and
// project they touch with access.
var methodNeeds = map[string]need{
	adminService + "Status":        needView,
	adminService + "ListApps":      needView,
	adminService + "GetAppSpec":    needView,
	adminService + "ListRevisions": needView,
	adminService + "ListSecrets":   needView,
	adminService + "ListVolumes":   needView,
	adminService + "ListDomains":   needView,
	adminService + "ListJobs":      needView,
	adminService + "ListJobRuns":   needView,
	adminService + "ListProjects":  needView,
	adminService + "Logs":          needView,
	adminService + "Top":           needView,
	adminService + "Events":        needView,

	adminService + "Deploy":       needDeploy,
	adminService + "Scale":        needDeploy,
	adminService + "Rollback":     needDeploy,
	adminService + "SetTraffic":   needDeploy,
	adminService + "SetSecret":    needDeploy,
	adminService + "DeleteSecret": needDeploy,
	adminService + "RunJob":       needDeploy,
	adminService + "CancelJob":    needDeploy,
	adminService + "VerifyDomain": needDeploy,

	adminService + "Exec":                  needAdmin,
	adminService + "BackupVolume":          needAdmin,
	adminService + "RestoreVolume":         needAdmin,
	adminService + "RemoveVolume":          needAdmin,
	adminService + "ListVolumeSnapshots":   needView,
	adminService + "CreateVolumeSnapshot":  needAdmin,
	adminService + "RestoreVolumeSnapshot": needAdmin,
	adminService + "RemoveApp":             needAdmin,
	adminService + "DeleteJob":             needAdmin,
	// Also project-creator, checked by the handler.
	adminService + "DeleteProject": needAdmin,

	adminService + "CreateProject": needCreateProjects,

	adminService + "RenewOwnCertificate": needSelf,
}

// roleLevel is the project level a role gives.
var roleLevel = map[string]need{
	store.RoleViewer:   needView,
	store.RoleDeployer: needDeploy,
	store.RoleAdmin:    needAdmin,
}

type accessKey struct{}

// access is what the caller of an AdminService method may reach.
type access struct {
	// id is the caller: a principal (user: or service:), or the server
	// itself (internalContext).
	id pki.Identity
	// p holds the principal's roles; nil for the server.
	p *store.Principal
	// need is what the method being called asks for.
	need need
}

// internalContext marks ctx as the server's own, for handlers it calls
// itself (the metrics collector) to see the whole cluster.
func (s *Server) internalContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, identityKey{}, pki.Identity{Kind: pki.KindServer, Name: "self"})
}

func accessFrom(ctx context.Context) access {
	if a, ok := ctx.Value(accessKey{}).(access); ok {
		return a
	}
	id, _ := IdentityFrom(ctx)
	return access{id: id}
}

// admin reports whether the caller has cluster-admin, or is the server
// itself (the API never authorizes a server identity).
func (a access) admin() bool {
	if a.id.Kind == pki.KindServer && a.p == nil {
		return true
	}
	return a.p != nil && a.p.Has(store.Grant{Role: store.RoleClusterAdmin})
}

// creates reports whether the caller may create projects.
func (a access) creates() bool {
	return a.admin() || (a.p != nil && a.p.Has(store.Grant{Role: store.RoleProjectCreator}))
}

// level is the most the caller's roles give in project.
func (a access) level(project string) need {
	if a.admin() {
		return needAdmin
	}
	if a.p == nil {
		return needClusterAdmin
	}
	best := needClusterAdmin
	for _, g := range a.p.Roles {
		l, ok := roleLevel[g.Role]
		if ok && (g.Project == project || (g.Project == "" && g.Role == store.RoleViewer)) && l > best {
			best = l
		}
	}
	return best
}

// reaches reports whether the caller's roles give anything a method of
// need could use, so a principal with no fitting role is refused before
// the handler runs.
func (a access) reaches(n need) bool {
	switch n {
	case needSelf:
		return true
	case needCreateProjects:
		return a.creates()
	case needView, needDeploy, needAdmin:
		for _, g := range a.p.Roles {
			if roleLevel[g.Role] >= n {
				return true
			}
		}
	}
	return false
}

// required is the project level the method being called asks for; a
// method placed elsewhere that still names a project asks for admin.
func (a access) required() need {
	if a.need >= needView && a.need <= needAdmin {
		return a.need
	}
	return needAdmin
}

func (a access) allows(project string) bool {
	if project == "" {
		project = spec.DefaultProject
	}
	return a.level(project) >= a.required()
}

// sees reports whether the caller may reach the app (or job) with ID id
// at the level of the method.
func (a access) sees(id string) bool {
	if a.admin() {
		return true
	}
	p, _, ok := spec.SplitAppID(id)
	return ok && a.allows(p)
}

// app returns PermissionDenied unless the caller may act on the app (or
// job) with ID id. The message is the same whether or not the app exists.
func (a access) app(id string) error {
	if a.sees(id) {
		return nil
	}
	return status.Errorf(codes.PermissionDenied, "%s may not %s %s", a.id, a.verb(), id)
}

// project returns PermissionDenied unless the caller may act in project.
func (a access) project(p string) error {
	if a.admin() || a.allows(p) {
		return nil
	}
	if p == "" {
		p = spec.DefaultProject
	}
	return status.Errorf(codes.PermissionDenied, "%s may not %s project %s", a.id, a.verb(), p)
}

func (a access) verb() string {
	switch a.required() {
	case needView:
		return "see"
	case needDeploy:
		return "deploy to"
	}
	return "manage"
}

// placement returns PermissionDenied if a spec requires node labels its
// caller may not name: restricted nodes may be kept for other projects.
func (a access) placement(sp *spec.App) error {
	if a.admin() || sp.Placement == nil {
		return nil
	}
	if a.p == nil {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	for k, vs := range sp.Placement.Require {
		if strings.HasPrefix(k, spec.ReservedLabelPrefix) {
			continue
		}
		allowed := a.p.Labels[k]
		for _, v := range vs {
			if !slices.Contains(allowed, v) {
				return status.Errorf(codes.PermissionDenied, "%s may not require node label %s=%s", a.id, k, v)
			}
		}
	}
	return nil
}
