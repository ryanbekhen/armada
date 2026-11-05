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

// automationMethods are the AdminService methods an automation identity
// may call (ADR 0026). Every other method, including any added later, is
// refused, and each of these checks the request against the identity's
// scope with access.
var automationMethods = map[string]bool{
	"/armada.v1.AdminService/Deploy":        true,
	"/armada.v1.AdminService/Status":        true,
	"/armada.v1.AdminService/Scale":         true,
	"/armada.v1.AdminService/SetTraffic":    true,
	"/armada.v1.AdminService/ListVolumes":   true,
	"/armada.v1.AdminService/RemoveVolume":  true,
	"/armada.v1.AdminService/BackupVolume":  true,
	"/armada.v1.AdminService/RestoreVolume": true,
	"/armada.v1.AdminService/Logs":          true,
	"/armada.v1.AdminService/ListDomains":   true,
	"/armada.v1.AdminService/VerifyDomain":  true,
	"/armada.v1.AdminService/ListRevisions": true,
	"/armada.v1.AdminService/Rollback":      true,
	"/armada.v1.AdminService/SetSecret":     true,
	"/armada.v1.AdminService/ListSecrets":   true,
	"/armada.v1.AdminService/DeleteSecret":  true,
	"/armada.v1.AdminService/Exec":          true,
	"/armada.v1.AdminService/Top":           true,
	"/armada.v1.AdminService/Events":        true,
	"/armada.v1.AdminService/RunJob":        true,
	"/armada.v1.AdminService/ListJobs":      true,
	"/armada.v1.AdminService/ListJobRuns":   true,
	"/armada.v1.AdminService/CancelJob":     true,
	"/armada.v1.AdminService/DeleteJob":     true,
	"/armada.v1.AdminService/CreateProject": true,
	"/armada.v1.AdminService/ListProjects":  true,
	"/armada.v1.AdminService/DeleteProject": true,
	// Only automation identities renew this way; administrators are
	// refused in the handler.
	"/armada.v1.AdminService/RenewAutomationCertificate": true,
}

type scopeKey struct{}

// access is what the caller of an admin RPC may reach: everything for an
// administrator, the projects of its scope for an automation identity.
type access struct {
	id    pki.Identity
	scope *store.Automation
}

// internalContext marks ctx as the server's own, for handlers it calls
// itself (the metrics collector) to see the whole cluster.
func (s *Server) internalContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, identityKey{}, pki.Identity{Kind: pki.KindServer, Name: "self"})
}

func accessFrom(ctx context.Context) access {
	id, _ := IdentityFrom(ctx)
	a := access{id: id}
	if sc, ok := ctx.Value(scopeKey{}).(store.Automation); ok && id.Kind == pki.KindAutomation {
		a.scope = &sc
	}
	return a
}

// admin reports whether the caller is an administrator, or the server
// itself (internalContext; the API never authorizes a server identity).
func (a access) admin() bool { return a.id.Kind == pki.KindAdmin || a.id.Kind == pki.KindServer }

// automation returns the name of the caller's automation identity, or "".
func (a access) automation() string {
	if a.scope == nil {
		return ""
	}
	return a.id.Name
}

// sees reports whether the caller may see the app with ID id.
func (a access) sees(id string) bool {
	if a.admin() {
		return true
	}
	if a.scope == nil {
		return false
	}
	p, _, ok := spec.SplitAppID(id)
	return ok && a.scope.Manages(p)
}

// app returns PermissionDenied unless the caller may manage the app (or
// job) with ID id. The message is the same whether or not the app exists.
func (a access) app(id string) error {
	if a.sees(id) {
		return nil
	}
	return status.Errorf(codes.PermissionDenied, "%s may not manage %s", a.id, id)
}

// project returns PermissionDenied unless the caller may manage project.
func (a access) project(p string) error {
	if p == "" {
		p = spec.DefaultProject
	}
	if a.admin() || (a.scope != nil && a.scope.Manages(p)) {
		return nil
	}
	return status.Errorf(codes.PermissionDenied, "%s may not manage project %s", a.id, p)
}

// placement returns PermissionDenied if an automation identity's spec
// requires node labels outside its scope: restricted nodes may be kept for
// other projects.
func (a access) placement(sp *spec.App) error {
	if a.admin() || sp.Placement == nil {
		return nil
	}
	if a.scope == nil {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	for k, vs := range sp.Placement.Require {
		if strings.HasPrefix(k, spec.ReservedLabelPrefix) {
			continue
		}
		allowed := a.scope.Labels[k]
		for _, v := range vs {
			if !slices.Contains(allowed, v) {
				return status.Errorf(codes.PermissionDenied, "%s may not require node label %s=%s", a.id, k, v)
			}
		}
	}
	return nil
}
