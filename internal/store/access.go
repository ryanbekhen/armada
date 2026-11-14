package store

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/spec"
)

// Principal kinds (ADR 0033).
const (
	// KindUser is a person.
	KindUser = "user"
	// KindService is a tool such as a CI system.
	KindService = "service"
)

// Roles (ADR 0033). They are built in.
const (
	RoleViewer       = "viewer"
	RoleDeployer     = "deployer"
	RoleAdmin        = "admin"
	RoleSpaceCreator = "space-creator"
	RoleClusterAdmin = "cluster-admin"
)

// Roles lists every role, from the least to the most.
var Roles = []string{RoleViewer, RoleDeployer, RoleAdmin, RoleSpaceCreator, RoleClusterAdmin}

// MaxServiceCerts bounds the certificates recorded per service; issuing
// more drops the oldest.
const MaxServiceCerts = 8

// MaxGrants bounds the assignments of one principal.
const MaxGrants = 1000

// Grant is a role given to a principal, in a space or, with no space,
// over the whole cluster.
type Grant struct {
	Role  string
	Space string
}

func (g Grant) String() string {
	if g.Space == "" {
		return g.Role
	}
	return g.Role + " in " + g.Space
}

// CheckGrant validates a role and where it is given.
func CheckGrant(g Grant) error {
	switch g.Role {
	case RoleClusterAdmin, RoleSpaceCreator:
		if g.Space != "" {
			return fmt.Errorf("role %s applies to the whole cluster: give it without a space", g.Role)
		}
	case RoleViewer:
		if g.Space != "" && g.Space != spec.DefaultSpace && !spec.ValidSpace(g.Space) {
			return fmt.Errorf("invalid space %q", g.Space)
		}
	case RoleDeployer, RoleAdmin:
		if g.Space == "" {
			return fmt.Errorf("role %s is given in one space: name it", g.Role)
		}
		if g.Space == spec.DefaultSpace {
			return fmt.Errorf("role %s cannot be given in the default space, whose containers may reach the platform; give viewer there, or cluster-admin: %w", g.Role, ErrPrecondition)
		}
		if !spec.ValidSpace(g.Space) {
			return fmt.Errorf("invalid space %q", g.Space)
		}
	default:
		return fmt.Errorf("unknown role %q (one of %s)", g.Role, strings.Join(Roles, ", "))
	}
	return nil
}

// CheckLabels validates the node label values a principal's apps may
// require.
func CheckLabels(labels map[string][]string) error {
	if len(labels) > spec.MaxNodeLabels {
		return fmt.Errorf("at most %d label keys", spec.MaxNodeLabels)
	}
	for k, vs := range labels {
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

// Principal is a user or a service and what it may do (ADR 0033).
type Principal struct {
	Kind string
	Name string
	// Roles are its assignments, sorted.
	Roles []Grant
	// Labels are the node label values its apps' placement.require may
	// name, per key; armada.* labels are always allowed.
	Labels    map[string][]string
	CreatedAt time.Time
	CreatedBy string
	// Users: certificates issued (NotBefore) before Since are refused, and
	// every one once Removed. SinceSerial is the serial of the certificate
	// Since came from: when it is set, only that certificate and ones issued
	// after the record was written are accepted (see userAllowed).
	Since       time.Time
	SinceSerial string
	Removed     bool
	// Services: its valid certificates, newest last.
	Certs []NodeCert
}

// Has reports whether p holds g.
func (p Principal) Has(g Grant) bool { return slices.Contains(p.Roles, g) }

type grantRec struct {
	Role  string `json:"role"`
	Space string `json:"space,omitempty"`
}

type principalRec struct {
	Name      string              `json:"name"`
	Roles     []grantRec          `json:"roles,omitempty"`
	Labels    map[string][]string `json:"labels,omitempty"`
	CreatedAt int64               `json:"createdAt,omitempty"`
	CreatedBy string              `json:"createdBy,omitempty"`
	// Since is in seconds, like a certificate's NotBefore.
	Since int64 `json:"since,omitempty"`
	// SinceSerial and Cutoff (Unix seconds when Since was written) bind a
	// user's latest certificate: see userAllowed.
	SinceSerial string    `json:"sinceSerial,omitempty"`
	Cutoff      int64     `json:"cutoff,omitempty"`
	Removed     bool      `json:"removed,omitempty"`
	Certs       []certRec `json:"certs,omitempty"`
}

// certBackdate is how far the CA backdates a certificate's NotBefore
// (pki.ClockSkew): NotBefore + certBackdate is when it was issued.
const certBackdate = pki.ClockSkew

// userAllowed reports whether r accepts a user certificate. Records written
// since the cutoff accept the certificate Since came from (by serial) and
// certificates issued in a later second than the record was written, so
// that one renewed from a replaced key, even in the same second, is
// refused; older records compare whole seconds of NotBefore with Since.
func (r principalRec) userAllowed(notBefore time.Time, serial string) bool {
	if r.Removed {
		return false
	}
	if r.Cutoff != 0 {
		return (r.SinceSerial != "" && serial == r.SinceSerial) || notBefore.Add(certBackdate).Unix() > r.Cutoff
	}
	return notBefore.Unix() >= r.Since
}

const (
	pfxUsers    = "users/"
	pfxServices = "services/"
)

func principalKey(kind, name string) (string, error) {
	switch kind {
	case KindUser:
		return pfxUsers + name, nil
	case KindService:
		return pfxServices + name, nil
	}
	return "", fmt.Errorf("unknown principal kind %q (user or service)", kind)
}

func (r principalRec) principal(kind string, now time.Time) Principal {
	p := Principal{Kind: kind, Name: r.Name, Labels: maps.Clone(r.Labels), CreatedAt: fromMS(r.CreatedAt),
		CreatedBy: r.CreatedBy, Removed: r.Removed}
	p.SinceSerial = r.SinceSerial
	if r.Since != 0 {
		p.Since = time.Unix(r.Since, 0)
	}
	for _, g := range r.Roles {
		p.Roles = append(p.Roles, Grant(g))
	}
	for _, c := range r.Certs {
		if c.NotAfter > now.UnixMilli() {
			p.Certs = append(p.Certs, NodeCert{Serial: c.Serial, NotAfter: fromMS(c.NotAfter)})
		}
	}
	return p
}

// setRoles stores roles sorted and without repeats.
func (r *principalRec) setRoles(roles []Grant) {
	r.Roles = nil
	for _, g := range roles {
		gr := grantRec(g)
		if !slices.Contains(r.Roles, gr) {
			r.Roles = append(r.Roles, gr)
		}
	}
	slices.SortFunc(r.Roles, func(a, b grantRec) int {
		if c := strings.Compare(a.Space, b.Space); c != 0 {
			return c
		}
		return slices.Index(Roles, a.Role) - slices.Index(Roles, b.Role)
	})
}

// checkGrants validates roles in t: each space must exist.
func (t *etx) checkGrants(roles []Grant) error {
	if len(roles) > MaxGrants {
		return fmt.Errorf("at most %d assignments", MaxGrants)
	}
	for _, g := range roles {
		if err := CheckGrant(g); err != nil {
			return err
		}
		if g.Space != "" {
			if err := t.spaceExists(g.Space); err != nil {
				return err
			}
		}
	}
	return nil
}

// CreateUser records a user whose certificates issued before p.Since are
// refused. ErrConflict while a user of that name is on record; a deleted
// user's name can be given again.
func (s *Etcd) CreateUser(ctx context.Context, p Principal, actor string) (Principal, error) {
	if err := CheckLabels(p.Labels); err != nil {
		return Principal{}, err
	}
	now := s.now()
	var out Principal
	err := s.tx(ctx, func(t *etx) error {
		if err := t.checkGrants(p.Roles); err != nil {
			return err
		}
		var r principalRec
		ok, err := t.get(pfxUsers+p.Name, &r)
		if err != nil {
			return err
		}
		if ok && !r.Removed {
			return fmt.Errorf("user %s exists; give them a new certificate with `armada rbac user credentials`: %w", p.Name, ErrConflict)
		}
		r = principalRec{Name: p.Name, Labels: p.Labels, CreatedAt: now.UnixMilli(), CreatedBy: actor, Since: p.Since.Unix(), SinceSerial: p.SinceSerial}
		if p.SinceSerial != "" {
			r.Cutoff = s.now().Unix() // in the transaction: later than any certificate it refuses
		}
		r.setRoles(p.Roles)
		if err := t.put(pfxUsers+p.Name, r); err != nil {
			return err
		}
		out = r.principal(KindUser, now)
		return t.audit(now, actor, "user.create", p.Name, rolesDetail(out.Roles))
	})
	return out, err
}

// KnowUser records a user with cluster-admin unless the name is on record:
// a certificate the CA signed outside the API (init, `armadad user renew`,
// clusters from before records) has full control, and so shows up in
// listings once it is used to renew.
func (s *Etcd) KnowUser(ctx context.Context, name string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var r principalRec
		ok, err := t.get(pfxUsers+name, &r)
		if err != nil || ok {
			return err
		}
		r = principalRec{Name: name, CreatedAt: now.UnixMilli()}
		r.setRoles([]Grant{{Role: RoleClusterAdmin}})
		return t.put(pfxUsers+name, r)
	})
}

// SetUserSince refuses a user's certificates issued before since, after a
// new one (serial) was issued to them: from then on only that certificate
// and ones issued later are accepted (userAllowed).
func (s *Etcd) SetUserSince(ctx context.Context, name string, since time.Time, serial, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var r principalRec
		ok, err := t.get(pfxUsers+name, &r)
		if err != nil {
			return err
		}
		if !ok || r.Removed {
			return notFoundf("user %s", name)
		}
		r.Since = since.Unix()
		r.SinceSerial = serial
		// Read in the transaction, so a renewal that committed before it
		// (RenewedUser) issued its certificate at or before the cutoff.
		r.Cutoff = s.now().Unix()
		if err := t.put(pfxUsers+name, r); err != nil {
			return err
		}
		return t.audit(now, actor, "user.certificate", name, "")
	})
}

// CreateService records a service. ErrConflict if it exists.
func (s *Etcd) CreateService(ctx context.Context, p Principal, actor string) (Principal, error) {
	if err := CheckLabels(p.Labels); err != nil {
		return Principal{}, err
	}
	now := s.now()
	var out Principal
	err := s.tx(ctx, func(t *etx) error {
		if err := t.checkGrants(p.Roles); err != nil {
			return err
		}
		ok, err := t.get(pfxServices+p.Name, &principalRec{})
		if err != nil {
			return err
		}
		if ok {
			return fmt.Errorf("service %s exists: %w", p.Name, ErrConflict)
		}
		r := principalRec{Name: p.Name, Labels: p.Labels, CreatedAt: now.UnixMilli(), CreatedBy: actor}
		r.setRoles(p.Roles)
		if err := t.put(pfxServices+p.Name, r); err != nil {
			return err
		}
		out = r.principal(KindService, now)
		return t.audit(now, actor, "service.create", p.Name, rolesDetail(out.Roles))
	})
	return out, err
}

func rolesDetail(roles []Grant) string {
	parts := make([]string, len(roles))
	for i, g := range roles {
		parts[i] = g.String()
	}
	return "roles=" + strings.Join(parts, ",")
}

// GetPrincipal returns a user or service on record.
func (s *Etcd) GetPrincipal(ctx context.Context, kind, name string) (Principal, error) {
	key, err := principalKey(kind, name)
	if err != nil {
		return Principal{}, err
	}
	var out Principal
	err = s.view(ctx, func(t *etx) error {
		var r principalRec
		ok, err := t.get(key, &r)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("%s %s", kind, name)
		}
		out = r.principal(kind, s.now())
		return nil
	})
	return out, err
}

// ListPrincipals lists users, then services, by name; kind "" lists both.
func (s *Etcd) ListPrincipals(ctx context.Context, kind string) ([]Principal, error) {
	var out []Principal
	err := s.view(ctx, func(t *etx) error {
		out = nil
		now := s.now()
		for _, k := range []string{KindUser, KindService} {
			if kind != "" && kind != k {
				continue
			}
			pfx, _ := principalKey(k, "")
			err := listInto(t, pfx, func(_ string, r principalRec) error {
				out = append(out, r.principal(k, now))
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// update applies fn to a principal on record (not a deleted user) and
// audits action.
func (s *Etcd) update(ctx context.Context, kind, name, actor, action string, fn func(*etx, *principalRec) (string, error)) (Principal, error) {
	key, err := principalKey(kind, name)
	if err != nil {
		return Principal{}, err
	}
	now := s.now()
	var out Principal
	err = s.tx(ctx, func(t *etx) error {
		var r principalRec
		ok, err := t.get(key, &r)
		if err != nil {
			return err
		}
		if !ok || r.Removed {
			return notFoundf("%s %s", kind, name)
		}
		detail, err := fn(t, &r)
		if err != nil {
			return err
		}
		if err := t.put(key, r); err != nil {
			return err
		}
		out = r.principal(kind, now)
		return t.audit(now, actor, action, kind+":"+name, detail)
	})
	return out, err
}

// SetPrincipalLabels replaces the node labels a principal's apps may
// require.
func (s *Etcd) SetPrincipalLabels(ctx context.Context, kind, name string, labels map[string][]string, actor string) (Principal, error) {
	if err := CheckLabels(labels); err != nil {
		return Principal{}, err
	}
	return s.update(ctx, kind, name, actor, "principal.update", func(_ *etx, r *principalRec) (string, error) {
		r.Labels = labels
		return "", nil
	})
}

// Assign gives a principal a role; giving one it holds changes nothing.
func (s *Etcd) Assign(ctx context.Context, kind, name string, g Grant, actor string) (Principal, error) {
	return s.update(ctx, kind, name, actor, "assignment.create", func(t *etx, r *principalRec) (string, error) {
		if err := t.checkGrants([]Grant{g}); err != nil {
			return "", err
		}
		roles := r.principal(kind, time.Time{}).Roles
		if len(roles) >= MaxGrants {
			return "", fmt.Errorf("at most %d assignments", MaxGrants)
		}
		r.setRoles(append(roles, g))
		return g.String(), nil
	})
}

// Unassign takes a role back; ErrNotFound unless the principal holds it.
func (s *Etcd) Unassign(ctx context.Context, kind, name string, g Grant, actor string) (Principal, error) {
	return s.update(ctx, kind, name, actor, "assignment.delete", func(_ *etx, r *principalRec) (string, error) {
		roles := r.principal(kind, time.Time{}).Roles
		i := slices.Index(roles, g)
		if i < 0 {
			return "", notFoundf("%s %s has no role %s", kind, name, g)
		}
		r.setRoles(slices.Delete(roles, i, i+1))
		return g.String(), nil
	})
}

// DeletePrincipal deletes a service, or marks a user deleted: the record
// stays so that every certificate of the name is refused, also one the
// cluster never recorded.
func (s *Etcd) DeletePrincipal(ctx context.Context, kind, name, actor string) error {
	key, err := principalKey(kind, name)
	if err != nil {
		return err
	}
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var r principalRec
		ok, err := t.get(key, &r)
		if err != nil {
			return err
		}
		switch {
		case kind == KindService && !ok:
			return notFoundf("service %s", name)
		case kind == KindService:
			t.delete(key)
		default:
			if !ok {
				r = principalRec{Name: name}
			}
			r.Removed, r.Roles, r.Labels = true, nil, nil
			if err := t.put(key, r); err != nil {
				return err
			}
		}
		return t.audit(now, actor, kind+".delete", name, "")
	})
}

// RecordServiceCert records a certificate issued to a service and drops
// expired ones (and the oldest beyond MaxServiceCerts). A non-empty keep
// (the serial of the certificate that asked for a renewal) revokes every
// other certificate.
func (s *Etcd) RecordServiceCert(ctx context.Context, name string, c NodeCert, keep, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var r principalRec
		ok, err := t.get(pfxServices+name, &r)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundf("service %s", name)
		}
		var certs []certRec
		for _, old := range r.Certs {
			if old.NotAfter > now.UnixMilli() && (keep == "" || old.Serial == keep) {
				certs = append(certs, old)
			}
		}
		certs = append(certs, certRec{Serial: c.Serial, NotAfter: c.NotAfter.UnixMilli()})
		if len(certs) > MaxServiceCerts {
			certs = certs[len(certs)-MaxServiceCerts:]
		}
		r.Certs = certs
		if err := t.put(pfxServices+name, r); err != nil {
			return err
		}
		return t.audit(now, actor, "service.certificate", name, "serial="+c.Serial)
	})
}

// UserAccess returns what the user may do and whether a certificate of
// theirs that starts at notBefore is accepted. A name not on record has
// cluster-admin: only the CA on a server signs such certificates.
func (s *Etcd) UserAccess(ctx context.Context, name string, notBefore time.Time, serial string) (Principal, bool, error) {
	var out Principal
	allowed := false
	err := s.view(ctx, func(t *etx) error {
		var r principalRec
		ok, err := t.get(pfxUsers+name, &r)
		if err != nil {
			return err
		}
		if !ok {
			out = Principal{Kind: KindUser, Name: name, Roles: []Grant{{Role: RoleClusterAdmin}}}
			allowed = true
			return nil
		}
		out = r.principal(KindUser, s.now())
		allowed = r.userAllowed(notBefore, serial)
		return nil
	})
	return out, allowed, err
}

// RenewedUser records that a user renewed their own certificate (serial)
// with a certificate that starts at callerNotBefore and has callerSerial,
// recording a name not on record with cluster-admin like KnowUser. It
// refuses (ErrPrecondition) when the caller's certificate is no longer
// accepted: the check and the record are one transaction, so a renewal
// either commits before a replacement (SetUserSince), whose cutoff then
// refuses the renewed certificate, or sees the replacement and fails.
func (s *Etcd) RenewedUser(ctx context.Context, name string, callerNotBefore time.Time, callerSerial, serial string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var r principalRec
		ok, err := t.get(pfxUsers+name, &r)
		if err != nil {
			return err
		}
		if !ok {
			r = principalRec{Name: name, CreatedAt: now.UnixMilli()}
			r.setRoles([]Grant{{Role: RoleClusterAdmin}})
			if err := t.put(pfxUsers+name, r); err != nil {
				return err
			}
		} else if !r.userAllowed(callerNotBefore, callerSerial) {
			return fmt.Errorf("certificate of user:%s was replaced or revoked: %w", name, ErrPrecondition)
		}
		return t.audit(now, "user:"+name, "user.certificate", name, "serial="+serial)
	})
}

// ServiceAccess returns what the service may do and whether serial is one
// of its valid certificates (false when it does not exist).
func (s *Etcd) ServiceAccess(ctx context.Context, name, serial string) (Principal, bool, error) {
	var out Principal
	allowed := false
	err := s.view(ctx, func(t *etx) error {
		var r principalRec
		ok, err := t.get(pfxServices+name, &r)
		if err != nil || !ok {
			allowed = false
			return err
		}
		out = r.principal(KindService, s.now())
		allowed = slices.ContainsFunc(out.Certs, func(c NodeCert) bool { return c.Serial == serial })
		return nil
	})
	return out, allowed, err
}

// grantSpace makes the principal that creates space its admin, inside
// t; the principal must hold space-creator.
func (t *etx) grantSpace(kind, name, space string) error {
	key, err := principalKey(kind, name)
	if err != nil {
		return err
	}
	var r principalRec
	ok, err := t.get(key, &r)
	if err != nil {
		return err
	}
	p := r.principal(kind, time.Time{})
	if !ok || r.Removed || !p.Has(Grant{Role: RoleSpaceCreator}) {
		return fmt.Errorf("%s %s may not create spaces: %w", kind, name, ErrPrecondition)
	}
	r.setRoles(append(p.Roles, Grant{Role: RoleAdmin, Space: space}))
	return t.put(key, r)
}

// forgetSpace takes every role in a deleted space back, so a space
// created later under the same name is not handed over.
func (t *etx) forgetSpace(space string) error {
	for _, pfx := range []string{pfxUsers, pfxServices} {
		kvs, err := t.list(pfx)
		if err != nil {
			return err
		}
		for _, e := range kvs {
			var r principalRec
			if err := json.Unmarshal(e.val, &r); err != nil {
				return fmt.Errorf("decode %s: %w", e.key, err)
			}
			keep := slices.DeleteFunc(slices.Clone(r.Roles), func(g grantRec) bool { return g.Space == space })
			if len(keep) != len(r.Roles) {
				r.Roles = keep
				if err := t.put(e.key, r); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// migrateAccess moves administrators and automation identities to users
// and services (schema 8 to 9, ADR 0033) without changing what any of them
// may do.
func migrateAccess(t *etx) error {
	type adminRec struct {
		Name    string `json:"name"`
		Since   int64  `json:"since,omitempty"`
		Removed bool   `json:"removed,omitempty"`
		AddedAt int64  `json:"addedAt,omitempty"`
		AddedBy string `json:"addedBy,omitempty"`
	}
	type automationRec struct {
		Name string `json:"name"`
		// Written before spaces had their name (schema 11).
		Spaces       []string            `json:"projects,omitempty"`
		CreateSpaces bool                `json:"createProjects,omitempty"`
		Labels       map[string][]string `json:"labels,omitempty"`
		CreatedAt    int64               `json:"createdAt"`
		CreatedBy    string              `json:"createdBy,omitempty"`
		Certs        []certRec           `json:"certs,omitempty"`
	}
	err := listInto(t, "admins/", func(_ string, a adminRec) error {
		r := principalRec{Name: a.Name, CreatedAt: a.AddedAt, CreatedBy: a.AddedBy, Since: a.Since, Removed: a.Removed}
		if !a.Removed {
			r.setRoles([]Grant{{Role: RoleClusterAdmin}})
		}
		return t.put(pfxUsers+a.Name, r)
	})
	if err != nil {
		return err
	}
	err = listInto(t, "automation/", func(_ string, a automationRec) error {
		r := principalRec{Name: a.Name, Labels: a.Labels, CreatedAt: a.CreatedAt, CreatedBy: a.CreatedBy, Certs: a.Certs}
		var roles []Grant
		for _, p := range a.Spaces {
			roles = append(roles, Grant{Role: RoleAdmin, Space: p})
		}
		if a.CreateSpaces {
			roles = append(roles, Grant{Role: RoleSpaceCreator})
		}
		r.setRoles(roles)
		return t.put(pfxServices+a.Name, r)
	})
	if err != nil {
		return err
	}
	t.deletePrefix("admins/")
	t.deletePrefix("automation/")
	return nil
}
