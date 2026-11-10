package store

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestUsers(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	since := time.Unix(1_800_000_000, 0)

	// A name not on record has full control: only the CA signs such
	// certificates.
	p, ok, err := s.UserAccess(ctx, "root", since)
	if err != nil || !ok || !p.Has(Grant{Role: RoleClusterAdmin}) {
		t.Fatalf("unrecorded user: %+v %v %v", p, ok, err)
	}

	if _, err := s.CreateProject(ctx, "shop", "user:root", nil); err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUser(ctx, Principal{Name: "ana", Since: since, Roles: []Grant{{Role: RoleDeployer, Project: "shop"}, {Role: RoleViewer}}}, "user:root")
	if err != nil || len(u.Roles) != 2 || u.Roles[0] != (Grant{Role: RoleViewer}) {
		t.Fatalf("create: %+v %v", u, err)
	}
	if _, err := s.CreateUser(ctx, Principal{Name: "ana", Since: since}, "user:root"); !errors.Is(err, ErrConflict) {
		t.Errorf("second create = %v", err)
	}
	if _, ok, _ := s.UserAccess(ctx, "ana", since.Add(-time.Second)); ok {
		t.Error("accepted a certificate from before the user's latest")
	}
	if p, ok, _ := s.UserAccess(ctx, "ana", since); !ok || p.Has(Grant{Role: RoleClusterAdmin}) || !p.Has(Grant{Role: RoleDeployer, Project: "shop"}) {
		t.Errorf("ana: %+v %v", p, ok)
	}
	later := since.Add(time.Hour)
	if err := s.SetUserSince(ctx, "ana", later, "user:root"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.UserAccess(ctx, "ana", since); ok {
		t.Error("an older certificate stayed valid after a new one")
	}

	// KnowUser leaves a user on record alone.
	if err := s.KnowUser(ctx, "ana"); err != nil {
		t.Fatal(err)
	}
	if p, _, _ := s.UserAccess(ctx, "ana", later); p.Has(Grant{Role: RoleClusterAdmin}) {
		t.Error("KnowUser gave a recorded user cluster-admin")
	}
	if err := s.KnowUser(ctx, "root"); err != nil {
		t.Fatal(err)
	}
	if p, err := s.GetPrincipal(ctx, KindUser, "root"); err != nil || !p.Has(Grant{Role: RoleClusterAdmin}) {
		t.Errorf("known user: %+v %v", p, err)
	}

	// Deleted: every certificate refused, also for a name never recorded,
	// and the name can be given again.
	if err := s.DeletePrincipal(ctx, KindUser, "ana", "user:root"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePrincipal(ctx, KindUser, "ghost", "user:root"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"ana", "ghost"} {
		if _, ok, _ := s.UserAccess(ctx, n, later.Add(time.Hour)); ok {
			t.Errorf("deleted user %s accepted", n)
		}
	}
	if _, err := s.Assign(ctx, KindUser, "ana", Grant{Role: RoleViewer}, "user:root"); !errors.Is(err, ErrNotFound) {
		t.Errorf("assign to a deleted user = %v", err)
	}
	if _, err := s.CreateUser(ctx, Principal{Name: "ana", Since: later.Add(time.Hour)}, "user:root"); err != nil {
		t.Errorf("give a deleted name again: %v", err)
	}
}

func TestAssignments(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if _, err := s.CreateProject(ctx, "shop", "user:root", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateService(ctx, Principal{Name: "ci"}, "user:root"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateService(ctx, Principal{Name: "ci"}, "user:root"); !errors.Is(err, ErrConflict) {
		t.Errorf("second create = %v", err)
	}
	for _, bad := range []Grant{
		{Role: RoleDeployer, Project: "default"},
		{Role: RoleAdmin, Project: "default"},
		{Role: RoleDeployer},
		{Role: RoleClusterAdmin, Project: "shop"},
		{Role: RoleProjectCreator, Project: "shop"},
		{Role: RoleAdmin, Project: "nope"},
		{Role: "owner", Project: "shop"},
		{Role: RoleViewer, Project: "Bad!"},
	} {
		if _, err := s.Assign(ctx, KindService, "ci", bad, "user:root"); err == nil {
			t.Errorf("assigned %+v", bad)
		}
	}
	for _, good := range []Grant{{Role: RoleViewer, Project: "default"}, {Role: RoleAdmin, Project: "shop"}, {Role: RoleAdmin, Project: "shop"}} {
		if _, err := s.Assign(ctx, KindService, "ci", good, "user:root"); err != nil {
			t.Errorf("assign %+v: %v", good, err)
		}
	}
	p, _ := s.GetPrincipal(ctx, KindService, "ci")
	if len(p.Roles) != 2 {
		t.Errorf("roles = %+v (repeats kept?)", p.Roles)
	}
	if _, err := s.Unassign(ctx, KindService, "ci", Grant{Role: RoleDeployer, Project: "shop"}, "user:root"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unassign a role not held = %v", err)
	}
	if p, err := s.Unassign(ctx, KindService, "ci", Grant{Role: RoleViewer, Project: "default"}, "user:root"); err != nil || len(p.Roles) != 1 {
		t.Errorf("unassign: %+v %v", p.Roles, err)
	}
	if _, err := s.SetPrincipalLabels(ctx, KindService, "ci", map[string][]string{"pool": {"shop"}}, "user:root"); err != nil {
		t.Error(err)
	}
	if _, err := s.SetPrincipalLabels(ctx, KindService, "ci", map[string][]string{"pool": nil}, "user:root"); err == nil {
		t.Error("accepted a label with no values")
	}

	// Creating a project needs project-creator and makes the creator its
	// admin; deleting it takes every role in it back.
	if _, err := s.CreateProject(ctx, "two", "service:ci", &p); !errors.Is(err, ErrPrecondition) {
		t.Errorf("create without project-creator = %v", err)
	}
	if _, err := s.Assign(ctx, KindService, "ci", Grant{Role: RoleProjectCreator}, "user:root"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProject(ctx, "two", "service:ci", &p); err != nil {
		t.Fatal(err)
	}
	p, _ = s.GetPrincipal(ctx, KindService, "ci")
	if !p.Has(Grant{Role: RoleAdmin, Project: "two"}) {
		t.Errorf("creator is not admin: %+v", p.Roles)
	}
	if err := s.DeleteProject(ctx, "two", "service:ci"); err != nil {
		t.Fatal(err)
	}
	p, _ = s.GetPrincipal(ctx, KindService, "ci")
	if p.Has(Grant{Role: RoleAdmin, Project: "two"}) || !p.Has(Grant{Role: RoleAdmin, Project: "shop"}) {
		t.Errorf("after deleting two: %+v", p.Roles)
	}
}

func TestServiceCertificates(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.RecordServiceCert(ctx, "ci", NodeCert{Serial: "1", NotAfter: time.Now().Add(time.Hour)}, "", "user:root"); !errors.Is(err, ErrNotFound) {
		t.Errorf("cert for a missing service = %v", err)
	}
	if _, err := s.CreateService(ctx, Principal{Name: "ci"}, "user:root"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ServiceAccess(ctx, "ci", "1"); ok {
		t.Error("accepted an unrecorded serial")
	}
	for _, serial := range []string{"1", "2"} {
		if err := s.RecordServiceCert(ctx, "ci", NodeCert{Serial: serial, NotAfter: time.Now().Add(time.Hour)}, "", "user:root"); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok, _ := s.ServiceAccess(ctx, "ci", "1"); !ok {
		t.Error("refused a recorded serial")
	}
	// Renewal from 2 revokes 1.
	if err := s.RecordServiceCert(ctx, "ci", NodeCert{Serial: "3", NotAfter: time.Now().Add(time.Hour)}, "2", "service:ci"); err != nil {
		t.Fatal(err)
	}
	for serial, want := range map[string]bool{"1": false, "2": true, "3": true} {
		if _, ok, _ := s.ServiceAccess(ctx, "ci", serial); ok != want {
			t.Errorf("serial %s accepted = %v", serial, ok)
		}
	}
	if err := s.DeletePrincipal(ctx, KindService, "ci", "user:root"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ServiceAccess(ctx, "ci", "3"); ok {
		t.Error("deleted service accepted")
	}
	if err := s.DeletePrincipal(ctx, KindService, "ci", "user:root"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete = %v", err)
	}
}

// Schema 9 moves administrators and automation identities without
// changing what any of them may do.
func TestMigrateAccess(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if _, err := s.CreateProject(ctx, "shop", "admin:root", nil); err != nil {
		t.Fatal(err)
	}
	atSchema(t, s, 8)
	future := time.Now().Add(time.Hour).UnixMilli()
	err := s.tx(ctx, func(tx *etx) error {
		for k, v := range map[string]any{
			"admins/root": map[string]any{"name": "root", "since": 1_800_000_000, "addedAt": 5, "addedBy": "admin:init"},
			"admins/old":  map[string]any{"name": "old", "removed": true},
			"automation/ci": map[string]any{"name": "ci", "projects": []string{"shop"}, "createProjects": true,
				"labels": map[string][]string{"pool": {"a"}}, "createdAt": 7, "certs": []map[string]any{{"serial": "9", "notAfter": future}}},
			"automation/ro": map[string]any{"name": "ro", "projects": []string{"shop"}},
		} {
			if err := tx.put(k, v); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	root, ok, _ := s.UserAccess(ctx, "root", time.Unix(1_800_000_000, 0))
	if !ok || !slices.Equal(root.Roles, []Grant{{Role: RoleClusterAdmin}}) || root.CreatedBy != "admin:init" {
		t.Errorf("root: %+v %v", root, ok)
	}
	if _, ok, _ := s.UserAccess(ctx, "root", time.Unix(1_799_999_999, 0)); ok {
		t.Error("migration dropped Since")
	}
	if _, ok, _ := s.UserAccess(ctx, "old", time.Now()); ok {
		t.Error("a removed administrator is accepted after the migration")
	}
	ci, ok, _ := s.ServiceAccess(ctx, "ci", "9")
	want := []Grant{{Role: RoleProjectCreator}, {Role: RoleAdmin, Project: "shop"}}
	if !ok || !slices.Equal(ci.Roles, want) || len(ci.Labels["pool"]) != 1 {
		t.Errorf("ci: %+v %v", ci, ok)
	}
	if ro, _ := s.GetPrincipal(ctx, KindService, "ro"); !slices.Equal(ro.Roles, []Grant{{Role: RoleAdmin, Project: "shop"}}) {
		t.Errorf("ro: %+v", ro.Roles)
	}
	for _, pfx := range []string{"admins/", "automation/"} {
		if resp, _ := s.c.Get(ctx, s.prefix+pfx, clientv3.WithPrefix()); len(resp.Kvs) != 0 {
			t.Errorf("%s left behind", pfx)
		}
	}
}
