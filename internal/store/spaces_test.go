package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestSpaces(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()

	ps, err := s.ListSpaces(ctx)
	if err != nil || len(ps) != 1 || ps[0].Name != "default" {
		t.Fatalf("fresh cluster: %+v %v", ps, err)
	}
	if _, err := s.GetSpace(ctx, "default"); err != nil {
		t.Errorf("default: %v", err)
	}
	if _, err := s.GetSpace(ctx, "staging"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing space = %v", err)
	}

	p, err := s.CreateSpace(ctx, "staging", "admin:test", nil)
	if err != nil || p.Name != "staging" || p.CreatedBy != "admin:test" || p.CreatedAt.IsZero() {
		t.Fatalf("create: %+v %v", p, err)
	}
	if _, err := s.CreateSpace(ctx, "staging", "admin:test", nil); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate = %v", err)
	}
	if _, err := s.CreateSpace(ctx, "default", "admin:test", nil); !errors.Is(err, ErrConflict) {
		t.Errorf("default = %v", err)
	}
	for _, bad := range []string{"", "Staging", "a--b", "a.b", "a/b", "-a", strings.Repeat("a", 31)} {
		if _, err := s.CreateSpace(ctx, bad, "admin:test", nil); err == nil {
			t.Errorf("CreateSpace(%q) accepted", bad)
		}
	}
	got, err := s.GetSpace(ctx, "staging")
	if err != nil || !got.CreatedAt.Equal(p.CreatedAt) {
		t.Errorf("get: %+v %v (created %v)", got, err, p.CreatedAt)
	}
	ps, _ = s.ListSpaces(ctx)
	if len(ps) != 2 || ps[0].Name != "default" || ps[1].Name != "staging" {
		t.Errorf("list: %+v", ps)
	}
	if err := s.DeleteSpace(ctx, "default", "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("delete default = %v", err)
	}
	if err := s.DeleteSpace(ctx, "nope", "admin:test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing = %v", err)
	}
}

func TestDeployIntoSpace(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	sp := mustParse(t, "name: web\nimage: nginx:1\n")
	sp.Space = "staging"
	if _, _, err := s.Deploy(ctx, sp, "admin:test"); !errors.Is(err, ErrPrecondition) || !strings.Contains(err.Error(), "space staging does not exist") {
		t.Fatalf("deploy into a missing space = %v", err)
	}
	if _, err := s.CreateSpace(ctx, "staging", "admin:test", nil); err != nil {
		t.Fatal(err)
	}
	rev, created, err := s.Deploy(ctx, sp, "admin:test")
	if err != nil || !created || rev.Name != "web.staging--r1" || rev.App != "web.staging" {
		t.Fatalf("deploy: %+v %v %v", rev, created, err)
	}
	// The same name in the default space is another app.
	def, _, err := s.Deploy(ctx, mustParse(t, "name: web\nimage: nginx:2\n"), "admin:test")
	if err != nil || def.Name != "web--r1" {
		t.Fatalf("default deploy: %+v %v", def, err)
	}
	a, err := s.GetApp(ctx, "web.staging")
	if err != nil || a.Spec.Image != "nginx:1" || a.Spec.Space != "staging" {
		t.Fatalf("space app: %+v %v", a, err)
	}
	if a, err := s.GetApp(ctx, "web"); err != nil || a.Spec.Image != "nginx:2" || a.Spec.Space != "" {
		t.Fatalf("default app: %+v %v", a, err)
	}

	// A space that still holds anything cannot be removed.
	err = s.DeleteSpace(ctx, "staging", "admin:test")
	if !errors.Is(err, ErrPrecondition) || !strings.Contains(err.Error(), "apps (web.staging)") {
		t.Fatalf("delete with an app = %v", err)
	}
}

func TestSpaceSecrets(t *testing.T) {
	t.Parallel()
	s, ctx, k := open(t), context.Background(), testKeyring(t)
	if _, _, err := s.SetSecret(ctx, "db.staging", "pw", nil, false, "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("secret in a missing space = %v", err)
	}
	for _, bad := range []string{"db.default", "db.Staging", "db/x"} {
		if _, _, err := s.SetSecret(ctx, bad, "pw", nil, false, "admin:test"); err == nil {
			t.Errorf("SetSecret(%q) accepted", bad)
		}
	}
	if _, err := s.CreateSpace(ctx, "staging", "admin:test", nil); err != nil {
		t.Fatal(err)
	}
	setSecret(t, s, k, "db.staging", "pw", "x", false)
	err := s.DeleteSpace(ctx, "staging", "admin:test")
	if !errors.Is(err, ErrPrecondition) || !strings.Contains(err.Error(), "secrets (db.staging)") {
		t.Fatalf("delete with a secret = %v", err)
	}
	if err := s.DeleteSecret(ctx, "db.staging", "pw", "admin:test"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSpace(ctx, "staging", "admin:test"); err != nil {
		t.Fatalf("delete an empty space: %v", err)
	}
	// Removed means gone: nothing can be added to it again.
	if _, _, err := s.SetSecret(ctx, "db.staging", "pw", nil, false, "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("secret after removal = %v", err)
	}
}

// A domain serves one space: another space can neither route a path
// of it nor inherit its verification.
func TestDomainsStayInOneSpace(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if _, err := s.CreateSpace(ctx, "b", "admin:test", nil); err != nil {
		t.Fatal(err)
	}
	ext := func(name, path string) string {
		return "name: " + name + "\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n  domains: [shop.example.org]\n  routes:\n    - path: " + path + "\n"
	}
	if _, _, err := s.Deploy(ctx, mustParse(t, ext("web", "/")), "admin:test"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDomainVerification(ctx, "shop.example.org", true, ""); err != nil {
		t.Fatal(err)
	}
	other := mustParse(t, ext("api", "/api"))
	other.Space = "b"
	if _, _, err := s.Deploy(ctx, other, "admin:test"); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "used by space default") {
		t.Fatalf("another space on the same domain = %v", err)
	}
	// The same space may add paths.
	if _, _, err := s.Deploy(ctx, mustParse(t, ext("api", "/api")), "admin:test"); err != nil {
		t.Fatalf("same space, other path: %v", err)
	}
}

func TestMigrateSpaces(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	atSchema(t, s, 10)
	err := s.tx(ctx, func(tx *etx) error {
		for k, v := range map[string]any{
			"projects/shop":            map[string]any{"name": "shop", "createdAt": 5, "createdBy": "user:ana"},
			"domains/shop.example.com": map[string]any{"name": "shop.example.com", "project": "shop"},
			"domains/example.com":      map[string]any{"name": "example.com"},
			"revs/web.shop/0000000001": map[string]any{"name": "web.shop--r1", "app": "web.shop", "seq": 1,
				"spec": map[string]any{"name": "web", "image": "nginx", "project": "shop"}},
			"users/ana": map[string]any{"name": "ana", "roles": []map[string]any{
				{"role": "admin", "project": "shop"}, {"role": "project-creator"}, {"role": "viewer"}}},
			"services/ci": map[string]any{"name": "ci"},
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
	if sp, err := s.GetSpace(ctx, "shop"); err != nil || sp.CreatedBy != "user:ana" {
		t.Errorf("space: %+v %v", sp, err)
	}
	ana, err := s.GetPrincipal(ctx, KindUser, "ana")
	want := []Grant{{Role: RoleAdmin, Space: "shop"}, {Role: RoleSpaceCreator}, {Role: RoleViewer}}
	if err != nil || !slices.Equal(ana.Roles, want) {
		t.Errorf("ana: %+v %v, want %+v", ana.Roles, err, want)
	}
	err = s.tx(ctx, func(tx *etx) error {
		var d domainRec
		if _, err := tx.get(pfxDomains+"shop.example.com", &d); err != nil || d.Space != "shop" {
			t.Errorf("domain: %+v %v", d, err)
		}
		var r revRec
		if _, err := tx.get("revs/web.shop/0000000001", &r); err != nil {
			return err
		}
		rev, err := decodeRev(r)
		if err != nil || rev.Spec.Space != "shop" || rev.Spec.Image != "nginx" {
			t.Errorf("revision: %+v %v", rev.Spec, err)
		}
		if old, _ := tx.list("projects/"); len(old) != 0 {
			t.Errorf("projects/ left behind: %v", old)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
