package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProjects(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()

	ps, err := s.ListProjects(ctx)
	if err != nil || len(ps) != 1 || ps[0].Name != "default" {
		t.Fatalf("fresh cluster: %+v %v", ps, err)
	}
	if _, err := s.GetProject(ctx, "default"); err != nil {
		t.Errorf("default: %v", err)
	}
	if _, err := s.GetProject(ctx, "staging"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing project = %v", err)
	}

	p, err := s.CreateProject(ctx, "staging", "", "admin:test", "")
	if err != nil || p.Name != "staging" || p.CreatedBy != "admin:test" || p.CreatedAt.IsZero() {
		t.Fatalf("create: %+v %v", p, err)
	}
	if _, err := s.CreateProject(ctx, "staging", "", "admin:test", ""); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate = %v", err)
	}
	if _, err := s.CreateProject(ctx, "default", "", "admin:test", ""); !errors.Is(err, ErrConflict) {
		t.Errorf("default = %v", err)
	}
	for _, bad := range []string{"", "Staging", "a--b", "a.b", "a/b", "-a", strings.Repeat("a", 31)} {
		if _, err := s.CreateProject(ctx, bad, "", "admin:test", ""); err == nil {
			t.Errorf("CreateProject(%q) accepted", bad)
		}
	}
	got, err := s.GetProject(ctx, "staging")
	if err != nil || !got.CreatedAt.Equal(p.CreatedAt) {
		t.Errorf("get: %+v %v (created %v)", got, err, p.CreatedAt)
	}
	ps, _ = s.ListProjects(ctx)
	if len(ps) != 2 || ps[0].Name != "default" || ps[1].Name != "staging" {
		t.Errorf("list: %+v", ps)
	}
	if err := s.DeleteProject(ctx, "default", "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("delete default = %v", err)
	}
	if err := s.DeleteProject(ctx, "nope", "admin:test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing = %v", err)
	}
}

func TestDeployIntoProject(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	sp := mustParse(t, "name: web\nimage: nginx:1\n")
	sp.Project = "staging"
	if _, _, err := s.Deploy(ctx, sp, "admin:test"); !errors.Is(err, ErrPrecondition) || !strings.Contains(err.Error(), "project staging does not exist") {
		t.Fatalf("deploy into a missing project = %v", err)
	}
	if _, err := s.CreateProject(ctx, "staging", "", "admin:test", ""); err != nil {
		t.Fatal(err)
	}
	rev, created, err := s.Deploy(ctx, sp, "admin:test")
	if err != nil || !created || rev.Name != "web.staging--r1" || rev.App != "web.staging" {
		t.Fatalf("deploy: %+v %v %v", rev, created, err)
	}
	// The same name in the default project is another app.
	def, _, err := s.Deploy(ctx, mustParse(t, "name: web\nimage: nginx:2\n"), "admin:test")
	if err != nil || def.Name != "web--r1" {
		t.Fatalf("default deploy: %+v %v", def, err)
	}
	a, err := s.GetApp(ctx, "web.staging")
	if err != nil || a.Spec.Image != "nginx:1" || a.Spec.Project != "staging" {
		t.Fatalf("project app: %+v %v", a, err)
	}
	if a, err := s.GetApp(ctx, "web"); err != nil || a.Spec.Image != "nginx:2" || a.Spec.Project != "" {
		t.Fatalf("default app: %+v %v", a, err)
	}

	// A project that still holds anything cannot be removed.
	err = s.DeleteProject(ctx, "staging", "admin:test")
	if !errors.Is(err, ErrPrecondition) || !strings.Contains(err.Error(), "apps (web.staging)") {
		t.Fatalf("delete with an app = %v", err)
	}
}

func TestProjectSecrets(t *testing.T) {
	t.Parallel()
	s, ctx, k := open(t), context.Background(), testKeyring(t)
	if _, _, err := s.SetSecret(ctx, "db.staging", "pw", nil, false, "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("secret in a missing project = %v", err)
	}
	for _, bad := range []string{"db.default", "db.Staging", "db/x"} {
		if _, _, err := s.SetSecret(ctx, bad, "pw", nil, false, "admin:test"); err == nil {
			t.Errorf("SetSecret(%q) accepted", bad)
		}
	}
	if _, err := s.CreateProject(ctx, "staging", "", "admin:test", ""); err != nil {
		t.Fatal(err)
	}
	setSecret(t, s, k, "db.staging", "pw", "x", false)
	err := s.DeleteProject(ctx, "staging", "admin:test")
	if !errors.Is(err, ErrPrecondition) || !strings.Contains(err.Error(), "secrets (db.staging)") {
		t.Fatalf("delete with a secret = %v", err)
	}
	if err := s.DeleteSecret(ctx, "db.staging", "pw", "admin:test"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteProject(ctx, "staging", "admin:test"); err != nil {
		t.Fatalf("delete an empty project: %v", err)
	}
	// Removed means gone: nothing can be added to it again.
	if _, _, err := s.SetSecret(ctx, "db.staging", "pw", nil, false, "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("secret after removal = %v", err)
	}
}

// A domain serves one project: another project can neither route a path
// of it nor inherit its verification.
func TestDomainsStayInOneProject(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if _, err := s.CreateProject(ctx, "b", "", "admin:test", ""); err != nil {
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
	other.Project = "b"
	if _, _, err := s.Deploy(ctx, other, "admin:test"); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "used by project default") {
		t.Fatalf("another project on the same domain = %v", err)
	}
	// The same project may add paths.
	if _, _, err := s.Deploy(ctx, mustParse(t, ext("api", "/api")), "admin:test"); err != nil {
		t.Fatalf("same project, other path: %v", err)
	}
}
