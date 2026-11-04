package store

import (
	"context"
	"errors"
	"testing"

	"github.com/ryanbekhen/armada/internal/spec"
)

func TestProjectIsolation(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	level := func(p string) string {
		t.Helper()
		got, err := s.GetProject(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		return got.Isolation
	}
	// The default project runs containers; a new project the sandbox,
	// unless it is created with another level.
	if l := level("default"); l != spec.IsolationContainer {
		t.Errorf("default = %q", l)
	}
	if p, err := s.CreateProject(ctx, "shop", "", "admin:test", ""); err != nil || p.Isolation != spec.IsolationSandbox {
		t.Fatalf("create: %+v %v", p, err)
	}
	if _, err := s.CreateProject(ctx, "plain", spec.IsolationContainer, "admin:test", ""); err != nil || level("plain") != spec.IsolationContainer {
		t.Fatalf("create with container: %v", err)
	}
	for _, bad := range []string{spec.IsolationVM, "gvisor"} {
		if _, err := s.CreateProject(ctx, "x", bad, "admin:test", ""); !errors.Is(err, ErrPrecondition) {
			t.Errorf("create with %q = %v", bad, err)
		}
		if err := s.SetProjectIsolation(ctx, "shop", bad, "admin:test"); !errors.Is(err, ErrPrecondition) {
			t.Errorf("set %q = %v", bad, err)
		}
	}
	if err := s.SetProjectIsolation(ctx, "ghost", spec.IsolationSandbox, "admin:test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing project = %v", err)
	}
	ps, err := s.ListProjects(ctx)
	if err != nil || len(ps) != 3 || ps[0].Isolation != spec.IsolationContainer || ps[2].Isolation != spec.IsolationSandbox {
		t.Fatalf("list: %+v %v", ps, err)
	}

	// Revisions pin the project's level.
	deploy := func(project, image string) (Revision, bool) {
		t.Helper()
		sp, err := spec.ParseIn([]byte("name: web\nimage: nginx:"+image+"\n"), project)
		if err != nil {
			t.Fatal(err)
		}
		rev, created, err := s.Deploy(ctx, sp, "admin:test")
		if err != nil {
			t.Fatal(err)
		}
		return rev, created
	}
	r1, _ := deploy("shop", "1")
	if !r1.Sandboxed() {
		t.Errorf("shop revision isolation = %q", r1.Isolation)
	}
	if got, err := s.GetRevision(ctx, r1.Name); err != nil || !got.Sandboxed() {
		t.Errorf("stored isolation: %+v %v", got.Isolation, err)
	}
	if d, _ := deploy("default", "1"); d.Sandboxed() {
		t.Error("default revision sandboxed")
	}

	// Lowering the level: the same spec deployed again is a new revision.
	if err := s.SetProjectIsolation(ctx, "shop", spec.IsolationContainer, "admin:test"); err != nil {
		t.Fatal(err)
	}
	r2, created := deploy("shop", "1")
	if !created || r2.Sandboxed() {
		t.Fatalf("redeploy after lowering: created %v, isolation %q", created, r2.Isolation)
	}
	if err := s.CompleteRollout(ctx, "web.shop", r2.Name); err != nil {
		t.Fatal(err)
	}
	// Rolling back to the sandboxed revision is fine: it is stronger.
	if _, err := s.Rollback(ctx, "web.shop", r1.Name, "admin:test"); err != nil {
		t.Fatalf("rollback to a stronger revision: %v", err)
	}
	if err := s.CompleteRollout(ctx, "web.shop", r1.Name); err != nil {
		t.Fatal(err)
	}
	// Raising it again: the container revision can no longer serve.
	if err := s.SetProjectIsolation(ctx, "shop", spec.IsolationSandbox, "admin:test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rollback(ctx, "web.shop", r2.Name, "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("rollback to a weaker revision = %v", err)
	}

	// The default project can be raised too.
	if err := s.SetProjectIsolation(ctx, "default", spec.IsolationSandbox, "admin:test"); err != nil || level("default") != spec.IsolationSandbox {
		t.Fatalf("default to sandbox: %v", err)
	}
	if d, created := deploy("default", "1"); !created || !d.Sandboxed() {
		t.Errorf("default redeploy: created %v, isolation %q", created, d.Isolation)
	}
}

func TestTrafficRefusesWeakerRevision(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	r1 := deployJob(t, s, "name: web\nimage: nginx:1\ningress:\n  type: internal\n  port: 80\n")
	if err := s.CompleteRollout(ctx, "web", r1.Name); err != nil {
		t.Fatal(err)
	}
	if err := s.SetProjectIsolation(ctx, "default", spec.IsolationSandbox, "admin:test"); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.Deploy(ctx, mustParse(t, multiSpec("2", "    - revision: web--r1\n      weight: 50\n    - revision: latest\n      weight: 50\n")), "admin:test")
	if !errors.Is(err, ErrPrecondition) {
		t.Fatalf("traffic to a container revision = %v", err)
	}
	r2 := deployJob(t, s, multiSpec("2", "    - revision: latest\n      weight: 100\n"))
	if !r2.Sandboxed() {
		t.Fatal("not sandboxed")
	}
	if _, err := s.SetTraffic(ctx, "web", []spec.TrafficTarget{{Revision: r1.Name, Weight: 100}}, "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("SetTraffic to a container revision = %v", err)
	}
}

// Projects created before schema 8 keep container, written explicitly.
func TestMigrateProjectIsolation(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.tx(ctx, func(tx *etx) error {
		return tx.put(pfxProjects+"old", projectRec{Name: "old", CreatedAt: 1})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProject(ctx, "new", "", "admin:test", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.tx(ctx, migrations[6]); err != nil {
		t.Fatal(err)
	}
	var r projectRec
	if err := s.view(ctx, func(tx *etx) error { _, err := tx.get(pfxProjects+"old", &r); return err }); err != nil || r.Isolation != spec.IsolationContainer {
		t.Errorf("old project after migration: %+v %v", r, err)
	}
	if p, _ := s.GetProject(ctx, "new"); p.Isolation != spec.IsolationSandbox {
		t.Errorf("new project changed: %q", p.Isolation)
	}
}
