package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
)

func TestProjectQuota(t *testing.T) {
	t.Parallel()
	s, ctx, k := open(t), context.Background(), testKeyring(t)
	if _, err := s.CreateProject(ctx, "shop", "", "admin:test", ""); err != nil {
		t.Fatal(err)
	}
	q := spec.Quota{CPUMillis: 1000, MemoryBytes: 1 << 30, Replicas: 4, Volumes: 1, Domains: 1, Secrets: 1, Jobs: 1}
	if err := s.SetProjectQuota(ctx, "shop", q, "admin:test"); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.GetProject(ctx, "shop"); p.Quota != q {
		t.Fatalf("stored quota = %+v", p.Quota)
	}
	deploy := func(y string) error {
		t.Helper()
		sp, err := spec.ParseIn([]byte(y), "shop")
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = s.Deploy(ctx, sp, "admin:test")
		return err
	}
	over := func(what string, err error, want string) {
		t.Helper()
		if !errors.Is(err, ErrQuota) || !errors.Is(err, ErrPrecondition) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s = %v, want over quota on %s", what, err, want)
		}
	}

	// 2 replicas × 250m / 256Mi fit; a third app of 3 does not (replicas).
	if err := deploy("name: web\nimage: nginx:1\nresources:\n  cpu: 250m\nscale:\n  min: 2\n"); err != nil {
		t.Fatal(err)
	}
	over("third app", deploy("name: api\nimage: nginx:1\nscale:\n  min: 3\n"), "replicas 5 of 4")
	// Autoscaled apps count scale.max.
	over("autoscaled", deploy("name: api\nimage: nginx:1\nscale:\n  min: 1\n  max: 5\n  rules:\n    - type: cpu\n      utilization: 70\n"), "replicas 7 of 4")
	// CPU: 2 × 250m + 2 × 400m > 1.
	over("cpu", deploy("name: api\nimage: nginx:1\nresources:\n  cpu: 400m\nscale:\n  min: 2\n"), "cpu 1.3 of 1")
	over("scale up", s.SetReplicas(ctx, "web.shop", 5, "admin:test"), "replicas 5 of 4")
	if err := s.SetReplicas(ctx, "web.shop", 4, "admin:test"); err != nil {
		t.Fatalf("scale to the quota: %v", err)
	}
	if u, err := s.ProjectUsage(ctx); err != nil || u["shop"].Replicas != 4 || u["shop"].CPUMillis != 1000 || u["shop"].MemoryBytes != 1<<30 {
		t.Fatalf("usage = %+v %v", u["shop"], err)
	}
	if err := s.SetReplicas(ctx, "web.shop", 2, "admin:test"); err != nil {
		t.Fatal(err)
	}

	// Secrets: one name, any number of versions.
	set := func(app, name string) error {
		_, _, err := s.SetSecret(ctx, app, name, func(v int) (secrets.Sealed, error) {
			return k.Seal(app, name, v, secrets.NewValue([]byte("x")))
		}, false, "admin:test")
		return err
	}
	if err := set("web.shop", "a"); err != nil {
		t.Fatal(err)
	}
	if err := set("web.shop", "a"); err != nil {
		t.Errorf("new version of a counted secret: %v", err)
	}
	over("second secret", set("web.shop", "b"), "secrets 2 of 1")
	if err := set("web", "b"); err != nil {
		t.Errorf("default project bounded by shop's quota: %v", err)
	}

	// Domains and volumes.
	over("domains", deploy("name: site\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n  domains: [a.example.com, b.example.com]\n"), "domains 2 of 1")
	over("volumes", deploy("name: db\nimage: nginx:1\nvolumes:\n  - name: a\n    path: /a\n  - name: b\n    path: /b\n"), "volumes 2 of 1")

	// Lowered below use: what runs stays, shrinking works, growing does not.
	if err := s.SetProjectQuota(ctx, "shop", spec.Quota{Replicas: 1}, "admin:test"); err != nil {
		t.Fatal(err)
	}
	if err := deploy("name: web\nimage: nginx:2\nresources:\n  cpu: 250m\nscale:\n  min: 2\n"); err != nil {
		t.Errorf("same size over a lowered quota: %v", err)
	}
	if err := s.SetReplicas(ctx, "web.shop", 1, "admin:test"); err != nil {
		t.Errorf("shrink: %v", err)
	}
	over("grow again", s.SetReplicas(ctx, "web.shop", 2, "admin:test"), "replicas 2 of 1")

	// Job attempts at once.
	if err := s.SetProjectQuota(ctx, "shop", spec.Quota{Jobs: 1}, "admin:test"); err != nil {
		t.Fatal(err)
	}
	for _, j := range []string{"a", "b"} {
		if err := deploy("kind: job\nname: job-" + j + "\nimage: busybox\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	attempt := func(job, id string) error {
		run, err := s.CreateJobRun(ctx, job, TriggerManual, s.now(), "admin:test")
		if err != nil {
			t.Fatal(err)
		}
		return s.CreateReplica(ctx, Replica{ID: id, App: job, Revision: run.Revision, NodeID: "n1", Run: run.Seq})
	}
	if err := attempt("job-a.shop", "job-a.shop-j1-aaaaa"); err != nil {
		t.Fatal(err)
	}
	over("second attempt", attempt("job-b.shop", "job-b.shop-j1-bbbbb"), "jobs 2 of 1")
	if err := s.SetReplicaDone(ctx, "job-a.shop-j1-aaaaa"); err != nil {
		t.Fatal(err)
	}
	if err := attempt("job-b.shop", "job-b.shop-j1-ccccc"); err != nil {
		t.Errorf("attempt after the first ended: %v", err)
	}

	if err := s.SetProjectQuota(ctx, "shop", spec.Quota{Replicas: -1}, "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("negative quota = %v", err)
	}
	if err := s.SetProjectQuota(ctx, "ghost", spec.Quota{Replicas: 1}, "admin:test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing project = %v", err)
	}
	// The default project can have one too, without losing its isolation.
	if err := s.SetProjectIsolation(ctx, "default", spec.IsolationSandbox, "admin:test"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetProjectQuota(ctx, "default", spec.Quota{Secrets: 1}, "admin:test"); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.GetProject(ctx, "default"); p.Quota.Secrets != 1 || p.Isolation != spec.IsolationSandbox {
		t.Errorf("default = %+v", p)
	}
	over("default secrets", set("web", "c"), "secrets 2 of 1")
}

// Projects an automation identity creates get its quota.
func TestAutomationQuota(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	q := spec.Quota{Replicas: 2}
	if _, err := s.SetAutomation(ctx, Automation{Name: "portal", CreateProjects: true, Quota: q}, "admin:test"); err != nil {
		t.Fatal(err)
	}
	if a, err := s.GetAutomation(ctx, "portal"); err != nil || a.Quota != q {
		t.Fatalf("automation quota = %+v %v", a.Quota, err)
	}
	p, err := s.CreateProject(ctx, "mine", "", "automation:portal", "portal")
	if err != nil || p.Quota != q {
		t.Fatalf("created: %+v %v", p, err)
	}
	if got, _ := s.GetProject(ctx, "mine"); got.Quota != q {
		t.Errorf("stored = %+v", got.Quota)
	}
	if _, err := s.SetAutomation(ctx, Automation{Name: "bad", Quota: spec.Quota{Jobs: -1}}, "admin:test"); err == nil {
		t.Error("negative automation quota accepted")
	}
}
