package store

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestAutomation(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	for _, p := range []string{"a", "b"} {
		if _, err := s.CreateProject(ctx, p, "", "admin:test", ""); err != nil {
			t.Fatal(err)
		}
	}

	for _, bad := range []Automation{
		{Name: "Portal"},
		{Name: "portal", Projects: []string{"default"}},
		{Name: "portal", Projects: []string{"Bad"}},
		{Name: "portal", Projects: []string{"missing"}},
		{Name: "portal", Labels: map[string][]string{"tier": nil}},
		{Name: "portal", Labels: map[string][]string{"Tier!": {"x"}}},
	} {
		if _, err := s.SetAutomation(ctx, bad, "admin:test"); err == nil {
			t.Errorf("SetAutomation(%+v) accepted", bad)
		}
	}
	a, err := s.SetAutomation(ctx, Automation{Name: "portal", Projects: []string{"b", "a", "a"}, Labels: map[string][]string{"tier": {"shared"}}}, "admin:test")
	if err != nil || !slices.Equal(a.Projects, []string{"a", "b"}) || a.CreatedBy != "admin:test" {
		t.Fatalf("create: %+v %v", a, err)
	}
	if !a.Manages("a") || a.Manages("c") || a.Manages("default") {
		t.Errorf("Manages: %+v", a)
	}

	// Certificates: only recorded serials count, renewal revokes the rest.
	if _, ok, _ := s.AutomationScope(ctx, "portal", "s1"); ok {
		t.Error("unrecorded serial accepted")
	}
	exp := time.Now().Add(time.Hour)
	for _, serial := range []string{"s1", "s2"} {
		if err := s.RecordAutomationCert(ctx, "portal", NodeCert{Serial: serial, NotAfter: exp}, "", "admin:test"); err != nil {
			t.Fatal(err)
		}
	}
	if sc, ok, _ := s.AutomationScope(ctx, "portal", "s1"); !ok || !sc.Manages("b") {
		t.Errorf("s1: %+v %v", sc, ok)
	}
	if err := s.RecordAutomationCert(ctx, "portal", NodeCert{Serial: "s3", NotAfter: exp}, "s2", "automation:portal"); err != nil {
		t.Fatal(err)
	}
	for serial, want := range map[string]bool{"s1": false, "s2": true, "s3": true} {
		if _, ok, _ := s.AutomationScope(ctx, "portal", serial); ok != want {
			t.Errorf("after renewal, %s allowed = %v", serial, ok)
		}
	}
	if err := s.RecordAutomationCert(ctx, "portal", NodeCert{Serial: "old", NotAfter: time.Now().Add(-time.Minute)}, "", "admin:test"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.AutomationScope(ctx, "portal", "old"); ok {
		t.Error("expired certificate accepted")
	}
	if err := s.RecordAutomationCert(ctx, "ghost", NodeCert{Serial: "x", NotAfter: exp}, "", "admin:test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("certificate for a missing identity = %v", err)
	}

	// Updating the scope keeps the certificates.
	if _, err := s.SetAutomation(ctx, Automation{Name: "portal", Projects: []string{"a"}}, "admin:test"); err != nil {
		t.Fatal(err)
	}
	if sc, ok, _ := s.AutomationScope(ctx, "portal", "s3"); !ok || sc.Manages("b") || len(sc.Labels) != 0 {
		t.Errorf("after update: %+v %v", sc, ok)
	}

	// Creating projects needs the permission, and grants the new project.
	if _, err := s.CreateProject(ctx, "c", "", "automation:portal", "portal"); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("create without permission = %v", err)
	}
	if _, err := s.GetProject(ctx, "c"); !errors.Is(err, ErrNotFound) {
		t.Error("a refused project was created anyway")
	}
	if _, err := s.SetAutomation(ctx, Automation{Name: "portal", Projects: []string{"a"}, CreateProjects: true}, "admin:test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProject(ctx, "c", "", "automation:portal", "portal"); err != nil {
		t.Fatal(err)
	}
	if sc, _ := s.GetAutomation(ctx, "portal"); !sc.Manages("c") {
		t.Errorf("created project not granted: %+v", sc)
	}

	// A removed project leaves every scope, so its name is not handed over
	// again.
	if err := s.DeleteProject(ctx, "c", "automation:portal"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProject(ctx, "c", "", "admin:test", ""); err != nil {
		t.Fatal(err)
	}
	if sc, _ := s.GetAutomation(ctx, "portal"); sc.Manages("c") {
		t.Error("a recreated project went back to the identity")
	}

	// Removing the identity revokes its certificates.
	if err := s.DeleteAutomation(ctx, "portal", "admin:test"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.AutomationScope(ctx, "portal", "s3"); ok {
		t.Error("certificate of a removed identity accepted")
	}
	if l, _ := s.ListAutomations(ctx); len(l) != 0 {
		t.Errorf("list after delete: %+v", l)
	}
}
