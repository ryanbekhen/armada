package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAdmins(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	t0 := time.Unix(1_800_000_000, 0)
	allowed := func(name string, notBefore time.Time) bool {
		t.Helper()
		ok, err := s.AdminAllowed(ctx, name, notBefore)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	// Names not on record keep working: certificates from before records.
	if !allowed("root", t0) {
		t.Error("unrecorded name refused")
	}
	// KnowAdmin records without refusing anything, and only once.
	if err := s.KnowAdmin(ctx, "root"); err != nil {
		t.Fatal(err)
	}
	if err := s.KnowAdmin(ctx, "root"); err != nil {
		t.Fatal(err)
	}
	if !allowed("root", t0.Add(-1000*time.Hour)) {
		t.Error("known admin refused")
	}

	// AddAdmin refuses older certificates of the name.
	if err := s.AddAdmin(ctx, "alice", t0, "admin:root"); err != nil {
		t.Fatal(err)
	}
	if allowed("alice", t0.Add(-time.Second)) || !allowed("alice", t0) || !allowed("alice", t0.Add(time.Hour)) {
		t.Error("since not applied")
	}
	if err := s.AddAdmin(ctx, "alice", t0.Add(time.Hour), "admin:root"); !errors.Is(err, ErrConflict) {
		t.Errorf("adding an active admin again: %v", err)
	}
	if err := s.AddAdmin(ctx, "root", t0, "admin:alice"); !errors.Is(err, ErrConflict) {
		t.Errorf("adding a known admin: %v", err)
	}

	// RemoveAdmin refuses every certificate, also of names never on record.
	for _, name := range []string{"alice", "ghost"} {
		if err := s.RemoveAdmin(ctx, name, "admin:root"); err != nil {
			t.Fatal(err)
		}
		if allowed(name, t0.Add(time.Hour)) {
			t.Errorf("%s still allowed after removal", name)
		}
	}
	// KnowAdmin does not bring a removed one back; AddAdmin does, with only
	// the new certificate.
	if err := s.KnowAdmin(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if allowed("alice", t0.Add(time.Hour)) {
		t.Error("KnowAdmin restored a removed admin")
	}
	if err := s.AddAdmin(ctx, "alice", t0.Add(2*time.Hour), "admin:root"); err != nil {
		t.Fatal(err)
	}
	if allowed("alice", t0.Add(time.Hour)) || !allowed("alice", t0.Add(2*time.Hour)) {
		t.Error("re-added admin: old certificate accepted or new refused")
	}

	list, err := s.ListAdmins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Admin{}
	for _, a := range list {
		got[a.Name] = a
	}
	if len(got) != 3 || got["alice"].Removed || !got["ghost"].Removed || got["alice"].AddedBy != "admin:root" || got["root"].Removed {
		t.Errorf("list: %+v", list)
	}
	audit, err := s.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range audit {
		if e.Action == "admin.add" || e.Action == "admin.remove" {
			n++
		}
	}
	if n != 4 {
		t.Errorf("audit events: %d, want 4", n)
	}
}
