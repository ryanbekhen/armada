package store

import (
	"context"
	"errors"
	"testing"
)

func TestRemoveApp(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.2", State: NodeReady}); err != nil {
		t.Fatal(err)
	}
	deployJob(t, s, "name: web\nimage: nginx:1\n")
	deployJob(t, s, "name: web2\nimage: nginx:1\n")
	if err := s.DeleteApp(ctx, "web"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("delete without marking: %v", err)
	}
	if err := s.MarkAppRemoving(ctx, "ghost", "admin:test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("mark unknown: %v", err)
	}
	if err := s.MarkAppRemoving(ctx, "web", "admin:test"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkAppRemoving(ctx, "web", "admin:test"); err != nil {
		t.Errorf("mark twice: %v", err)
	}
	a, err := s.GetApp(ctx, "web")
	if err != nil || !a.Removing {
		t.Fatalf("after marking: %+v, %v", a, err)
	}
	if err := s.CreateReplica(ctx, Replica{ID: "web-r1-a", App: "web", Revision: a.TargetRevision, NodeID: "n1", State: ReplicaPending}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteApp(ctx, "web"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("delete with a replica left: %v", err)
	}
	if err := s.DeleteReplica(ctx, "web-r1-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteApp(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetApp(ctx, "web"); !errors.Is(err, ErrNotFound) {
		t.Errorf("app after delete: %v", err)
	}
	if revs, _ := s.ListRevisions(ctx, "web"); len(revs) != 0 {
		t.Errorf("revisions after delete: %v", revs)
	}
	// An app whose name starts the same stays.
	if _, err := s.GetApp(ctx, "web2"); err != nil {
		t.Errorf("other app: %v", err)
	}
	if revs, _ := s.ListRevisions(ctx, "web2"); len(revs) != 1 {
		t.Errorf("other app's revisions: %v", revs)
	}
	// Gone already: nothing to do.
	if err := s.DeleteApp(ctx, "web"); err != nil {
		t.Errorf("delete twice: %v", err)
	}
}

// A verified domain belongs to the space that proved it, not to its name:
// deleting the last app that routes it, or the space, drops its record,
// so a space created again under the name must prove it afresh.
func TestDeletedSpaceForgetsDomains(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	for _, sp := range []string{"b", "c"} {
		if _, err := s.CreateSpace(ctx, sp, "user:root", nil); err != nil {
			t.Fatal(err)
		}
	}
	deploy := func(name, space string, domains []string, paths ...string) {
		t.Helper()
		a := ingressSpec(t, name, domains, paths...)
		a.Space = space
		if _, _, err := s.Deploy(ctx, a, "user:owner"); err != nil {
			t.Fatal(err)
		}
	}
	remove := func(id string) {
		t.Helper()
		if err := s.MarkAppRemoving(ctx, id, "user:owner"); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteApp(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	deploy("web", "b", []string{"shop.example.org", "keep.example.org"})
	deploy("api", "b", []string{"keep.example.org"}, "/api")
	for _, d := range []string{"shop.example.org", "keep.example.org"} {
		if err := s.SetDomainVerification(ctx, d, true, ""); err != nil {
			t.Fatal(err)
		}
	}
	old, err := s.GetDomain(ctx, "shop.example.org")
	if err != nil || !old.Verified {
		t.Fatalf("verified domain: %+v %v", old, err)
	}

	// Deleting web drops the domain only it used and keeps the shared one.
	remove("web.b")
	if _, err := s.GetDomain(ctx, "shop.example.org"); !errors.Is(err, ErrNotFound) {
		t.Errorf("domain of a deleted app: %v", err)
	}
	if d, err := s.GetDomain(ctx, "keep.example.org"); err != nil || !d.Verified {
		t.Errorf("domain another app still routes: %+v %v", d, err)
	}
	remove("api.b")
	if _, err := s.GetDomain(ctx, "keep.example.org"); !errors.Is(err, ErrNotFound) {
		t.Errorf("domain of the last app: %v", err)
	}

	// Records an older version left behind go with their space only.
	err = s.tx(ctx, func(tx *etx) error {
		if err := tx.put(pfxDomains+"left.example.org", domainRec{Name: "left.example.org", Token: "t1", Verified: true, Space: "b"}); err != nil {
			return err
		}
		return tx.put(pfxDomains+"other.example.org", domainRec{Name: "other.example.org", Token: "t2", Verified: true, Space: "c"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSpace(ctx, "b", "user:owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDomain(ctx, "left.example.org"); !errors.Is(err, ErrNotFound) {
		t.Errorf("domain of a deleted space: %v", err)
	}
	if _, err := s.GetDomain(ctx, "other.example.org"); err != nil {
		t.Errorf("another space's domain: %v", err)
	}

	// Someone else creates b again and names the domains: unverified, with
	// new tokens.
	if _, err := s.CreateSpace(ctx, "b", "service:mallory", nil); err != nil {
		t.Fatal(err)
	}
	deploy("grab", "b", []string{"shop.example.org", "left.example.org"})
	for _, name := range []string{"shop.example.org", "left.example.org"} {
		d, err := s.GetDomain(ctx, name)
		if err != nil || d.Verified || d.Token == "" || d.Token == old.Token || d.Token == "t1" {
			t.Errorf("%s in the recreated space: %+v %v", name, d, err)
		}
	}
}
