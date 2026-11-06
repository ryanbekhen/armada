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
