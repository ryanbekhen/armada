package store

import (
	"context"
	"maps"
	"testing"
	"time"
)

// Placements outlive their replicas, stay with their app (not one whose ID
// shares the prefix), and are pruned by age.
func TestReplicaPlacements(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	for _, n := range []Node{{ID: "n1", PrivateIP: "10.0.0.1"}, {ID: "n2", PrivateIP: "10.0.0.2"}} {
		if err := s.UpsertNode(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"web", "web-api"} {
		if _, _, err := s.Deploy(ctx, appSpec(t, name, "nginx", 1), "a"); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-48 * time.Hour)
	s.now = func() time.Time { return old }
	for _, r := range []Replica{
		{ID: "web-r1-aaaaa", App: "web", Revision: "web--r1", NodeID: "n1"},
		{ID: "web-api-r1-bbbbb", App: "web-api", Revision: "web-api--r1", NodeID: "n2"},
	} {
		if err := s.CreateReplica(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	s.now = time.Now
	if err := s.CreateReplica(ctx, Replica{ID: "web-r2-ccccc", App: "web", Revision: "web--r1", NodeID: "n2"}); err != nil {
		t.Fatal(err)
	}
	// The first replica is gone: its placement stays.
	if err := s.DeleteReplica(ctx, "web-r1-aaaaa"); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReplicaPlacements(ctx, "web")
	want := map[string]string{"web-r1-aaaaa": "n1", "web-r2-ccccc": "n2"}
	if err != nil || !maps.Equal(got, want) {
		t.Errorf("placements of web = %v, %v; want %v", got, err, want)
	}

	n, err := s.PrunePlacements(ctx, time.Now().Add(-24*time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("pruned %d, %v; want the 2 old records", n, err)
	}
	got, _ = s.ReplicaPlacements(ctx, "web")
	if want := map[string]string{"web-r2-ccccc": "n2"}; !maps.Equal(got, want) {
		t.Errorf("after pruning = %v, want %v", got, want)
	}
	// A live replica counts even without a record (created before records
	// were kept, or past pruning).
	got, _ = s.ReplicaPlacements(ctx, "web-api")
	if want := map[string]string{"web-api-r1-bbbbb": "n2"}; !maps.Equal(got, want) {
		t.Errorf("live replica without a record = %v, want %v", got, want)
	}
}
