package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// replicaIDs returns the IDs of app's replicas.
func replicaIDs(t *testing.T, s *Etcd, app string) []string {
	t.Helper()
	rs, err := s.ListReplicas(context.Background(), ReplicaFilter{App: app})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range rs {
		ids = append(ids, r.ID)
	}
	return ids
}

// Apps whose names share a prefix ("web" and "web-r2") never see each
// other's replicas, though one's replica IDs start with the other's prefix.
func TestReplicasOfOneApp(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"web", "web-r2", "api", "api-x"} {
		if _, _, err := s.Deploy(ctx, appSpec(t, name, "nginx", 1), "a"); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []Replica{
		{ID: "web-r1-aaaaa", App: "web", Revision: "web--r1"},
		{ID: "web-r2-r1-bbbbb", App: "web-r2", Revision: "web-r2--r1"},
		{ID: "api-r1-ccccc", App: "api", Revision: "api--r1"},
		{ID: "api-x-r1-ddddd", App: "api-x", Revision: "api-x--r1"},
	} {
		r.NodeID = "n1"
		if err := s.CreateReplica(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	for app, want := range map[string][]string{
		"web": {"web-r1-aaaaa"}, "web-r2": {"web-r2-r1-bbbbb"},
		"api": {"api-r1-ccccc"}, "api-x": {"api-x-r1-ddddd"},
	} {
		if got := replicaIDs(t, s, app); !slices.Equal(got, want) {
			t.Errorf("replicas of %s = %v, want %v", app, got, want)
		}
	}
	both, err := s.ListReplicas(ctx, ReplicaFilter{App: "web", NodeID: "n2"})
	if err != nil || len(both) != 0 {
		t.Errorf("app and node filter = %v, %v", both, err)
	}

	// A replica ID outside its app's prefix is refused: reads rely on it.
	for _, r := range []Replica{
		{ID: "api-r1-eeeee", App: "web", Revision: "web--r1", NodeID: "n1"},
		{ID: "webr1-fffff", App: "web", Revision: "web--r1", NodeID: "n1"},
	} {
		if err := s.CreateReplica(ctx, r); !errors.Is(err, ErrPrecondition) {
			t.Errorf("CreateReplica(%s of %s) = %v", r.ID, r.App, err)
		}
	}

	// Pruning web keeps the revision its replica runs; web-r2's replica
	// does not hold any of web's.
	for i := range RevisionsToKeep + 2 {
		if _, _, err := s.Deploy(ctx, appSpec(t, "web", fmt.Sprintf("nginx:%d", i), 1), "a"); err != nil {
			t.Fatal(err)
		}
	}
	revs, err := s.ListRevisions(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range revs {
		names = append(names, r.Name)
	}
	if !slices.Contains(names, "web--r1") || slices.Contains(names, "web--r2") || len(names) != RevisionsToKeep+1 {
		t.Errorf("web revisions after pruning = %v", names)
	}
	if _, err := s.GetRevision(ctx, "web-r2--r1"); err != nil {
		t.Errorf("another app's revision: %v", err)
	}

	// Removing web waits for its own replica only; web-r2's stays.
	if err := s.MarkAppRemoving(ctx, "web", "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteApp(ctx, "web"); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("DeleteApp with a replica left = %v", err)
	}
	if err := s.DeleteReplica(ctx, "web-r1-aaaaa"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteApp(ctx, "web"); err != nil {
		t.Fatalf("DeleteApp: %v", err)
	}
	if got := replicaIDs(t, s, "web-r2"); !slices.Equal(got, []string{"web-r2-r1-bbbbb"}) {
		t.Errorf("web-r2 replicas after removing web = %v", got)
	}
}

// Deleting and cancelling a job's runs touch only its own attempts.
func TestJobReplicasOfOneJob(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"backup", "backup-j1"} {
		deployJob(t, s, "kind: job\nname: "+name+"\nimage: busybox:1\n")
		run, err := s.CreateJobRun(ctx, name, TriggerManual, time.Time{}, "admin:test")
		if err != nil {
			t.Fatal(err)
		}
		id := fmt.Sprintf("%s-j%d-aaaaa", name, run.Seq)
		if err := s.CreateReplica(ctx, Replica{ID: id, App: name, Revision: run.Revision, NodeID: "n1", Run: run.Seq}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CancelJobRuns(ctx, "backup", "admin:test"); err != nil {
		t.Fatal(err)
	}
	rs, _ := s.ListReplicas(ctx, ReplicaFilter{})
	for _, r := range rs {
		if want := r.App == "backup"; r.Done != want {
			t.Errorf("after cancelling backup, %s done = %v", r.ID, r.Done)
		}
	}
	if err := s.DeleteJob(ctx, "backup", "admin:test"); err != nil {
		t.Fatal(err)
	}
	if got := replicaIDs(t, s, ""); !slices.Equal(got, []string{"backup-j1-j1-aaaaa"}) {
		t.Errorf("replicas after deleting backup = %v", got)
	}
}

// Deploys, rollouts, and app replica lists read the replicas of their own
// app only, however many other apps run.
func TestReplicaReadsStayWithTheApp(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	addApp := func(name string, replicas int) {
		t.Helper()
		if _, _, err := s.Deploy(ctx, appSpec(t, name, "nginx", 1), "a"); err != nil {
			t.Fatal(err)
		}
		for i := range replicas {
			r := Replica{ID: fmt.Sprintf("%s-r1-%05d", name, i), App: name, Revision: name + "--r1", NodeID: "n1"}
			if err := s.CreateReplica(ctx, r); err != nil {
				t.Fatal(err)
			}
		}
	}
	addApp("web", 2)
	// What one deploy, one completed rollout, and one list read under
	// replicas/: the most of any single list.
	measure := func(image string) int {
		t.Helper()
		var most int
		s.onList = func(prefix string, keys int) {
			if strings.HasPrefix(prefix, pfxReplicas) || strings.HasPrefix(pfxReplicas, prefix) {
				most = max(most, keys)
			}
		}
		defer func() { s.onList = nil }()
		rev, _, err := s.Deploy(ctx, appSpec(t, "web", image, 1), "a")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.CompleteRollout(ctx, "web", rev.Name); err != nil {
			t.Fatal(err)
		}
		if got := replicaIDs(t, s, "web"); len(got) != 2 {
			t.Fatalf("web replicas = %v", got)
		}
		return most
	}
	before := measure("nginx:2")
	if before != 2 {
		t.Errorf("a deploy read %d replica keys, want web's 2", before)
	}
	addApp("web-r2", 20) // shares web's prefix: still read, then skipped
	for i := range 10 {
		addApp(fmt.Sprintf("other%d", i), 5)
	}
	if after := measure("nginx:3"); after != before+20 {
		t.Errorf("a deploy read %d replica keys with 70 unrelated replicas, want %d", after, before+20)
	}
}
