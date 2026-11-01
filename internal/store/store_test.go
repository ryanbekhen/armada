package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/spec"
)

func appSpec(t *testing.T, name, image string, replicas int) *spec.App {
	t.Helper()
	a, err := spec.Parse(fmt.Appendf(nil, "name: %s\nimage: %s\nscale:\n  min: %d\n  max: 10\n", name, image, replicas))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestMeta(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()

	if _, err := s.GetMeta(ctx, "cluster"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v", err)
	}
	if err := s.SetMeta(ctx, "cluster", "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMeta(ctx, "cluster", "b"); err != nil {
		t.Fatal(err)
	}
	if v, err := s.GetMeta(ctx, "cluster"); err != nil || v != "b" {
		t.Errorf("GetMeta = %q, %v", v, err)
	}
}

func TestNodes(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()

	if err := s.UpsertNode(ctx, Node{ID: "node-2", PrivateIP: "10.0.0.3"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(ctx, Node{ID: "node-1", PrivateIP: "10.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	n, err := s.GetNode(ctx, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if n.State != NodeUnknown || n.CreatedAt.IsZero() || !n.LastSeen.IsZero() {
		t.Errorf("node defaults = %+v", n)
	}

	seen := time.UnixMilli(time.Now().UnixMilli())
	if err := s.SetNodeStatus(ctx, "node-1", NodeStatus{State: NodeReady, LastSeen: seen, CPUMillis: 2000, MemoryBytes: 4 << 30}); err != nil {
		t.Fatal(err)
	}
	n, _ = s.GetNode(ctx, "node-1")
	if n.State != NodeReady || !n.LastSeen.Equal(seen) || n.CPUMillis != 2000 || n.MemoryBytes != 4<<30 {
		t.Errorf("after status = %+v", n)
	}
	if err := s.SetNodeStatus(ctx, "ghost", NodeStatus{State: NodeReady}); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetNodeStatus(ghost) = %v", err)
	}
	if _, err := s.GetNode(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetNode(ghost) = %v", err)
	}

	nodes, err := s.ListNodes(ctx)
	if err != nil || len(nodes) != 2 || nodes[0].ID != "node-1" {
		t.Errorf("ListNodes = %+v, %v", nodes, err)
	}
}

func TestDeployCreatesRevisions(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()

	r1, created, err := s.Deploy(ctx, appSpec(t, "web", "nginx:1", 2), "admin:ryan")
	if err != nil || !created {
		t.Fatalf("Deploy = %v, %v", created, err)
	}
	if r1.Name != "web--r1" || r1.Seq != 1 {
		t.Errorf("revision = %+v", r1)
	}

	// Identical spec: no new revision, but replicas reset.
	if err := s.SetReplicas(ctx, "web", 5, "admin:ryan"); err != nil {
		t.Fatal(err)
	}
	again, created, err := s.Deploy(ctx, appSpec(t, "web", "nginx:1", 2), "admin:ryan")
	if err != nil || created || again.Name != "web--r1" {
		t.Errorf("redeploy = %+v, %v, %v", again, created, err)
	}
	app, err := s.GetApp(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if app.Replicas != 2 || app.ActiveRevision != "web--r1" || app.Spec.Image != "nginx:1" {
		t.Errorf("app = %+v", app)
	}

	r2, created, err := s.Deploy(ctx, appSpec(t, "web", "nginx:2", 3), "admin:ryan")
	if err != nil || !created || r2.Name != "web--r2" {
		t.Fatalf("Deploy v2 = %+v, %v, %v", r2, created, err)
	}
	// v2 is rolled out; v1 keeps serving until the rollout completes.
	app, _ = s.GetApp(ctx, "web")
	if app.ActiveRevision != "web--r1" || app.TargetRevision != "web--r2" || !app.Rolling() || app.Replicas != 3 || app.Spec.Image != "nginx:1" {
		t.Errorf("app after v2 = %+v", app)
	}
	if err := s.CompleteRollout(ctx, "web", "web--r2"); err != nil {
		t.Fatal(err)
	}
	app, _ = s.GetApp(ctx, "web")
	if app.ActiveRevision != "web--r2" || app.Rolling() || app.RolloutState != RolloutNone || app.Spec.Image != "nginx:2" {
		t.Errorf("app after rollout = %+v", app)
	}

	revs, err := s.ListRevisions(ctx, "web")
	if err != nil || len(revs) != 2 || revs[0].Name != "web--r2" {
		t.Errorf("ListRevisions = %+v, %v", revs, err)
	}

	events, err := s.ListAudit(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range events {
		actions = append(actions, e.Action)
		if e.Actor != "admin:ryan" && e.Actor != "system" {
			t.Errorf("audit actor = %q", e.Actor)
		}
	}
	want := []string{"rollout.complete", "deploy", "deploy.unchanged", "scale", "deploy"}
	if fmt.Sprint(actions) != fmt.Sprint(want) {
		t.Errorf("audit actions = %v, want %v", actions, want)
	}
}

func TestDeployPrunesOldRevisions(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.2"}); err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 3; i++ {
		if _, _, err := s.Deploy(ctx, appSpec(t, "web", fmt.Sprintf("nginx:%d", i), 1), "a"); err != nil {
			t.Fatal(err)
		}
	}
	// Revision 1 still has a running replica, so it must survive pruning.
	if err := s.CreateReplica(ctx, Replica{ID: "web-r1-a", App: "web", Revision: "web--r1", NodeID: "n1"}); err != nil {
		t.Fatal(err)
	}
	for i := 4; i <= RevisionsToKeep+5; i++ {
		if _, _, err := s.Deploy(ctx, appSpec(t, "web", fmt.Sprintf("nginx:%d", i), 1), "a"); err != nil {
			t.Fatal(err)
		}
	}
	revs, err := s.ListRevisions(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != RevisionsToKeep+1 {
		t.Errorf("kept %d revisions, want %d", len(revs), RevisionsToKeep+1)
	}
	if revs[len(revs)-1].Name != "web--r1" {
		t.Errorf("oldest kept = %s, want web--r1 (still referenced)", revs[len(revs)-1].Name)
	}
	if _, err := s.GetRevision(ctx, "web--r2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("web--r2 should be pruned: %v", err)
	}
}

func TestSetReplicas(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()

	if err := s.SetReplicas(ctx, "ghost", 2, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v", err)
	}
	if _, _, err := s.Deploy(ctx, appSpec(t, "web", "nginx", 1), "a"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, -1, spec.MaxReplicas + 1} {
		if err := s.SetReplicas(ctx, "web", n, "a"); err == nil {
			t.Errorf("SetReplicas(%d) accepted", n)
		}
	}
	if _, err := s.GetApp(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetApp(ghost) = %v", err)
	}
}

func TestReplicas(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()

	for _, id := range []string{"n1", "n2"} {
		if err := s.UpsertNode(ctx, Node{ID: id, PrivateIP: "10.0.0.1"}); err != nil {
			t.Fatal(err)
		}
	}
	rev, _, err := s.Deploy(ctx, appSpec(t, "web", "nginx", 2), "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Deploy(ctx, appSpec(t, "api", "nginx", 1), "a"); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Replica{
		{ID: "web-1", App: "web", Revision: rev.Name, NodeID: "n1"},
		{ID: "web-2", App: "web", Revision: rev.Name, NodeID: "n2"},
		{ID: "api-1", App: "api", Revision: "api--r1", NodeID: "n1"},
	} {
		if err := s.CreateReplica(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateReplica(ctx, Replica{ID: "bad", App: "web", Revision: rev.Name, NodeID: "ghost"}); err == nil {
		t.Error("foreign key on node_id not enforced")
	}

	byNode, _ := s.ListReplicas(ctx, ReplicaFilter{NodeID: "n1"})
	byApp, _ := s.ListReplicas(ctx, ReplicaFilter{App: "web"})
	all, _ := s.ListReplicas(ctx, ReplicaFilter{})
	if len(byNode) != 2 || len(byApp) != 2 || len(all) != 3 {
		t.Errorf("filters: node=%d app=%d all=%d", len(byNode), len(byApp), len(all))
	}
	if all[0].State != ReplicaPending {
		t.Errorf("default state = %q", all[0].State)
	}

	st := ReplicaStatus{ID: "web-1", State: ReplicaRunning, ContainerID: "c1", Address: "10.0.0.1:32768"}
	if err := s.UpdateReplicaStatus(ctx, "n1", st); err != nil {
		t.Fatal(err)
	}
	// A different node must not be able to update web-1.
	if err := s.UpdateReplicaStatus(ctx, "n2", ReplicaStatus{ID: "web-1", State: ReplicaFailed}); !errors.Is(err, ErrNotFound) {
		t.Errorf("cross-node update err = %v, want ErrNotFound", err)
	}
	got, _ := s.ListReplicas(ctx, ReplicaFilter{App: "web", NodeID: "n1"})
	if len(got) != 1 || got[0].State != ReplicaRunning || got[0].Address != "10.0.0.1:32768" || got[0].ContainerID != "c1" {
		t.Errorf("replica = %+v", got)
	}

	if err := s.DeleteReplica(ctx, "web-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteReplica(ctx, "web-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete = %v", err)
	}
}

func TestRevisionDigest(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()

	rev, _, err := s.Deploy(ctx, appSpec(t, "web", "nginx:1", 1), "a")
	if err != nil {
		t.Fatal(err)
	}
	if rev.Image() != "nginx:1" {
		t.Errorf("Image() = %q", rev.Image())
	}
	pinned := "nginx@sha256:" + fmt.Sprintf("%064d", 1)
	if err := s.SetRevisionDigest(ctx, rev.Name, pinned); err != nil {
		t.Fatal(err)
	}
	// The first digest wins; later reports cannot change it.
	if err := s.SetRevisionDigest(ctx, rev.Name, "nginx@sha256:"+fmt.Sprintf("%064d", 2)); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRevision(ctx, rev.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got.Image() != pinned {
		t.Errorf("Image() = %q, want %q", got.Image(), pinned)
	}
	if _, err := s.GetRevision(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetRevision(nope) = %v", err)
	}
}

func TestAppsList(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()

	for _, n := range []string{"zeta", "alpha"} {
		if _, _, err := s.Deploy(ctx, appSpec(t, n, "nginx", 1), "a"); err != nil {
			t.Fatal(err)
		}
	}
	apps, err := s.ListApps(ctx)
	if err != nil || len(apps) != 2 || apps[0].Name != "alpha" || apps[0].Spec == nil {
		t.Errorf("ListApps = %+v, %v", apps, err)
	}
}

func ingressSpec(t *testing.T, name string, domains []string, paths ...string) *spec.App {
	t.Helper()
	y := fmt.Sprintf("name: %s\nimage: nginx\ningress:\n  type: external\n  port: 80\n  domains: [%s]\n", name, strings.Join(domains, ", "))
	if len(paths) > 0 {
		y += "  routes:\n"
		for _, p := range paths {
			y += "    - path: " + p + "\n"
		}
	}
	a, err := spec.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestDomainsLifecycle(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()

	if _, _, err := s.Deploy(ctx, ingressSpec(t, "web", []string{"example.org", "www.example.org"}), "a"); err != nil {
		t.Fatal(err)
	}
	ds, err := s.ListDomains(ctx)
	if err != nil || len(ds) != 2 || ds[0].Name != "example.org" || ds[0].Verified || len(ds[0].Token) != 32 {
		t.Fatalf("ListDomains = %+v, %v", ds, err)
	}
	if ds[0].Token == ds[1].Token {
		t.Error("domains share a verification token")
	}
	token := ds[0].Token

	if err := s.SetDomainVerification(ctx, "example.org", false, "TXT record not found"); err != nil {
		t.Fatal(err)
	}
	d, _ := s.GetDomain(ctx, "example.org")
	if d.Verified || d.Message != "TXT record not found" {
		t.Errorf("after failed check = %+v", d)
	}
	if err := s.SetDomainVerification(ctx, "example.org", true, ""); err != nil {
		t.Fatal(err)
	}
	d, _ = s.GetDomain(ctx, "example.org")
	if !d.Verified || d.VerifiedAt.IsZero() || d.Message != "" {
		t.Errorf("after verify = %+v", d)
	}
	// A later failed check (e.g. TXT removed) does not revoke verification.
	if err := s.SetDomainVerification(ctx, "example.org", false, "gone"); err != nil {
		t.Fatal(err)
	}
	if d, _ = s.GetDomain(ctx, "example.org"); !d.Verified {
		t.Error("verification was revoked")
	}
	if err := s.SetDomainVerification(ctx, "ghost.id", true, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("verify unknown domain = %v", err)
	}
	if err := s.SetDomainVerification(ctx, "ghost.id", false, "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("fail unknown domain = %v", err)
	}

	// Redeploying keeps the token and verification. A dropped domain stays
	// while the active revision still serves it, and goes once the rollout
	// completes.
	rev, _, err := s.Deploy(ctx, ingressSpec(t, "web", []string{"example.org"}, "/app"), "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDomain(ctx, "www.example.org"); err != nil {
		t.Errorf("domain of the active revision removed mid-rollout: %v", err)
	}
	if err := s.CompleteRollout(ctx, "web", rev.Name); err != nil {
		t.Fatal(err)
	}
	ds, _ = s.ListDomains(ctx)
	if len(ds) != 1 || ds[0].Token != token || !ds[0].Verified {
		t.Errorf("after redeploy = %+v", ds)
	}
	if _, err := s.GetDomain(ctx, "www.example.org"); !errors.Is(err, ErrNotFound) {
		t.Error("unused domain not removed")
	}
}

func TestDomainRouteConflicts(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()

	if _, _, err := s.Deploy(ctx, ingressSpec(t, "frontend", []string{"example.org"}), "a"); err != nil {
		t.Fatal(err)
	}
	// Path-based sharing of one domain across apps is allowed.
	if _, _, err := s.Deploy(ctx, ingressSpec(t, "api", []string{"example.org"}, "/api"), "a"); err != nil {
		t.Fatalf("path-based sharing rejected: %v", err)
	}
	// But two apps cannot claim the same host and path.
	_, _, err := s.Deploy(ctx, ingressSpec(t, "evil", []string{"example.org"}, "/api"), "a")
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "app api") {
		t.Errorf("conflict err = %v", err)
	}
	if _, err := s.GetApp(ctx, "evil"); !errors.Is(err, ErrNotFound) {
		t.Error("conflicting deploy was partially applied")
	}
	// Shared domains survive when one of the apps stops using them.
	if _, _, err := s.Deploy(ctx, ingressSpec(t, "api", []string{"api.example.org"}), "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDomain(ctx, "example.org"); err != nil {
		t.Errorf("domain still used by frontend was removed: %v", err)
	}
}

func TestRolloutLifecycle(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()

	// The first revision of a new app is active at once.
	r1, _, err := s.Deploy(ctx, appSpec(t, "web", "nginx:1", 2), "a")
	if err != nil {
		t.Fatal(err)
	}
	app, _ := s.GetApp(ctx, "web")
	if app.ActiveRevision != r1.Name || app.TargetRevision != r1.Name || app.Rolling() {
		t.Fatalf("new app = %+v", app)
	}

	r2, _, _ := s.Deploy(ctx, appSpec(t, "web", "nginx:2", 2), "a")
	// Redeploying the target is a no-op; a stale or foreign completion is
	// rejected.
	if again, created, err := s.Deploy(ctx, appSpec(t, "web", "nginx:2", 2), "a"); err != nil || created || again.Name != r2.Name {
		t.Errorf("redeploy target = %v %v %v", again.Name, created, err)
	}
	if err := s.CompleteRollout(ctx, "web", r1.Name); !errors.Is(err, ErrNotFound) {
		t.Errorf("complete non-target = %v", err)
	}

	// The rollout fails: the active revision stays and the failure is kept.
	if err := s.FailRollout(ctx, "web", r2.Name, "readiness probe failed"); err != nil {
		t.Fatal(err)
	}
	app, _ = s.GetApp(ctx, "web")
	if app.ActiveRevision != r1.Name || app.TargetRevision != r1.Name || app.RolloutState != RolloutFailed ||
		app.RolloutMessage != "readiness probe failed" || app.Rolling() {
		t.Errorf("after failure = %+v", app)
	}
	if err := s.FailRollout(ctx, "web", r2.Name, "again"); !errors.Is(err, ErrNotFound) {
		t.Errorf("fail twice = %v", err)
	}
	if err := s.CompleteRollout(ctx, "web", r2.Name); !errors.Is(err, ErrNotFound) {
		t.Errorf("complete failed rollout = %v", err)
	}

	// Deploying the active spec while rolling cancels the rollout.
	r3, _, _ := s.Deploy(ctx, appSpec(t, "web", "nginx:3", 2), "a")
	if got, created, err := s.Deploy(ctx, appSpec(t, "web", "nginx:1", 2), "a"); err != nil || created || got.Name != r1.Name {
		t.Errorf("cancel = %v %v %v", got.Name, created, err)
	}
	app, _ = s.GetApp(ctx, "web")
	if app.Rolling() || app.TargetRevision != r1.Name || app.RolloutState != RolloutNone {
		t.Errorf("after cancel = %+v", app)
	}

	// Roll back to r3 (never active), then complete it.
	if _, err := s.Rollback(ctx, "web", r3.Name, "admin:ryan"); err != nil {
		t.Fatal(err)
	}
	app, _ = s.GetApp(ctx, "web")
	if !app.Rolling() || app.TargetRevision != r3.Name {
		t.Errorf("after rollback = %+v", app)
	}
	if err := s.CompleteRollout(ctx, "web", r3.Name); err != nil {
		t.Fatal(err)
	}
	if app, _ = s.GetApp(ctx, "web"); app.ActiveRevision != r3.Name || app.Spec.Image != "nginx:3" {
		t.Errorf("after completing rollback = %+v", app)
	}
	events, _ := s.ListAudit(ctx, 1)
	if len(events) != 1 || events[0].Action != "rollout.complete" {
		t.Errorf("audit = %+v", events)
	}
}

func TestRollbackRejectsForeignRevisions(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if _, _, err := s.Deploy(ctx, appSpec(t, "web", "nginx:1", 1), "a"); err != nil {
		t.Fatal(err)
	}
	other, _, _ := s.Deploy(ctx, appSpec(t, "other", "redis:7", 1), "a")
	if _, err := s.Rollback(ctx, "web", other.Name, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("rollback to another app's revision = %v", err)
	}
	if _, err := s.Rollback(ctx, "web", "web--r99", "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("rollback to missing revision = %v", err)
	}
	if _, err := s.Rollback(ctx, "ghost", other.Name, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("rollback of missing app = %v", err)
	}
	if app, _ := s.GetApp(ctx, "web"); app.TargetRevision != "web--r1" {
		t.Errorf("rejected rollback changed the target: %+v", app)
	}
}

func TestRollbackReclaimsDomains(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	r1, _, _ := s.Deploy(ctx, ingressSpec(t, "web", []string{"example.org"}), "a")
	r2, _, _ := s.Deploy(ctx, ingressSpec(t, "web", []string{"baru.id"}), "a")
	if err := s.CompleteRollout(ctx, "web", r2.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDomain(ctx, "example.org"); !errors.Is(err, ErrNotFound) {
		t.Fatal("dropped domain kept")
	}
	// Another app takes the route in the meantime: rolling back must not
	// steal it.
	if _, _, err := s.Deploy(ctx, ingressSpec(t, "shop", []string{"example.org"}), "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rollback(ctx, "web", r1.Name, "a"); !errors.Is(err, ErrConflict) {
		t.Errorf("rollback onto a taken route = %v", err)
	}
	// Without the conflict, rolling back registers the domain again.
	r3, _, _ := s.Deploy(ctx, ingressSpec(t, "shop", []string{"toko.id"}), "a")
	if err := s.CompleteRollout(ctx, "shop", r3.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rollback(ctx, "web", r1.Name, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDomain(ctx, "example.org"); err != nil {
		t.Errorf("rollback did not register its domain: %v", err)
	}
}

func TestReplicaReadinessAndDraining(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	rev, _, _ := s.Deploy(ctx, appSpec(t, "web", "nginx:1", 1), "a")
	if err := s.CreateReplica(ctx, Replica{ID: "web-1", App: "web", Revision: rev.Name, NodeID: "n1"}); err != nil {
		t.Fatal(err)
	}
	clock := time.UnixMilli(1_000_000)
	s.now = func() time.Time { return clock }
	get := func() Replica {
		t.Helper()
		rs, err := s.ListReplicas(ctx, ReplicaFilter{App: "web"})
		if err != nil || len(rs) != 1 {
			t.Fatalf("ListReplicas = %v, %v", rs, err)
		}
		return rs[0]
	}
	report := func(state string, ready bool) {
		t.Helper()
		if err := s.UpdateReplicaStatus(ctx, "n1", ReplicaStatus{ID: "web-1", State: state, Ready: ready}); err != nil {
			t.Fatal(err)
		}
	}

	report(ReplicaRunning, false)
	if r := get(); r.Ready || !r.ReadySince.IsZero() {
		t.Errorf("not ready = %+v", r)
	}
	report(ReplicaRunning, true)
	if r := get(); !r.Ready || !r.ReadySince.Equal(clock) {
		t.Errorf("ready = %+v", r)
	}
	// Staying ready keeps the original timestamp.
	clock = clock.Add(time.Minute)
	report(ReplicaRunning, true)
	if r := get(); !r.ReadySince.Equal(clock.Add(-time.Minute)) {
		t.Errorf("ready_since moved: %+v", r)
	}
	// An agent cannot claim readiness for a container that is not running.
	report(ReplicaExited, true)
	if r := get(); r.Ready || !r.ReadySince.IsZero() {
		t.Errorf("exited but ready: %+v", r)
	}

	if err := s.SetReplicaMoving(ctx, "web-1", true); err != nil {
		t.Fatal(err)
	}
	since := get().MovingSince
	clock = clock.Add(time.Minute)
	if err := s.SetReplicaMoving(ctx, "web-1", true); err != nil {
		t.Fatal(err)
	}
	if r := get(); !r.Moving() || !r.MovingSince.Equal(since) {
		t.Errorf("moving = %+v (first %v)", r, since)
	}
	report(ReplicaRunning, true)
	if r := get(); !r.Moving() {
		t.Error("a status report cleared the moving mark")
	}
	if err := s.SetReplicaMoving(ctx, "web-1", false); err != nil {
		t.Fatal(err)
	}
	if get().Moving() {
		t.Error("moving mark not cleared")
	}
	if err := s.SetReplicaMoving(ctx, "ghost", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("move missing replica = %v", err)
	}

	if err := s.DrainReplica(ctx, "web-1"); err != nil {
		t.Fatal(err)
	}
	first := get().DrainingSince
	clock = clock.Add(time.Minute)
	if err := s.DrainReplica(ctx, "web-1"); err != nil {
		t.Fatal(err)
	}
	if r := get(); !r.Draining() || !r.DrainingSince.Equal(first) {
		t.Errorf("draining = %+v (first %v)", r, first)
	}
	if err := s.DrainReplica(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("drain missing replica = %v", err)
	}
}

func TestPruneKeepsActiveAndTarget(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	r1, _, _ := s.Deploy(ctx, appSpec(t, "web", "nginx:0", 1), "a")
	for i := 1; i <= RevisionsToKeep+2; i++ {
		if _, _, err := s.Deploy(ctx, appSpec(t, "web", fmt.Sprintf("nginx:%d", i), 1), "a"); err != nil {
			t.Fatal(err)
		}
	}
	// r1 is still active because no rollout completed.
	if _, err := s.GetRevision(ctx, r1.Name); err != nil {
		t.Errorf("active revision pruned: %v", err)
	}
	revs, _ := s.ListRevisions(ctx, "web")
	if len(revs) != RevisionsToKeep+1 {
		t.Errorf("kept %d revisions, want %d", len(revs), RevisionsToKeep+1)
	}
}
