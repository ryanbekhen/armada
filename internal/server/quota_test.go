package server

import (
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

func TestProjectQuotaAPI(t *testing.T) {
	t.Parallel()
	c, auto, _ := automationCluster(t)
	info := func(p string) *armadav1.ProjectInfo {
		t.Helper()
		resp, err := c.admin.ListProjects(c.ctx, &armadav1.ListProjectsRequest{})
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range resp.Projects {
			if i.Name == p {
				return i
			}
		}
		t.Fatalf("no project %s", p)
		return nil
	}
	// Project a already runs web (1 replica, 100m, 256Mi).
	if u := info("a").Used; u.GetReplicas() != 1 || u.GetCpuMillis() != 100 || u.GetMemoryBytes() != 256<<20 {
		t.Errorf("used = %v", u)
	}
	got, err := c.admin.UpdateProject(c.ctx, &armadav1.UpdateProjectRequest{Name: "a", Quota: &armadav1.Quota{Replicas: 1}})
	if err != nil || got.GetQuota().GetReplicas() != 1 {
		t.Fatalf("set quota: %v %v", got, err)
	}
	_, err = c.admin.Scale(c.ctx, &armadav1.ScaleRequest{App: "web.a", Replicas: 2})
	wantCode(t, "scale past the quota", err, codes.FailedPrecondition)
	_, err = auto.Scale(c.ctx, &armadav1.ScaleRequest{App: "web.a", Replicas: 2})
	wantCode(t, "automation scales past the quota", err, codes.FailedPrecondition)
	_, err = auto.Deploy(c.ctx, &armadav1.DeployRequest{Spec: []byte("name: api\nimage: nginx:1\n"), Project: "a"})
	wantCode(t, "automation deploys past the quota", err, codes.FailedPrecondition)

	_, err = c.admin.UpdateProject(c.ctx, &armadav1.UpdateProjectRequest{Name: "a", Quota: &armadav1.Quota{Replicas: -1}})
	wantCode(t, "negative quota", err, codes.InvalidArgument)
	// Automation identities never set quotas, not even on their projects.
	_, err = auto.UpdateProject(c.ctx, &armadav1.UpdateProjectRequest{Name: "a", Quota: &armadav1.Quota{}})
	wantCode(t, "automation clears its quota", err, codes.PermissionDenied)
	if info("a").GetQuota().GetReplicas() != 1 {
		t.Error("quota changed")
	}
	// An empty quota removes it.
	if _, err := c.admin.UpdateProject(c.ctx, &armadav1.UpdateProjectRequest{Name: "a", Quota: &armadav1.Quota{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.admin.Scale(c.ctx, &armadav1.ScaleRequest{App: "web.a", Replicas: 2}); err != nil {
		t.Errorf("scale without a quota: %v", err)
	}

	// Admins may create a project with a quota; the projects of an
	// automation identity get its scope's.
	if p, err := c.admin.CreateProject(c.ctx, &armadav1.CreateProjectRequest{Name: "q", Quota: &armadav1.Quota{Secrets: 3}}); err != nil || p.GetQuota().GetSecrets() != 3 {
		t.Fatalf("admin create with quota: %v %v", p, err)
	}
	if _, err := c.admin.SetAutomation(c.ctx, &armadav1.SetAutomationRequest{Name: "portal", Projects: []string{"a"}, CreateProjects: true,
		Quota: &armadav1.Quota{Replicas: 5, CpuMillis: 2000}}); err != nil {
		t.Fatal(err)
	}
	_, err = auto.CreateProject(c.ctx, &armadav1.CreateProjectRequest{Name: "mine", Quota: &armadav1.Quota{}})
	wantCode(t, "automation picks a quota", err, codes.PermissionDenied)
	p, err := auto.CreateProject(c.ctx, &armadav1.CreateProjectRequest{Name: "mine"})
	if err != nil || p.GetQuota().GetReplicas() != 5 || p.GetQuota().GetCpuMillis() != 2000 {
		t.Fatalf("automation project quota: %v %v", p, err)
	}
	list, err := c.admin.ListAutomations(c.ctx, &armadav1.ListAutomationsRequest{})
	if err != nil || len(list.Automations) != 1 || list.Automations[0].GetQuota().GetReplicas() != 5 {
		t.Errorf("automation list: %v %v", list, err)
	}
}

// A project's job attempts wait for room in its quota, and start once an
// attempt ends.
func TestJobAttemptsWaitForQuota(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d := c.addNode("n1", "10.0.0.11")
	if _, err := c.admin.CreateProject(c.ctx, &armadav1.CreateProjectRequest{Name: "shop", Isolation: spec.IsolationContainer,
		Quota: &armadav1.Quota{Jobs: 1}}); err != nil {
		t.Fatal(err)
	}
	for _, j := range []string{"a", "b"} {
		if _, err := c.admin.Deploy(c.ctx, &armadav1.DeployRequest{Spec: []byte("kind: job\nname: job-" + j + "\nimage: busybox:1\n"), Project: "shop"}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.admin.RunJob(c.ctx, &armadav1.RunJobRequest{Job: "job-" + j + ".shop"}); err != nil {
			t.Fatal(err)
		}
	}
	c.eventually("one attempt", func() bool {
		return c.runState("job-a.shop", 1).GetState() == store.RunRunning || c.runState("job-b.shop", 1).GetState() == store.RunRunning
	})
	first, second := "job-a.shop", "job-b.shop"
	if c.runState(first, 1).GetState() != store.RunRunning {
		first, second = second, first
	}
	c.eventually("quota event", func() bool {
		evs, _ := c.store.ListEvents(c.ctx, time.Time{})
		return slices.ContainsFunc(evs, func(e store.Event) bool { return e.Reason == "QuotaExceeded" && e.App == second })
	})
	if s := c.runState(second, 1).GetState(); s != store.RunPending || containerCount(d) != 1 {
		t.Fatalf("second run %s with %d containers", s, containerCount(d))
	}
	exitAttempt(t, []*fake.Driver{d}, c.runState(first, 1).GetReplica(), 0)
	c.eventually("second runs", func() bool { return c.runState(second, 1).GetState() == store.RunRunning })
}
