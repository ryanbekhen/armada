package server

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/store"
)

func TestTop(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	drivers := map[string]interface {
		SetUsage(string, runtime.Stats)
	}{"n1": c.addNode("n1", "127.0.0.1"), "n2": c.addNode("n2", "127.0.0.2")}
	c.deploy(webSpec("nginx:1", 2) + "resources:\n  cpu: 250m\n  memory: 128Mi\n")
	c.eventually("2 running", func() bool { return len(c.running("web")) == 2 })
	owner := map[string]string{} // replica -> node
	for _, r := range c.running("web") {
		owner[r.Id] = r.NodeId
		drivers[r.NodeId].SetUsage(r.Id, runtime.Stats{MemoryBytes: 50 << 20})
	}

	top := func(app string) *armadav1.TopResponse {
		t.Helper()
		resp, err := c.admin.Top(c.ctx, &armadav1.TopRequest{App: app})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	c.eventually("both replicas measured", func() bool {
		n := 0
		for _, r := range top("").GetReplicas() {
			if r.GetMeasured() && r.GetMemoryBytes() == 50<<20 {
				n++
			}
		}
		return n == 2
	})
	resp := top("")
	for _, r := range resp.GetReplicas() {
		if r.GetApp() != "web" || r.GetNodeId() != owner[r.GetId()] || r.GetCpuReservedMillis() != 250 || r.GetCpuLimitMillis() != 250 ||
			r.GetMemoryLimitBytes() != 128<<20 || r.GetSampledAt() == nil {
			t.Errorf("replica %v", r)
		}
	}
	if len(resp.GetNodes()) != 2 {
		t.Fatalf("nodes %v", resp.GetNodes())
	}
	for _, n := range resp.GetNodes() {
		// 2000m and 2Gi less what Armada keeps on a node.
		if !n.GetMeasured() || n.GetReplicas() != 1 || n.GetMemoryBytes() != 50<<20 || n.GetCpuReservedMillis() != 250 ||
			n.GetMemoryReservedBytes() != 128<<20 || n.GetCpuAllocatableMillis() != 1900 || n.GetMemoryAllocatableBytes() != 2<<30-128<<20 {
			t.Errorf("node %v", n)
		}
	}
	if r := top("web"); len(r.GetReplicas()) != 2 || len(r.GetNodes()) != 0 {
		t.Errorf("top web: %v", r)
	}
	if _, err := c.admin.Top(c.ctx, &armadav1.TopRequest{App: "ghost"}); status.Code(err) != codes.NotFound {
		t.Errorf("top ghost: %v", err)
	}

	// Another node's report about these replicas changes nothing: usage
	// only counts from the node a replica is assigned to.
	if err := c.store.UpsertNode(c.ctx, store.Node{ID: "evil", PrivateIP: "10.0.0.66"}); err != nil {
		t.Fatal(err)
	}
	client := armadav1.NewAgentServiceClient(c.dial(c.ca, pki.Identity{Kind: pki.KindNode, Name: "evil"}))
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	stream, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Hello{Hello: &armadav1.Hello{PrivateIp: "10.0.0.66"}}}); err != nil {
		t.Fatal(err)
	}
	forged := &armadav1.UsageReport{}
	for id := range owner {
		forged.Replicas = append(forged.Replicas, &armadav1.ReplicaUsage{Id: id, CpuMillis: 9000, MemoryBytes: 1 << 40})
	}
	if err := stream.Send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Usage{Usage: forged}}); err != nil {
		t.Fatal(err)
	}
	c.eventually("evil node measured", func() bool {
		for _, n := range top("").GetNodes() {
			if n.GetId() == "evil" {
				return n.GetMeasured()
			}
		}
		return false
	})
	resp = top("")
	for _, r := range resp.GetReplicas() {
		if r.GetMemoryBytes() != 50<<20 || r.GetCpuMillis() != 0 {
			t.Errorf("forged usage counted: %v", r)
		}
	}
	for _, n := range resp.GetNodes() {
		if n.GetId() == "evil" && (n.GetReplicas() != 0 || n.GetMemoryBytes() != 0 || n.GetCpuMillis() != 0) {
			t.Errorf("evil node: %v", n)
		}
	}

	// A node that disconnects is no longer measured.
	c.stopAgent("n1")
	for _, n := range top("").GetNodes() {
		if n.GetId() == "n1" && n.GetMeasured() {
			t.Errorf("disconnected node measured: %v", n)
		}
	}
}

func TestUsageStore(t *testing.T) {
	t.Parallel()
	u := newUsageStore()
	now := time.Now()
	u.set("n1", &armadav1.UsageReport{Replicas: []*armadav1.ReplicaUsage{
		{Id: "a", CpuMillis: -5, MemoryBytes: -1},
		{Id: "b", CpuMillis: 1 << 40, MemoryBytes: 1 << 60},
		{Id: strings.Repeat("x", maxReplicaIDLen+1), CpuMillis: 1},
		{Id: "", CpuMillis: 1},
	}}, now)
	n, ok := u.node("n1", now)
	if !ok || len(n.replicas) != 2 {
		t.Fatalf("sample %v %v", n, ok)
	}
	if a := n.replicas["a"]; a.cpu != 0 || a.mem != 0 {
		t.Errorf("negative values kept: %+v", a)
	}
	if b := n.replicas["b"]; b.cpu != maxNodeCPUMillis || b.mem != maxNodeMemory {
		t.Errorf("huge values kept: %+v", b)
	}
	if _, ok := u.node("n1", now.Add(usageMaxAge+time.Second)); ok {
		t.Error("stale sample returned")
	}

	u.set("n1", &armadav1.UsageReport{ConntrackEntries: -1, ConntrackMax: 1 << 60}, now)
	if n, _ := u.node("n1", now); n.conntrackEntries != 0 || n.conntrackMax != maxConntrack {
		t.Errorf("connection tracking values not bounded: %d, %d", n.conntrackEntries, n.conntrackMax)
	}

	// Too many replicas: the node counts as unmeasured.
	big := &armadav1.UsageReport{}
	for range maxUsageReplicas + 1 {
		big.Replicas = append(big.Replicas, &armadav1.ReplicaUsage{Id: "r"})
	}
	u.set("n1", big, now)
	if _, ok := u.node("n1", now); ok {
		t.Error("oversized report kept")
	}
}

func TestUsageStoreCountsProjects(t *testing.T) {
	t.Parallel()
	u := newUsageStore()
	now := time.Now()
	report := &armadav1.UsageReport{
		Replicas:     []*armadav1.ReplicaUsage{{Id: "web.p-r1-a", EgressBytes: 100}, {Id: "api-r1-b", EgressBytes: 7}},
		Load:         []*armadav1.ReplicaLoad{{Id: "web.p-r1-a", Requests: 3}, {Id: "api-r1-b", Requests: 5}},
		LoadMeasured: true,
	}
	// Nothing counts before the reconciler says who owns what.
	u.set("n1", report, now)
	if got, since := u.projectTotals("p"); got != (projectTotals{}) || !since.IsZero() {
		t.Fatalf("counted without owners: %+v since %v", got, since)
	}

	u.setOwners([]store.Replica{
		{ID: "web.p-r1-a", App: "web.p", NodeID: "n1"},
		{ID: "api-r1-b", App: "api", NodeID: "n2"},
	}, now)
	u.set("n1", report, now)
	u.set("n1", report, now)
	if got, since := u.projectTotals("p"); got != (projectTotals{requests: 6, egress: 200}) || !since.Equal(now) {
		t.Errorf("project p: %+v since %v", got, since)
	}
	// n1 cannot claim egress for a replica on n2; requests come from any
	// node's proxy.
	if got, _ := u.projectTotals("default"); got != (projectTotals{requests: 10}) {
		t.Errorf("default project: %+v", got)
	}

	// Untrusted values are bounded, and a replica nobody owns counts nowhere.
	u.set("n1", &armadav1.UsageReport{
		Replicas:     []*armadav1.ReplicaUsage{{Id: "web.p-r1-a", EgressBytes: -5}, {Id: "ghost", EgressBytes: 1}},
		Load:         []*armadav1.ReplicaLoad{{Id: "web.p-r1-a", Requests: -5}, {Id: "ghost", Requests: 1}},
		LoadMeasured: true,
	}, now)
	if got, _ := u.projectTotals("p"); got != (projectTotals{requests: 6, egress: 200}) {
		t.Errorf("negative or unknown values counted: %+v", got)
	}
	u.set("n1", &armadav1.UsageReport{
		Replicas:     []*armadav1.ReplicaUsage{{Id: "web.p-r1-a", EgressBytes: math.MaxInt64}},
		Load:         []*armadav1.ReplicaLoad{{Id: "web.p-r1-a", Requests: math.MaxInt64}},
		LoadMeasured: true,
	}, now)
	if got, _ := u.projectTotals("p"); got != (projectTotals{requests: 6 + maxReportRequests, egress: 200 + maxReportEgress}) {
		t.Errorf("huge values kept: %+v", got)
	}
	if saturatingAdd(math.MaxInt64-1, 5) != math.MaxInt64 {
		t.Error("counter overflowed")
	}
	// Load that was not measured adds nothing.
	u.set("n1", &armadav1.UsageReport{Load: []*armadav1.ReplicaLoad{{Id: "api-r1-b", Requests: 5}}}, now)
	if got, _ := u.projectTotals("default"); got.requests != 10 {
		t.Errorf("unmeasured load counted: %+v", got)
	}

	// The first counting time stays, and removed replicas keep their counts.
	u.setOwners(nil, now.Add(time.Hour))
	if got, since := u.projectTotals("p"); got.requests == 0 || !since.Equal(now) {
		t.Errorf("after replicas left: %+v since %v", got, since)
	}
	u.forgetProject("p")
	if got, _ := u.projectTotals("p"); got != (projectTotals{}) {
		t.Errorf("removed project kept: %+v", got)
	}
}

func TestTopProjects(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d := c.addNode("n1", "127.0.0.1")
	if _, err := c.admin.CreateProject(c.ctx, &armadav1.CreateProjectRequest{Name: "shop"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.admin.CreateProject(c.ctx, &armadav1.CreateProjectRequest{Name: "other"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.admin.Deploy(c.ctx, &armadav1.DeployRequest{Spec: []byte(webSpec("nginx:1", 1) + "resources:\n  cpu: 250m\n  memory: 128Mi\n"), Project: "shop"}); err != nil {
		t.Fatal(err)
	}
	c.eventually("web.shop running", func() bool { return len(c.running("web.shop")) == 1 })
	id := c.running("web.shop")[0].Id
	d.SetUsage(id, runtime.Stats{MemoryBytes: 50 << 20})

	project := func(resp *armadav1.TopResponse, name string) *armadav1.ProjectTop {
		for _, p := range resp.GetProjects() {
			if p.GetName() == name {
				return p
			}
		}
		return nil
	}
	var bytes int64 = 1000
	c.eventually("egress counted", func() bool {
		bytes += 1000
		d.SetUsage(id, runtime.Stats{MemoryBytes: 50 << 20, EgressBytes: bytes})
		resp, err := c.admin.Top(c.ctx, &armadav1.TopRequest{})
		if err != nil {
			t.Fatal(err)
		}
		p := project(resp, "shop")
		return p != nil && p.GetMeasured() == 1 && p.GetEgressBytes() > 0
	})
	resp, err := c.admin.Top(c.ctx, &armadav1.TopRequest{})
	if err != nil {
		t.Fatal(err)
	}
	p := project(resp, "shop")
	if p.GetReplicas() != 1 || p.GetMemoryBytes() != 50<<20 || p.GetCpuReservedMillis() != 250 || p.GetMemoryReservedBytes() != 128<<20 {
		t.Errorf("shop: %v", p)
	}
	if resp.GetCountedSince() == nil {
		t.Error("no counting start")
	}
	if o := project(resp, "other"); o == nil || o.GetReplicas() != 0 || o.GetEgressBytes() != 0 {
		t.Errorf("other: %v", o)
	}
	if project(resp, "default") == nil {
		t.Error("default project missing")
	}

	// One app's listing has no project totals.
	if resp, err := c.admin.Top(c.ctx, &armadav1.TopRequest{App: "web.shop"}); err != nil || len(resp.GetProjects()) != 0 {
		t.Errorf("app listing: %v %v", resp.GetProjects(), err)
	}
}

func TestTopProjectsScope(t *testing.T) {
	t.Parallel()
	c, tool, _ := automationCluster(t)
	if _, err := c.admin.CreateProject(c.ctx, &armadav1.CreateProjectRequest{Name: "elsewhere"}); err != nil {
		t.Fatal(err)
	}
	resp, err := tool.Top(c.ctx, &armadav1.TopRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetProjects()) != 1 || resp.GetProjects()[0].GetName() != "a" {
		t.Errorf("automation identity sees %v", resp.GetProjects())
	}
	all, err := c.admin.Top(c.ctx, &armadav1.TopRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all.GetProjects()) != 4 {
		t.Errorf("admin sees %v", all.GetProjects())
	}
}
