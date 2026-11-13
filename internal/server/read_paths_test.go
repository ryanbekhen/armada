package server

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// readCounter counts the store reads whose cost grows with the cluster.
type readCounter struct {
	store.Store
	allReplicas, appReplicas, servers, domains, apps, getApp, getRevision, nodes atomic.Int64
	// jobRunsGate, when set, holds every ListJobRuns call until it is closed,
	// after telling jobRunsEntered.
	jobRunsGate    chan struct{}
	jobRunsEntered chan struct{}
}

func (c *readCounter) ListReplicas(ctx context.Context, f store.ReplicaFilter) ([]store.Replica, error) {
	if f.App == "" && f.NodeID == "" {
		c.allReplicas.Add(1)
	} else {
		c.appReplicas.Add(1)
	}
	return c.Store.ListReplicas(ctx, f)
}

func (c *readCounter) ListServers(ctx context.Context) ([]store.Server, error) {
	c.servers.Add(1)
	return c.Store.ListServers(ctx)
}

func (c *readCounter) ListDomains(ctx context.Context) ([]store.Domain, error) {
	c.domains.Add(1)
	return c.Store.ListDomains(ctx)
}

func (c *readCounter) ListApps(ctx context.Context) ([]store.App, error) {
	c.apps.Add(1)
	return c.Store.ListApps(ctx)
}

func (c *readCounter) GetApp(ctx context.Context, name string) (store.App, error) {
	c.getApp.Add(1)
	return c.Store.GetApp(ctx, name)
}

func (c *readCounter) GetRevision(ctx context.Context, name string) (store.Revision, error) {
	c.getRevision.Add(1)
	return c.Store.GetRevision(ctx, name)
}

func (c *readCounter) ListNodes(ctx context.Context) ([]store.Node, error) {
	c.nodes.Add(1)
	return c.Store.ListNodes(ctx)
}

func (c *readCounter) ListJobRuns(ctx context.Context, job string) ([]store.JobRun, error) {
	if c.jobRunsGate != nil {
		select {
		case c.jobRunsEntered <- struct{}{}:
		default:
		}
		<-c.jobRunsGate
	}
	return c.Store.ListJobRuns(ctx, job)
}

func (c *readCounter) reset() {
	for _, n := range []*atomic.Int64{&c.allReplicas, &c.appReplicas, &c.servers, &c.domains, &c.apps, &c.getApp, &c.getRevision, &c.nodes} {
		n.Store(0)
	}
}

// One app's Status equals that app in the whole cluster's Status, and reads
// the other replicas, the servers, and every domain only when its placement
// message needs them.
func TestAppStatusReadsOnlyTheApp(t *testing.T) {
	t.Parallel()
	c := placementSetup(t, map[string]string{"region": "java"}, map[string]string{"region": "sulawesi"})
	admin := c.srv.internalContext(c.ctx)
	if err := c.st.SetMeta(c.ctx, metaRootDomain, "apps.example.org"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.st.CreateSpace(c.ctx, "shop", "t", nil); err != nil {
		t.Fatal(err)
	}
	c.deploy("name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n  domains: [shop.example.com, other.example.com]\nscale:\n  min: 2\n")
	if err := c.st.SetDomainVerification(c.ctx, "shop.example.com", true, ""); err != nil {
		t.Fatal(err)
	}
	c.deploy("name: api\nimage: nginx:1\ningress:\n  type: internal\n  port: 80\n")
	c.deploy("name: spread\nimage: nginx:1\ningress:\n  type: external\n  port: 80\nscale:\n  min: 2\nplacement:\n  spreadBy: region\n")
	c.deploy("name: stuck\nimage: nginx:1\nplacement:\n  require:\n    region: papua\n")
	c.deploy("kind: job\nname: migrate\nimage: busybox:1\n")
	sp, err := spec.ParseIn([]byte("name: cart\nimage: nginx:1\n"), "shop")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.st.Deploy(c.ctx, sp, "t"); err != nil {
		t.Fatal(err)
	}
	c.reconcile()
	c.serveAll()

	full, err := c.srv.Status(admin, &armadav1.StatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Nodes) != 2 {
		t.Fatalf("full status has %d nodes", len(full.Nodes))
	}
	counting := &readCounter{Store: c.st}
	c.srv.store = counting
	seen := map[string]bool{}
	for _, want := range full.Apps {
		seen[want.Name] = true
		counting.reset()
		one, err := c.srv.Status(admin, &armadav1.StatusRequest{App: want.Name})
		if err != nil {
			t.Fatal(err)
		}
		if len(one.Apps) != 1 || !proto.Equal(one.Apps[0], want) {
			t.Errorf("%s alone:\n%v\nin the cluster:\n%v", want.Name, one.Apps, want)
		}
		if len(one.Nodes) != 0 {
			t.Errorf("%s alone has %d nodes", want.Name, len(one.Nodes))
		}
		if counting.appReplicas.Load() != 1 || counting.domains.Load() != 0 {
			t.Errorf("%s: %d reads of its replicas, %d of every domain", want.Name, counting.appReplicas.Load(), counting.domains.Load())
		}
		// Only a placement message that compares with other apps reads them.
		needsCluster := want.Name == "spread" || want.Name == "stuck"
		if got := counting.allReplicas.Load() == 1 && counting.servers.Load() == 1; got != needsCluster {
			t.Errorf("%s: %d reads of every replica, %d of the servers", want.Name, counting.allReplicas.Load(), counting.servers.Load())
		}
	}
	for _, name := range []string{"web", "api", "spread", "stuck", "cart.shop"} {
		if !seen[name] {
			t.Errorf("%s missing from the full status", name)
		}
	}
	for _, a := range full.Apps {
		switch a.Name {
		case "stuck":
			if !strings.Contains(a.PlacementMessage, "papua") {
				t.Errorf("stuck: placement %q", a.PlacementMessage)
			}
		case "web":
			if !slices.Contains(a.Urls, "https://shop.example.com/") || slices.Contains(a.Urls, "https://other.example.com/") || !slices.Contains(a.Urls, "https://web.apps.example.org/") {
				t.Errorf("web: urls %v", a.Urls)
			}
		}
	}
	if _, err := c.srv.Status(admin, &armadav1.StatusRequest{App: "migrate"}); err == nil {
		t.Error("status of a job")
	}
}

// ListVolumes reads every app with volumes and their target revisions in
// one batch each, and says the same as reading them one app at a time.
func TestListVolumesBatched(t *testing.T) {
	t.Parallel()
	c := newClockServer(t)
	if err := c.st.SetNodeStatus(c.ctx, "n1", store.NodeStatus{State: store.NodeReady, LastSeen: c.clock, Volumes: true}); err != nil {
		t.Fatal(err)
	}
	vols := func(names ...string) string {
		s := "volumes:\n"
		for _, n := range names {
			s += "  - name: " + n + "\n    path: /" + n + "\n"
		}
		return s
	}
	c.deploy("name: a\nimage: nginx:1\n" + vols("data"))
	c.deploy("name: b\nimage: nginx:1\n" + vols("data", "logs"))
	c.deploy("name: d\nimage: nginx:1\n" + vols("cache"))
	c.serveAll()
	// b rolls out a spec without logs, and with a path of its own for data:
	// both revisions count while it does. d rolls out a spec without its
	// volume, which its serving revision still mounts.
	if _, _, err := c.st.Deploy(c.ctx, mustSpec(t, "name: b\nimage: nginx:2\nvolumes:\n  - name: data\n    path: /var/data\n"), "t"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.st.Deploy(c.ctx, mustSpec(t, "name: d\nimage: nginx:2\n"), "t"); err != nil {
		t.Fatal(err)
	}
	if a, _ := c.st.GetApp(c.ctx, "b"); !a.Rolling() {
		t.Fatalf("b is not rolling out: %+v", a)
	}
	admin := c.srv.internalContext(c.ctx)
	counting := &readCounter{Store: c.st}
	c.srv.store = counting
	resp, err := c.srv.ListVolumes(admin, &armadav1.ListVolumesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if n := counting.getApp.Load() + counting.getRevision.Load(); n != 0 {
		t.Errorf("%d reads of single apps or revisions", n)
	}
	if len(resp.Volumes) != 4 {
		t.Fatalf("volumes: %v", resp.Volumes)
	}
	for _, v := range resp.Volumes {
		m, err := c.srv.mountedVolumes(c.ctx, v.App)
		if err != nil {
			t.Fatal(err)
		}
		sv, inUse := m[v.Name]
		if v.InUse != inUse || v.Path != sv.Path {
			t.Errorf("%s/%s: in use %v at %q, one app at a time says %v at %q", v.App, v.Name, v.InUse, v.Path, inUse, sv.Path)
		}
	}
	got := map[string]string{}
	for _, v := range resp.Volumes {
		got[v.App+"/"+v.Name] = v.Path
	}
	want := map[string]string{"a/data": "/data", "b/data": "/var/data", "b/logs": "/logs", "d/cache": "/cache"}
	for k, p := range want {
		if gp, ok := got[k]; !ok || gp != p {
			t.Errorf("%s: path %q (listed %v), want %q", k, gp, ok, p)
		}
	}
	one, err := c.srv.ListVolumes(admin, &armadav1.ListVolumesRequest{App: "b"})
	if err != nil || len(one.Volumes) != 2 {
		t.Errorf("b's volumes: %v %v", one, err)
	}
}

// listJobsOneByOne is how ListJobs read the runs before it grouped them.
func listJobsOneByOne(apps []store.App, runs []store.JobRun, now time.Time) []*armadav1.JobInfo {
	var out []*armadav1.JobInfo
	for _, a := range apps {
		if !a.Spec.IsJob() {
			continue
		}
		info := &armadav1.JobInfo{Name: a.Name, Revision: a.ActiveRevision, Image: a.Spec.Image, Schedule: a.Spec.Schedule, TimeZone: a.Spec.TimeZone}
		for _, r := range runs {
			if r.Job != a.Name {
				continue
			}
			info.LastRun = runInfo(r)
			if r.Active() {
				info.Active++
			}
		}
		if sched, ok := a.Spec.JobSchedule(); ok {
			info.NextRun = timestamppb.New(sched.Next(now))
		}
		out = append(out, info)
	}
	return out
}

// jobCluster deploys apps and jobs in two spaces, with runs in every
// state, without reconciling: the runs stay as written.
func jobCluster(t *testing.T) *clockServer {
	t.Helper()
	c := newClockServer(t)
	if _, err := c.st.CreateSpace(c.ctx, "shop", "t", nil); err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct{ space, yaml string }{
		{"default", "name: web\nimage: nginx:1\n"},
		{"default", "name: api\nimage: nginx:1\n"},
		{"default", "kind: job\nname: migrate\nimage: busybox:1\n"},
		{"default", "kind: job\nname: nightly\nimage: busybox:1\nschedule: \"0 3 * * *\"\n"},
		{"default", "kind: job\nname: idle\nimage: busybox:1\n"},
		{"shop", "name: cart\nimage: nginx:1\n"},
		{"shop", "kind: job\nname: report\nimage: busybox:1\n"},
	} {
		sp, err := spec.ParseIn([]byte(s.yaml), s.space)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.st.Deploy(c.ctx, sp, "t"); err != nil {
			t.Fatal(err)
		}
	}
	states := []string{store.RunSucceeded, store.RunFailed, store.RunSucceeded, store.RunRunning, store.RunPending}
	for _, job := range []string{"migrate", "nightly", "report.shop"} {
		for i, state := range states {
			c.clock = c.clock.Add(time.Minute)
			r, err := c.st.CreateJobRun(c.ctx, job, store.TriggerManual, time.Time{}, "t")
			if err != nil {
				t.Fatal(err)
			}
			if job == "report.shop" && i > 1 {
				break // fewer runs, ending in a failure
			}
			r.State = state
			if !r.Active() {
				r.FinishedAt = c.clock.Add(time.Duration(i) * time.Second)
			}
			if err := c.st.UpdateJobRun(c.ctx, r); err != nil {
				t.Fatal(err)
			}
		}
	}
	return c
}

func TestListJobsGroupsRuns(t *testing.T) {
	t.Parallel()
	c := jobCluster(t)
	admin := c.srv.internalContext(c.ctx)
	resp, err := c.srv.ListJobs(admin, &armadav1.ListJobsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	apps, _ := c.st.ListApps(c.ctx)
	runs, _ := c.st.ListJobRuns(c.ctx, "")
	want := listJobsOneByOne(apps, runs, c.clock)
	if len(resp.Jobs) != 4 || len(want) != 4 {
		t.Fatalf("%d jobs, want 4: %v", len(resp.Jobs), resp.Jobs)
	}
	for i := range want {
		if !proto.Equal(resp.Jobs[i], want[i]) {
			t.Errorf("job %d:\n%v\nwant\n%v", i, resp.Jobs[i], want[i])
		}
	}
	for _, j := range resp.Jobs {
		if j.Name == "migrate" && (j.Active != 2 || j.LastRun.GetRun() != 5) {
			t.Errorf("migrate: %v", j)
		}
	}
}

func TestListSpacesCountsFromIDs(t *testing.T) {
	t.Parallel()
	c := jobCluster(t)
	admin := c.srv.internalContext(c.ctx)
	counting := &readCounter{Store: c.st}
	c.srv.store = counting
	resp, err := c.srv.ListSpaces(admin, &armadav1.ListSpacesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if n := counting.apps.Load(); n != 0 {
		t.Errorf("%d full reads of every app", n)
	}
	apps, _ := c.st.ListApps(c.ctx)
	want := map[string]int32{}
	for _, a := range apps {
		p, _, _ := spec.SplitAppID(a.Name)
		want[p]++
	}
	if want["default"] != 5 || want["shop"] != 2 {
		t.Fatalf("setup: %v", want)
	}
	if len(resp.Spaces) != 2 {
		t.Fatalf("spaces: %v", resp.Spaces)
	}
	for _, p := range resp.Spaces {
		if p.Apps != want[p.Name] {
			t.Errorf("%s: %d apps, want %d", p.Name, p.Apps, want[p.Name])
		}
	}
	ids, err := c.st.ListAppIDs(c.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids, ",") != "api,cart.shop,idle,migrate,nightly,report.shop,web" {
		t.Errorf("ids: %v", ids)
	}
}

// scrapeText gathers reg as the endpoint writes it.
func scrapeText(t *testing.T, reg *prometheus.Registry) string {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, mf := range mfs {
		if _, err := expfmt.MetricFamilyToText(&b, mf); err != nil {
			t.Fatal(err)
		}
	}
	return b.String()
}

// Scrapes within the interval share one gathering; scrapes that arrive
// during one wait for it; the metrics stay those an uncached collector
// gives.
func TestMetricsGatherOncePerInterval(t *testing.T) {
	t.Parallel()
	c := jobCluster(t)
	counting := &readCounter{Store: c.st}
	c.srv.store = counting

	plain := prometheus.NewRegistry()
	plain.MustRegister(&clusterCollector{s: c.srv})
	want := scrapeText(t, plain)
	for _, w := range []string{
		`armada_job_runs_active{job="migrate"} 2`,
		`armada_job_last_success_timestamp_seconds{job="migrate"}`,
		`armada_job_runs_active{job="idle"} 0`,
		`armada_app_replicas_desired{app="cart.shop"} 1`,
	} {
		if !strings.Contains(want, w) {
			t.Errorf("metrics lack %q", w)
		}
	}
	if strings.Contains(want, `armada_job_last_success_timestamp_seconds{job="report.shop"}`) == false {
		t.Errorf("report.shop has a successful run:\n%s", want)
	}

	cached := &clusterCollector{s: c.srv, every: 10 * time.Second}
	reg := prometheus.NewRegistry()
	reg.MustRegister(cached)
	counting.reset()
	if got := scrapeText(t, reg); got != want {
		t.Errorf("cached collector:\n%s\nwant\n%s", got, want)
	}
	perGather := counting.nodes.Load()
	if perGather == 0 {
		t.Fatal("a gathering reads no nodes")
	}
	c.clock = c.clock.Add(9 * time.Second)
	if got := scrapeText(t, reg); got != want {
		t.Errorf("second scrape:\n%s\nwant\n%s", got, want)
	}
	if n := counting.nodes.Load(); n != perGather {
		t.Errorf("two scrapes within the interval gathered %d times", n/perGather)
	}
	c.clock = c.clock.Add(time.Second)
	scrapeText(t, reg)
	if n := counting.nodes.Load(); n != 2*perGather {
		t.Errorf("a scrape after the interval: %d gatherings, want 2", n/perGather)
	}

	// Concurrent scrapes after the interval: one gathers, held in the store
	// until the others have started, and they all get its metrics.
	c.clock = c.clock.Add(10 * time.Second)
	counting.jobRunsGate, counting.jobRunsEntered = make(chan struct{}), make(chan struct{}, 1)
	var wg sync.WaitGroup
	results := make([][]prometheus.Metric, 8)
	wg.Add(1)
	go func() {
		defer wg.Done()
		results[0] = cached.metrics()
	}()
	<-counting.jobRunsEntered
	for i := 1; i < len(results); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = cached.metrics()
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(counting.jobRunsGate)
	wg.Wait()
	if n := counting.nodes.Load(); n != 3*perGather {
		t.Errorf("concurrent scrapes: %d gatherings, want 1 more", n/perGather-2)
	}
	for i, r := range results {
		if len(r) == 0 || len(r) != len(results[0]) || &r[0] != &results[0][0] {
			t.Errorf("scrape %d got other metrics (%d)", i, len(r))
		}
	}
}
