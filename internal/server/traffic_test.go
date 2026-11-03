package server

import (
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/proxy"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

func TestTrafficShares(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		total   int
		weights []int
		want    []int
	}{
		{4, []int{75, 25}, []int{3, 1}},
		{10, []int{90, 10}, []int{9, 1}},
		{2, []int{95, 5}, []int{2, 1}},  // at least one each
		{3, []int{100, 0}, []int{3, 1}}, // a label-only revision runs one
		{5, []int{50, 50}, []int{3, 3}}, // halves round up
	} {
		var traffic []spec.TrafficTarget
		for _, w := range c.weights {
			traffic = append(traffic, spec.TrafficTarget{Weight: w})
		}
		if got := trafficShares(c.total, traffic); !slices.Equal(got, c.want) {
			t.Errorf("trafficShares(%d, %v) = %v, want %v", c.total, c.weights, got, c.want)
		}
	}
}

func TestWeighServers(t *testing.T) {
	t.Parallel()
	app := store.App{Name: "web", Traffic: []spec.TrafficTarget{{Revision: "web--r1", Weight: 90}, {Revision: "web--r2", Weight: 10}}}
	reps := []store.Replica{{ID: "a", Revision: "web--r1"}, {ID: "b", Revision: "web--r1"}, {ID: "c", Revision: "web--r1"}, {ID: "d", Revision: "web--r2"}}
	servers := []proxy.Server{{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}}
	weighServers(app, reps, servers)
	// 90% over three servers, 10% on one: 77 each against 26.
	sum1 := servers[0].Weight + servers[1].Weight + servers[2].Weight
	if servers[0].Weight != 77 || servers[3].Weight != 26 || sum1*10 < servers[3].Weight*80 || sum1*10 > servers[3].Weight*100 {
		t.Errorf("weights %+v", servers)
	}
	// A revision with weight 1 spread over many servers still gets weight 1
	// per server, never 0 (which would take it out of rotation).
	app.Traffic = []spec.TrafficTarget{{Revision: "web--r1", Weight: 99}, {Revision: "web--r2", Weight: 1}}
	reps = append(reps, store.Replica{ID: "e", Revision: "web--r2"}, store.Replica{ID: "f", Revision: "web--r2"})
	servers = append(servers, proxy.Server{Name: "e"}, proxy.Server{Name: "f"})
	weighServers(app, reps, servers)
	for _, s := range servers {
		if s.Weight < 1 || s.Weight > proxy.MaxWeight {
			t.Errorf("weight out of range: %+v", s)
		}
	}
}

func trafficSpec(image string, replicas int, traffic string) string {
	return "name: web\nimage: " + image + "\ningress:\n  type: internal\n  port: 80\nscale:\n  min: " + string(rune('0'+replicas)) +
		"\n  max: 10\nrevisions:\n  mode: multiple\n  traffic:\n" + traffic
}

func backend(cfg proxy.Config, name string) (proxy.Backend, bool) {
	for _, b := range cfg.Backends {
		if b.Name == name {
			return b, true
		}
	}
	return proxy.Backend{}, false
}

func TestTrafficSplitting(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	c.addNode("n1", "127.0.0.1")
	c.addNode("n2", "127.0.0.2")
	applied := func() proxy.Config {
		_, cfg := c.proxies["n1"].Applied()
		return cfg
	}
	revsIn := func(b proxy.Backend) map[string]int {
		reps, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "web"})
		rev := map[string]string{}
		for _, r := range reps {
			rev[r.ID] = r.Revision
		}
		out := map[string]int{}
		for _, s := range b.Servers {
			out[rev[s.Name]]++
		}
		return out
	}

	c.deploy("name: web\nimage: nginx:1\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 4\n  max: 10\n")
	c.eventually("r1 serves", func() bool {
		b, _ := backend(applied(), "web")
		return revsIn(b)["web--r1"] == 4
	})

	// 75/25 with a label: three replicas of r1 and one of r2 share the
	// app's backend; r2 also serves alone under canary--web.
	resp := c.deploy(trafficSpec("nginx:2", 4, "    - revision: web--r1\n      weight: 75\n    - revision: latest\n      weight: 25\n      label: canary\n"))
	if resp.Revision != "web--r2" {
		t.Fatalf("revision %s", resp.Revision)
	}
	c.eventually("split 3/1", func() bool {
		b, _ := backend(applied(), "web")
		lb, ok := backend(applied(), "canary--web")
		got := revsIn(b)
		return got["web--r1"] == 3 && got["web--r2"] == 1 && ok && len(lb.Servers) == 1 && revsIn(lb)["web--r2"] == 1
	})
	b, _ := backend(applied(), "web")
	for _, s := range b.Servers {
		if s.Weight != 64 { // 75% over three, 25% over one
			t.Errorf("server %s weight %d", s.Name, s.Weight)
		}
	}
	if !slices.ContainsFunc(applied().Rules, func(r proxy.Rule) bool {
		return r.Host == "canary--web.internal" && r.Backend == "canary--web" && r.Internal
	}) {
		t.Errorf("no rule for the label: %+v", applied().Rules)
	}
	a := c.app("web")
	if len(a.Traffic) != 2 || a.Traffic[1].Label != "canary" || a.Traffic[1].Replicas != 1 || a.DesiredReplicas != 4 ||
		len(a.Traffic[1].Urls) != 1 || a.Traffic[1].Urls[0] != "http://canary--web.internal/" {
		t.Errorf("status traffic %+v desired %d", a.Traffic, a.DesiredReplicas)
	}

	// Scaling and rollback refuse; armada traffic moves everything to r2.
	if _, err := c.admin.Rollback(c.ctx, &armadav1.RollbackRequest{App: "web", Revision: "web--r1"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("rollback: %v", err)
	}
	if _, err := c.admin.SetTraffic(c.ctx, &armadav1.SetTrafficRequest{App: "web", Traffic: []*armadav1.TrafficTarget{{Revision: "web--r2", Weight: 90}}}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("weights not adding up: %v", err)
	}
	if _, err := c.admin.SetTraffic(c.ctx, &armadav1.SetTrafficRequest{App: "web", Traffic: []*armadav1.TrafficTarget{{Revision: "web--r2", Weight: 100}}}); err != nil {
		t.Fatal(err)
	}
	c.eventually("all on r2", func() bool {
		b, _ := backend(applied(), "web")
		reps, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "web"})
		return revsIn(b)["web--r2"] == 4 && len(revsIn(b)) == 1 && !slices.ContainsFunc(reps, func(r store.Replica) bool { return r.Revision == "web--r1" })
	})

	// Back to single mode: a rollout, after which the label is gone.
	c.deploy("name: web\nimage: nginx:3\ningress:\n  type: internal\n  port: 80\nscale:\n  min: 2\n  max: 10\n")
	c.eventually("r3 serves alone", func() bool {
		b, _ := backend(applied(), "web")
		_, label := backend(applied(), "canary--web")
		a := c.app("web")
		return revsIn(b)["web--r3"] == 2 && len(revsIn(b)) == 1 && !label && a.RolloutState == "" && len(a.Traffic) == 0
	})
	evs, err := c.store.ListEvents(c.ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(evs, func(e store.Event) bool {
		return e.Reason == "TrafficChanged" && strings.Contains(e.Message, "web--r2 100%")
	}) {
		t.Errorf("no TrafficChanged event: %+v", evs)
	}
}
