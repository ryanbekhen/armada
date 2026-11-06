package server

import (
	"context"
	"log/slog"
	"maps"
	"strings"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/store/storetest"
)

func mustSpec(t *testing.T, y string) *spec.App {
	t.Helper()
	a, err := spec.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPickNode(t *testing.T) {
	t.Parallel()

	nodes := []store.Node{
		{ID: "a", State: store.NodeReady, MemoryBytes: 1 << 30},
		{ID: "b", State: store.NodeReady, MemoryBytes: 2 << 30},
		{ID: "c", State: store.NodeUnknown, MemoryBytes: 8 << 30},
	}
	mem := func(store.Replica) resources { return resources{mem: 512 << 20} }

	n, ok := pickNode(nodes, nil, nil, "", resources{mem: 512 << 20}, mem)
	if !ok || n.ID != "b" {
		t.Errorf("empty cluster picked %v, want b (most free memory)", n.ID)
	}
	n, _ = pickNode(nodes, []store.Replica{{App: "web", NodeID: "b"}}, []store.Replica{{App: "web", NodeID: "b"}}, "", resources{mem: 512 << 20}, mem)
	if n.ID != "a" {
		t.Errorf("picked %v, want a (spread replicas)", n.ID)
	}
	full := []store.Replica{{App: "x", NodeID: "a"}, {App: "x", NodeID: "a"}, {App: "web", NodeID: "b"}}
	n, _ = pickNode(nodes, full, full[2:], "", resources{mem: 512 << 20}, mem)
	if n.ID != "b" {
		t.Errorf("picked %v, want b (a is full)", n.ID)
	}
	if _, ok := pickNode(nodes, nil, nil, "", resources{mem: 4 << 30}, mem); ok {
		t.Error("scheduled replica that fits nowhere")
	}
	if _, ok := pickNode([]store.Node{{ID: "z", State: store.NodeUnknown}}, nil, nil, "", resources{mem: 1}, mem); ok {
		t.Error("scheduled on a node that is not ready")
	}
	n, ok = pickNode([]store.Node{{ID: "u", State: store.NodeReady}}, nil, nil, "", resources{mem: 1 << 40}, mem)
	if !ok || n.ID != "u" {
		t.Error("unknown capacity (0) should not block scheduling")
	}
	// A node advertising absurd memory does not attract a new app's replica
	// while it already runs more replicas than the others.
	greedy := []store.Node{
		{ID: "honest", State: store.NodeReady, MemoryBytes: 2 << 30},
		{ID: "liar", State: store.NodeReady, MemoryBytes: 16 << 40},
	}
	n, _ = pickNode(greedy, []store.Replica{{App: "x", NodeID: "liar"}}, nil, "", resources{mem: 512 << 20}, mem)
	if n.ID != "honest" {
		t.Errorf("picked %v, want honest (fewest replicas beats reported memory)", n.ID)
	}
	// Replicas on their way out (an old revision, draining) count toward
	// load and memory but not toward the spread.
	leaving := []store.Replica{{App: "web", NodeID: "a"}, {App: "web", NodeID: "a"}}
	stay := []store.Replica{{App: "web", NodeID: "b"}}
	n, _ = pickNode(nodes, append(leaving, stay...), stay, "", resources{mem: 256 << 20}, func(store.Replica) resources { return resources{mem: 256 << 20} })
	if n.ID != "a" {
		t.Errorf("picked %v, want a (no replica of the app stays there)", n.ID)
	}
}

func TestPickNodeReservesCPU(t *testing.T) {
	t.Parallel()
	nodes := []store.Node{
		{ID: "a", State: store.NodeReady, CPUMillis: 1000, MemoryBytes: 8 << 30},
		{ID: "b", State: store.NodeReady, CPUMillis: 500, MemoryBytes: 8 << 30},
	}
	small := func(store.Replica) resources { return resources{cpu: 100, mem: 256 << 20} }
	// a has 400m left, b 0: the replica goes to a, though b runs fewer.
	on := []store.Replica{
		{App: "x", NodeID: "a"}, {App: "x", NodeID: "a"}, {App: "x", NodeID: "a"}, {App: "x", NodeID: "a"}, {App: "x", NodeID: "a"}, {App: "x", NodeID: "a"},
		{App: "y", NodeID: "b"}, {App: "y", NodeID: "b"}, {App: "y", NodeID: "b"}, {App: "y", NodeID: "b"}, {App: "y", NodeID: "b"},
	}
	if n, ok := pickNode(nodes, on, nil, "", resources{cpu: 100, mem: 256 << 20}, small); !ok || n.ID != "a" {
		t.Errorf("picked %v (%v), want a (b has no CPU left)", n.ID, ok)
	}
	// No overcommit: 500m fits nowhere.
	if n, ok := pickNode(nodes, on, nil, "", resources{cpu: 500, mem: 256 << 20}, small); ok {
		t.Errorf("scheduled on %s with too little CPU", n.ID)
	}
	// Equal replica counts and memory: the node with more free CPU wins.
	if n, _ := pickNode(nodes, nil, nil, "", resources{cpu: 100}, small); n.ID != "a" {
		t.Errorf("picked %v, want a (more free CPU)", n.ID)
	}
	// Unknown CPU capacity (0) does not block scheduling.
	if _, ok := pickNode([]store.Node{{ID: "u", State: store.NodeReady}}, nil, nil, "", resources{cpu: 64000}, small); !ok {
		t.Error("unknown CPU capacity blocked scheduling")
	}
}

func TestPickNodeSkipsFullSubnet(t *testing.T) {
	t.Parallel()
	nodes := []store.Node{
		{ID: "a", State: store.NodeReady, Subnet: "10.120.0.0/24"},
		{ID: "b", State: store.NodeReady, Subnet: "10.120.1.0/24"},
	}
	none := func(store.Replica) resources { return resources{} }
	on := func(node string, n int, done bool) []store.Replica {
		out := make([]store.Replica, n)
		for i := range out {
			out[i] = store.Replica{App: "x", NodeID: node, Done: done}
		}
		return out
	}
	// a is full, so the replica goes to b, though the app already runs there.
	spread := []store.Replica{{App: "web", NodeID: "b"}}
	all := append(on("a", maxSubnetReplicas, false), spread...)
	if n, ok := pickNode(nodes, all, spread, "", resources{}, none); !ok || n.ID != "b" {
		t.Errorf("picked %v (%v), want b (a has no address left)", n.ID, ok)
	}
	// Every node full: nothing fits, even with free CPU and memory.
	all = append(on("a", maxSubnetReplicas, false), on("b", maxSubnetReplicas, false)...)
	if n, ok := pickNode(nodes, all, nil, "", resources{}, none); ok {
		t.Errorf("scheduled on %s with no address left", n.ID)
	}
	// One below the limit still fits.
	all = append(on("a", maxSubnetReplicas-1, false), on("b", maxSubnetReplicas, false)...)
	if n, ok := pickNode(nodes, all, nil, "", resources{}, none); !ok || n.ID != "a" {
		t.Errorf("picked %v (%v), want a (one address left)", n.ID, ok)
	}
	// A finished attempt's kept container holds no address.
	all = append(all, on("a", 5, true)...)
	if n, ok := pickNode(nodes, all, nil, "", resources{}, none); !ok || n.ID != "a" {
		t.Errorf("picked %v (%v), want a (finished attempts hold no address)", n.ID, ok)
	}
	// A node with no subnet of its own has no such limit.
	plain := []store.Node{{ID: "a", State: store.NodeReady}}
	if _, ok := pickNode(plain, on("a", maxSubnetReplicas, false), nil, "", resources{}, none); !ok {
		t.Error("the limit applied to a node with no subnet of its own")
	}
}

func TestPickVictim(t *testing.T) {
	t.Parallel()

	rs := []store.Replica{
		{ID: "1", NodeID: "a", State: store.ReplicaRunning},
		{ID: "2", NodeID: "b", State: store.ReplicaRunning},
		{ID: "3", NodeID: "b", State: store.ReplicaRunning},
	}
	if v := pickVictim(rs, nil); v.NodeID != "b" {
		t.Errorf("victim = %+v, want one from the busiest node", v)
	}
	rs = append(rs, store.Replica{ID: "4", NodeID: "a", State: store.ReplicaFailed})
	if v := pickVictim(rs, nil); v.ID != "4" {
		t.Errorf("victim = %+v, want the failed replica", v)
	}
}

func TestReplicaSpec(t *testing.T) {
	t.Parallel()

	sp := mustSpec(t, "name: api\nimage: ghcr.io/a/api:v1\ncommand: [/srv]\nargs: [-v]\nenv:\n  - name: MODE\n    value: prod\ningress:\n  type: external\n  port: 3000\nresources:\n  cpu: 500m\n  memory: 1Gi\n"+
		"probes:\n  readiness: /ready\n  liveness:\n    path: /live\n    port: 9000\n    initialDelay: 5s\n    period: 2s\n    failureThreshold: 4\n")
	rev := store.Revision{Name: "api--r3", Spec: sp, ImageDigest: "ghcr.io/a/api@sha256:" + strings.Repeat("f", 64)}
	got, err := replicaSpec(store.Replica{ID: "api-r3-xyz", App: "api", Revision: "api--r3"}, rev, nil)
	if err != nil {
		t.Fatal(err)
	}

	if got.Image != rev.ImageDigest {
		t.Errorf("image = %q, want pinned digest", got.Image)
	}
	if got.Port != 3000 || got.MemoryBytes != 1<<30 || got.NanoCpus != 5e8 || got.PidsLimit != spec.DefaultPids {
		t.Errorf("spec = %v", got)
	}
	if r := got.Readiness; r.GetPath() != "/ready" || r.GetPort() != 3000 || r.GetPeriodMs() != 10000 || r.GetFailureThreshold() != 3 {
		t.Errorf("readiness = %v", r)
	}
	if l := got.Liveness; l.GetPath() != "/live" || l.GetPort() != 9000 || l.GetInitialDelayMs() != 5000 || l.GetPeriodMs() != 2000 || l.GetFailureThreshold() != 4 {
		t.Errorf("liveness = %v", l)
	}
	if got.Startup != nil {
		t.Errorf("startup = %v", got.Startup)
	}
	env := map[string]string{}
	for _, e := range got.Env {
		env[e.Name] = e.Value
	}
	if env["MODE"] != "prod" || env["PORT"] != "3000" || env["ARMADA_REPLICA"] != "api-r3-xyz" || env["ARMADA_REVISION"] != "api--r3" {
		t.Errorf("env = %v", env)
	}

	worker, err := replicaSpec(store.Replica{ID: "w"}, store.Revision{Spec: mustSpec(t, "name: w\nimage: busybox\n")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if worker.Port != 0 {
		t.Errorf("worker port = %d", worker.Port)
	}
	for _, e := range worker.Env {
		if e.Name == "PORT" {
			t.Error("worker got PORT env")
		}
	}
}

func TestImageRepo(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"nginx": "nginx", "nginx:1": "nginx", "localhost:5000/a": "localhost:5000/a",
		"localhost:5000/a:2": "localhost:5000/a", "ghcr.io/x/y@sha256:abc": "ghcr.io/x/y",
	} {
		if got := imageRepo(in); got != want {
			t.Errorf("imageRepo(%q) = %q, want %q", in, got, want)
		}
	}
	if normalizeRepo("docker.io/library/nginx") != "nginx" {
		t.Error("normalizeRepo")
	}
}

func TestApplyReportDistrustsAgent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	st := storetest.Open(t)
	s := &Server{store: st, log: slog.New(slog.DiscardHandler), trigger: make(chan struct{}, 1)}

	for _, n := range []store.Node{{ID: "n1", PrivateIP: "10.0.0.2"}, {ID: "n2", PrivateIP: "10.0.0.3"}} {
		_ = st.UpsertNode(ctx, n)
	}
	if _, _, err := st.Deploy(ctx, mustSpec(t, "name: web\nimage: ghcr.io/me/web:v1\n"), "t"); err != nil {
		t.Fatal(err)
	}
	_ = st.CreateReplica(ctx, store.Replica{ID: "mine", App: "web", Revision: "web--r1", NodeID: "n1"})
	_ = st.CreateReplica(ctx, store.Replica{ID: "theirs", App: "web", Revision: "web--r1", NodeID: "n2"})

	node, _ := st.GetNode(ctx, "n1")
	evilDigest := "ghcr.io/attacker/web@sha256:" + strings.Repeat("e", 64)
	s.applyReport(ctx, node, &armadav1.ReplicaReport{Replicas: []*armadav1.ReplicaState{
		{Id: "mine", State: "running", Address: "192.168.99.1:80", ImageDigest: evilDigest, Message: strings.Repeat("x", 5000)},
		{Id: "theirs", State: "failed"},
		{Id: "ghost", State: "running"},
	}})

	reps, _ := st.ListReplicas(ctx, store.ReplicaFilter{})
	for _, r := range reps {
		switch r.ID {
		case "mine":
			if r.State != "running" || r.Address != "" || len(r.Message) != 512 {
				t.Errorf("mine = %+v (address outside private IP must be dropped, message truncated)", r)
			}
		case "theirs":
			if r.State != store.ReplicaPending {
				t.Errorf("n1 modified n2's replica: %+v", r)
			}
		}
	}
	rev, _ := st.GetRevision(ctx, "web--r1")
	if rev.ImageDigest != "" {
		t.Errorf("digest from another repository accepted: %q", rev.ImageDigest)
	}

	good := "ghcr.io/me/web@sha256:" + strings.Repeat("a", 64)
	s.applyReport(ctx, node, &armadav1.ReplicaReport{Replicas: []*armadav1.ReplicaState{
		{Id: "mine", State: "running", Address: "10.0.0.2:32768", ImageDigest: good},
	}})
	reps, _ = st.ListReplicas(ctx, store.ReplicaFilter{App: "web", NodeID: "n1"})
	if reps[0].Address != "10.0.0.2:32768" {
		t.Errorf("valid address dropped: %+v", reps[0])
	}
	rev, _ = st.GetRevision(ctx, "web--r1")
	if rev.ImageDigest != good {
		t.Errorf("valid digest not recorded: %q", rev.ImageDigest)
	}

	// The container address goes into every node's firewall (ADR 0026):
	// only one in the node's own subnet is kept.
	node.Subnet = "10.120.3.0/24"
	for ip, want := range map[string]string{"10.120.4.7": "", "10.120.3.1": "", "10.120.3.7": "10.120.3.7"} {
		s.applyReport(ctx, node, &armadav1.ReplicaReport{Replicas: []*armadav1.ReplicaState{{Id: "mine", State: "running", Ip: ip}}})
		reps, _ = st.ListReplicas(ctx, store.ReplicaFilter{App: "web", NodeID: "n1"})
		if reps[0].IP != want {
			t.Errorf("reported IP %s stored as %q, want %q", ip, reps[0].IP, want)
		}
	}
}

func TestRandomID(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}
	for range 1000 {
		id := randomID(8)
		if len(id) != 8 || strings.Trim(id, idAlphabet) != "" {
			t.Fatalf("randomID = %q", id)
		}
		seen[id] = true
	}
	if len(seen) < 999 {
		t.Errorf("only %d unique IDs out of 1000", len(seen))
	}
}

func TestReplicaSpecSecrets(t *testing.T) {
	t.Parallel()
	sp := mustSpec(t, "name: api\nimage: ghcr.io/a/api:v1\nenv:\n  - name: DB\n    secretRef: db\n  - name: MODE\n    value: prod\n"+
		"secretFiles:\n  - secretRef: tls\n    path: /run/secrets/tls.key\nregistry:\n  server: ghcr.io\n  username: bot\n  passwordSecretRef: ghcr\n")
	rev := store.Revision{Name: "api--r2", App: "api", Spec: sp, Secrets: map[string]int{"db": 4, "tls": 1, "ghcr": 2}}
	vals := map[string]secrets.Value{
		"db": secrets.NewValue([]byte("db-pass")), "tls": secrets.NewValue([]byte("KEY")), "ghcr": secrets.NewValue([]byte("token")),
	}
	got, err := replicaSpec(store.Replica{ID: "x", App: "api", Revision: "api--r2"}, rev, vals)
	if err != nil {
		t.Fatal(err)
	}
	if e := got.Env[0]; e.Name != "DB" || e.Value != "db-pass" || e.Ref != "db@v4" {
		t.Errorf("secret env = %v", e)
	}
	if e := got.Env[1]; e.Value != "prod" || e.Ref != "" {
		t.Errorf("plain env = %v", e)
	}
	if len(got.SecretFiles) != 1 || got.SecretFiles[0].Path != "/run/secrets/tls.key" || string(got.SecretFiles[0].Data) != "KEY" || got.SecretFiles[0].Ref != "tls@v1" {
		t.Errorf("secret files = %v", got.SecretFiles)
	}
	if r := got.Registry; r.GetServer() != "ghcr.io" || r.GetUsername() != "bot" || r.GetPassword() != "token" || r.GetRef() != "ghcr@v2" {
		t.Errorf("registry = %v", r)
	}

	delete(vals, "tls")
	if _, err := replicaSpec(store.Replica{ID: "x"}, rev, vals); err == nil {
		t.Error("replica spec built with an unresolved secret")
	}
}

// A report lists every replica of a node: only those it says something new
// about are written, or each change costs a write per replica on the node.
func TestApplyReportWritesOnlyChanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := storetest.Open(t)
	s := &Server{store: st, log: slog.New(slog.DiscardHandler), trigger: make(chan struct{}, 1)}
	if err := st.UpsertNode(ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Deploy(ctx, mustSpec(t, "name: web\nimage: ghcr.io/me/web:v1\n"), "t"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		if err := st.CreateReplica(ctx, store.Replica{ID: id, App: "web", Revision: "web--r1", NodeID: "n1"}); err != nil {
			t.Fatal(err)
		}
	}
	node, err := st.GetNode(ctx, "n1")
	if err != nil {
		t.Fatal(err)
	}
	updated := func() map[string]time.Time {
		reps, err := st.ListReplicas(ctx, store.ReplicaFilter{App: "web"})
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]time.Time{}
		for _, r := range reps {
			m[r.ID] = r.UpdatedAt
		}
		return m
	}
	report := func(bMessage string) {
		s.applyReport(ctx, node, &armadav1.ReplicaReport{Replicas: []*armadav1.ReplicaState{
			{Id: "a", State: "running", Ready: true, Address: "10.0.0.2:80", ContainerId: "ca"},
			{Id: "b", State: "running", Address: "10.0.0.2:81", ContainerId: "cb", Message: bMessage},
		}})
	}
	report("starting")
	before := updated()
	time.Sleep(5 * time.Millisecond)
	report("starting")
	if after := updated(); !maps.Equal(before, after) {
		t.Errorf("an unchanged report wrote: %v then %v", before, after)
	}
	time.Sleep(5 * time.Millisecond)
	report("readiness probe failed")
	after := updated()
	if !after["a"].Equal(before["a"]) {
		t.Errorf("replica a was written though only b changed")
	}
	if after["b"].Equal(before["b"]) {
		t.Errorf("replica b changed but was not written")
	}
}

func TestSameStatusFinishedJob(t *testing.T) {
	t.Parallel()
	have := store.Replica{State: store.ReplicaExited, Finished: true, ExitCode: 3}
	// A done attempt's stopped container may report another exit code,
	// which the store ignores.
	if !sameStatus(have, store.ReplicaStatus{State: store.ReplicaExited, Finished: true, ExitCode: 137}) {
		t.Error("a finished attempt's new exit code counted as a change")
	}
	if sameStatus(store.Replica{State: store.ReplicaExited}, store.ReplicaStatus{State: store.ReplicaExited, ExitCode: 1}) {
		t.Error("the exit code of an unfinished replica was ignored")
	}
}
