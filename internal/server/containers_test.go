package server

import (
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/store"
)

const sidecarSpec = `name: web
image: nginx:1
ingress:
  type: internal
  port: 80
env:
  - name: MODE
    value: prod
initContainers:
  - name: migrate
    image: ghcr.io/acme/web:1
    command: ["./migrate"]
    env:
      - name: DATABASE_URL
        secretRef: db
    resources:
      memory: 1Gi
sidecars:
  - name: log
    image: ghcr.io/acme/shipper:2
    resources:
      cpu: 200m
      memory: 128Mi
`

// noSecrets is sidecarSpec without the secret, for clusters without a
// master key.
var noSecrets = strings.Replace(sidecarSpec, "    env:\n      - name: DATABASE_URL\n        secretRef: db\n", "", 1)

// The assignment carries a replica's init containers and sidecars with
// their own env, the replica's identity, and no app variables (ADR 0038).
func TestReplicaSpecContainers(t *testing.T) {
	t.Parallel()
	sp := mustSpec(t, sidecarSpec)
	rev := store.Revision{Name: "web--r1", App: "web", Spec: sp, Secrets: map[string]int{"db": 3}}
	got, err := replicaSpec(store.Replica{ID: "web-r1-a", App: "web", Revision: "web--r1"}, rev, map[string]secrets.Value{"db": secrets.NewValue([]byte("pw"))})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.InitContainers) != 1 || len(got.Sidecars) != 1 {
		t.Fatalf("containers %v %v", got.InitContainers, got.Sidecars)
	}
	m := got.InitContainers[0]
	if m.GetImage() != "ghcr.io/acme/web:1" || !slices.Equal(m.GetCommand(), []string{"./migrate"}) || m.GetMemoryBytes() != 1<<30 || m.GetPidsLimit() == 0 {
		t.Errorf("init container %v", m)
	}
	env := map[string]*armadav1.EnvVar{}
	for _, e := range m.GetEnv() {
		env[e.GetName()] = e
	}
	if e := env["DATABASE_URL"]; e.GetValue() != "pw" || e.GetRef() != "db@v3" {
		t.Errorf("secret env %v", e)
	}
	if env["ARMADA_REPLICA"].GetValue() != "web-r1-a" || env["ARMADA_CONTAINER"].GetValue() != "migrate" {
		t.Errorf("identity env %v", env)
	}
	if env["MODE"] != nil || env["PORT"] != nil {
		t.Errorf("app variables leaked into a container: %v", env)
	}
	if s := got.Sidecars[0]; s.GetCpuReserveMillis() != 200 || s.GetNanoCpus() != 200_000_000 {
		t.Errorf("sidecar %v", s)
	}
	// The replica reserves the app and its sidecar, or the init container's
	// memory, whichever is more.
	if res := reservation(rev); res.cpu != 100+200 || res.mem != 1<<30 {
		t.Errorf("reservation %+v", res)
	}
	// A node whose agent does not run them gets none of these replicas.
	if placementAllows(store.Node{ID: "old", State: store.NodeReady}, rev) {
		t.Error("placed on a node without init containers and sidecars")
	}
	if !placementAllows(store.Node{ID: "new", State: store.NodeReady, Containers: true}, rev) {
		t.Error("not placed on a node that runs them")
	}
	if !placementAllows(store.Node{ID: "old", State: store.NodeReady}, store.Revision{Spec: mustSpec(t, "name: w\nimage: busybox\n")}) {
		t.Error("an app without them needs a new node")
	}
}

// Replicas run with their sidecars on agents that announce them, and logs
// and exec reach a sidecar by name.
func TestContainersInCluster(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	d := c.addNode("n1", "127.0.0.1")
	c.deploy(noSecrets)
	c.eventually("running", func() bool { return len(c.running("web")) == 1 })
	cs, _ := d.List(c.ctx, nil)
	if len(cs) != 1 || len(cs[0].Members) != 2 {
		t.Fatalf("containers %v", cs)
	}

	logs := func(container string) (string, error) {
		stream, err := c.admin.Logs(c.ctx, &armadav1.LogsRequest{App: "web", Container: container})
		if err != nil {
			return "", err
		}
		var b strings.Builder
		for {
			e, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				return b.String(), nil
			}
			if err != nil {
				return b.String(), err
			}
			b.Write(e.GetData())
		}
	}
	if out, err := logs("log"); err != nil || strings.Contains(out, "[armada]") {
		t.Errorf("sidecar logs %q %v", out, err)
	}
	if out, err := logs("ghost"); err != nil || !strings.Contains(out, "has no container ghost") {
		t.Errorf("unknown container logs %q %v", out, err)
	}
	if _, err := logs("Bad Name"); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad container name: %v", err)
	}
}

func TestCheckContainerName(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"", "app", "log", "log-shipper"} {
		if err := checkContainerName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"Log", "../x", "a b", strings.Repeat("a", 31), "-x"} {
		if err := checkContainerName(bad); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestContainersNeedCapableNode(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	c.addNode("n1", "127.0.0.1")
	c.stopAgent("n1")
	c.nodes["n1"].d.NoMembers = true
	c.startAgent("n1")
	c.deploy(noSecrets)
	c.eventually("Unschedulable", func() bool {
		evs, _ := c.store.ListEvents(c.ctx, time.Time{})
		for _, e := range evs {
			if e.Reason == "Unschedulable" && e.App == "web" {
				return true
			}
		}
		return false
	})
	if rs, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "web"}); len(rs) != 0 {
		t.Errorf("replicas on a node that cannot run sidecars: %v", rs)
	}
}
