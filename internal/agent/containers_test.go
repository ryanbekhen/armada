package agent

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
	"github.com/ryanbekhen/armada/internal/store"
)

// podReplica is a replica with two init containers and a sidecar (ADR 0038).
func podReplica(id string) *armadav1.ReplicaSpec {
	s := replica(id, "ghcr.io/acme/web:1", 8080)
	s.InitContainers = []*armadav1.ContainerSpec{
		{Name: "migrate", Image: "ghcr.io/acme/web:1", Command: []string{"./migrate"}, MemoryBytes: 64 << 20, PidsLimit: 1024,
			Env: []*armadav1.EnvVar{{Name: "DATABASE_URL", Value: "postgres://secret", Ref: "database-url@v1"}}},
		{Name: "seed", Image: "busybox:1", MemoryBytes: 64 << 20, PidsLimit: 1024},
	}
	s.Sidecars = []*armadav1.ContainerSpec{
		{Name: "log", Image: "ghcr.io/acme/shipper:2", Args: []string{"--to", "x"}, MemoryBytes: 64 << 20, PidsLimit: 1024},
	}
	return s
}

func onlyContainer(t *testing.T, d *fake.Driver) runtime.Container {
	t.Helper()
	cs, err := d.List(t.Context(), map[string]string{runtime.LabelManaged: "true"})
	if err != nil || len(cs) != 1 {
		t.Fatalf("containers %v %v", cs, err)
	}
	return cs[0]
}

// Init containers run in order before the sidecars, which start before the
// replica's own container; all are listed with it.
func TestReplicaContainersStartInOrder(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	a, d := newAgent(t)
	s := podReplica("web-r1-a")
	a.setDesired([]*armadav1.ReplicaSpec{s}, nil)
	report, err := a.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st := onlyState(t, report); st.State != store.ReplicaRunning {
		t.Fatalf("state %v", st)
	}
	if got, want := d.TakeEvents(), []string{"start migrate", "start seed", "start log", "start app"}; !slices.Equal(got, want) {
		t.Errorf("events %v, want %v", got, want)
	}
	for _, image := range []string{"ghcr.io/acme/web:1", "busybox:1", "ghcr.io/acme/shipper:2"} {
		if !slices.Contains(d.Pulls, image) {
			t.Errorf("%s not pulled: %v", image, d.Pulls)
		}
	}
	c := onlyContainer(t, d)
	if len(c.Members) != 3 {
		t.Fatalf("members %v", c.Members)
	}
	cs, _ := d.Spec(c.ID)
	if len(cs.Init) != 2 || cs.Init[0].Name != "migrate" || !slices.Equal(cs.Init[0].Env, []string{"DATABASE_URL=postgres://secret"}) ||
		len(cs.Sidecars) != 1 || !slices.Equal(cs.Sidecars[0].Cmd, []string{"--to", "x"}) {
		t.Errorf("spec %+v", cs)
	}

	// A restarted agent adopts all of them as they are.
	b := New(Config{NodeID: "n1", PrivateIP: "10.0.0.2", Driver: d, Check: a.cfg.Check})
	b.setDesired([]*armadav1.ReplicaSpec{s}, nil)
	if _, err := b.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if after := onlyContainer(t, d); after.ID != c.ID || len(d.TakeEvents()) != 0 {
		t.Errorf("not adopted: %v", after)
	}

	// The replica's own container stops before its sidecars.
	a.remove(ctx, c.ID)
	if got, want := d.TakeEvents(), []string{"stop app", "stop log"}; !slices.Equal(got, want) {
		t.Errorf("events %v, want %v", got, want)
	}
	if cs, _ := d.List(ctx, nil); len(cs) != 0 {
		t.Errorf("left %v", cs)
	}
}

// A replica whose init container fails is not started; it is kept for the
// init container's logs and retried with crash backoff.
func TestReplicaInitContainerFails(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	a, d := newAgent(t)
	a.crashBase = time.Hour
	d.InitExits = map[string]int{"seed": 3}
	a.setDesired([]*armadav1.ReplicaSpec{podReplica("web-r1-a")}, nil)
	const want = "init container seed exited with code 3"
	report, _ := a.Reconcile(ctx)
	if st := onlyState(t, report); st.State != store.ReplicaExited || st.Message != want {
		t.Fatalf("state %v", st)
	}
	if got := d.TakeEvents(); !slices.Equal(got, []string{"start migrate", "start seed"}) {
		t.Errorf("events %v", got)
	}
	// Retried once at once, then it waits, and the init container's output
	// stays readable meanwhile.
	report, _ = a.Reconcile(ctx)
	if st := onlyState(t, report); st.Message != want {
		t.Fatalf("state %v", st)
	}
	first := onlyContainer(t, d)
	report, _ = a.Reconcile(ctx)
	if st := onlyState(t, report); !strings.HasPrefix(st.Message, want+"; restarting in") {
		t.Fatalf("state %v", st)
	}
	c := onlyContainer(t, d)
	if c.ID != first.ID {
		t.Error("recreated during backoff")
	}
	if id, err := containerFor([]runtime.Container{c}, "seed"); err != nil || id == c.ID {
		t.Errorf("init container %q %v", id, err)
	}
}

// A sidecar that stops restarts the replica, all of its containers.
func TestReplicaSidecarStops(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	a, d := newAgent(t)
	a.setDesired([]*armadav1.ReplicaSpec{podReplica("web-r1-a")}, nil)
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	c := onlyContainer(t, d)
	d.TakeEvents()
	d.SetMemberState(c.ID, "log", runtime.StateExited, 2)
	rep, err := a.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	after := onlyContainer(t, d)
	if after.ID == c.ID {
		t.Fatal("not restarted")
	}
	if got := d.TakeEvents(); !slices.Equal(got, []string{"stop app", "start migrate", "start seed", "start log", "start app"}) {
		t.Errorf("events %v", got)
	}
	// The note waits for the next report, or rides on this one when the
	// new replica was ready at once, after which it is dropped.
	a.mu.Lock()
	note := a.notes["web-r1-a"]
	a.mu.Unlock()
	for _, r := range rep.GetReplicas() {
		if r.GetId() == "web-r1-a" && r.GetReady() {
			note += r.GetMessage()
		}
	}
	if !strings.Contains(note, "sidecar log exited with code 2") {
		t.Errorf("restart note %q", note)
	}
}

// While the runtime brings up its init containers, a replica is starting,
// never recreated.
func TestReplicaStarting(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	a, d := newAgent(t)
	d.HoldStarts = true
	a.setDesired([]*armadav1.ReplicaSpec{podReplica("web-r1-a")}, nil)
	for range 2 {
		report, _ := a.Reconcile(ctx)
		if st := onlyState(t, report); st.State != store.ReplicaStarting {
			t.Fatalf("state %v", st)
		}
	}
	c := onlyContainer(t, d)
	d.FinishStarts()
	report, _ := a.Reconcile(ctx)
	if st := onlyState(t, report); st.State != store.ReplicaRunning || onlyContainer(t, d).ID != c.ID {
		t.Fatalf("state %v", st)
	}
}

// An init container or sidecar whose replica's container is gone is
// removed.
func TestStrayMemberRemoved(t *testing.T) {
	t.Parallel()
	a, d := newAgent(t)
	a.setDesired([]*armadav1.ReplicaSpec{replica("web-r1-a", "nginx", 80)}, nil)
	d.AddMember("gone", runtime.Container{ID: "m1", State: runtime.StateRunning, Labels: map[string]string{
		runtime.LabelManaged: "true", runtime.LabelReplica: "web-r1-a", runtime.LabelRole: runtime.RoleSidecar, runtime.LabelContainer: "log",
	}})
	if _, err := a.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Inspect(t.Context(), "m1"); err == nil {
		t.Error("stray sidecar kept")
	}
	if c := onlyContainer(t, d); c.Labels[runtime.LabelRole] != "" {
		t.Errorf("replica container %v", c)
	}
}

// A node whose runtime cannot run them refuses such a replica.
func TestReplicaContainersUnsupported(t *testing.T) {
	t.Parallel()
	a, d := newAgent(t)
	d.NoMembers = true
	a.setDesired([]*armadav1.ReplicaSpec{podReplica("web-r1-a")}, nil)
	report, _ := a.Reconcile(t.Context())
	if st := onlyState(t, report); st.State != store.ReplicaFailed || !strings.Contains(st.Message, "no init containers or sidecars") {
		t.Errorf("state %v", st)
	}
}

// Init containers and sidecars get the replica's secret files and volumes
// they name, and nothing else.
func TestReplicaContainerMounts(t *testing.T) {
	t.Parallel()
	a, d := newAgent(t)
	a.cfg.SecretsDir = t.TempDir()
	s := podReplica("web-r1-a")
	s.SecretFiles = []*armadav1.SecretFile{{Path: "/run/a", Data: []byte("a"), Ref: "a@v1"}, {Path: "/run/b", Data: []byte("b"), Ref: "b@v1"}}
	s.Sidecars[0].SecretFiles = []string{"/run/b"}
	a.setDesired([]*armadav1.ReplicaSpec{s}, nil)
	if _, err := a.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	cs, _ := d.Spec(onlyContainer(t, d).ID)
	if len(cs.Files) != 2 || len(cs.Sidecars[0].Files) != 1 || cs.Sidecars[0].Files[0] != cs.Files[1] || len(cs.Init[0].Files) != 0 {
		t.Errorf("files: replica %v, sidecar %v, init %v", cs.Files, cs.Sidecars[0].Files, cs.Init[0].Files)
	}

	bad := podReplica("web-r1-b")
	bad.Sidecars[0].Volumes = []string{"data"}
	if err := withMemberMounts(bad, &runtime.ContainerSpec{Sidecars: memberSpecs(bad.Sidecars)}); err == nil {
		t.Error("a volume the replica does not have was mounted")
	}
}

// plainHash is the spec hash of replica("web-r1-a", "nginx", 80): empty
// lists of init containers and sidecars marshal to nothing, so it is the
// same as before they existed, and running replicas are not recreated by
// an upgrade.
const plainHash = "eff92c660f35de496b554a742569d31d"

// Replicas without init containers or sidecars keep their hash; theirs
// count, secret values aside.
func TestSpecHashContainers(t *testing.T) {
	t.Parallel()
	plain := replica("web-r1-a", "nginx", 80)
	empty := proto.Clone(plain).(*armadav1.ReplicaSpec)
	empty.InitContainers, empty.Sidecars = []*armadav1.ContainerSpec{}, []*armadav1.ContainerSpec{}
	if specHash(plain) != specHash(empty) {
		t.Error("empty lists changed the hash")
	}
	// Pinned: the hash of a plain replica is what it was before init
	// containers and sidecars existed.
	if got := specHash(plain); got != plainHash {
		t.Errorf("plain replica hash %s, want %s", got, plainHash)
	}
	a, b := podReplica("x"), podReplica("x")
	b.InitContainers[0].Env[0].Value = "postgres://other"
	if specHash(a) != specHash(b) {
		t.Error("a secret value changed the hash")
	}
	b.InitContainers[0].Env[0].Ref = "database-url@v2"
	if specHash(a) == specHash(b) {
		t.Error("a new secret version kept the hash")
	}
	c := podReplica("x")
	c.Sidecars[0].Image = "ghcr.io/acme/shipper:3"
	if specHash(a) == specHash(c) {
		t.Error("a sidecar's image kept the hash")
	}
	if specHash(plain) == specHash(podReplica("web-r1-a")) {
		t.Error("adding containers kept the hash")
	}
}

// A job's attempt ends with its own container: its sidecars stop then. An
// init container that fails ends it with its exit code.
func TestJobAttemptContainers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, d := newAgent(t)
	s := attemptSpec(false)
	s.Sidecars = []*armadav1.ContainerSpec{{Name: "proxy", Image: "envoy"}}
	a.setDesired([]*armadav1.ReplicaSpec{s}, nil)
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	c := onlyContainer(t, d)
	d.TakeEvents()
	// A job's sidecar that stops ends nothing.
	d.SetMemberState(c.ID, "proxy", runtime.StateExited, 1)
	report, _ := a.Reconcile(ctx)
	if st := onlyState(t, report); st.State != store.ReplicaRunning {
		t.Fatalf("state %v", st)
	}
	d.SetMemberState(c.ID, "proxy", runtime.StateRunning, 0)
	d.SetState(c.ID, runtime.StateExited, 0)
	report, _ = a.Reconcile(ctx)
	if st := onlyState(t, report); !st.Finished || st.ExitCode != 0 {
		t.Fatalf("state %v", st)
	}
	if got := d.TakeEvents(); !slices.Equal(got, []string{"stop proxy"}) {
		t.Errorf("events %v", got)
	}

	b, d2 := newAgent(t)
	d2.InitExits = map[string]int{"migrate": 4}
	f := attemptSpec(false)
	f.InitContainers = []*armadav1.ContainerSpec{{Name: "migrate", Image: "x"}}
	b.setDesired([]*armadav1.ReplicaSpec{f}, nil)
	for range 2 {
		report, _ = b.Reconcile(ctx)
		if st := onlyState(t, report); !st.Finished || st.ExitCode != 4 || st.Message != "init container migrate exited with code 4" {
			t.Fatalf("state %v", st)
		}
	}
	if got := d2.TakeEvents(); !slices.Equal(got, []string{"start migrate"}) {
		t.Errorf("run again: %v", got)
	}
}

// Logs and exec reach an init container or sidecar by name.
func TestContainerFor(t *testing.T) {
	t.Parallel()
	c := runtime.Container{ID: "c1", Labels: map[string]string{}, Members: []runtime.Member{
		{ID: "m1", Name: "migrate", Role: runtime.RoleInit}, {ID: "m2", Name: "log", Role: runtime.RoleSidecar},
	}}
	stray := runtime.Container{ID: "s1", Labels: map[string]string{runtime.LabelRole: runtime.RoleSidecar}}
	for name, want := range map[string]string{"": "c1", "app": "c1", "migrate": "m1", "log": "m2"} {
		if got, err := containerFor([]runtime.Container{stray, c}, name); err != nil || got != want {
			t.Errorf("%q: %s %v", name, got, err)
		}
	}
	if _, err := containerFor([]runtime.Container{c}, "other"); err == nil {
		t.Error("unknown container found")
	}
	if _, err := containerFor([]runtime.Container{stray}, ""); err == nil {
		t.Error("a stray sidecar was taken for the replica")
	}
}

func TestServeExecSidecar(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, d := newAgent(t)
	var ran []string
	d.ExecAppFunc = func(_ context.Context, id string, _ runtime.ExecOptions) (int, error) {
		ran = append(ran, id)
		return 0, nil
	}
	a.setDesired([]*armadav1.ReplicaSpec{podReplica("web-1")}, nil)
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	c := onlyContainer(t, d)
	for _, tc := range []struct{ container, want string }{
		{"migrate", "no running sidecar migrate"}, // an init container has run to its end
		{"other", "no running sidecar other"},
	} {
		s := newExecStream()
		a.cfg.Client = execClient{stream: s}
		close(s.in)
		a.serveExec(ctx, &armadav1.ExecRequest{RequestId: "r", ReplicaId: "web-1", Container: tc.container, Cmd: []string{"sh"}})
		if m := s.next(t); !strings.Contains(m.GetError(), tc.want) {
			t.Errorf("%s: %v", tc.container, m)
		}
	}
	s := newExecStream()
	a.cfg.Client = execClient{stream: s}
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.serveExec(ctx, &armadav1.ExecRequest{RequestId: "r", ReplicaId: "web-1", Container: "log", Cmd: []string{"sh", "-c", "x"}})
	}()
	if m := s.next(t); m.GetError() != "" {
		t.Fatalf("first message %v", m)
	}
	for m := s.next(t); ; m = s.next(t) {
		if _, ok := m.GetOutput().(*armadav1.ExecSessionOutput_ExitCode); ok {
			break
		}
	}
	close(s.in)
	<-done
	if log, _ := c.Member("log"); !slices.Equal(ran, []string{log.ID}) {
		t.Errorf("ran in %v, want the sidecar %s", ran, log.ID)
	}
}
