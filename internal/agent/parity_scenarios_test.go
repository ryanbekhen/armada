package agent

import (
	"errors"
	"strconv"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// The agent's scenarios on the parity harness (parity_test.go), ported
// from this package's tests of the loop: reconcile, starts, failures,
// crashes, probes, jobs, held replicas, fencing, init containers and
// sidecars, secret files, volumes, image prunes, and usage samples.

// pr is a replica of app web (or app) with a port.
func pr(id, image string, port int32) *armadav1.ReplicaSpec {
	return &armadav1.ReplicaSpec{
		Id: id, App: "web", Revision: "web--r1", Image: image, Port: port,
		Command: []string{"/bin/web"}, Args: []string{"--x"},
		Env:         []*armadav1.EnvVar{{Name: "A", Value: "1"}, {Name: "S", Value: "secret", Ref: "s/v1"}},
		MemoryBytes: 256 << 20, PidsLimit: 1024, NanoCpus: 500_000_000, CpuReserveMillis: 100,
		// No verdict for an hour: reports of scenarios that are not about
		// probes do not race a probe's first answer.
		Readiness: &armadav1.Probe{Path: "/r", InitialDelayMs: 3_600_000},
	}
}

// noProbe is s with the implicit readiness of its port, or none.
func noProbe(s *armadav1.ReplicaSpec) *armadav1.ReplicaSpec {
	s.Readiness = nil
	return s
}

// adopted is a running container of s left from an agent before this one.
func adopted(s *armadav1.ReplicaSpec, id string, started time.Time) runtime.Container {
	cs := ContainerSpec(s, "10.0.0.2", specHash(s))
	return runtime.Container{ID: id, Name: cs.Name, Image: s.GetImage(), Labels: cs.Labels, State: runtime.StateRunning,
		HostIP: "10.0.0.2", HostPort: 31000, StartedAt: started}
}

// report finds a replica's state in r.
func report(r *armadav1.ReplicaReport, id string) *armadav1.ReplicaState {
	for _, s := range r.GetReplicas() {
		if s.GetId() == id {
			return s
		}
	}
	return nil
}

func ready(id string) func(*armadav1.ReplicaReport) bool {
	return func(r *armadav1.ReplicaReport) bool { return report(r, id).GetReady() }
}

func TestAgentParity(t *testing.T) {
	t.Parallel()
	scenarios := []struct {
		name string
		opts func(*parityOpts)
		body func(p *parityRun)
	}{
		{"before the first assignment", nil, func(p *parityRun) {
			p.f.add(adopted(pr("web-r1-a", "nginx:1", 8080), "old", parityT0.Add(-time.Minute)))
			p.reconcile("no assignment: nothing happens")
			p.other("fence with contact up", func(a agentUnderTest) { a.contact(true); a.fence() })
		}},
		{"starts and adopts", nil, func(p *parityRun) {
			p.f.set(func(f *pfake) {
				f.digests["nginx:1"] = "nginx@sha256:aa"
				f.platforms["nginx:1"] = []string{"linux/amd64", "linux/arm64"}
			})
			p.assign(noProbe(pr("web-r1-a", "nginx:1", 8080)), noProbe(pr("web-r1-b", "nginx:1", 8080)), noProbe(pr("worker-r1-a", "busybox", 0)))
			p.until("ready", func(r *armadav1.ReplicaReport) bool {
				return report(r, "web-r1-a").GetReady() && report(r, "web-r1-b").GetReady() && report(r, "worker-r1-a").GetReady()
			})
			p.reconcile("adopted, nothing to do")
			// The server pins the image's digest: no restart.
			a, b := noProbe(pr("web-r1-a", "nginx@sha256:aa", 8080)), noProbe(pr("web-r1-b", "nginx@sha256:aa", 8080))
			p.assign(a, b)
			p.reconcile("pinned, worker removed")
			// A changed spec recreates.
			a.Env = append(a.Env, &armadav1.EnvVar{Name: "B", Value: "2"})
			p.assign(a, b)
			// The recreated container's first verdict races the report: wait
			// for it.
			p.until("spec changed", func(r *armadav1.ReplicaReport) bool {
				return report(r, a.Id).GetReady() && report(r, a.Id).GetContainerId() == "armada-web-r1-a-2"
			})
		}},
		{"strays", nil, func(p *parityRun) {
			s := pr("web-r1-a", "nginx:1", 0)
			p.f.add(adopted(s, "a1", parityT0.Add(-time.Minute)))
			dup := adopted(s, "a2", parityT0.Add(-time.Minute))
			dup.Name = "armada-web-r1-a-dup"
			p.f.add(dup)
			p.f.add(adopted(pr("gone-r1-a", "nginx:1", 0), "gone", parityT0.Add(-time.Minute)))
			lone := adopted(s, "lone", parityT0.Add(-time.Minute))
			lone.Name, lone.Labels[runtime.LabelRole] = "armada-web-r1-a-side", runtime.RoleSidecar
			p.f.add(lone)
			p.f.add(runtime.Container{ID: "other", Name: "other", Labels: map[string]string{"x": "y"}, State: runtime.StateRunning})
			p.assign(s)
			p.reconcile("strays removed, the first kept")
		}},
		{"failures", nil, func(p *parityRun) {
			p.f.set(func(f *pfake) {
				f.pullErr["private:1"] = errors.New("pull private:1: unauthorized")
				f.pullErr["arm-only:1"] = &runtime.PlatformError{Image: "arm-only:1", Want: "linux/amd64", Have: []string{"linux/arm64"}}
				f.runErr["broken:1"] = "create container: invalid mount"
			})
			s := pr("web-r1-a", "private:1", 80)
			s.Registry = &armadav1.RegistryAuth{Server: "reg.example", Username: "u", Password: "p"}
			p.assign(s, pr("web-r1-b", "arm-only:1", 80), pr("web-r1-c", "broken:1", 80))
			p.reconcile("pull, platform, and run failures")
			p.reconcile("tried again")
		}},
		{"crash backoff", nil, func(p *parityRun) {
			p.assign(pr("web-r1-a", "nginx:1", 0))
			p.reconcile("started")
			id := "armada-web-r1-a-1"
			p.f.setState(id, runtime.StateExited, 3)
			p.reconcile("first crash: recreated at once")
			p.f.setState("armada-web-r1-a-2", runtime.StateExited, 3)
			p.reconcile("second crash: waits")
			p.advance(500 * time.Millisecond)
			p.reconcile("still waiting")
			p.advance(600 * time.Millisecond)
			p.reconcile("recreated")
			p.f.setState("armada-web-r1-a-3", runtime.StateExited, 1)
			p.reconcile("third crash: waits longer")
			p.advance(11 * time.Minute)
			p.reconcile("recreated after a long while")
			p.f.setState("armada-web-r1-a-4", runtime.StateExited, 1)
			p.reconcile("the count started over")
			p.advance(2 * time.Second)
			p.reconcile("recreated")
			p.f.setState("armada-web-r1-a-5", runtime.StateDead, 0)
			p.reconcile("dead")
		}},
		{"out of memory and created", nil, func(p *parityRun) {
			p.assign(pr("web-r1-a", "nginx:1", 0), pr("web-r1-b", "nginx:1", 0))
			p.reconcile("started")
			p.f.set(func(f *pfake) { f.usage["web-r1-a"] = runtime.Stats{OOMKills: 1} })
			p.f.setState("armada-web-r1-a-1", runtime.StateExited, 137)
			p.f.setState("armada-web-r1-b-1", runtime.StateCreated, 0)
			p.reconcile("recreated with why")
		}},
		{"machine restarted", nil, func(p *parityRun) {
			s := pr("web-r1-a", "nginx:1", 0)
			c := adopted(s, "before", parityT0.Add(-2*time.Hour))
			c.State, c.ExitCode = runtime.StateExited, 255
			p.f.add(c)
			p.assign(s)
			p.reconcile("recreated with no backoff")
		}},
		{"adopted waits for its probes", nil, func(p *parityRun) {
			s := noProbe(pr("web-r1-a", "nginx:1", 8080))
			p.f.add(adopted(s, "old", parityT0.Add(-time.Minute)))
			p.f.set(func(f *pfake) {
				f.checks["10.0.0.2:31000 "] = "slow 300ms dial tcp 10.0.0.2:31000: connect: connection refused"
			})
			p.assign(s)
			p.reconcile("left out until the first verdict")
			p.until("not ready", func(r *armadav1.ReplicaReport) bool { return report(r, "web-r1-a") != nil })
		}},
		{"readiness", nil, func(p *parityRun) {
			s := pr("web-r1-a", "nginx:1", 8080)
			s.Readiness = &armadav1.Probe{Path: "/ready", PeriodMs: 20, FailureThreshold: 2}
			p.assign(s)
			p.f.set(func(f *pfake) { f.checks["10.0.0.2:"+port(s.Id)+" /ready"] = "HTTP 503" })
			p.until("not ready with why", func(r *armadav1.ReplicaReport) bool { return report(r, s.Id).GetMessage() != "" })
			p.f.set(func(f *pfake) { f.checks["10.0.0.2:"+port(s.Id)+" /ready"] = "" })
			p.until("ready", ready(s.Id))
		}},
		{"liveness restarts", nil, func(p *parityRun) {
			s := noProbe(pr("web-r1-a", "nginx:1", 8080))
			s.Liveness = &armadav1.Probe{Path: "/live", PeriodMs: 20, FailureThreshold: 2}
			p.f.set(func(f *pfake) { f.checks["10.0.0.2:"+port(s.Id)+" /live"] = "fail 2 HTTP 500" })
			p.assign(s)
			p.until("restarted", func(r *armadav1.ReplicaReport) bool {
				return report(r, s.Id).GetContainerId() == "armada-web-r1-a-2" && report(r, s.Id).GetReady()
			})
			p.reconcile("the note was reported")
		}},
		{"startup probe", nil, func(p *parityRun) {
			s := pr("web-r1-a", "nginx:1", 8080)
			s.Startup = &armadav1.Probe{Path: "/up", PeriodMs: 20, FailureThreshold: 2}
			s.Readiness = &armadav1.Probe{Path: "/ready", PeriodMs: 20}
			p.f.set(func(f *pfake) { f.checks["10.0.0.2:"+port(s.Id)+" /up"] = "fail 2 HTTP 404" })
			p.assign(s)
			p.reconcile("started")
			p.until("restarted after its startup probe failed", func(r *armadav1.ReplicaReport) bool {
				return report(r, s.Id).GetContainerId() == "armada-web-r1-a-2" && report(r, s.Id).GetReady()
			})
		}},
		{"command probes", nil, func(p *parityRun) {
			a, b, c := pr("web-r1-a", "nginx:1", 0), pr("web-r1-b", "nginx:1", 0), pr("web-r1-c", "nginx:1", 0)
			a.Readiness = &armadav1.Probe{Command: []string{"check", "--secret"}, PeriodMs: 20}
			b.Readiness = &armadav1.Probe{Command: []string{"sleep"}, PeriodMs: 20, TimeoutMs: 30}
			c.Readiness = &armadav1.Probe{Command: []string{"missing"}, PeriodMs: 20}
			p.f.set(func(f *pfake) { f.execCodes["check"] = 2 })
			p.assign(a, b, c)
			p.until("failing", func(r *armadav1.ReplicaReport) bool {
				return report(r, a.Id).GetMessage() != "" && report(r, b.Id).GetMessage() != "" && report(r, c.Id).GetMessage() != ""
			})
			p.f.set(func(f *pfake) { f.execCodes["check"] = 0 })
			p.until("ready", ready(a.Id))
		}},
		{"command probes unsupported", func(o *parityOpts) { o.exec = false }, func(p *parityRun) {
			s := pr("web-r1-a", "nginx:1", 0)
			s.Readiness = &armadav1.Probe{Command: []string{"check"}, PeriodMs: 20}
			p.assign(s)
			p.until("why", func(r *armadav1.ReplicaReport) bool { return report(r, s.Id).GetMessage() != "" })
		}},
		{"probe addresses", nil, func(p *parityRun) {
			a, b := pr("web-r1-a", "nginx:1", 8080), pr("web-r1-b", "nginx:1", 0)
			a.Readiness = &armadav1.Probe{Path: "/x", Port: 70000, PeriodMs: 20}
			b.Readiness = &armadav1.Probe{Path: "/x", Port: 9090, PeriodMs: 20}
			c := pr("web-r1-c", "nginx:1", 80)
			c.Readiness = &armadav1.Probe{Path: "no-slash", PeriodMs: 20}
			p.assign(a, b, c)
			p.until("refused", func(r *armadav1.ReplicaReport) bool {
				return report(r, a.Id).GetMessage() != "" && report(r, b.Id).GetMessage() != "" && report(r, c.Id).GetMessage() != ""
			})
		}},
		{"no readiness and no port", nil, func(p *parityRun) {
			p.assign(noProbe(pr("worker-r1-a", "busybox", 0)))
			p.until("ready at once", ready("worker-r1-a"))
		}},
		{"jobs", nil, func(p *parityRun) {
			job := func(id string, done bool) *armadav1.ReplicaSpec {
				s := pr(id, "busybox", 0)
				s.App, s.Job = "batch", &armadav1.JobAttempt{Job: "batch", Run: 1, Done: done}
				return s
			}
			p.assign(job("batch-j1-a", false), job("batch-j1-b", false))
			p.reconcile("attempts started")
			p.f.setState("armada-batch-j1-a-1", runtime.StateExited, 0)
			p.f.setState("armada-batch-j1-b-1", runtime.StateExited, 2)
			p.reconcile("finished, never restarted")
			p.reconcile("still finished")
			p.assign(job("batch-j1-a", true), job("batch-j1-b", true), job("batch-j1-c", true))
			p.reconcile("done: kept, never started")
		}},
		{"job done while running", nil, func(p *parityRun) {
			s := pr("batch-j1-a", "busybox", 0)
			s.App, s.Job = "batch", &armadav1.JobAttempt{Job: "batch", Run: 1}
			p.assign(s)
			p.reconcile("started")
			done := pr("batch-j1-a", "busybox", 0)
			done.App, done.Job = "batch", &armadav1.JobAttempt{Job: "batch", Run: 1, Done: true}
			p.assign(done)
			p.reconcile("stopped, outside the hash")
		}},
		{"job created but never started", nil, func(p *parityRun) {
			s := pr("batch-j1-a", "busybox", 0)
			s.App, s.Job = "batch", &armadav1.JobAttempt{Job: "batch", Run: 1}
			c := adopted(s, "created", parityT0.Add(-time.Minute))
			c.State = runtime.StateCreated
			p.f.add(c)
			p.f.set(func(f *pfake) { f.runErr["busybox"] = "no space left" })
			p.assign(s)
			p.reconcile("removed, failed to start again")
		}},
		{"held replicas", nil, func(p *parityRun) {
			s := pr("web-r1-a", "nginx:1", 8080)
			s.Hold = true
			s.Sidecars = []*armadav1.ContainerSpec{{Name: "log", Image: "fluent:1"}}
			p.f.set(func(f *pfake) { f.digests["nginx:1"] = "nginx@sha256:bb" })
			p.f.add(adopted(s, "held-old", parityT0.Add(-time.Minute)))
			hold := make(chan struct{})
			p.f.set(func(f *pfake) { f.pullHold = hold })
			p.assign(s)
			p.reconcile("pulling")
			close(hold)
			p.f.set(func(f *pfake) { f.pullHold = nil })
			p.until("pulled", func(r *armadav1.ReplicaReport) bool { return report(r, s.Id).GetState() == "pulled" })
			lifted := pr("web-r1-a", "nginx:1", 8080)
			lifted.Sidecars = s.Sidecars
			p.assign(lifted)
			p.reconcile("hold lifted: started")
		}},
		{"held replica pull fails", nil, func(p *parityRun) {
			p.f.set(func(f *pfake) {
				f.pullErr["arm-only:1"] = &runtime.PlatformError{Image: "arm-only:1", Want: "linux/amd64", Have: []string{"linux/arm64"}}
			})
			s := pr("web-r1-a", "arm-only:1", 8080)
			s.Hold = true
			p.assign(s)
			p.until("failed", func(r *armadav1.ReplicaReport) bool { return report(r, s.Id).GetState() == "failed" })
			p.advance(10 * time.Second)
			p.reconcile("not retried yet")
			p.f.set(func(f *pfake) { delete(f.pullErr, "arm-only:1") })
			p.advance(30 * time.Second)
			p.until("retried", func(r *armadav1.ReplicaReport) bool { return report(r, s.Id).GetState() == "pulled" })
		}},
		{"fencing", nil, func(p *parityRun) {
			s := pr("web-r1-a", "nginx:1", 0)
			s.FenceAfterSeconds = 30
			p.other("in touch", func(a agentUnderTest) { a.contact(true) })
			p.assign(s, pr("web-r1-b", "nginx:1", 0))
			p.reconcile("started with the label")
			p.other("cut off", func(a agentUnderTest) { a.contact(false) })
			p.advance(20 * time.Second)
			p.reconcile("not yet")
			p.advance(11 * time.Second)
			p.reconcile("fenced")
			p.reconcile("still fenced")
			p.other("back", func(a agentUnderTest) { a.contact(true) })
			p.reconcile("started again at once")
		}},
		{"fencing before the first assignment", nil, func(p *parityRun) {
			s := pr("web-r1-a", "nginx:1", 0)
			s.FenceAfterSeconds = 30
			p.f.add(adopted(s, "fenced", parityT0.Add(-time.Minute)))
			bad := adopted(pr("web-r1-b", "nginx:1", 0), "odd", parityT0.Add(-time.Minute))
			bad.Labels[runtime.LabelFenceAfter] = "x"
			p.f.add(bad)
			p.other("too early", func(a agentUnderTest) { a.fence() })
			p.advance(31 * time.Second)
			p.other("stopped", func(a agentUnderTest) { a.fence() })
			p.assign(s)
			p.reconcile("assigned while cut off")
		}},
		{"init containers and sidecars", nil, func(p *parityRun) {
			s := noProbe(pr("web-r1-a", "nginx:1", 8080))
			s.InitContainers = []*armadav1.ContainerSpec{{Name: "migrate", Image: "migrate:1", Command: []string{"/m"},
				Env: []*armadav1.EnvVar{{Name: "K", Value: "v", Ref: "k/1"}}, MemoryBytes: 64 << 20}}
			s.Sidecars = []*armadav1.ContainerSpec{{Name: "log", Image: "fluent:1", Args: []string{"-c"}, NanoCpus: 10_000_000}}
			p.f.set(func(f *pfake) { f.digests["fluent:1"] = "fluent@sha256:cc" })
			p.assign(s)
			p.until("ready", ready(s.Id))
			p.f.setMemberState("armada-web-r1-a-1", "log", runtime.StateExited, 1)
			p.until("sidecar stopped: recreated", func(r *armadav1.ReplicaReport) bool {
				return report(r, s.Id).GetReady() && report(r, s.Id).GetContainerId() == "armada-web-r1-a-2"
			})
			p.f.setMemberState("armada-web-r1-a-2", "log", runtime.StateDead, 0)
			p.reconcile("sidecar dead: waits")
			p.other("prune", func(a agentUnderTest) { a.prune() })
		}},
		{"init container fails", nil, func(p *parityRun) {
			s := pr("web-r1-a", "nginx:1", 0)
			s.InitContainers = []*armadav1.ContainerSpec{{Name: "migrate", Image: "migrate:1"}}
			p.f.set(func(f *pfake) { f.initExits["migrate"] = 4 })
			p.assign(s)
			p.reconcile("started")
			p.reconcile("init failed: recreated")
			p.reconcile("waits")
		}},
		{"replica starting", nil, func(p *parityRun) {
			s := pr("web-r1-a", "nginx:1", 0)
			s.Sidecars = []*armadav1.ContainerSpec{{Name: "log", Image: "fluent:1"}}
			p.f.set(func(f *pfake) { f.holdStarts = true })
			p.assign(s)
			p.reconcile("started")
			p.reconcile("starting its members")
		}},
		{"members unsupported", func(o *parityOpts) { o.members = false }, func(p *parityRun) {
			s := pr("web-r1-a", "nginx:1", 0)
			s.Sidecars = []*armadav1.ContainerSpec{{Name: "log", Image: "fluent:1"}}
			p.assign(s)
			p.reconcile("refused")
		}},
		{"member platform", nil, func(p *parityRun) {
			p.f.set(func(f *pfake) {
				f.pullErr["fluent:1"] = &runtime.PlatformError{Image: "fluent:1", Want: "linux/amd64", Have: []string{"linux/arm64"}}
			})
			s := pr("web-r1-a", "nginx:1", 0)
			s.Sidecars = []*armadav1.ContainerSpec{{Name: "log", Image: "fluent:1"}}
			p.assign(s)
			p.reconcile("a plain error")
		}},
		{"job with members", nil, func(p *parityRun) {
			s := pr("batch-j1-a", "busybox", 0)
			s.App, s.Job = "batch", &armadav1.JobAttempt{Job: "batch", Run: 1}
			s.InitContainers = []*armadav1.ContainerSpec{{Name: "fetch", Image: "fetch:1"}}
			s.Sidecars = []*armadav1.ContainerSpec{{Name: "proxy", Image: "proxy:1"}}
			p.assign(s)
			p.reconcile("started")
			p.f.setMemberState("armada-batch-j1-a-1", "proxy", runtime.StateExited, 0)
			p.reconcile("a stopped sidecar does not end a job")
			p.f.setState("armada-batch-j1-a-1", runtime.StateExited, 0)
			p.reconcile("ended with its sidecars stopped")
			s2 := pr("batch-j1-b", "busybox", 0)
			s2.App, s2.Job = "batch", &armadav1.JobAttempt{Job: "batch", Run: 2}
			s2.InitContainers = []*armadav1.ContainerSpec{{Name: "fetch", Image: "fetch:1"}}
			p.f.set(func(f *pfake) { f.initExits["fetch"] = 9 })
			p.assign(s, s2)
			p.reconcile("init failed: the attempt ends with its code")
		}},
		{"secret files and mounts", nil, func(p *parityRun) {
			s := pr("web-r1-a", "nginx:1", 0)
			s.SecretFiles = []*armadav1.SecretFile{{Path: "/run/secrets/db", Data: []byte("pw"), Ref: "db/1"}, {Path: "/etc/key", Data: []byte("k")}}
			s.Volumes = []*armadav1.VolumeSpec{{Name: "data", Path: "/data", Owner: "1000:1000"}}
			s.Sidecars = []*armadav1.ContainerSpec{{Name: "log", Image: "fluent:1", SecretFiles: []string{"/etc/key"}, Volumes: []string{"data"}}}
			bad := pr("web-r1-b", "nginx:1", 0)
			bad.SecretFiles = []*armadav1.SecretFile{{Path: "/a/../b", Data: []byte("x")}}
			odd := pr("web-r1-c", "nginx:1", 0)
			odd.Sidecars = []*armadav1.ContainerSpec{{Name: "log", Image: "fluent:1", SecretFiles: []string{"/nope"}}, {Name: "two", Image: "fluent:1", Volumes: []string{"none"}}}
			upper := pr("Web-R1", "nginx:1", 0)
			upper.SecretFiles = []*armadav1.SecretFile{{Path: "/x", Data: []byte("x")}}
			nfs := pr("web-r1-d", "nginx:1", 0)
			nfs.Volumes = []*armadav1.VolumeSpec{{Name: "share", Path: "/share", Nfs: &armadav1.NfsSource{Server: "10.0.0.9", Path: "/export"}}}
			badVol := pr("web-r1-e", "nginx:1", 0)
			badVol.Volumes = []*armadav1.VolumeSpec{{Name: "data", Path: "relative"}}
			p.assign(s, bad, odd, upper, nfs, badVol)
			p.reconcile("written and mounted, or refused")
			p.assign(pr("web-r1-a", "nginx:1", 0))
			p.reconcile("files removed with the replicas")
		}},
		{"no secrets or volumes on the node", func(o *parityOpts) { o.noSecretsDir, o.volumesDir = true, false }, func(p *parityRun) {
			s := pr("web-r1-a", "nginx:1", 0)
			s.SecretFiles = []*armadav1.SecretFile{{Path: "/x", Data: []byte("x")}}
			v := pr("web-r1-b", "nginx:1", 0)
			v.Volumes = []*armadav1.VolumeSpec{{Name: "data", Path: "/data"}}
			p.assign(s, v)
			p.reconcile("refused")
		}},
		{"unpublished with internal DNS", func(o *parityOpts) {
			o.unpublished, o.bridge, o.dns = true, "10.120.0.", "10.120.0.1"
		}, func(p *parityRun) {
			s := noProbe(pr("web-r1-a", "nginx:1", 8080))
			o := noProbe(pr("api.shop-r1-a", "api:1", 9000))
			o.App = "api.shop"
			p.assign(s, o, pr("worker-r1-a", "busybox", 0))
			p.until("ready", func(r *armadav1.ReplicaReport) bool { return report(r, s.Id).GetReady() && report(r, o.Id).GetReady() })
		}},
		{"image prune", nil, func(p *parityRun) {
			p.other("before the first assignment", func(a agentUnderTest) { a.prune() })
			s := pr("web-r1-a", "nginx:1", 0)
			s.Sidecars = []*armadav1.ContainerSpec{{Name: "log", Image: "fluent:1"}}
			p.f.set(func(f *pfake) { f.digests["nginx:1"] = "nginx@sha256:dd"; f.digests["fluent:1"] = "fluent@sha256:ee" })
			p.assign(s, pr("web-r1-b", "redis:7", 0))
			p.reconcile("started")
			p.other("keeps what is assigned", func(a agentUnderTest) { a.prune() })
		}},
		{"usage", nil, func(p *parityRun) {
			p.f.set(func(f *pfake) {
				f.agentStatus = runtime.AgentStatus{Agent: runtime.AgentSupervisorRust, GoImages: true, ImagesToPull: 3}
			})
			p.assign(pr("web-r1-a", "nginx:1", 0), pr("web-r1-b", "nginx:1", 0))
			p.reconcile("started")
			p.f.set(func(f *pfake) {
				f.usage["web-r1-a"] = runtime.Stats{CPU: time.Second, MemoryBytes: 100, EgressBytes: 10, NetworkLost: true}
				f.usage["web-r1-b"] = runtime.Stats{CPU: 2 * time.Second, MemoryBytes: 200, EgressBytes: 50}
			})
			p.sample("first: no rate yet")
			p.advance(10 * time.Second)
			p.f.set(func(f *pfake) {
				f.usage["web-r1-a"] = runtime.Stats{CPU: 3 * time.Second, MemoryBytes: 150, EgressBytes: 30, NetworkLost: true, OOMKills: 1}
				f.usage["web-r1-b"] = runtime.Stats{CPU: time.Second, MemoryBytes: 200, EgressBytes: 40}
			})
			p.sample("second: rates, the lost network asks for a restart")
			p.reconcile("recreated for its network")
		}},
		{"usage without stats", func(o *parityOpts) { o.stats = false }, func(p *parityRun) {
			p.assign(pr("web-r1-a", "nginx:1", 0))
			p.reconcile("started")
			p.sample("nothing to say")
		}},
		{"many starts", nil, func(p *parityRun) {
			var rs []*armadav1.ReplicaSpec
			for i := range 20 {
				rs = append(rs, pr("web-r1-"+string(rune('a'+i)), "nginx:1", 80))
			}
			p.assign(rs...)
			r := p.reconcile("twenty at most eight at a time")
			if len(r.GetReplicas()) != 20 {
				p.t.Errorf("reported %d", len(r.GetReplicas()))
			}
		}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			opts := defaultOpts()
			if sc.opts != nil {
				sc.opts(&opts)
			}
			runAgentParity(t, opts, sc.body)
		})
	}
}

// port is the host port pfake gives replica id's container.
func port(id string) string {
	return strconv.Itoa(30000 + nameHash("armada-"+id)%2000)
}
