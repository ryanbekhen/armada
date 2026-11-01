// Package agent runs on every node: it receives the desired set of replicas
// from the server and reconciles local containers against it.
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/proxy"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/version"
)

const (
	defaultResync = 10 * time.Second
	stopGrace     = 10 * time.Second
	maxBackoff    = 30 * time.Second
	// reconnectDelay is the pause after a session the server had accepted.
	reconnectDelay = 100 * time.Millisecond

	// Stopped containers are recreated with exponential backoff, like a
	// crash loop: crashBackoff, doubling up to maxCrashBackoff. The count
	// resets after crashReset without a crash.
	crashBackoff    = time.Second
	maxCrashBackoff = 5 * time.Minute
	crashReset      = 10 * time.Minute
)

// Config configures an Agent.
type Config struct {
	NodeID    string
	PrivateIP string
	Driver    runtime.Driver
	Client    armadav1.AgentServiceClient
	Logger    *slog.Logger
	// Resync is how often containers are reconciled without a trigger.
	Resync time.Duration
	// Capacity reported to the scheduler; zero values are auto-detected.
	CPUMillis   int64
	MemoryBytes int64
	// Proxy applies the ingress configuration; nil disables ingress on this
	// node.
	Proxy proxy.Driver
	// Check runs health checks (default DefaultCheck).
	Check CheckFunc
	// SecretsDir is a private directory on tmpfs for secret files. Empty
	// means replicas with secret files fail to start on this node.
	SecretsDir string
	// DNS is the node-local resolver for <app>.internal; nil leaves
	// containers with the engine's default DNS.
	DNS InternalDNS
	// Servers are the control plane addresses the agent started with;
	// OnServers receives them whenever the server sends a different list.
	Servers   []string
	OnServers func(servers []string)
}

// InternalDNS is the node-local resolver the agent keeps in sync with the
// proxy's internal routes.
type InternalDNS interface {
	// Address is the nameserver containers are given.
	Address() string
	// SetNames replaces the apps that resolve under .internal.
	SetNames(apps []string)
}

// Agent reconciles containers on one node.
type Agent struct {
	cfg Config
	log *slog.Logger

	mu      sync.Mutex
	desired map[string]*armadav1.ReplicaSpec // nil until the first assignment
	servers []string                         // last control plane list received
	digests map[string]string                // image ref -> pinned ref
	cancels map[string]context.CancelFunc    // log request -> cancel
	probes  map[string]*probeWorker          // replica -> probes of its container
	// restarts holds containers a failed probe asked to restart, with the
	// reason; notes carries that reason to the replacement's status.
	restarts map[string]string // container ID -> reason
	notes    map[string]string // replica -> message
	crashes  map[string]crashLoop
	// crashBase is the first recreate delay (crashBackoff; shorter in tests).
	crashBase time.Duration

	proxyDesired *armadav1.ProxyConfig
	proxyApplied *armadav1.ProxyConfig

	trigger chan struct{}

	streamMu sync.Mutex
	stream   armadav1.AgentService_ConnectClient
	lastSent *armadav1.ReplicaReport
}

// New returns an Agent.
func New(cfg Config) *Agent {
	if cfg.Resync == 0 {
		cfg.Resync = defaultResync
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Check == nil {
		cfg.Check = DefaultCheck
	}
	if cfg.CPUMillis == 0 || cfg.MemoryBytes == 0 {
		cpu, mem := detectCapacity()
		if cfg.CPUMillis == 0 {
			cfg.CPUMillis = cpu
		}
		if cfg.MemoryBytes == 0 {
			cfg.MemoryBytes = mem
		}
	}
	return &Agent{
		cfg:      cfg,
		servers:  slices.Clone(cfg.Servers),
		log:      cfg.Logger.With("component", "agent", "node", cfg.NodeID),
		digests:  map[string]string{},
		cancels:  map[string]context.CancelFunc{},
		probes:   map[string]*probeWorker{},
		restarts: map[string]string{},
		notes:    map[string]string{},
		crashes:  map[string]crashLoop{},
		trigger:  make(chan struct{}, 1),

		crashBase: crashBackoff,
	}
}

// Run connects to the server and reconciles until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.cfg.Driver.Ping(ctx); err != nil {
		return fmt.Errorf("container runtime: %w", err)
	}
	go a.reconcileLoop(ctx)

	backoff := time.Second
	for {
		start := time.Now()
		established, err := a.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		wait := backoff
		// A session the server accepted (e.g. one ended by a certificate
		// renewal) is not a failure to back off from: reconnect quickly.
		if established || time.Since(start) > time.Minute {
			wait, backoff = reconnectDelay, time.Second
		} else {
			backoff = min(backoff*2, maxBackoff)
		}
		a.log.Warn("disconnected from server", "err", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// session runs one stream; established reports whether the server
// accepted it (sent at least one message).
func (a *Agent) session(ctx context.Context) (established bool, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := a.cfg.Client.Connect(ctx)
	if err != nil {
		return false, err
	}
	hello := &armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Hello{Hello: &armadav1.Hello{
		CpuMillis: a.cfg.CPUMillis, MemoryBytes: a.cfg.MemoryBytes, Version: version.Get().Version, PrivateIp: a.cfg.PrivateIP,
	}}}
	if err := stream.Send(hello); err != nil {
		return false, err
	}
	a.streamMu.Lock()
	a.stream, a.lastSent = stream, nil
	a.streamMu.Unlock()
	defer func() {
		a.streamMu.Lock()
		a.stream = nil
		a.streamMu.Unlock()
	}()

	for {
		msg, err := stream.Recv()
		if err != nil {
			return established, err
		}
		if !established {
			established = true
			a.log.Info("connected to server")
		}
		switch m := msg.Msg.(type) {
		case *armadav1.ServerMessage_Assignment:
			a.setDesired(m.Assignment.GetReplicas(), m.Assignment.GetProxy())
			a.setServers(m.Assignment.GetServers())
		case *armadav1.ServerMessage_LogRequest:
			go a.serveLogs(ctx, m.LogRequest)
		case *armadav1.ServerMessage_LogCancel:
			a.cancelLogs(m.LogCancel.GetRequestId())
		}
	}
}

func (a *Agent) setServers(servers []string) {
	if len(servers) == 0 || a.cfg.OnServers == nil {
		return
	}
	a.mu.Lock()
	changed := !slices.Equal(a.servers, servers)
	if changed {
		a.servers = slices.Clone(servers)
	}
	a.mu.Unlock()
	if changed {
		a.cfg.OnServers(slices.Clone(servers))
	}
}

func (a *Agent) setDesired(replicas []*armadav1.ReplicaSpec, px *armadav1.ProxyConfig) {
	d := make(map[string]*armadav1.ReplicaSpec, len(replicas))
	for _, r := range replicas {
		d[r.GetId()] = r
	}
	a.mu.Lock()
	a.desired = d
	if px != nil {
		a.proxyDesired = px
	}
	a.mu.Unlock()
	a.Trigger()
}

// Trigger requests a reconcile as soon as possible.
func (a *Agent) Trigger() {
	select {
	case a.trigger <- struct{}{}:
	default:
	}
}

func (a *Agent) reconcileLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.Resync)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.trigger:
		}
		report, err := a.Reconcile(ctx)
		if err != nil {
			a.log.Error("reconcile failed", "err", err)
			continue
		}
		if report != nil {
			a.sendReport(report)
		}
	}
}

func (a *Agent) sendReport(r *armadav1.ReplicaReport) {
	a.streamMu.Lock()
	defer a.streamMu.Unlock()
	if a.stream == nil || proto.Equal(r, a.lastSent) {
		return
	}
	if err := a.stream.Send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Report{Report: r}}); err != nil {
		a.log.Warn("send report failed", "err", err)
		return
	}
	a.lastSent = r
}

// Reconcile makes local containers match the desired replicas and returns
// their status. Before the first assignment it does nothing and returns nil:
// an agent that restarts while the server is down must not remove anything.
func (a *Agent) Reconcile(ctx context.Context) (*armadav1.ReplicaReport, error) {
	a.mu.Lock()
	if a.desired == nil {
		a.mu.Unlock()
		return nil, nil
	}
	desired := make(map[string]*armadav1.ReplicaSpec, len(a.desired))
	for k, v := range a.desired {
		desired[k] = v
	}
	a.mu.Unlock()

	containers, err := a.cfg.Driver.List(ctx, map[string]string{runtime.LabelManaged: "true"})
	if err != nil {
		return nil, err
	}

	byReplica := map[string]runtime.Container{}
	for _, c := range containers {
		id := c.Labels[runtime.LabelReplica]
		_, want := desired[id]
		_, dup := byReplica[id]
		if !want || dup {
			a.log.Info("removing container", "container", c.Name, "replica", id)
			a.remove(ctx, c.ID)
			continue
		}
		byReplica[id] = c
	}

	report := &armadav1.ReplicaReport{}
	for _, id := range sortedKeys(desired) {
		spec := desired[id]
		hash := specHash(spec)
		c, ok := byReplica[id]
		if ok && c.Labels[runtime.LabelSpecHash] != hash {
			a.log.Info("spec changed, recreating", "replica", id)
			a.remove(ctx, c.ID)
			ok = false
		}
		if ok {
			a.mu.Lock()
			reason, restart := a.restarts[c.ID]
			delete(a.restarts, c.ID)
			if restart {
				a.notes[id] = "restarted: " + reason
			}
			a.mu.Unlock()
			if restart {
				a.remove(ctx, c.ID)
				ok = false
			}
		}
		if ok && stopped(c.State) {
			// The runtime restarts nothing itself (ADR 0011): a crashed
			// container, one left exited by a reboot, or a failed start is
			// recreated here with crash backoff.
			msg, wait := a.crashed(ctx, id, c)
			if wait > 0 {
				report.Replicas = append(report.Replicas, &armadav1.ReplicaState{
					Id: id, State: store.ReplicaExited, ContainerId: c.ID,
					Message: fmt.Sprintf("%s; restarting in %s", msg, wait.Round(time.Second)),
				})
				continue
			}
			a.log.Warn("container stopped, recreating", "replica", id, "reason", msg)
			a.mu.Lock()
			a.notes[id] = "restarted: " + msg
			a.mu.Unlock()
			a.remove(ctx, c.ID)
			ok = false
		}
		if !ok {
			c, err = a.start(ctx, spec, hash)
			if err != nil {
				a.log.Error("start replica failed", "replica", id, "err", err)
				a.stopProbes(id)
				report.Replicas = append(report.Replicas, &armadav1.ReplicaState{Id: id, State: store.ReplicaFailed, Message: err.Error()})
				continue
			}
		}
		report.Replicas = append(report.Replicas, a.state(ctx, spec, c))
	}
	a.cleanSecretFiles(desired)
	a.mu.Lock()
	for id := range a.probes {
		if _, ok := desired[id]; !ok {
			a.probes[id].cancel()
			delete(a.probes, id)
		}
	}
	for id := range a.notes {
		if _, ok := desired[id]; !ok {
			delete(a.notes, id)
		}
	}
	for id := range a.crashes {
		if _, ok := desired[id]; !ok {
			delete(a.crashes, id)
		}
	}
	a.mu.Unlock()
	a.applyProxy(ctx)
	return report, nil
}

// crashLoop tracks how often a replica's container stopped.
type crashLoop struct {
	count int
	last  time.Time // last recreate
	next  time.Time // earliest time to recreate it again
}

func stopped(state string) bool {
	switch state {
	case runtime.StateExited, runtime.StateDead, runtime.StateCreated:
		return true
	}
	return false
}

// crashed describes why c stopped and returns how long to wait before
// recreating it (zero: now). Each recreate doubles the next delay.
func (a *Agent) crashed(ctx context.Context, replica string, c runtime.Container) (string, time.Duration) {
	msg := "container " + c.State
	// Listing does not include the exit code.
	if full, err := a.cfg.Driver.Inspect(ctx, c.ID); err == nil && full.State != runtime.StateCreated {
		msg = "exited with code " + strconv.Itoa(full.ExitCode)
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	cl := a.crashes[replica]
	if wait := cl.next.Sub(now); wait > 0 {
		return msg, wait
	}
	if now.Sub(cl.last) > crashReset {
		cl.count = 0
	}
	delay := a.crashBase << min(cl.count, 20)
	cl.count++
	cl.last = now
	cl.next = now.Add(min(delay, maxCrashBackoff))
	a.crashes[replica] = cl
	return msg, 0
}

func (a *Agent) stopProbes(replica string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if w := a.probes[replica]; w != nil {
		w.cancel()
		delete(a.probes, replica)
	}
}

// readiness makes sure the probes of c are running and returns their
// verdict. Probes only start once the container runs.
func (a *Agent) readiness(ctx context.Context, s *armadav1.ReplicaSpec, c runtime.Container) (bool, string) {
	if c.State != runtime.StateRunning {
		return false, ""
	}
	a.mu.Lock()
	w := a.probes[s.GetId()]
	if w != nil && w.containerID != c.ID {
		w.cancel()
		w = nil
	}
	if w == nil {
		w = a.startProbes(ctx, s, c, a.notes[s.GetId()])
		a.probes[s.GetId()] = w
	}
	a.mu.Unlock()
	return w.status()
}

// applyProxy hands the latest ingress configuration to the proxy driver. A
// failure is logged and retried on the next reconcile; the proxy keeps
// serving its previous configuration meanwhile. An unchanged configuration
// is applied again when the proxy is not healthy, which starts it if it
// stopped. The config holds TLS private keys, so it is never logged.
func (a *Agent) applyProxy(ctx context.Context) {
	if a.cfg.Proxy == nil {
		return
	}
	a.mu.Lock()
	want, have := a.proxyDesired, a.proxyApplied
	a.mu.Unlock()
	if want == nil {
		return
	}
	if proto.Equal(want, have) {
		err := a.cfg.Proxy.Health(ctx)
		if err == nil {
			return
		}
		a.log.Warn("proxy unhealthy, applying its configuration again", "err", err)
	}
	cfg := proxy.FromProto(want)
	if err := a.cfg.Proxy.Apply(ctx, cfg); err != nil {
		a.log.Error("applying proxy config failed", "err", err)
		return
	}
	if a.cfg.DNS != nil {
		// Resolve exactly the names HAProxy now routes.
		var apps []string
		for _, r := range cfg.Rules {
			if r.Internal && !slices.Contains(apps, r.Backend) {
				apps = append(apps, r.Backend)
			}
		}
		a.cfg.DNS.SetNames(apps)
	}
	a.mu.Lock()
	a.proxyApplied = want
	a.mu.Unlock()
}

func (a *Agent) remove(ctx context.Context, id string) {
	if err := a.cfg.Driver.Stop(ctx, id, stopGrace); err != nil && !errors.Is(err, runtime.ErrNotFound) {
		a.log.Warn("stop failed", "container", id, "err", err)
	}
	if err := a.cfg.Driver.Remove(ctx, id); err != nil && !errors.Is(err, runtime.ErrNotFound) {
		a.log.Warn("remove failed", "container", id, "err", err)
	}
}

func (a *Agent) start(ctx context.Context, s *armadav1.ReplicaSpec, hash string) (runtime.Container, error) {
	pinned, err := a.cfg.Driver.Pull(ctx, s.GetImage(), registryAuth(s))
	if err != nil {
		return runtime.Container{}, err
	}
	if pinned != "" {
		a.mu.Lock()
		a.digests[s.GetImage()] = pinned
		a.mu.Unlock()
	}
	cs := ContainerSpec(s, a.cfg.PrivateIP, hash)
	if a.cfg.DNS != nil {
		// Not part of the spec hash: enabling internal DNS must not restart
		// running replicas; they pick it up on their next replacement.
		cs.DNS = []string{a.cfg.DNS.Address()}
	}
	if cs.Files, err = a.writeSecretFiles(s); err != nil {
		return runtime.Container{}, err
	}
	id, err := a.cfg.Driver.Run(ctx, cs)
	if err != nil {
		return runtime.Container{}, err
	}
	return a.cfg.Driver.Inspect(ctx, id)
}

func (a *Agent) state(ctx context.Context, s *armadav1.ReplicaSpec, c runtime.Container) *armadav1.ReplicaState {
	st := &armadav1.ReplicaState{Id: s.GetId(), ContainerId: c.ID}
	a.mu.Lock()
	st.ImageDigest = a.digests[s.GetImage()]
	a.mu.Unlock()
	switch c.State {
	case runtime.StateRunning:
		st.State = store.ReplicaRunning
		st.Ready, st.Message = a.readiness(ctx, s, c)
		if st.Ready {
			a.mu.Lock()
			delete(a.notes, s.GetId())
			a.mu.Unlock()
		}
	case runtime.StateCreated, runtime.StateRestarting:
		st.State = store.ReplicaStarting
	default:
		st.State = store.ReplicaExited
		st.Message = "exit code " + strconv.Itoa(c.ExitCode)
	}
	if c.HostPort != 0 {
		st.Address = net.JoinHostPort(c.HostIP, strconv.Itoa(c.HostPort))
	}
	return st
}

// ContainerSpec converts a replica assignment into a container spec.
func ContainerSpec(s *armadav1.ReplicaSpec, hostIP, hash string) runtime.ContainerSpec {
	env := make([]string, 0, len(s.GetEnv()))
	for _, e := range s.GetEnv() {
		env = append(env, e.GetName()+"="+e.GetValue())
	}
	return runtime.ContainerSpec{
		Name:       "armada-" + s.GetId(),
		Image:      s.GetImage(),
		Entrypoint: s.GetCommand(),
		Cmd:        s.GetArgs(),
		Env:        env,
		Labels: map[string]string{
			runtime.LabelManaged:  "true",
			runtime.LabelApp:      s.GetApp(),
			runtime.LabelRevision: s.GetRevision(),
			runtime.LabelReplica:  s.GetId(),
			runtime.LabelSpecHash: hash,
		},
		Port:        int(s.GetPort()),
		HostIP:      hostIP,
		MemoryBytes: s.GetMemoryBytes(),
		NanoCPUs:    s.GetNanoCpus(),
		PidsLimit:   s.GetPidsLimit(),
	}
}

// specHash fingerprints everything about a replica except its image: a
// replica belongs to one immutable revision, and the server swaps the tag
// for the pinned digest after the first pull, which must not trigger a
// restart. Secret values are replaced by their pinned version reference, so
// the hash (stored in a container label) reveals nothing about them.
func specHash(s *armadav1.ReplicaSpec) string {
	c := proto.Clone(s).(*armadav1.ReplicaSpec)
	c.Image = ""
	for _, e := range c.Env {
		if e.Ref != "" {
			e.Value = ""
		}
	}
	for _, f := range c.SecretFiles {
		f.Data = nil
	}
	if c.Registry != nil {
		c.Registry.Password = ""
	}
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

func (a *Agent) serveLogs(ctx context.Context, req *armadav1.LogRequest) {
	ctx, cancel := context.WithCancel(ctx)
	a.mu.Lock()
	a.cancels[req.GetRequestId()] = cancel
	a.mu.Unlock()
	defer func() {
		cancel()
		a.mu.Lock()
		delete(a.cancels, req.GetRequestId())
		a.mu.Unlock()
	}()

	push, err := a.cfg.Client.PushLogs(ctx)
	if err != nil {
		a.log.Warn("open log stream failed", "err", err)
		return
	}
	finish := func(msg string) {
		if msg != "" {
			_ = push.Send(&armadav1.LogPush{RequestId: req.GetRequestId(), Error: msg})
		}
		_, _ = push.CloseAndRecv()
	}

	cs, err := a.cfg.Driver.List(ctx, map[string]string{runtime.LabelManaged: "true", runtime.LabelReplica: req.GetReplicaId()})
	if err != nil || len(cs) == 0 {
		finish("replica " + req.GetReplicaId() + " has no container on this node")
		return
	}
	ls, err := a.cfg.Driver.Logs(ctx, cs[0].ID, runtime.LogOptions{Follow: req.GetFollow(), Tail: int(req.GetTail())})
	if err != nil {
		finish(err.Error())
		return
	}
	defer ls.Close()
	for {
		f, err := ls.Next()
		if errors.Is(err, io.EOF) || ctx.Err() != nil {
			finish("")
			return
		}
		if err != nil {
			finish(err.Error())
			return
		}
		stream := armadav1.Stream_STREAM_STDOUT
		if f.Stream == runtime.Stderr {
			stream = armadav1.Stream_STREAM_STDERR
		}
		if err := push.Send(&armadav1.LogPush{RequestId: req.GetRequestId(), Stream: stream, Data: f.Data}); err != nil {
			return
		}
	}
}

func (a *Agent) cancelLogs(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.cancels[id]; ok {
		c()
	}
}
