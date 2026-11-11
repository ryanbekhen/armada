// Package agent runs on every node: it receives the desired set of replicas
// from the server and reconciles local containers against it.
package agent

import (
	"maps"
	"net/netip"
	"strings"

	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	goruntime "runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ryanbekhen/armada/internal/spec"

	"golang.org/x/sync/singleflight"
	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/conntrack"
	"github.com/ryanbekhen/armada/internal/proxy"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/version"
	"github.com/ryanbekhen/armada/internal/volbackup"
)

const (
	defaultResync = 10 * time.Second
	// maxConcurrentStarts bounds the replicas a node starts at a time.
	maxConcurrentStarts = 8
	// startReportInterval is how often the server hears from an agent that
	// is busy starting replicas.
	startReportInterval = time.Second
	stopGrace           = 10 * time.Second
	maxBackoff          = 30 * time.Second
	// reconnectDelay is the pause after a session the server had accepted.
	reconnectDelay = 100 * time.Millisecond

	// Stopped containers are recreated with exponential backoff, like a
	// crash loop: crashBackoff, doubling up to maxCrashBackoff. The count
	// resets after crashReset without a crash.
	crashBackoff    = time.Second
	maxCrashBackoff = 5 * time.Minute
	crashReset      = 10 * time.Minute

	// Images no container uses and no replica of the node's assignment
	// names are removed every defaultImagePrune, once pulled more than
	// imagePruneGrace ago (pulls outside a reconcile, such as the proxy's,
	// are that recent).
	defaultImagePrune = 10 * time.Minute
	imagePruneGrace   = time.Hour
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
	// UsageInterval is how often replicas are sampled for armada app top
	// (default 10s, ADR 0016).
	UsageInterval time.Duration
	// QueueInterval is how often queue rules' commands run (default 15s,
	// ADR 0034).
	QueueInterval time.Duration
	// SandboxInterval, if set, reads every job queue that often instead of
	// its trigger's polling interval (tests; ADR 0040).
	SandboxInterval time.Duration
	// ImagePrune is how often unused images are removed (default 10m,
	// negative turns it off).
	ImagePrune time.Duration

	// Conntrack is the node's connection tracking table, raised and reported
	// with each sample; nil leaves it alone (ADR 0025).
	Conntrack *conntrack.Table
	// VolumeInterval is how often volumes are measured (default 1m, ADR
	// 0023).
	VolumeInterval time.Duration
	// NFSDir holds the mount points of NFS volumes (ADR 0042); empty
	// disables them.
	NFSDir string
	// MountNFS mounts an export (tests); nil: the kernel's NFSv4 client.
	MountNFS func(ctx context.Context, server, export, target string, readOnly bool) error
	// Buckets opens a volume's backup bucket (ADR 0041); nil: S3.
	Buckets func(volbackup.Target) (volbackup.Objects, error)
	// WakeSocket is where the proxy sends requests for apps with no replica
	// up (ADR 0021); empty disables it. It must be in a directory only root
	// can reach.
	WakeSocket string
	// Capacity reported to the scheduler; zero values are auto-detected.
	CPUMillis   int64
	MemoryBytes int64
	// Proxy applies the ingress configuration; nil disables ingress on this
	// node.
	Proxy proxy.Driver
	// Network applies the cluster network (ADR 0025); nil when the node is
	// not part of one. NetworkKey is the node's public key, announced in
	// Hello.
	Network    Network
	NetworkKey string
	// Unpublished makes replicas publish no port: the cluster network
	// routes their own addresses, in the node's subnet, to every node, and
	// replicas are reported at <container IP>:<port> (ADR 0025).
	Unpublished bool
	// Check runs health checks (default DefaultCheck).
	Check CheckFunc
	// VolumesDir holds persistent volumes (ADR 0023); empty: the node
	// mounts none.
	VolumesDir string
	// SecretsDir is a private directory on tmpfs for secret files. Empty
	// means replicas with secret files fail to start on this node.
	SecretsDir string
	// DNS is the node-local resolver for <app>.internal; nil leaves
	// containers with the engine's default DNS.
	DNS InternalDNS
	// OS and Arch are the platform containers run on, reported as the
	// armada.os and armada.arch labels (default: the agent's own).
	OS, Arch string
	// Servers are the control plane addresses the agent started with;
	// OnServers receives them whenever the server sends a different list.
	Servers   []string
	OnServers func(servers []string)
}

// Network sets up the cluster network on the node (ADR 0025).
type Network interface {
	// Apply makes the node's tunnel, routes, and firewall rules match cfg.
	// It is called again whenever cfg changes and on every resync, so it
	// must be idempotent and repair what drifted.
	// local maps the addresses of this node's containers to their app
	// IDs; it is newer than the endpoints in cfg, which come back from the
	// control plane only after the agent reports them (nil on nodes whose
	// containers are not in the node subnet).
	Apply(ctx context.Context, cfg *armadav1.NetworkConfig, local map[netip.Addr]string) error
}

// InternalDNS is the node-local resolver the agent keeps in sync with the
// proxy's internal routes.
type InternalDNS interface {
	// Address is the nameserver containers are given.
	Address() string
	// SetNames replaces the apps that resolve under .internal.
	SetNames(apps []string)
	// SetClients maps the addresses of this node's containers to their app
	// IDs, so that each resolves only its own project's names (ADR 0026).
	SetClients(clients map[netip.Addr]string)
}

// Agent reconciles containers on one node.
type Agent struct {
	cfg   Config
	log   *slog.Logger
	began time.Time

	mu        sync.Mutex
	desired   map[string]*armadav1.ReplicaSpec // nil until the first assignment
	servers   []string                         // last control plane list received
	digests   map[string]string                // image ref -> pinned ref
	platforms map[string][]string              // image ref -> its platforms
	cancels   map[string]context.CancelFunc    // log request -> cancel
	probes    map[string]*probeWorker          // replica -> probes of its container
	// restarts holds containers a failed probe asked to restart, with the
	// reason; notes carries that reason to the replacement's status.
	restarts map[string]string // container ID -> reason
	queues   queueLengths
	// sb holds the network sandboxes job queues are read from (ADR 0040).
	sb      sandboxes
	notes   map[string]string // replica -> message
	crashes map[string]crashLoop
	// holds holds the image pulls of held replicas (ADR 0023).
	holds map[string]*heldPull
	// contactUp is whether a session with the server is open, contactLost
	// when the last one ended; fencedIDs are containers stopped for being
	// cut off (ADR 0041).
	contactUp   bool
	contactLost time.Time
	fencedIDs   map[string]bool
	// crashBase is the first recreate delay (crashBackoff; shorter in tests).
	crashBase time.Duration

	proxyDesired *armadav1.ProxyConfig
	proxyApplied *armadav1.ProxyConfig
	// certs holds the proxy certificates fetched by reference, by name;
	// only applyProxy uses it.
	certs map[string]cachedCert
	// networkDesired is the last cluster network received; networkFailed
	// holds the last error applying it, logged once per change.
	networkDesired *armadav1.NetworkConfig
	networkFailed  string
	// local maps the addresses of this node's containers in the node
	// subnet to their app IDs (Config.Unpublished only).
	local map[netip.Addr]string
	// proxyChanged is closed and replaced when proxyApplied changes.
	proxyChanged chan struct{}
	wakes        *waker

	trigger chan struct{}

	streamMu sync.Mutex
	stream   armadav1.AgentService_ConnectClient
	lastSent *armadav1.ReplicaReport

	// volumeOps counts running volume sessions (maxVolumeSessions).
	volumeOps atomic.Int32
	// paused holds apps whose containers stay stopped for a volume
	// operation (ADR 0023).
	paused map[string]int
	// reconcileMu keeps pause from racing a Reconcile that starts the app.
	reconcileMu sync.Mutex
	// repos keeps one backup operation per volume at a time (ADR 0041).
	repos keyedMutex
	// nfsMounts keeps one mount or unmount per NFS volume at a time.
	nfsMounts keyedMutex
	// execs counts running exec sessions (maxExecSessions).
	execs atomic.Int32
}

// New returns an Agent.
func New(cfg Config) *Agent {
	if cfg.Resync == 0 {
		cfg.Resync = defaultResync
	}
	if cfg.UsageInterval == 0 {
		cfg.UsageInterval = defaultUsageInterval
	}
	if cfg.QueueInterval == 0 {
		cfg.QueueInterval = defaultQueueInterval
	}
	if cfg.ImagePrune == 0 {
		cfg.ImagePrune = defaultImagePrune
	}
	if cfg.VolumeInterval == 0 {
		cfg.VolumeInterval = volumeMeasureEvery
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
		began:     time.Now(),
		cfg:       cfg,
		servers:   slices.Clone(cfg.Servers),
		log:       cfg.Logger.With("component", "agent", "node", cfg.NodeID),
		digests:   map[string]string{},
		platforms: map[string][]string{},
		cancels:   map[string]context.CancelFunc{},
		probes:    map[string]*probeWorker{},
		restarts:  map[string]string{},
		notes:     map[string]string{},
		crashes:   map[string]crashLoop{},
		holds:     map[string]*heldPull{},
		fencedIDs: map[string]bool{},
		paused:    map[string]int{},
		trigger:   make(chan struct{}, 1),

		crashBase: crashBackoff,

		proxyChanged: make(chan struct{}),
		wakes:        newWaker(),
		sb:           sandboxes{have: map[string]*sandboxState{}, kick: make(chan struct{}, 1)},
	}
}

// Run connects to the server and reconciles until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.cfg.Driver.Ping(ctx); err != nil {
		return fmt.Errorf("container runtime: %w", err)
	}
	go a.reconcileLoop(ctx)
	go a.usageLoop(ctx)
	go a.queueLoop(ctx)
	go a.sandboxLoop(ctx)
	if a.cfg.WakeSocket != "" {
		go a.serveWake(ctx)
	}

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
		Os: cmp.Or(a.cfg.OS, goruntime.GOOS), Arch: cmp.Or(a.cfg.Arch, goruntime.GOARCH),
		Jobs: true, Volumes: a.mountsVolumes(), Containers: runtime.CanRunMembers(a.cfg.Driver), NetworkKey: a.cfg.NetworkKey,
		CertificateRefs: true, QueueSandboxes: a.sandboxesOn(), HeldReplicas: true,
		VolumeBackups: a.mountsVolumes(), Nfs: a.mountsNFS(),
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
			a.setContact(true)
			defer a.setContact(false)
			a.log.Info("connected to server")
		}
		switch m := msg.Msg.(type) {
		case *armadav1.ServerMessage_Assignment:
			a.setNetwork(m.Assignment.GetNetwork())
			a.setDesired(m.Assignment.GetReplicas(), m.Assignment.GetProxy())
			a.setServers(m.Assignment.GetServers())
			if a.sandboxesOn() {
				a.setSandboxes(m.Assignment.GetQueueSandboxes())
			}
		case *armadav1.ServerMessage_LogRequest:
			go a.serveLogs(ctx, m.LogRequest)
		case *armadav1.ServerMessage_LogCancel:
			a.cancelLogs(m.LogCancel.GetRequestId())
		case *armadav1.ServerMessage_ExecRequest:
			go a.serveExec(ctx, m.ExecRequest)
		case *armadav1.ServerMessage_VolumeRequest:
			go a.serveVolume(ctx, m.VolumeRequest)
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
	lastPrune := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.trigger:
		}
		a.fenceUnassigned(ctx)
		report, err := a.Reconcile(ctx)
		if err != nil {
			a.log.Error("reconcile failed", "err", err)
			continue
		}
		if report != nil {
			a.sendReport(report)
		}
		if a.cfg.ImagePrune > 0 && time.Since(lastPrune) >= a.cfg.ImagePrune {
			lastPrune = time.Now()
			a.PruneImages(ctx)
		}
	}
}

// PruneImages removes images that neither a container nor a replica of
// the node's assignment needs. It holds reconcileMu, so no replica starts
// meanwhile, and does nothing before the first assignment.
func (a *Agent) PruneImages(ctx context.Context) {
	p, ok := a.cfg.Driver.(runtime.ImagePruner)
	if !ok {
		return
	}
	a.reconcileMu.Lock()
	defer a.reconcileMu.Unlock()
	a.mu.Lock()
	if a.desired == nil {
		a.mu.Unlock()
		return
	}
	var keep []string
	for _, s := range a.desired {
		for _, image := range append([]string{s.GetImage()}, memberImages(s)...) {
			keep = append(keep, image)
			if ref := a.digests[image]; ref != "" {
				keep = append(keep, ref)
			}
		}
	}
	a.mu.Unlock()
	removed, err := p.PruneImages(ctx, keep, imagePruneGrace)
	if len(removed) > 0 {
		a.log.Info("removed unused images", "images", removed)
	}
	if err != nil {
		a.log.Warn("remove unused images", "err", err)
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
	a.reconcileMu.Lock()
	defer a.reconcileMu.Unlock()
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
		// An init container or sidecar listed by itself has lost its
		// replica's container (ADR 0038): it is removed like a stray.
		if !want || dup || c.Labels[runtime.LabelRole] != "" {
			a.log.Info("removing container", "container", c.Name, "replica", id)
			a.remove(ctx, c.ID)
			continue
		}
		byReplica[id] = c
	}

	// Replicas in a state of their own, those whose container exists, and
	// those to start: starts run at once after this loop, which itself never
	// waits on an image or a container being created.
	var settled []*armadav1.ReplicaState
	var running []runningReplica
	var pending []pendingStart
	for _, id := range sortedKeys(desired) {
		spec := desired[id]
		hash := specHash(spec)
		c, ok := byReplica[id]
		if ok && c.Labels[runtime.LabelSpecHash] != hash {
			a.log.Info("spec changed, recreating", "replica", id)
			a.remove(ctx, c.ID)
			ok = false
		}
		if a.fenced(spec) {
			// Cut off from the control plane: its volumes may be restored
			// on another node, so it must not write them here (ADR 0041).
			if ok && !stopped(c.State) {
				a.log.Warn("stopping a replica cut off from the control plane", "replica", id)
				_ = a.cfg.Driver.Stop(ctx, c.ID, volumeStopGrace)
			}
			if ok {
				a.markFenced(c.ID)
			}
			a.stopProbes(id)
			settled = append(settled, &armadav1.ReplicaState{Id: id, State: store.ReplicaExited, ContainerId: c.ID, Message: fencedMessage})
			continue
		}
		if ok && stopped(c.State) && a.unfence(c.ID) {
			// Back in touch: start it again at once.
			a.remove(ctx, c.ID)
			ok = false
		}
		if a.isPaused(spec.GetApp()) && spec.GetJob() == nil {
			// A volume backup or restore runs (ADR 0023).
			if ok && !stopped(c.State) {
				_ = a.cfg.Driver.Stop(ctx, c.ID, volumeStopGrace)
			}
			a.stopProbes(id)
			settled = append(settled, &armadav1.ReplicaState{Id: id, State: store.ReplicaExited, ContainerId: c.ID, Message: pausedMessage})
			continue
		}
		if spec.GetHold() {
			// Its volume is still in use by the old replica: pull, start
			// nothing (ADR 0023).
			if ok {
				a.log.Info("removing container of a held replica", "replica", id)
				a.remove(ctx, c.ID)
			}
			a.stopProbes(id)
			settled = append(settled, a.held(ctx, spec))
			continue
		}
		if spec.GetJob() != nil {
			a.mu.Lock()
			delete(a.restarts, c.ID) // an attempt runs once, whatever happens
			a.mu.Unlock()
			if st := a.attempt(ctx, spec, hash, c, ok); st != nil {
				settled = append(settled, st)
			}
			continue
		}
		if ok {
			a.mu.Lock()
			reason, restart := a.restarts[c.ID]
			delete(a.restarts, c.ID)
			if restart {
				a.notes[id] = store.RestartNote + reason
			}
			a.mu.Unlock()
			if restart {
				a.remove(ctx, c.ID)
				ok = false
			}
		}
		if ok && (stopped(c.State) || memberDown(spec, c) != "") {
			// The runtime restarts nothing itself (ADR 0011): a crashed
			// container, one left exited by a reboot, or a failed start is
			// recreated here with crash backoff. So is a replica whose init
			// container failed or whose sidecar stopped, with all of its
			// containers (ADR 0038).
			msg, wait := a.crashed(ctx, spec, c)
			if wait > 0 {
				settled = append(settled, &armadav1.ReplicaState{
					Id: id, State: store.ReplicaExited, ContainerId: c.ID,
					Message: fmt.Sprintf("%s; restarting in %s", msg, wait.Round(time.Second)),
				})
				continue
			}
			a.log.Warn("container stopped, recreating", "replica", id, "reason", msg)
			a.mu.Lock()
			a.notes[id] = store.RestartNote + msg
			a.mu.Unlock()
			a.remove(ctx, c.ID)
			ok = false
		}
		if !ok {
			pending = append(pending, pendingStart{id: id, spec: spec, hash: hash})
			continue
		}
		running = append(running, runningReplica{spec: spec, container: c})
	}
	report := a.startPending(ctx, pending, settled, running)
	a.forgetHolds(desired)
	a.cleanSecretFiles(desired)
	a.cleanNFS(desired)
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
	a.applyNetwork(ctx)
	a.applyProxy(ctx)
	return report, nil
}

// pendingStart is a replica Reconcile has to create a container for.
type pendingStart struct {
	id   string
	spec *armadav1.ReplicaSpec
	hash string
}

// runningReplica is a replica with a container, whatever its state.
type runningReplica struct {
	spec      *armadav1.ReplicaSpec
	container runtime.Container
}

// startPending starts replicas, at most maxConcurrentStarts at a time, and
// returns the status of every replica. A start can take long, as long as a
// large image takes to pull, and the replicas that already run must not
// wait for it: the server only keeps a replica in the proxies while it
// hears it is ready. So while starts run this keeps telling the server what
// it knows, tells the firewall about new containers before the server hears
// of them, and applies proxy changes. A replica still starting is left out
// of the reports, and keeps the status the server has.
func (a *Agent) startPending(ctx context.Context, pending []pendingStart, settled []*armadav1.ReplicaState, running []runningReplica) *armadav1.ReplicaReport {
	build := func() *armadav1.ReplicaReport {
		r := &armadav1.ReplicaReport{Replicas: slices.Clone(settled)}
		for _, x := range running {
			// In this order: a verdict seen here is one state reports.
			a.readiness(ctx, x.spec, x.container)
			if !a.awaitsVerdict(x.spec, x.container) {
				r.Replicas = append(r.Replicas, a.state(ctx, x.spec, x.container))
			}
		}
		slices.SortFunc(r.Replicas, func(x, y *armadav1.ReplicaState) int { return cmp.Compare(x.GetId(), y.GetId()) })
		return r
	}
	if len(pending) == 0 {
		return build()
	}

	type result struct {
		start     pendingStart
		container runtime.Container
		err       error
	}
	results := make(chan result, len(pending))
	pull := newPullOnce(a.cfg.Driver)
	limit := make(chan struct{}, maxConcurrentStarts)
	go func() {
		for _, p := range pending {
			limit <- struct{}{}
			go func() {
				defer func() { <-limit }()
				c, err := a.start(ctx, p.spec, p.hash, pull.pull)
				results <- result{start: p, container: c, err: err}
			}()
		}
	}()

	var finished []result
	// absorb makes finished starts part of what is reported, once the
	// firewall knows their containers.
	absorb := func() {
		if len(finished) == 0 {
			return
		}
		if a.cfg.Unpublished && a.cfg.Network != nil {
			a.applyNetworkNow(ctx)
		}
		for _, f := range finished {
			if f.err == nil {
				running = append(running, runningReplica{spec: f.start.spec, container: f.container})
				continue
			}
			a.log.Error("start replica failed", "replica", f.start.id, "err", f.err)
			a.stopProbes(f.start.id)
			failed := &armadav1.ReplicaState{Id: f.start.id, State: store.ReplicaFailed, Message: f.err.Error()}
			// The server learns where the image can run instead.
			if pe := (*runtime.PlatformError)(nil); errors.As(f.err, &pe) {
				failed.ImagePlatforms = pe.Have
			}
			settled = append(settled, failed)
		}
		finished = nil
	}

	a.sendReport(build())
	t := time.NewTicker(startReportInterval)
	defer t.Stop()
	for left := len(pending); left > 0; {
		select {
		case r := <-results:
			finished = append(finished, r)
			left--
		case <-t.C:
			absorb()
			a.applyProxy(ctx)
			a.sendReport(build())
		}
	}
	absorb()
	return build()
}

// pullOnce pulls each image once, for the replicas starting together: they
// share the answer of the registry, or its failure. Replicas with other
// credentials ask for themselves, so an image is never handed to a replica
// on the strength of another's credentials. It lasts for one set of starts,
// so a tag is still resolved anew by a later deploy.
type pullOnce struct {
	driver runtime.Driver
	flight singleflight.Group
}

func newPullOnce(d runtime.Driver) *pullOnce { return &pullOnce{driver: d} }

func (p *pullOnce) pull(ctx context.Context, image string, auth *runtime.RegistryAuth) (runtime.Image, error) {
	h := sha256.New()
	key := []string{image}
	if auth != nil {
		key = append(key, auth.Username, auth.Password, auth.ServerAddress)
	}
	for _, v := range key {
		_, _ = fmt.Fprintf(h, "%d:%s", len(v), v)
	}
	v, err, _ := p.flight.Do(hex.EncodeToString(h.Sum(nil)), func() (any, error) {
		return p.driver.Pull(ctx, image, auth)
	})
	if err != nil {
		return runtime.Image{}, err
	}
	return v.(runtime.Image), nil
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

// outOfMemory reports whether the kernel killed a process of a stopped
// container at its memory limit.
func (a *Agent) outOfMemory(ctx context.Context, id string) bool {
	sr, ok := a.cfg.Driver.(runtime.StatsReader)
	if !ok || !runtime.CanStats(a.cfg.Driver) {
		return false
	}
	st, err := sr.Stats(ctx, id)
	return err == nil && st.OOMKills > 0
}

// crashed describes why c stopped and returns how long to wait before
// recreating it (zero: now). Each recreate doubles the next delay.
func (a *Agent) crashed(ctx context.Context, s *armadav1.ReplicaSpec, c runtime.Container) (string, time.Duration) {
	replica := s.GetId()
	msg := "container " + c.State
	// Listing does not include the exit code.
	if down := memberDown(s, c); down != "" {
		msg = down
	} else if full, err := a.cfg.Driver.Inspect(ctx, c.ID); err == nil && full.State != runtime.StateCreated {
		msg = "exited with code " + strconv.Itoa(full.ExitCode)
		if a.outOfMemory(ctx, c.ID) {
			msg = "out of memory at its limit, " + msg
		}
	}
	return msg, a.backoff(replica)
}

// backoff returns how long to wait before recreating replica's container
// (zero: now, which counts as a recreate). Each recreate doubles the next
// delay.
func (a *Agent) backoff(replica string) time.Duration {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	cl := a.crashes[replica]
	if wait := cl.next.Sub(now); wait > 0 {
		return wait
	}
	if now.Sub(cl.last) > crashReset {
		cl.count = 0
	}
	delay := a.crashBase << min(cl.count, 20)
	cl.count++
	cl.last = now
	cl.next = now.Add(min(delay, maxCrashBackoff))
	a.crashes[replica] = cl
	return 0
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

// awaitsVerdict reports whether c was already running when this agent started
// and its probes have not said anything yet. The agent knows nothing about it
// then, but the server does: saying "not ready" would take a container that is
// serving out of every proxy each time an agent restarts. It is left out of
// the reports, and keeps the status the server has, until the first verdict.
func (a *Agent) awaitsVerdict(s *armadav1.ReplicaSpec, c runtime.Container) bool {
	if c.State != runtime.StateRunning || c.StartedAt.IsZero() || !c.StartedAt.Before(a.began) {
		return false
	}
	a.mu.Lock()
	w := a.probes[s.GetId()]
	a.mu.Unlock()
	return w != nil && !w.hasVerdict()
}

// applyProxy hands the latest ingress configuration to the proxy driver. A
// failure is logged and retried on the next reconcile; the proxy keeps
// serving its previous configuration meanwhile. An unchanged configuration
// is applied again when the proxy is not healthy, which starts it if it
// stopped. The config holds TLS private keys, so it is never logged.
func (a *Agent) setNetwork(cfg *armadav1.NetworkConfig) {
	if cfg == nil {
		return
	}
	a.mu.Lock()
	a.networkDesired = cfg
	a.mu.Unlock()
}

// applyNetwork applies the cluster network before the proxy and the
// containers that use it. A failure leaves the node on the network it has
// and is retried on the next pass.
func (a *Agent) applyNetwork(ctx context.Context) {
	if a.cfg.Network == nil {
		return
	}
	if a.cfg.Unpublished {
		if local, err := a.listLocal(ctx); err == nil {
			a.mu.Lock()
			a.local = local
			a.mu.Unlock()
		}
	}
	a.applyNetworkNow(ctx)
}

// applyNetworkNow applies the last cluster network received with the
// containers known on this node, and tells the DNS server who asks.
func (a *Agent) applyNetworkNow(ctx context.Context) {
	a.mu.Lock()
	want := a.networkDesired
	var local map[netip.Addr]string
	if a.cfg.Unpublished {
		local = maps.Clone(a.local)
		if local == nil {
			local = map[netip.Addr]string{}
		}
	}
	a.mu.Unlock()
	if want == nil {
		return
	}
	if local != nil && a.cfg.DNS != nil {
		a.cfg.DNS.SetClients(local)
	}
	if cs, ok := a.cfg.Proxy.(proxy.ClientSetter); ok && local != nil {
		if err := cs.SetClients(ctx, local); err != nil {
			a.log.Warn("updating the proxy's callers failed", "err", err)
		}
	}
	err := a.cfg.Network.Apply(ctx, want, local)
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	a.mu.Lock()
	changed := msg != a.networkFailed
	a.networkFailed = msg
	a.mu.Unlock()
	switch {
	case err != nil && changed:
		a.log.Error("applying the cluster network failed", "err", err)
	case err == nil && changed:
		a.log.Info("cluster network applied again")
	}
}

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
	cfg, err := a.withCertificates(ctx, want)
	if err != nil {
		// Applied on a later pass: the last configuration keeps serving.
		a.log.Error("fetching proxy certificates failed", "err", err)
		return
	}
	if err := a.cfg.Proxy.Apply(ctx, cfg); err != nil {
		a.log.Error("applying proxy config failed", "err", err)
		return
	}
	if a.cfg.DNS != nil {
		// Resolve exactly the names HAProxy now routes.
		var apps []string
		for _, r := range cfg.Rules {
			name := strings.TrimSuffix(r.Host, spec.InternalSuffix)
			if r.Internal && !slices.Contains(apps, name) {
				apps = append(apps, name)
			}
		}
		// And the internal TCP apps (ADR 0039).
		for _, r := range cfg.TCP {
			if !slices.Contains(apps, r.Backend) {
				apps = append(apps, r.Backend)
			}
		}
		a.cfg.DNS.SetNames(apps)
	}
	a.mu.Lock()
	a.proxyApplied = want
	close(a.proxyChanged)
	a.proxyChanged = make(chan struct{})
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

// start pulls an image with pull and runs a replica's container. Starts may
// run at once. The caller applies the cluster network afterwards.
func (a *Agent) start(ctx context.Context, s *armadav1.ReplicaSpec, hash string, pull func(context.Context, string, *runtime.RegistryAuth) (runtime.Image, error)) (runtime.Container, error) {
	img, err := pull(ctx, s.GetImage(), registryAuth(s))
	if err != nil {
		return runtime.Container{}, err
	}
	a.mu.Lock()
	if img.Ref != "" {
		a.digests[s.GetImage()] = img.Ref
	}
	if len(img.Platforms) > 0 {
		a.platforms[s.GetImage()] = img.Platforms
	}
	a.mu.Unlock()
	if hasMembers(s) {
		if !runtime.CanRunMembers(a.cfg.Driver) {
			return runtime.Container{}, errors.New("this node's container runtime runs no init containers or sidecars")
		}
		if err := a.pullMembers(ctx, s, pull); err != nil {
			return runtime.Container{}, err
		}
	}
	cs := ContainerSpec(s, a.cfg.PrivateIP, hash)
	if a.cfg.Unpublished {
		// Not part of the spec hash either: replicas started with a port
		// keep it until they are replaced.
		cs.Port, cs.HostIP = 0, ""
	}
	if a.cfg.DNS != nil {
		// Not part of the spec hash: enabling internal DNS must not restart
		// running replicas; they pick it up on their next replacement.
		cs.DNS = []string{a.cfg.DNS.Address()}
	}
	if cs.Files, err = a.writeSecretFiles(s); err != nil {
		return runtime.Container{}, err
	}
	if cs.Volumes, err = a.prepareVolumes(s); err != nil {
		return runtime.Container{}, err
	}
	if err := withMemberMounts(s, &cs); err != nil {
		return runtime.Container{}, err
	}
	id, err := a.cfg.Driver.Run(ctx, cs)
	if err != nil {
		return runtime.Container{}, err
	}
	c, err := a.cfg.Driver.Inspect(ctx, id)
	if err == nil && a.cfg.Unpublished && a.cfg.Network != nil {
		// The firewall and the DNS server learn the new container before the
		// control plane hears of it: until then, it is treated as an unknown
		// address and reaches little.
		if ip, perr := netip.ParseAddr(c.IP); perr == nil {
			a.mu.Lock()
			if a.local == nil {
				a.local = map[netip.Addr]string{}
			}
			a.local[ip] = s.GetApp()
			a.mu.Unlock()
		}
	}
	return c, err
}

// listLocal maps the addresses of this node's running containers to their
// app IDs.
func (a *Agent) listLocal(ctx context.Context) (map[netip.Addr]string, error) {
	cs, err := a.cfg.Driver.List(ctx, map[string]string{runtime.LabelManaged: "true"})
	if err != nil {
		return nil, err
	}
	local := map[netip.Addr]string{}
	for _, c := range cs {
		ip, err := netip.ParseAddr(c.IP)
		app := c.Labels[runtime.LabelApp]
		if err != nil || app == "" || stopped(c.State) {
			continue
		}
		local[ip] = app
	}
	a.localSandboxes(ctx, local)
	return local, nil
}

func (a *Agent) state(ctx context.Context, s *armadav1.ReplicaSpec, c runtime.Container) *armadav1.ReplicaState {
	st := &armadav1.ReplicaState{Id: s.GetId(), ContainerId: c.ID}
	a.mu.Lock()
	st.ImageDigest = a.digests[s.GetImage()]
	st.ImagePlatforms = a.platforms[s.GetImage()]
	a.mu.Unlock()
	switch c.State {
	case runtime.StateRunning:
		st.State = store.ReplicaRunning
		st.Ready, st.Message = a.readiness(ctx, s, c)
		if st.Ready {
			// This report carries the restart note, if any; later ones
			// do not.
			a.mu.Lock()
			delete(a.notes, s.GetId())
			if w := a.probes[s.GetId()]; w != nil {
				w.clearNote()
			}
			a.mu.Unlock()
		}
	case runtime.StateCreated, runtime.StateRestarting, runtime.StateStarting:
		st.State = store.ReplicaStarting
		if c.State == runtime.StateStarting {
			st.Message = "starting its init containers and sidecars"
		}
	default:
		st.State = store.ReplicaExited
		st.Message = "exit code " + strconv.Itoa(c.ExitCode)
		if down := memberDown(s, c); down != "" {
			st.Message = down
		}
	}
	switch {
	case c.HostPort != 0:
		st.Address = net.JoinHostPort(c.HostIP, strconv.Itoa(c.HostPort))
	case a.cfg.Unpublished && c.IP != "" && s.GetPort() != 0:
		st.Address = net.JoinHostPort(c.IP, strconv.Itoa(int(s.GetPort())))
	}
	if a.cfg.Unpublished {
		st.Ip = c.IP
	}
	return st
}

// ContainerSpec converts a replica assignment into a container spec.
func ContainerSpec(s *armadav1.ReplicaSpec, hostIP, hash string) runtime.ContainerSpec {
	env := make([]string, 0, len(s.GetEnv()))
	for _, e := range s.GetEnv() {
		env = append(env, e.GetName()+"="+e.GetValue())
	}
	cs := runtime.ContainerSpec{
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
		Port:             int(s.GetPort()),
		HostIP:           hostIP,
		MemoryBytes:      s.GetMemoryBytes(),
		NanoCPUs:         s.GetNanoCpus(),
		CPUReserveMillis: s.GetCpuReserveMillis(),
		PidsLimit:        s.GetPidsLimit(),
		Init:             memberSpecs(s.GetInitContainers()),
		Sidecars:         memberSpecs(s.GetSidecars()),
	}
	if n := s.GetFenceAfterSeconds(); n > 0 {
		cs.Labels[runtime.LabelFenceAfter] = strconv.FormatInt(n, 10)
	}
	return cs
}

// specHash fingerprints everything about a replica except its image: a
// replica belongs to one immutable revision, and the server swaps the tag
// for the pinned digest after the first pull, which must not trigger a
// restart. Secret values are replaced by their pinned version reference, so
// the hash (stored in a container label) reveals nothing about them.
func specHash(s *armadav1.ReplicaSpec) string {
	c := proto.Clone(s).(*armadav1.ReplicaSpec)
	c.Image = ""
	// Added after replicas existed, and fixed for a revision: hashing it
	// would recreate every replica, undrained, when the server is upgraded.
	c.CpuReserveMillis = 0
	// Queue rules are read by the queue loop, not the container.
	c.Queues = nil
	// Holding and fencing decide whether it runs, not how (ADR 0023, 0041).
	c.Hold, c.FenceAfterSeconds = false, 0
	// Marking a job attempt done stops its container; it must not
	// recreate it.
	if c.Job != nil {
		c.Job.Done = false
	}
	for _, e := range c.Env {
		if e.Ref != "" {
			e.Value = ""
		}
	}
	for _, f := range c.SecretFiles {
		f.Data = nil
	}
	// Init containers and sidecars (ADR 0038) are hashed with their images:
	// the server never pins those to a digest. Fields that are empty marshal
	// to nothing, so replicas without them keep their hash.
	for _, m := range slices.Concat(c.InitContainers, c.Sidecars) {
		for _, e := range m.Env {
			if e.Ref != "" {
				e.Value = ""
			}
		}
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
	// Attach at once: a container that has written nothing yet would
	// otherwise look like a node that never answered.
	if err := push.Send(&armadav1.LogPush{RequestId: req.GetRequestId()}); err != nil {
		return
	}

	cs, err := a.cfg.Driver.List(ctx, map[string]string{runtime.LabelManaged: "true", runtime.LabelReplica: req.GetReplicaId()})
	if err != nil || len(cs) == 0 {
		finish("replica " + req.GetReplicaId() + " has no container on this node")
		return
	}
	id, err := containerFor(cs, req.GetContainer())
	if err != nil {
		finish("replica " + req.GetReplicaId() + ": " + err.Error())
		return
	}
	ls, err := a.cfg.Driver.Logs(ctx, id, runtime.LogOptions{Follow: req.GetFollow(), Tail: int(req.GetTail())})
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
