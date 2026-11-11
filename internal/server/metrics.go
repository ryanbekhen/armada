package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

// metricsTimeout bounds the store reads of one scrape.
const metricsTimeout = 10 * time.Second

// serveMetrics serves /metrics on the metrics listener (ADR 0017): TLS 1.3
// with the API's server certificate, and only to client certificates of
// the metrics kind, or a user or service with cluster-admin.
func (s *Server) serveMetrics(ctx context.Context) error {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		s.reconcileSeconds, s.reconcileErrors, s.events.total, s.jobRuns,
		&clusterCollector{s: s, every: s.metricsCache},
	)
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError}))
	hs := &http.Server{
		Handler:           s.metricsAuth(mux),
		TLSConfig:         s.tlsCfg.Clone(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	lis, err := net.Listen("tcp", s.metricsAddr)
	if err != nil {
		return fmt.Errorf("metrics listener: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = hs.Close()
	}()
	go func() {
		if err := hs.ServeTLS(lis, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("metrics listener stopped", "err", err)
		}
	}()
	s.log.Info("metrics listening", "addr", s.metricsAddr)
	return nil
}

// metricsAuth lets only metrics certificates and users or services with
// cluster-admin through (ADR 0033); the TLS config has already verified the
// chain against the cluster CA.
func (s *Server) metricsAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.metricsAllowed(r.Context(), r.TLS) {
			http.Error(w, "a metrics certificate, or a user or service with cluster-admin, is required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) metricsAllowed(ctx context.Context, cs *tls.ConnectionState) bool {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return false
	}
	cert := cs.VerifiedChains[0][0]
	id, err := pki.IdentityFromCert(cert)
	switch {
	case err != nil:
		return false
	case id.Kind == pki.KindMetrics:
		return true
	}
	pid, ok := id.Principal()
	if !ok {
		return false
	}
	p, ok, err := s.principalAccess(ctx, pid, cert)
	return err == nil && ok && p.Has(store.Grant{Role: store.RoleClusterAdmin})
}

// metricsCacheFor is how long the cluster's metrics, once gathered, answer
// further scrapes: each gathering reads the whole cluster.
const metricsCacheFor = 10 * time.Second

// clusterCollector reads the cluster's state from the same sources as
// `armada app show` and `armada app top`, at most once per every: scrapes
// within it get the metrics last gathered, and scrapes that arrive while
// they are gathered wait for them. Label values are names the store has
// validated: apps, replicas, revisions, nodes, servers.
type clusterCollector struct {
	s *Server
	// every is how long gathered metrics are kept; 0 gathers on every
	// scrape that does not find a gathering under way.
	every time.Duration

	mu      sync.Mutex
	last    []prometheus.Metric // nil when the last gathering failed
	lastAt  time.Time
	pending *gathering
}

// gathering is one gathering of the cluster's metrics, shared by the
// scrapes that arrive while it runs.
type gathering struct {
	done    chan struct{}
	metrics []prometheus.Metric
}

func (c *clusterCollector) Collect(ch chan<- prometheus.Metric) {
	for _, m := range c.metrics() {
		ch <- m
	}
}

// metrics returns the cluster's metrics: the last ones gathered while they
// are fresh, else those of the gathering under way, else new ones.
func (c *clusterCollector) metrics() []prometheus.Metric {
	c.mu.Lock()
	if c.last != nil && c.s.now().Sub(c.lastAt) < c.every {
		m := c.last
		c.mu.Unlock()
		return m
	}
	if g := c.pending; g != nil {
		c.mu.Unlock()
		<-g.done
		return g.metrics
	}
	g := &gathering{done: make(chan struct{})}
	c.pending = g
	c.mu.Unlock()

	var ok bool
	defer func() {
		c.mu.Lock()
		c.pending = nil
		c.last, c.lastAt = nil, time.Time{}
		if ok {
			c.last, c.lastAt = g.metrics, c.s.now()
		}
		c.mu.Unlock()
		close(g.done)
	}()
	g.metrics, ok = c.gather()
	return g.metrics
}

var (
	descLeader           = prometheus.NewDesc("armada_server_leader", "1 on the control plane server that leads and serves this endpoint.", []string{"server"}, nil)
	descAgents           = prometheus.NewDesc("armada_agents_connected", "Agents connected to the leader.", nil, nil)
	descAppDesired       = prometheus.NewDesc("armada_app_replicas_desired", "Replicas an app should run.", []string{"app"}, nil)
	descAppReady         = prometheus.NewDesc("armada_app_replicas_ready", "Replicas of an app that are running, ready, and not draining.", []string{"app"}, nil)
	descAppRollout       = prometheus.NewDesc("armada_app_rollout", "1 for an app's current rollout state (idle, progressing, failed).", []string{"app", "state"}, nil)
	descReplicaReady     = prometheus.NewDesc("armada_replica_ready", "1 when a replica is running, ready, and not draining.", []string{"app", "replica", "revision", "node"}, nil)
	descReplicaRestarts  = prometheus.NewDesc("armada_replica_restarts_total", "How often the agent recreated a replica's container.", []string{"app", "replica", "node"}, nil)
	descReplicaLastRest  = prometheus.NewDesc("armada_replica_last_restart_timestamp_seconds", "When the agent last recreated a replica's container, and why (exited, out_of_memory, liveness, startup, network, volume, other, unknown).", []string{"app", "replica", "node", "reason"}, nil)
	descReplicaStart     = prometheus.NewDesc("armada_replica_start_time_seconds", "When a replica was scheduled.", []string{"app", "replica", "node"}, nil)
	descAppMin           = prometheus.NewDesc("armada_app_replicas_min", "The fewest replicas an autoscaled app may run.", []string{"app"}, nil)
	descAppMax           = prometheus.NewDesc("armada_app_replicas_max", "The most replicas an autoscaled app may run.", []string{"app"}, nil)
	descReplicaCPU       = prometheus.NewDesc("armada_replica_cpu_usage_cores", "CPU a replica used over its node's last sampling interval.", []string{"app", "replica", "node"}, nil)
	descReplicaMemory    = prometheus.NewDesc("armada_replica_memory_usage_bytes", "Memory a replica uses, without reclaimable page cache.", []string{"app", "replica", "node"}, nil)
	descReplicaCPURes    = prometheus.NewDesc("armada_replica_cpu_reserved_cores", "CPU a replica reserves on its node.", []string{"app", "replica", "node"}, nil)
	descReplicaCPULimit  = prometheus.NewDesc("armada_replica_cpu_limit_cores", "A replica's CPU limit, for apps that set one.", []string{"app", "replica", "node"}, nil)
	descReplicaMemLimit  = prometheus.NewDesc("armada_replica_memory_limit_bytes", "A replica's memory limit, which is also its reservation.", []string{"app", "replica", "node"}, nil)
	descNodeReady        = prometheus.NewDesc("armada_node_ready", "1 when a node's agent is connected and the node is ready.", []string{"node"}, nil)
	descNodeCordoned     = prometheus.NewDesc("armada_node_cordoned", "1 when a node is cordoned.", []string{"node"}, nil)
	descNodeReplicas     = prometheus.NewDesc("armada_node_replicas", "Replicas assigned to a node.", []string{"node"}, nil)
	descNodeCPUAlloc     = prometheus.NewDesc("armada_node_cpu_allocatable_cores", "CPU a node can give replicas, after what Armada keeps.", []string{"node"}, nil)
	descNodeMemAlloc     = prometheus.NewDesc("armada_node_memory_allocatable_bytes", "Memory a node can give replicas, after what Armada keeps.", []string{"node"}, nil)
	descNodeCPURes       = prometheus.NewDesc("armada_node_cpu_reserved_cores", "CPU the replicas on a node reserve.", []string{"node"}, nil)
	descNodeMemRes       = prometheus.NewDesc("armada_node_memory_reserved_bytes", "Memory the replicas on a node reserve.", []string{"node"}, nil)
	descNodeCPU          = prometheus.NewDesc("armada_node_cpu_usage_cores", "CPU the replicas on a node use, from its latest sample.", []string{"node"}, nil)
	descNodeMemory       = prometheus.NewDesc("armada_node_memory_usage_bytes", "Memory the replicas on a node use, from its latest sample.", []string{"node"}, nil)
	descNodeConntrack    = prometheus.NewDesc("armada_node_conntrack_entries", "Connections a node's kernel tracks, from its latest sample.", []string{"node"}, nil)
	descNodeConntrackMax = prometheus.NewDesc("armada_node_conntrack_max", "How many connections a node's kernel can track; new ones are dropped past it.", []string{"node"}, nil)
	descJobLastSuccess   = prometheus.NewDesc("armada_job_last_success_timestamp_seconds", "When the newest kept successful run of a job finished.", []string{"job"}, nil)
	descScaleCurrent     = prometheus.NewDesc("armada_app_autoscale_current", "An autoscaling rule's current value: the average per ready replica (requests in progress, or percent of the reservation), a queue's length, or the replicas an open schedule window asks for (0 when closed); absent while unmeasured.", []string{"app", "rule"}, nil)
	descScaleTarget      = prometheus.NewDesc("armada_app_autoscale_target", "An autoscaling rule's target: per replica, or a schedule's replicas.", []string{"app", "rule"}, nil)
	descJobActive        = prometheus.NewDesc("armada_job_runs_active", "Runs of a job that are pending or running.", []string{"job"}, nil)
	descJobQueueLength   = prometheus.NewDesc("armada_job_queue_length", "The length of the queue that starts a job's runs, as last read; absent while unread.", []string{"job"}, nil)
	descTrafficWeight    = prometheus.NewDesc("armada_app_traffic_weight", "A revision's percent of an app's requests in multiple revision mode.", []string{"app", "revision"}, nil)
	descProjectReplicas  = prometheus.NewDesc("armada_project_replicas", "Replicas of a project's apps.", []string{"project"}, nil)
	descProjectCPU       = prometheus.NewDesc("armada_project_cpu_usage_cores", "CPU a project's replicas used over the last sampling interval.", []string{"project"}, nil)
	descProjectMemory    = prometheus.NewDesc("armada_project_memory_usage_bytes", "Memory a project's replicas use, without reclaimable page cache.", []string{"project"}, nil)
	descProjectCPURes    = prometheus.NewDesc("armada_project_cpu_reserved_cores", "CPU a project's replicas reserve.", []string{"project"}, nil)
	descProjectMemRes    = prometheus.NewDesc("armada_project_memory_reserved_bytes", "Memory a project's replicas reserve.", []string{"project"}, nil)
	descProjectVolumes   = prometheus.NewDesc("armada_project_volume_used_bytes", "Bytes in a project's volumes, from their latest measurements.", []string{"project"}, nil)
	descProjectRequests  = prometheus.NewDesc("armada_project_requests_total", "Requests the proxies sent to a project's replicas; resets when the leader changes.", []string{"project"}, nil)
	descProjectEgress    = prometheus.NewDesc("armada_project_egress_bytes_total", "Bytes a project's containers sent; resets when the leader changes.", []string{"project"}, nil)
	descVolumeUsed       = prometheus.NewDesc("armada_volume_used_bytes", "Bytes in a volume's files, from its node's latest measurement; absent while unmeasured.", []string{"app", "volume", "node"}, nil)
	descBackupLast       = prometheus.NewDesc("armada_volume_backup_last_success_timestamp_seconds", "When a volume's last backup to its bucket worked (ADR 0041); absent before the first.", []string{"app", "volume"}, nil)
	descBackupStored     = prometheus.NewDesc("armada_volume_backup_stored_bytes", "Bytes a volume's backup repository held after its last backup.", []string{"app", "volume"}, nil)
	descBackupSnapshots  = prometheus.NewDesc("armada_volume_backup_snapshots", "Backups a volume's repository held after its last backup.", []string{"app", "volume"}, nil)
	descBackupFailing    = prometheus.NewDesc("armada_volume_backup_failing", "1 while a volume's last backup failed, 0 otherwise.", []string{"app", "volume"}, nil)
	descRevisionInfo     = prometheus.NewDesc("armada_revision_info", "1 for each revision of an app that serves, rolls out, or still has replicas, with the image its spec names.", []string{"app", "revision", "image"}, nil)
	descReplicaState     = prometheus.NewDesc("armada_replica_state", "1 for a replica's current state (pending, pulling, starting, running, exited, failed, unknown).", []string{"app", "replica", "node", "state"}, nil)
	descReplicaInfo      = prometheus.NewDesc("armada_replica_info", "1 for each replica, with its revision and the IP address it is reached at (empty until it has one).", []string{"app", "replica", "revision", "node", "ip"}, nil)
	descScaledAt         = prometheus.NewDesc("armada_app_autoscale_last_scale_timestamp_seconds", "When the autoscaler last changed an app's replica count; absent until it does.", []string{"app"}, nil)
)

func (c *clusterCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		descLeader, descAgents, descAppDesired, descAppReady, descAppRollout, descReplicaReady,
		descReplicaRestarts, descReplicaLastRest, descReplicaStart, descAppMin, descAppMax,
		descReplicaCPU, descReplicaMemory, descReplicaCPURes, descReplicaCPULimit, descReplicaMemLimit,
		descNodeReady, descNodeCordoned, descNodeReplicas, descNodeCPUAlloc, descNodeMemAlloc,
		descNodeCPURes, descNodeMemRes, descNodeCPU, descNodeMemory, descNodeConntrack, descNodeConntrackMax, descJobLastSuccess, descJobActive, descJobQueueLength,
		descScaleCurrent, descScaleTarget, descTrafficWeight, descVolumeUsed,
		descBackupLast, descBackupStored, descBackupSnapshots, descBackupFailing,
		descProjectReplicas, descProjectCPU, descProjectMemory, descProjectCPURes, descProjectMemRes,
		descProjectVolumes, descProjectRequests, descProjectEgress,
		descRevisionInfo, descReplicaState, descReplicaInfo, descScaledAt,
	} {
		ch <- d
	}
}

// gather reads the cluster's metrics; ok is false when a read failed and
// the metrics end with the error.
func (c *clusterCollector) gather() (out []prometheus.Metric, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), metricsTimeout)
	defer cancel()
	s := c.s
	emit := func(m prometheus.Metric) { out = append(out, m) }
	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		emit(prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...))
	}
	gauge(descLeader, 1, s.name)
	s.mu.Lock()
	agents := len(s.sessions)
	s.mu.Unlock()
	gauge(descAgents, float64(agents))

	ctx = s.internalContext(ctx)
	st, err := s.Status(ctx, &armadav1.StatusRequest{})
	if err != nil {
		emit(prometheus.NewInvalidMetric(descAppDesired, err))
		return out, false
	}
	for _, a := range st.GetApps() {
		gauge(descAppDesired, float64(a.GetDesiredReplicas()), a.GetName())
		ready := 0
		for _, r := range a.GetReplicas() {
			v := 0.0
			if r.GetReady() && r.GetState() == store.ReplicaRunning && !r.GetDraining() {
				v = 1
				ready++
			}
			gauge(descReplicaReady, v, a.GetName(), r.GetId(), r.GetRevision(), r.GetNodeId())
			gauge(descReplicaState, 1, a.GetName(), r.GetId(), r.GetNodeId(), replicaStateLabel(r.GetState()))
			gauge(descReplicaInfo, 1, a.GetName(), r.GetId(), r.GetRevision(), r.GetNodeId(), addressIP(r.GetAddress()))
			emit(prometheus.MustNewConstMetric(descReplicaRestarts, prometheus.CounterValue, float64(r.GetRestarts()), a.GetName(), r.GetId(), r.GetNodeId()))
			if t := r.GetLastRestartAt(); t != nil {
				gauge(descReplicaLastRest, float64(t.GetSeconds()), a.GetName(), r.GetId(), r.GetNodeId(), restartReason(r.GetLastRestart()))
			}
			if t := r.GetCreatedAt(); t != nil {
				gauge(descReplicaStart, float64(t.GetSeconds()), a.GetName(), r.GetId(), r.GetNodeId())
			}
		}
		gauge(descAppReady, float64(ready), a.GetName())
		state := a.GetRolloutState()
		if state == "" {
			state = "idle"
		}
		for _, v := range []string{"idle", store.RolloutProgressing, store.RolloutFailed} {
			gauge(descAppRollout, boolValue(v == state), a.GetName(), v)
		}
		if as := a.GetAutoscale(); as != nil {
			gauge(descAppMin, float64(as.GetMin()), a.GetName())
			gauge(descAppMax, float64(as.GetMax()), a.GetName())
		}
		if t := a.GetAutoscale().GetLastScaledAt(); t != nil {
			gauge(descScaledAt, float64(t.GetSeconds()), a.GetName())
		}
		for _, r := range a.GetAutoscale().GetRules() {
			gauge(descScaleTarget, float64(r.GetTarget()), a.GetName(), r.GetType())
			if r.GetMeasured() {
				gauge(descScaleCurrent, float64(r.GetCurrent()), a.GetName(), r.GetType())
			}
		}
		for _, t := range a.GetTraffic() {
			gauge(descTrafficWeight, float64(t.GetWeight()), a.GetName(), t.GetRevision())
		}
	}
	c.revisionInfo(ctx, st.GetApps(), gauge)
	for _, n := range st.GetNodes() {
		gauge(descNodeReady, boolValue(n.GetState() == store.NodeReady), n.GetId())
		gauge(descNodeCordoned, boolValue(n.GetCordoned()), n.GetId())
	}

	top, err := s.Top(ctx, &armadav1.TopRequest{})
	if err != nil {
		emit(prometheus.NewInvalidMetric(descReplicaCPU, err))
		return out, false
	}
	for _, r := range top.GetReplicas() {
		labels := []string{r.GetApp(), r.GetId(), r.GetNodeId()}
		if r.GetMeasured() {
			gauge(descReplicaCPU, cores(r.GetCpuMillis()), labels...)
			gauge(descReplicaMemory, float64(r.GetMemoryBytes()), labels...)
		}
		gauge(descReplicaCPURes, cores(r.GetCpuReservedMillis()), labels...)
		if r.GetCpuLimitMillis() > 0 {
			gauge(descReplicaCPULimit, cores(r.GetCpuLimitMillis()), labels...)
		}
		gauge(descReplicaMemLimit, float64(r.GetMemoryLimitBytes()), labels...)
	}
	if jobs, runs, err := s.listJobs(ctx); err == nil {
		for _, j := range jobs.GetJobs() {
			gauge(descJobActive, float64(j.GetActive()), j.GetName())
			if tr := j.GetTrigger(); tr.GetMeasured() {
				gauge(descJobQueueLength, float64(tr.GetLength()), j.GetName())
			}
			var last time.Time
			for _, r := range runs[j.GetName()] {
				if r.State == store.RunSucceeded && r.FinishedAt.After(last) {
					last = r.FinishedAt
				}
			}
			if !last.IsZero() {
				gauge(descJobLastSuccess, float64(last.Unix()), j.GetName())
			}
		}
	}
	if vols, err := s.ListVolumes(ctx, &armadav1.ListVolumesRequest{}); err == nil {
		for _, v := range vols.GetVolumes() {
			if v.GetUsedBytes() >= 0 {
				gauge(descVolumeUsed, float64(v.GetUsedBytes()), v.GetApp(), v.GetName(), v.GetNode())
			}
			if !v.GetBackup() {
				continue
			}
			if t := v.GetLastBackupAt(); t != nil {
				gauge(descBackupLast, float64(t.AsTime().Unix()), v.GetApp(), v.GetName())
				gauge(descBackupStored, float64(v.GetBackupStoredBytes()), v.GetApp(), v.GetName())
				gauge(descBackupSnapshots, float64(v.GetBackupSnapshots()), v.GetApp(), v.GetName())
			}
			failing := 0.0
			if v.GetBackupFailedAt() != nil {
				failing = 1
			}
			gauge(descBackupFailing, failing, v.GetApp(), v.GetName())
		}
	}
	for _, p := range top.GetProjects() {
		name := p.GetName()
		gauge(descProjectReplicas, float64(p.GetReplicas()), name)
		if p.GetMeasured() > 0 {
			gauge(descProjectCPU, cores(p.GetCpuMillis()), name)
			gauge(descProjectMemory, float64(p.GetMemoryBytes()), name)
		}
		gauge(descProjectCPURes, cores(p.GetCpuReservedMillis()), name)
		gauge(descProjectMemRes, float64(p.GetMemoryReservedBytes()), name)
		gauge(descProjectVolumes, float64(p.GetVolumeBytes()), name)
		emit(prometheus.MustNewConstMetric(descProjectRequests, prometheus.CounterValue, float64(p.GetRequests()), name))
		emit(prometheus.MustNewConstMetric(descProjectEgress, prometheus.CounterValue, float64(p.GetEgressBytes()), name))
	}
	for _, n := range top.GetNodes() {
		gauge(descNodeReplicas, float64(n.GetReplicas()), n.GetId())
		gauge(descNodeCPUAlloc, cores(n.GetCpuAllocatableMillis()), n.GetId())
		gauge(descNodeMemAlloc, float64(n.GetMemoryAllocatableBytes()), n.GetId())
		gauge(descNodeCPURes, cores(n.GetCpuReservedMillis()), n.GetId())
		gauge(descNodeMemRes, float64(n.GetMemoryReservedBytes()), n.GetId())
		if n.GetMeasured() {
			gauge(descNodeCPU, cores(n.GetCpuMillis()), n.GetId())
			gauge(descNodeMemory, float64(n.GetMemoryBytes()), n.GetId())
		}
		if n.GetConntrackMax() > 0 {
			gauge(descNodeConntrack, float64(n.GetConntrackEntries()), n.GetId())
			gauge(descNodeConntrackMax, float64(n.GetConntrackMax()), n.GetId())
		}
	}
	return out, true
}

// revisionInfo exports the image of every revision an app serves, rolls
// out, or still runs replicas of, read in one batch. The image passed the
// spec's validation when it was deployed.
func (c *clusterCollector) revisionInfo(ctx context.Context, apps []*armadav1.AppStatus, gauge func(*prometheus.Desc, float64, ...string)) {
	owner := map[string]string{}
	for _, a := range apps {
		names := []string{a.GetActiveRevision(), a.GetTargetRevision()}
		for _, t := range a.GetTraffic() {
			names = append(names, t.GetRevision())
		}
		for _, r := range a.GetReplicas() {
			names = append(names, r.GetRevision())
		}
		for _, n := range names {
			if n != "" {
				owner[n] = a.GetName()
			}
		}
	}
	if len(owner) == 0 {
		return
	}
	revs, err := c.s.store.GetRevisions(ctx, slices.Collect(maps.Keys(owner)))
	if err != nil {
		c.s.log.Warn("metrics: read revisions", "err", err)
		return
	}
	for name, app := range owner {
		if r, ok := revs[name]; ok && r.Spec != nil {
			gauge(descRevisionInfo, 1, app, name, r.Spec.Image)
		}
	}
}

// replicaStateLabel keeps the state label to the states the store knows.
func replicaStateLabel(state string) string {
	switch state {
	case store.ReplicaPending, store.ReplicaPulling, store.ReplicaPulled, store.ReplicaStarting, store.ReplicaRunning, store.ReplicaExited, store.ReplicaFailed:
		return state
	}
	return "unknown"
}

// addressIP is the IP of a replica's validated host:port address, or "".
func addressIP(addr string) string {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.Addr().String()
	}
	return ""
}

// restartReason names why a container was recreated from the agent's
// words, so that the label takes only a few values.
func restartReason(msg string) string {
	switch {
	case msg == "":
		return "unknown"
	case strings.Contains(msg, "out of memory"):
		return "out_of_memory"
	case strings.Contains(msg, "liveness probe"):
		return "liveness"
	case strings.Contains(msg, "startup probe"):
		return "startup"
	case strings.Contains(msg, "network interface"):
		return "network"
	case strings.Contains(msg, "volume backup"):
		return "volume"
	case strings.HasPrefix(msg, "exited with code"), strings.HasPrefix(msg, "container "):
		return "exited"
	}
	return "other"
}

func cores(millis int64) float64 { return float64(millis) / 1000 }

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// IssueMetricsCertificate signs a metrics client certificate from the
// caller's CSR (ADR 0017). The key never reaches the server, and the
// certificate can only scrape metrics: the API refuses its identity.
func (s *Server) IssueMetricsCertificate(ctx context.Context, req *armadav1.IssueMetricsCertificateRequest) (*armadav1.IssueMetricsCertificateResponse, error) {
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, "this server cannot issue certificates")
	}
	if _, err := pki.ParseIdentity(pki.KindMetrics + ":" + req.GetName()); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid name: use letters, digits, '.', '_', and '-' (at most 63)")
	}
	cert, err := s.ca.SignMetricsCSR(req.GetCsr(), req.GetName())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign certificate: %v", err)
	}
	if err := s.store.RecordAudit(ctx, actor(ctx), "metrics.certificate", req.GetName(), "serial="+cert.Serial); err != nil {
		return nil, storeErr(err)
	}
	s.log.Info("issued metrics certificate", "name", req.GetName(), "serial", cert.Serial, "by", actor(ctx))
	return &armadav1.IssueMetricsCertificateResponse{Cert: cert.PEM, CaCert: s.ca.CertPEM, ExpiresAt: timestamppb.New(cert.NotAfter)}, nil
}
