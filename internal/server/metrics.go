package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
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

// serveMetrics serves /metrics on the metrics listener (ADR 0019): TLS 1.3
// with the API's server certificate, and only to client certificates of
// the metrics or admin kind.
func (s *Server) serveMetrics(ctx context.Context) error {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		s.reconcileSeconds, s.reconcileErrors,
		&clusterCollector{s: s},
	)
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError}))
	hs := &http.Server{
		Handler:           metricsAuth(mux),
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

// metricsAuth lets only metrics and admin certificates through; the TLS
// config has already verified the chain against the cluster CA.
func metricsAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !metricsAllowed(r.TLS) {
			http.Error(w, "a metrics or admin client certificate is required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func metricsAllowed(cs *tls.ConnectionState) bool {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return false
	}
	id, err := pki.IdentityFromCert(cs.VerifiedChains[0][0])
	return err == nil && (id.Kind == pki.KindMetrics || id.Kind == pki.KindAdmin)
}

// clusterCollector reads the cluster's state on every scrape, from the same
// sources as `armada status` and `armada top`. Label values are names the
// store has validated: apps, replicas, revisions, nodes, servers.
type clusterCollector struct{ s *Server }

var (
	descLeader          = prometheus.NewDesc("armada_server_leader", "1 on the control plane server that leads and serves this endpoint.", []string{"server"}, nil)
	descAgents          = prometheus.NewDesc("armada_agents_connected", "Agents connected to the leader.", nil, nil)
	descAppDesired      = prometheus.NewDesc("armada_app_replicas_desired", "Replicas an app should run.", []string{"app"}, nil)
	descAppReady        = prometheus.NewDesc("armada_app_replicas_ready", "Replicas of an app that are running, ready, and not draining.", []string{"app"}, nil)
	descAppRollout      = prometheus.NewDesc("armada_app_rollout", "1 for an app's current rollout state (idle, progressing, failed).", []string{"app", "state"}, nil)
	descReplicaReady    = prometheus.NewDesc("armada_replica_ready", "1 when a replica is running, ready, and not draining.", []string{"app", "replica", "revision", "node"}, nil)
	descReplicaCPU      = prometheus.NewDesc("armada_replica_cpu_usage_cores", "CPU a replica used over its node's last sampling interval.", []string{"app", "replica", "node"}, nil)
	descReplicaMemory   = prometheus.NewDesc("armada_replica_memory_usage_bytes", "Memory a replica uses, without reclaimable page cache.", []string{"app", "replica", "node"}, nil)
	descReplicaCPURes   = prometheus.NewDesc("armada_replica_cpu_reserved_cores", "CPU a replica reserves on its node.", []string{"app", "replica", "node"}, nil)
	descReplicaCPULimit = prometheus.NewDesc("armada_replica_cpu_limit_cores", "A replica's CPU limit, for apps that set one.", []string{"app", "replica", "node"}, nil)
	descReplicaMemLimit = prometheus.NewDesc("armada_replica_memory_limit_bytes", "A replica's memory limit, which is also its reservation.", []string{"app", "replica", "node"}, nil)
	descNodeReady       = prometheus.NewDesc("armada_node_ready", "1 when a node's agent is connected and the node is ready.", []string{"node"}, nil)
	descNodeCordoned    = prometheus.NewDesc("armada_node_cordoned", "1 when a node is cordoned.", []string{"node"}, nil)
	descNodeReplicas    = prometheus.NewDesc("armada_node_replicas", "Replicas assigned to a node.", []string{"node"}, nil)
	descNodeCPUAlloc    = prometheus.NewDesc("armada_node_cpu_allocatable_cores", "CPU a node can give replicas, after what Armada keeps.", []string{"node"}, nil)
	descNodeMemAlloc    = prometheus.NewDesc("armada_node_memory_allocatable_bytes", "Memory a node can give replicas, after what Armada keeps.", []string{"node"}, nil)
	descNodeCPURes      = prometheus.NewDesc("armada_node_cpu_reserved_cores", "CPU the replicas on a node reserve.", []string{"node"}, nil)
	descNodeMemRes      = prometheus.NewDesc("armada_node_memory_reserved_bytes", "Memory the replicas on a node reserve.", []string{"node"}, nil)
	descNodeCPU         = prometheus.NewDesc("armada_node_cpu_usage_cores", "CPU the replicas on a node use, from its latest sample.", []string{"node"}, nil)
	descNodeMemory      = prometheus.NewDesc("armada_node_memory_usage_bytes", "Memory the replicas on a node use, from its latest sample.", []string{"node"}, nil)
)

func (c *clusterCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		descLeader, descAgents, descAppDesired, descAppReady, descAppRollout, descReplicaReady,
		descReplicaCPU, descReplicaMemory, descReplicaCPURes, descReplicaCPULimit, descReplicaMemLimit,
		descNodeReady, descNodeCordoned, descNodeReplicas, descNodeCPUAlloc, descNodeMemAlloc,
		descNodeCPURes, descNodeMemRes, descNodeCPU, descNodeMemory,
	} {
		ch <- d
	}
}

func (c *clusterCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), metricsTimeout)
	defer cancel()
	s := c.s
	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
	}
	gauge(descLeader, 1, s.name)
	s.mu.Lock()
	agents := len(s.sessions)
	s.mu.Unlock()
	gauge(descAgents, float64(agents))

	st, err := s.Status(ctx, &armadav1.StatusRequest{})
	if err != nil {
		ch <- prometheus.NewInvalidMetric(descAppDesired, err)
		return
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
		}
		gauge(descAppReady, float64(ready), a.GetName())
		state := a.GetRolloutState()
		if state == "" {
			state = "idle"
		}
		for _, v := range []string{"idle", store.RolloutProgressing, store.RolloutFailed} {
			gauge(descAppRollout, boolValue(v == state), a.GetName(), v)
		}
	}
	for _, n := range st.GetNodes() {
		gauge(descNodeReady, boolValue(n.GetState() == store.NodeReady), n.GetId())
		gauge(descNodeCordoned, boolValue(n.GetCordoned()), n.GetId())
	}

	top, err := s.Top(ctx, &armadav1.TopRequest{})
	if err != nil {
		ch <- prometheus.NewInvalidMetric(descReplicaCPU, err)
		return
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
	}
}

func cores(millis int64) float64 { return float64(millis) / 1000 }

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// IssueMetricsCertificate signs a metrics client certificate from the
// caller's CSR (ADR 0019). The key never reaches the server, and the
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
