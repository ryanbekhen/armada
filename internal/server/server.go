// Package server implements the control plane: the gRPC API for the CLI and
// agents, and the reconciler that turns desired state into assignments.
package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/certs"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/store"
)

const defaultResync = 5 * time.Second

// Config configures a Server.
type Config struct {
	Store  store.Store
	TLS    *tls.Config
	Logger *slog.Logger
	// Resync is how often the reconciler runs without a trigger.
	Resync time.Duration

	// Certs manages ACME certificates. Nil disables TLS certificate
	// management (HAProxy then only serves its self-signed default).
	Certs certs.Manager
	// ACMEAddr is the private ip:port where the server answers HTTP-01
	// challenges forwarded by every node's HAProxy. Required with Certs.
	ACMEAddr  string
	ACMEEmail string
	// Resolver looks up domain verification TXT records (default: system).
	Resolver       TXTResolver
	VerifyInterval time.Duration

	// Rollout timing; zero values use the defaults. DrainTimeout is how
	// long a replica keeps running after leaving the proxies, Warmup how
	// long a new replica must serve before an old one is drained, and
	// ProgressDeadline how long a rollout may go without a new replica
	// becoming ready (plus the time its probes may legitimately need).
	DrainTimeout     time.Duration
	Warmup           time.Duration
	ProgressDeadline time.Duration
	// NodeLostTimeout is how long a node may be disconnected before its
	// replicas are rescheduled on other nodes (default 5 minutes).
	NodeLostTimeout time.Duration
	// AutoscaleInterval is how often autoscaled apps are evaluated (ADR
	// 0020). Default 15s; tests shorten it.
	AutoscaleInterval time.Duration
	// JobRetryBase is the delay before a job's first retry (ADR 0019); it
	// doubles with each failed attempt. Default 10s; tests shorten it.
	JobRetryBase time.Duration
	// Now returns the current time (default time.Now); tests replace it.
	Now func() time.Time

	// Secrets holds the master key that encrypts secrets at rest. Nil
	// disables secrets.
	Secrets *secrets.Keyring

	// CA signs node certificates for joining and renewing nodes. Nil
	// disables both.
	CA *pki.CA
	// JoinAddr is the private ip:port of the join listener, which serves
	// only JoinService with JoinTLS (no client certificates). Empty
	// disables joining.
	JoinAddr string
	JoinTLS  *tls.Config
	// APIAddr is the control plane address given to joining agents.
	APIAddr string
	// NodeCertValidity is the lifetime of issued node certificates
	// (default pki.NodeValidity).
	NodeCertValidity time.Duration

	// MetricsAddr is the private ip:port of the metrics endpoint (ADR 0017),
	// served with TLS and only to metrics and admin certificates. Empty
	// disables it.
	MetricsAddr string

	// Name is this control plane node's name.
	Name string
	// Cluster manages the control plane's etcd membership. Nil disables
	// adding and removing servers.
	Cluster Cluster
}

// Server is the Armada control plane.
type Server struct {
	armadav1.UnimplementedAdminServiceServer
	armadav1.UnimplementedAgentServiceServer

	store   store.Store
	keys    *secrets.Keyring
	name    string
	cluster Cluster

	ca               *pki.CA
	tlsCfg           *tls.Config
	metricsAddr      string
	reconcileSeconds prometheus.Histogram
	reconcileErrors  prometheus.Counter
	joinAddr         string
	joinTLS          *tls.Config
	apiAddr          string
	nodeCertValidity time.Duration
	joinLimit        *keyedLimiter
	joinGlobal       *limiter
	renewLimit       *keyedLimiter
	log              *slog.Logger
	grpc             *grpc.Server
	resync           time.Duration
	trigger          chan struct{}

	certs          certs.Manager
	acmeAddr       string
	acmeEmail      string
	resolver       TXTResolver
	verifyInterval time.Duration

	mu       sync.Mutex
	sessions map[string]*session
	logs     *logRouter
	execs    *execRouter
	volumes  *volumeRouter
	usage    *usageStore
	events   *eventRecorder
	jobRuns  *prometheus.CounterVec
	// jobRetryBase is the delay before a job's first retry.
	jobRetryBase time.Duration
	// autoscaleInterval and scaler run the autoscaler (ADR 0020).
	autoscaleInterval time.Duration
	scaler            *autoscaler
	wakeLimit         *keyedLimiter

	certMu        sync.Mutex
	lastCertNames []string

	now              func() time.Time
	drainTimeout     time.Duration
	warmup           time.Duration
	progressDeadline time.Duration
	nodeLostTimeout  time.Duration

	progressMu sync.Mutex
	progress   map[string]rolloutProgress

	// rebalanceAfter holds, per app, when spreading it may be tried again
	// after a move whose replacement never served.
	rebalanceMu    sync.Mutex
	rebalanceAfter map[string]time.Time
	learned        learnedRevisions

	wakeMu    sync.Mutex
	wakeTimer *time.Timer
	wakeAt    time.Time
}

// New builds a Server. TLS must require and verify client certificates.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.TLS == nil {
		return nil, errors.New("server: Store and TLS are required")
	}
	if cfg.TLS.ClientAuth != tls.RequireAndVerifyClientCert {
		return nil, errors.New("server: TLS config must require and verify client certificates")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Resync == 0 {
		cfg.Resync = defaultResync
	}
	if cfg.Certs != nil {
		if err := netutil.CheckPrivateListen(cfg.ACMEAddr); err != nil {
			return nil, fmt.Errorf("server: ACME responder: %w", err)
		}
		// The address is advertised to every node's HAProxy, so it must be
		// a concrete port.
		if ap, _ := netip.ParseAddrPort(cfg.ACMEAddr); ap.Port() == 0 {
			return nil, errors.New("server: ACME responder needs a fixed port")
		}
	}
	if cfg.JoinAddr != "" {
		if cfg.CA == nil || cfg.JoinTLS == nil || cfg.APIAddr == "" {
			return nil, errors.New("server: joining needs CA, JoinTLS, and APIAddr")
		}
		if err := netutil.CheckPrivateListen(cfg.JoinAddr); err != nil {
			return nil, fmt.Errorf("server: join listener: %w", err)
		}
		if cfg.JoinTLS.ClientAuth != tls.NoClientCert {
			return nil, errors.New("server: the join listener must not request client certificates")
		}
	}
	if cfg.MetricsAddr != "" {
		if err := netutil.CheckPrivateListen(cfg.MetricsAddr); err != nil {
			return nil, fmt.Errorf("server: metrics listener: %w", err)
		}
	}
	if cfg.NodeCertValidity <= 0 || cfg.NodeCertValidity > pki.NodeValidity {
		cfg.NodeCertValidity = pki.NodeValidity
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.VerifyInterval == 0 {
		cfg.VerifyInterval = defaultVerifyInterval
	}
	if cfg.DrainTimeout == 0 {
		cfg.DrainTimeout = defaultDrainTimeout
	}
	if cfg.Warmup == 0 {
		cfg.Warmup = defaultWarmup
	}
	if cfg.ProgressDeadline == 0 {
		cfg.ProgressDeadline = defaultProgressDeadline
	}
	if cfg.NodeLostTimeout == 0 {
		cfg.NodeLostTimeout = DefaultNodeLostTimeout
	}
	if cfg.NodeLostTimeout < 0 {
		return nil, errors.New("server: NodeLostTimeout must be positive")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.JobRetryBase <= 0 {
		cfg.JobRetryBase = defaultJobRetryBase
	}
	if cfg.AutoscaleInterval <= 0 {
		cfg.AutoscaleInterval = defaultAutoscaleInterval
	}
	s := &Server{
		autoscaleInterval: cfg.AutoscaleInterval,
		scaler:            newAutoscaler(),
		// Wakes: a burst for several apps at once, then one a second.
		wakeLimit:    newKeyedLimiter(20, time.Second),
		jobRetryBase: cfg.JobRetryBase,
		store:        cfg.Store,
		keys:         cfg.Secrets,
		name:         cfg.Name,
		cluster:      cfg.Cluster,

		ca:               cfg.CA,
		joinAddr:         cfg.JoinAddr,
		joinTLS:          cfg.JoinTLS,
		apiAddr:          cfg.APIAddr,
		nodeCertValidity: cfg.NodeCertValidity,
		joinLimit:        newKeyedLimiter(joinBurst, joinRefill),
		joinGlobal:       newLimiter(joinGlobalBurst, joinGlobalRef),
		// Renewals: a burst for retries, then one per tenth of a lifetime.
		renewLimit: newKeyedLimiter(5, max(cfg.NodeCertValidity/10, time.Second)),
		log:        cfg.Logger.With("component", "server"),
		resync:     cfg.Resync,
		trigger:    make(chan struct{}, 1),
		sessions:   map[string]*session{},
		logs:       newLogRouter(),
		execs:      newExecRouter(),
		volumes:    newVolumeRouter(),
		tlsCfg:     cfg.TLS,

		metricsAddr: cfg.MetricsAddr,
		reconcileSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "armada_reconcile_duration_seconds", Help: "How long a reconcile of the whole cluster takes.",
			Buckets: prometheus.ExponentialBuckets(0.005, 2, 12),
		}),
		reconcileErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "armada_reconcile_errors_total", Help: "Reconciles that failed.",
		}),
		usage:   newUsageStore(),
		events:  newEventRecorder(),
		jobRuns: newJobRunsCounter(),

		certs:          cfg.Certs,
		acmeAddr:       cfg.ACMEAddr,
		acmeEmail:      cfg.ACMEEmail,
		resolver:       cfg.Resolver,
		verifyInterval: cfg.VerifyInterval,

		now:              cfg.Now,
		drainTimeout:     cfg.DrainTimeout,
		warmup:           cfg.Warmup,
		progressDeadline: cfg.ProgressDeadline,
		nodeLostTimeout:  cfg.NodeLostTimeout,
		progress:         map[string]rolloutProgress{},
		rebalanceAfter:   map[string]time.Time{},
	}
	s.grpc = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(cfg.TLS)),
		grpc.UnaryInterceptor(s.unaryAuth),
		grpc.StreamInterceptor(s.streamAuth),
		grpc.MaxRecvMsgSize(4<<20),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
	)
	armadav1.RegisterAdminServiceServer(s.grpc, s)
	armadav1.RegisterAgentServiceServer(s.grpc, s)
	return s, nil
}

// shutdownGrace is how long in-flight RPCs get when the server stops.
const shutdownGrace = 3 * time.Second

// Serve accepts connections on lis and runs the reconciler until ctx is
// cancelled. With several control plane nodes only the leader serves, for
// as long as its term lasts.
func (s *Server) Serve(ctx context.Context, lis net.Listener) error {
	if err := s.startTerm(ctx); err != nil {
		_ = lis.Close()
		return fmt.Errorf("start term: %w", err)
	}
	if s.certs != nil {
		acme, err := net.Listen("tcp", s.acmeAddr)
		if err != nil {
			return fmt.Errorf("ACME responder: %w", err)
		}
		hs := &http.Server{Handler: s.certs.HTTPHandler(), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			<-ctx.Done()
			_ = hs.Close()
		}()
		go func() {
			if err := hs.Serve(acme); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.log.Error("ACME responder stopped", "err", err)
			}
		}()
		s.log.Info("ACME HTTP-01 responder listening", "addr", s.acmeAddr)
	}
	if s.joinAddr != "" {
		if err := s.serveJoin(ctx); err != nil {
			return err
		}
	}
	if s.metricsAddr != "" {
		if err := s.serveMetrics(ctx); err != nil {
			return err
		}
	}
	go s.verifyLoop(ctx)
	go s.reconcileLoop(ctx)
	go s.autoscaleLoop(ctx)
	go func() {
		<-ctx.Done()
		// Agent streams are long-lived and never finish on their own, so a
		// graceful stop only gets a short grace period for in-flight RPCs;
		// agents reconnect to the next server process.
		done := make(chan struct{})
		go func() {
			s.grpc.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(shutdownGrace):
			s.grpc.Stop()
		}
	}()
	s.log.Info("listening", "addr", lis.Addr().String())
	err := s.grpc.Serve(lis)
	if errors.Is(err, grpc.ErrServerStopped) || ctx.Err() != nil {
		return nil
	}
	return err
}

// Trigger requests a reconcile as soon as possible.
func (s *Server) Trigger() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

func (s *Server) reconcileLoop(ctx context.Context) {
	t := time.NewTicker(s.resync)
	defer t.Stop()
	for {
		start := time.Now()
		err := s.Reconcile(ctx)
		s.reconcileSeconds.Observe(time.Since(start).Seconds())
		if err != nil && ctx.Err() == nil {
			s.reconcileErrors.Inc()
			s.log.Error("reconcile failed", "err", err)
		}
		s.promoteLearners(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.trigger:
		}
	}
}

const idAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// randomID returns n random characters from [a-z0-9].
func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	for i := range b {
		b[i] = idAlphabet[int(b[i])%len(idAlphabet)]
	}
	return string(b)
}
