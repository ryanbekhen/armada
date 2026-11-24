package daemon

import (
	"cmp"
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/clusternet"
	"github.com/ryanbekhen/armada/internal/conntrack"
	"github.com/ryanbekhen/armada/internal/nodeprog"
	"github.com/ryanbekhen/armada/internal/version"

	"google.golang.org/grpc"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/ryanbekhen/armada/internal/agent"
	"github.com/ryanbekhen/armada/internal/backup"
	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/dnsserver"
	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/proxy/haproxy"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/server"
	"github.com/ryanbekhen/armada/internal/store"
)

// agentMaxRecv bounds a message the agent takes from the server.
const agentMaxRecv = 64 << 20

func newLogger(w io.Writer, format string, verbose bool) (*slog.Logger, error) {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if verbose {
		opts.Level = slog.LevelDebug
	}
	switch format {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("unsupported --log-format %q (want text or json)", format)
	}
}

// leaderLease is how long leadership outlives a control plane node that
// stopped renewing it; a new leader is elected about this long after a
// leader fails. Tests shorten it.
var leaderLease = 10 * time.Second

func newServerCommand() *cobra.Command {
	var (
		dataDir     string
		withAgent   bool
		logFormat   string
		verbose     bool
		proxyKind   string
		secretsDir  string
		internalDNS bool
		joinListen  string
		metrics     string
		lostTimeout time.Duration
		tls         tlsFlags
	)
	cmd := &cobra.Command{
		Use:     "server",
		Aliases: []string{"servers"},
		Short:   "Run the control plane (and, by default, this node's agent)",
		Long: "Run the control plane (and, by default, this node's agent).\n\n" +
			"Every control plane node runs `armadad server`. They elect a leader, which serves\n" +
			"the API and runs the reconcilers; the others stand by and take over within\n" +
			"seconds if it fails. Add control plane nodes with `armadad server join`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tuneGC(os.Getenv)
			log, err := newLogger(cmd.ErrOrStderr(), logFormat, verbose)
			if err != nil {
				return err
			}
			if err := server.CheckNodeLostTimeout(lostTimeout); err != nil {
				return fmt.Errorf("--node-lost-timeout: %w", err)
			}
			if tls.enabled {
				if err := server.CheckACMECA(tls.ca); err != nil {
					return fmt.Errorf("--acme-ca: %w", err)
				}
			}
			if server.CheckDNSProvider(tls.dnsProvider) != nil {
				return fmt.Errorf("unsupported --dns-provider %q (want cloudflare)", tls.dnsProvider)
			}
			if tls.dnsProvider != "" && !tls.enabled {
				return errors.New("--dns-provider needs --tls")
			}
			if (tls.dnsProvider != "") != (tls.dnsTokenFile != "") {
				return errors.New("--dns-provider and --dns-token-file go together")
			}
			if tls.dnsTokenFile != "" {
				// A bad token file should fail at startup, not when this
				// server first leads.
				if _, err := readTokenFile(tls.dnsTokenFile); err != nil {
					return err
				}
			}
			ctx := cmd.Context()
			// A mesh server's etcd member and API listen on its mesh
			// address, which exists once the tunnel is up (ADR 0049).
			ac, err := loadAgentConfig(dataDir)
			if errors.Is(err, fs.ErrNotExist) {
				// Not initialized: openState says so.
				ac, err = &agentConfig{}, nil
			}
			if err != nil {
				return err
			}
			if err := upMesh(dataDir, ac, nil, log); err != nil {
				return err
			}
			st, member, err := openState(ctx, dataDir, log)
			if err != nil {
				return err
			}
			defer func() { _ = member.Close() }()
			pem, err := readPrivate(dataDir, fileCACert, fileCAKey)
			if err != nil {
				return err
			}
			ca, err := pki.LoadCA(pem[0], pem[1])
			if err != nil {
				return err
			}
			// Renew before loading, so a server that was down past the
			// renewal point, or past expiry, starts with a valid
			// certificate.
			certs := &certRenewer{dataDir: dataDir, ca: ca, member: member, log: log, now: time.Now}
			// Only a server run as root from the default data directory
			// owns the machine's shared admin config.
			if os.Geteuid() == 0 && dataDir == defaultDataDir {
				certs.st, certs.adminConfig = st, clientconfig.SystemPath
			}
			certs.check()
			pem, err = readPrivate(dataDir, fileCACert, fileServerCert, fileServerKey)
			if err != nil {
				return err
			}
			id, err := serverIdentity(pem[1])
			if err != nil {
				return err
			}
			ip, err := serverIP(pem[1])
			if err != nil {
				return err
			}
			self, err := ownServer(ctx, st, id.Name)
			if err != nil {
				return err
			}
			listen := self.APIAddr
			if err := netutil.CheckPrivateListen(listen); err != nil {
				return err
			}
			serverCert, err := pki.NewServerCert(pem[0], pem[1], pem[2])
			if err != nil {
				return err
			}
			certs.server = serverCert
			tlsCfg := serverCert.TLS()
			joinAddr, err := resolveJoinListen(joinListen, listen)
			if err != nil {
				return err
			}
			// A mesh cluster's machines join over the leader's public
			// endpoint, while a join token is open (ADR 0049).
			joinPublic := ac.Network == store.NetworkMesh && joinAddr != ""
			if joinPublic {
				if joinAddr, err = meshJoinListen(joinAddr, ac.endpoint()); err != nil {
					return err
				}
			}
			// Machines of another site join over the leader's endpoint,
			// while a token for one is open (ADR 0050).
			var joinSiteAddr string
			if ep, perr := netip.ParseAddr(announcedEndpoint(ac, log)); !joinPublic && joinAddr != "" && perr == nil {
				if joinSiteAddr, err = meshJoinListen(joinAddr, ep); err != nil {
					return err
				}
			}
			if metrics != "" {
				if err := netutil.CheckPrivateListen(metrics); err != nil {
					return fmt.Errorf("--metrics-listen: %w", err)
				}
			}
			var joinTLS *stdtls.Config
			if joinAddr != "" {
				joinTLS = serverCert.JoinTLS()
			}
			keys, err := loadMasterKey(ctx, st, dataDir, log)
			if err != nil {
				return err
			}
			var trigger atomic.Pointer[server.Server]
			onCert := func(name string, err error) {
				if srv := trigger.Load(); srv != nil {
					srv.CertificateEvent(name, err)
					if err == nil {
						srv.Trigger()
					}
				}
			}
			if _, err := acmeListen(tls.listen, listen); err != nil {
				return err
			}
			if err := st.UpsertServer(ctx, store.Server{Name: id.Name, PrivateIP: ip.String(), APIAddr: listen, JoinAddr: joinAddr, MemberID: member.ID(),
				Schema: store.SchemaVersion(), Version: version.Get().Version}); err != nil {
				return err
			}

			// One term: a server for as long as this node leads. A change of
			// the cluster's server settings (ADR 0031) runs it again with
			// them, keeping the leadership.
			runTerm := func(ctx context.Context, fenced store.Store, restart func()) error {
				ts, err := resolveSettings(ctx, fenced, keys, cmd.Flags(), tls, metrics, lostTimeout, ip.String(), log)
				if err != nil {
					return fmt.Errorf("cluster settings: %w", err)
				}
				cfg := server.Config{
					Store: fenced, TLS: tlsCfg, Logger: log,
					Secrets: keys,
					CA:      ca, JoinAddr: joinAddr, JoinTLS: joinTLS, JoinPublic: joinPublic, JoinSiteAddr: joinSiteAddr, APIAddr: listen,
					NodeLostTimeout:   ts.lostTimeout,
					MetricsAddr:       ts.metrics,
					OnSettingsChanged: restart,
					Name:              id.Name, Cluster: etcd.Cluster{C: member.Client()},
					// The scheduled backups to a bucket (ADR 0051) hold
					// what armadad backup writes.
					ControlPlaneBackup: func(ctx context.Context, fn func(dir string) error) error {
						_, err := backup.Stage(ctx, dataDir, member.Client(), func(dir string, _ backup.Manifest) error { return fn(dir) })
						return err
					},
				}
				if ts.metrics != "" {
					if err := netutil.CheckPrivateListen(ts.metrics); err != nil {
						return fmt.Errorf("metrics: %w", err)
					}
				}
				certOpts, acmeAddr, tlsOn, err := certOptions(ts.certs, tls.listen, listen, log, onCert)
				if err != nil {
					return err
				}
				// Without certificates the apps are served over plain HTTP.
				cfg.PlainHTTP = !tlsOn
				if tlsOn {
					cm, stop, err := newCertManager(member.Client(), certOpts)
					if err != nil {
						return err
					}
					defer stop()
					cfg.Certs, cfg.ACMEAddr, cfg.ACMEEmail = cm, acmeAddr, ts.certs.email
					cfg.ACMECA, cfg.DNSProvider = ts.certs.ca, ts.certs.dnsProvider
				}
				srv, err := server.New(cfg)
				if err != nil {
					return err
				}
				trigger.Store(srv)
				defer trigger.Store(nil)
				lis, err := net.Listen("tcp", listen)
				if err != nil {
					return err
				}
				return srv.Serve(ctx, lis)
			}
			term := func(ctx context.Context, lead *etcd.Leadership) error {
				fenced := st.Fenced(lead.Fence())
				if err := upgradeState(ctx, fenced, log); err != nil {
					return err
				}
				restarting := false
				for tries := 0; ; tries++ {
					tctx, cancel := context.WithCancel(ctx)
					var again atomic.Bool
					err := runTerm(tctx, fenced, func() { again.Store(true); cancel() })
					cancel()
					switch {
					case ctx.Err() != nil:
						return err
					case again.Load():
						log.Info("cluster settings changed; applying them")
						restarting, tries = true, 0
					case restarting && errors.Is(err, syscall.EADDRINUSE) && tries < 20:
						// The last run's listeners close as it ends.
					default:
						return err
					}
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(250 * time.Millisecond):
					}
				}
			}

			g, ctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				certs.loop(ctx)
				return nil
			})
			g.Go(func() error {
				return lead(ctx, member, id.Name, log, func(ctx context.Context) error { return waitLeadReady(ctx, st, log) }, term)
			})
			if withAgent {
				certs.renewNode(ctx, st)
				known := knownServers(ctx, st, dataDir, log)
				g.Go(func() error {
					return runAgent(ctx, dataDir, known, proxyKind, secretsDir, internalDNS, unitServer, log)
				})
			}
			return g.Wait()
		},
	}
	f := cmd.Flags()
	f.StringVar(&dataDir, "data-dir", defaultDataDir, "directory for cluster state and keys")
	f.BoolVar(&withAgent, "agent", true, "also run this node's agent")
	f.StringVar(&logFormat, "log-format", "text", "log format: text or json")
	f.BoolVarP(&verbose, "verbose", "v", false, "debug logging")
	f.StringVar(&proxyKind, "proxy", "haproxy", "ingress proxy for the embedded agent: haproxy or none")
	f.StringVar(&secretsDir, "secrets-dir", defaultSecretsDir, "tmpfs directory for the embedded agent's secret files")
	f.BoolVar(&internalDNS, "internal-dns", true, "serve <app>.internal to containers on this node (needs --proxy haproxy)")
	f.StringVar(&joinListen, "join-listen", "", "private ip:port for joining nodes (default: API port + 1; \"off\" disables joining)")
	f.StringVar(&metrics, "metrics-listen", "", "private ip:port for the Prometheus metrics endpoint, served by the leader to metrics and admin certificates (default: off)")
	f.DurationVar(&lostTimeout, "node-lost-timeout", server.DefaultNodeLostTimeout, "how long a node may be unreachable before its replicas move to other nodes")
	tls.register(cmd)
	cmd.AddCommand(newServerJoinCommand())
	return cmd
}

// lead campaigns for leadership and runs term while this node leads, until
// ctx ends. A term that ends because leadership was lost (the node was cut
// off, or paused past its lease) is followed by a new campaign; a term that
// fails is fatal, so a misconfigured node does not keep winning elections.
func lead(ctx context.Context, member *etcd.Member, name string, log *slog.Logger, ready func(context.Context) error, term func(context.Context, *etcd.Leadership) error) error {
	log = log.With("component", "control-plane")
	for {
		if err := ready(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if leader, err := etcd.Leader(ctx, member.Client()); err == nil && leader != "" && leader != name {
			log.Info("standing by", "leader", leader)
		}
		l, err := etcd.Campaign(ctx, member.Client(), leaderLease, name)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Warn("leader election failed; retrying", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
		}
		log.Info("elected leader")
		tctx, cancel := context.WithCancel(ctx)
		go func() {
			select {
			case <-l.Done():
			case <-tctx.Done():
			}
			cancel()
		}()
		err = term(tctx, l)
		lost := tctx.Err() != nil && ctx.Err() == nil
		cancel()
		rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = l.Resign(rctx)
		rcancel()
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, errStandBy):
			log.Info("standing by until every server is upgraded")
		case lost:
			log.Warn("lost leadership; standing by")
		case err != nil:
			return err
		default:
			return errors.New("control plane stopped unexpectedly")
		}
	}
}

// serverIdentity returns the identity of a server certificate.
func serverIdentity(certPEM []byte) (pki.Identity, error) {
	cert, err := pki.ParseCertPEM(certPEM)
	if err != nil {
		return pki.Identity{}, err
	}
	id, err := pki.IdentityFromCert(cert)
	if err != nil || id.Kind != pki.KindServer {
		return pki.Identity{}, fmt.Errorf("%s is not a server certificate", fileServerCert)
	}
	return id, nil
}

// ownServer returns this control plane node's record.
func ownServer(ctx context.Context, st store.Store, name string) (store.Server, error) {
	servers, err := st.ListServers(ctx)
	if err != nil {
		return store.Server{}, err
	}
	for _, s := range servers {
		if s.Name == name {
			return s, nil
		}
	}
	return store.Server{}, fmt.Errorf("server %s is not part of this cluster (it was removed, or the state is from another cluster)", name)
}

func newAgentCommand() *cobra.Command {
	var (
		dataDir     string
		servers     []string
		logFormat   string
		verbose     bool
		proxyKind   string
		secretsDir  string
		internalDNS bool
	)
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run the node agent",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tuneGC(os.Getenv)
			log, err := newLogger(cmd.ErrOrStderr(), logFormat, verbose)
			if err != nil {
				return err
			}
			return runAgent(cmd.Context(), dataDir, servers, proxyKind, secretsDir, internalDNS, unitAgent, log)
		},
	}
	f := cmd.Flags()
	f.StringVar(&dataDir, "data-dir", defaultDataDir, "directory holding the node certificate")
	f.StringSliceVar(&servers, "server", nil, "control plane addresses (default: from agent.json, kept up to date by the server)")
	f.StringVar(&logFormat, "log-format", "text", "log format: text or json")
	f.BoolVarP(&verbose, "verbose", "v", false, "debug logging")
	f.StringVar(&proxyKind, "proxy", "haproxy", "ingress proxy: haproxy or none")
	f.StringVar(&secretsDir, "secrets-dir", defaultSecretsDir, "tmpfs directory for secret files")
	f.BoolVar(&internalDNS, "internal-dns", true, "serve <app>.internal to containers on this node (needs --proxy haproxy)")
	return cmd
}

// unit is the systemd unit the agent runs in, restarted after the leader
// moved the node to the supervisor runtime (ADR 0054).
func runAgent(ctx context.Context, dataDir string, servers []string, proxyKind, secretsDir string, internalDNS bool, unit string, log *slog.Logger) error {
	unlock, err := lockDataDir(dataDir)
	if err != nil {
		return err
	}
	defer unlock()
	ac, err := loadAgentConfig(dataDir)
	if err != nil {
		return err
	}
	if len(servers) > 0 {
		if _, err := clientconfig.CheckServers(servers); err != nil {
			return err
		}
		ac.Servers = servers
	}
	if _, err := netutil.CheckPrivateIP(ac.PrivateIP); err != nil {
		return err
	}
	// A mesh node reaches the servers at mesh addresses (ADR 0049).
	if err := upMesh(dataDir, ac, nil, log); err != nil {
		return err
	}
	writeMachineServers(dataDir, ac.Servers, log)
	creds, err := agent.LoadCredentials(dataDir, ac.NodeID)
	if err != nil {
		return err
	}
	tlsCfg, err := creds.TLSConfig()
	if err != nil {
		return err
	}
	// The connection follows the control plane: the server sends the
	// current list of servers, which is saved for the next start and
	// applied to the live connection.
	var (
		connMu  sync.Mutex
		current *clientconfig.Conn
		addrs   = ac.Servers
		// acMu guards ac between its writers: the control plane list and
		// the move to the supervisor runtime.
		acMu sync.Mutex
	)
	conn, err := agent.NewServerConn(func() (*grpc.ClientConn, error) {
		connMu.Lock()
		defer connMu.Unlock()
		// Assignments carry the node's replicas, secrets included, and the
		// cluster's proxy configuration.
		c, err := clientconfig.Dial(addrs, tlsCfg, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(agentMaxRecv)))
		if err != nil {
			return nil, err
		}
		current = c
		return c.ClientConn, nil
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	onServers := func(list []string) {
		if _, err := clientconfig.CheckServers(list); err != nil {
			log.Warn("ignoring invalid control plane list", "err", err)
			return
		}
		connMu.Lock()
		addrs = list
		current.SetServers(list)
		connMu.Unlock()
		// Only the list changes, in agent.json as it is now (ac is what the
		// agent started with).
		acMu.Lock()
		ac.Servers = slices.Clone(list)
		_, err := updateAgentConfig(dataDir, func(c *agentConfig) error {
			c.Servers = list
			return nil
		})
		acMu.Unlock()
		if err != nil {
			log.Warn("save control plane list", "err", err)
			return
		}
		writeMachineServers(dataDir, list, log)
		log.Info("control plane updated", "servers", strings.Join(list, ","))
	}

	if err := checkProxyKind(proxyKind); err != nil {
		return err
	}
	// Only the agent moves images between the runtime's stores.
	ac.agent = true
	rt, err := newDriver(dataDir, ac)
	if err != nil {
		return err
	}
	if err := waitRuntime(ctx, rt, log); err != nil {
		return err
	}
	var dns nodeDNS
	var internalIP string
	if proxyKind != "none" && internalDNS {
		if dns = startInternalDNS(ctx, rt, dataDir, log); dns != nil {
			internalIP = dns.Address()
		}
	}
	cnet, networkKey, err := newClusterNet(dataDir, ac, log)
	if err != nil {
		return err
	}
	// On the cluster network replicas live on the node subnet and publish
	// no port; other nodes reach them through the tunnel (ADR 0025).
	unpublished := cnet != nil && ac.ContainerSubnet != ""
	subnet := ""
	if unpublished {
		subnet = ac.ContainerSubnet
	}
	px, err := newProxy(proxyKind, dataDir, ac.PrivateIP, internalIP, subnet, rt, log)
	if err != nil {
		return err
	}
	// The node's readings go through armada-node with the runtime's work
	// (ADR 0054 step 5): runtimeAgent "go", containerd, or a pack without
	// it keep Go's code.
	readings := nodeprog.New(ac.runtimeProgram(dataDir))
	acfg := agent.Config{
		NodeID:     ac.NodeID,
		PrivateIP:  ac.PrivateIP,
		Driver:     rt,
		Client:     conn.Client(),
		Logger:     log,
		Proxy:      px,
		Check:      probeCheck,
		SecretsDir: prepareSecretsDir(secretsDir, log),
		VolumesDir: prepareVolumesDir(filepath.Join(dataDir, backup.DirVolumes), log),
		NFSDir:     filepath.Join(dataDir, backup.DirNFS),
		Servers:    ac.Servers,
		OnServers:  onServers,

		VolumeProgram: ac.volumeProgram(dataDir),

		UsageInterval: usageInterval,
		Conntrack:     conntrack.New().WithProgram(readings),
		Node:          readings,
	}
	if px != nil {
		acfg.WakeSocket = haproxy.WakeSocket(filepath.Join(dataDir, dirHAProxy))
	}
	if dns != nil {
		acfg.DNS = dns
	}
	if cnet != nil {
		acfg.Network, acfg.NetworkKey, acfg.Unpublished = cnet, networkKey, unpublished
		acfg.Endpoint, acfg.BehindNAT = announcedEndpoint(ac, log), ac.BehindNAT
	}
	if cmp.Or(ac.Runtime, runtimeEmbedded) == runtimeEmbedded {
		// The leader moves containerd nodes to the supervisor runtime one
		// at a time (ADR 0054, "The runtime's move", step 4).
		mv := nodeMove{dataDir: dataDir, mu: &acMu, ac: ac, rt: rt, unit: unit, systemctl: systemctl, exit: os.Exit, log: log}
		if px != nil {
			// The image the restarted agent's proxy starts from, pulled
			// while this one still serves.
			mv.images = []string{haproxy.Image}
		}
		acfg.MoveRuntime, acfg.PrepareRuntimeMove = mv.run, mv.prepare
		acfg.OnRuntimeMove = func(p *armadav1.RuntimeMovePlan) {
			if err := saveRuntimeMovePlan(dataDir, p); err != nil {
				log.Warn("save the leader's plan for this node's runtime", "err", err)
			}
		}
	} else {
		_ = saveRuntimeMovePlan(dataDir, nil)
	}
	a := agent.New(acfg)
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return a.Run(ctx) })
	if dns != nil {
		// The resolver outlives the agent: armada-dns runs in a unit of its
		// own and answers while armadad restarts (ADR 0053), and the
		// resolver inside armadad answers until the process exits. The
		// containers keep running meanwhile, and the names and callers it
		// knows stay right for them.
		go func() {
			if err := dns.Run(context.WithoutCancel(ctx)); err != nil {
				log.Warn("internal DNS stopped", "err", err)
			}
		}()
	}
	g.Go(func() error {
		agent.RenewLoop(ctx, creds, conn, renewCheck, log.With("component", "agent"))
		return nil
	})
	return g.Wait()
}

// knownServers is the control plane list a server machine's agent starts
// with: agent.json's, then every server's API address the state records,
// so the agent finds the leader even when agent.json names only this
// machine (a standby answers no API). nil, and agent.json's list alone,
// when either cannot be read.
func knownServers(ctx context.Context, st store.Store, dataDir string, log *slog.Logger) []string {
	ac, err := loadAgentConfig(dataDir)
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	servers, err := st.ListServers(ctx)
	if err != nil {
		log.Warn("read the control plane's servers for this machine's agent; it starts with agent.json's list", "err", err)
		return nil
	}
	list := slices.Clone(ac.Servers)
	for _, sv := range servers {
		if sv.APIAddr != "" && !slices.Contains(list, sv.APIAddr) {
			list = append(list, sv.APIAddr)
		}
	}
	if _, err := clientconfig.CheckServers(list); err != nil {
		log.Warn("the control plane's servers are not a valid list; the agent starts with agent.json's", "err", err)
		return nil
	}
	return list
}

// newClusterNet returns the node's side of the cluster network (ADR 0025),
// or nil for a node of a cluster without one, with the node's public key.
// The key is made the first time, in both modes, so later sites need no
// migration. Tests replace it.
var newClusterNet = func(dataDir string, ac *agentConfig, log *slog.Logger) (agent.Network, string, error) {
	if ac.Network == "" {
		return nil, "", nil
	}
	key, err := clusternet.LoadOrCreateKey(filepath.Join(dataDir, fileNetworkKey))
	if err != nil {
		return nil, "", fmt.Errorf("cluster network key: %w", err)
	}
	cfg, err := meshConfig(dataDir, ac, key, log)
	if err != nil {
		return nil, "", err
	}
	n, err := clusternet.New(cfg)
	if err != nil {
		return nil, "", err
	}
	return &nodeNet{clusterNet: n, dataDir: dataDir, mode: ac.Network, log: log}, key.Public(), nil
}

// clusterNet is what the agent gets from clusternet.Net. nodeNet embeds it,
// so every optional interface the agent looks for on its Network must be
// listed here: a method missing from it is hidden from the agent, which
// then never offers the feature (key rotation, unreachable peers, userspace
// WireGuard).
type clusterNet interface {
	agent.NetworkSwitcher
	UnreachablePeers() []string
	RotateKey() (string, error)
	WireGuardUserspace() bool
}

var (
	_ clusterNet              = (*clusternet.Net)(nil)
	_ agent.NetworkSwitcher   = (*nodeNet)(nil)
	_ agent.PeerChecker       = (*nodeNet)(nil)
	_ agent.KeyRotator        = (*nodeNet)(nil)
	_ agent.WireGuardReporter = (*nodeNet)(nil)
)

// nodeNet records in agent.json the mode a switch of the cluster network
// ends in (ADR 0050), so the node starts in it: the containers' MTU and
// armadad doctor follow the mode recorded there.
type nodeNet struct {
	clusterNet
	dataDir string
	log     *slog.Logger

	mu   sync.Mutex
	mode string // as agent.json records it
}

func (n *nodeNet) Apply(ctx context.Context, cfg *armadav1.NetworkConfig, local map[netip.Addr]string) error {
	if err := n.clusterNet.Apply(ctx, cfg, local); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if cfg.GetSwitchTo() != "" || cfg.GetMode() == n.mode || n.mode == store.NetworkMesh || cfg.GetMode() == store.NetworkMesh {
		return nil
	}
	ac, err := updateAgentConfig(n.dataDir, func(c *agentConfig) error {
		c.Network = cfg.GetMode()
		return nil
	})
	if err != nil {
		n.log.Warn("record the cluster network's new mode", "err", err)
		return nil
	}
	n.log.Info("the cluster network's mode changed; containers created after the agent's next start use its MTU", "mode", ac.Network)
	n.mode = ac.Network
	return nil
}

// resolvConf is the host resolver configuration; tests replace it.
var resolvConf = "/etc/resolv.conf"

// usageInterval is how often the agent samples its replicas for armada app top;
// 0 is the agent's default (tests shorten it).
var usageInterval time.Duration

// nodeDNS is the node-local resolver the agent keeps in step: armada-dns
// (dnsserver.Process), or the resolver inside armadad (dnsserver.Server).
type nodeDNS interface {
	agent.InternalDNS
	Run(ctx context.Context) error
}

// dnsLauncher runs armada-dns; nil is systemd (tests replace it).
var dnsLauncher dnsserver.Launcher

// startInternalDNS prepares the node-local resolver on the container bridge
// gateway: armada-dns from the runtime pack (ADR 0053), else the resolver
// inside armadad. Internal ingress is optional: if anything is missing it
// logs why and returns nil, and containers keep the engine's default DNS.
func startInternalDNS(ctx context.Context, rt runtime.Driver, dataDir string, log *slog.Logger) nodeDNS {
	disabled := func(reason string, err error) nodeDNS {
		log.Warn("internal ingress and DNS disabled on this node", "reason", reason, "err", err)
		return nil
	}
	bi, ok := rt.(runtime.BridgeInspector)
	if !ok || !runtime.HasBridge(rt) {
		return disabled("the container runtime cannot report its bridge network", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	br, err := bi.Bridge(ctx)
	if err != nil {
		return disabled("no container bridge", err)
	}
	ups, err := dnsserver.HostUpstreams(resolvConf)
	if err != nil {
		return disabled("no upstream resolvers for other names", err)
	}
	if bin, err := filepath.EvalSymlinks(filepath.Join(runtimePaths(dataDir).Bin(), embedded.BinDNS)); err == nil {
		p, err := dnsserver.StartProcess(ctx, dnsserver.ProcessConfig{
			Bin: bin, Addr: br.Gateway, Clients: br.Subnet, Upstreams: ups,
			Dir: filepath.Join(runDir, "dns"), Launcher: dnsLauncher, Logger: log,
		})
		if err == nil {
			return p
		}
		log.Warn("armada-dns did not start; the resolver runs inside armadad", "err", err)
		if dnsLauncher == nil {
			// Free the port for it.
			if err := dnsserver.StopUnits(ctx); err != nil {
				log.Warn("cannot stop armada-dns", "err", err)
			}
		}
	}
	dns, err := dnsserver.New(dnsserver.Config{Addr: br.Gateway, Clients: br.Subnet, Upstreams: ups, Logger: log})
	if err != nil {
		return disabled("invalid bridge", err)
	}
	if err := dns.Listen(); err != nil {
		return disabled("cannot listen on the bridge gateway", err)
	}
	return dns
}

// resolveJoinListen returns the join listener address: flag "off" disables
// it, an empty flag means the API address with the next port.
func resolveJoinListen(flag, api string) (string, error) {
	switch flag {
	case "off":
		return "", nil
	case "":
		host, port, err := net.SplitHostPort(api)
		if err != nil {
			return "", err
		}
		p, err := strconv.Atoi(port)
		if err != nil || p >= 65535 {
			return "", fmt.Errorf("cannot derive a join port from %s; set --join-listen", api)
		}
		return net.JoinHostPort(host, strconv.Itoa(p+1)), nil
	}
	if err := netutil.CheckPrivateListen(flag); err != nil {
		return "", fmt.Errorf("--join-listen: %w", err)
	}
	return flag, nil
}

// prepareSecretsDir creates the agent's secret file directory and returns
// it, or "" (secret files disabled) if it is not on tmpfs.
func prepareSecretsDir(dir string, log *slog.Logger) string {
	if dir == "" {
		return ""
	}
	if err := fsutil.MkdirPrivate(dir); err != nil {
		log.Warn("secret files disabled", "dir", dir, "err", err)
		return ""
	}
	if err := checkTmpfs(dir); err != nil {
		log.Warn("secret files disabled: plaintext must not reach a disk", "dir", dir, "err", err)
		return ""
	}
	return dir
}

// prepareVolumesDir readies the node's volume directory; on failure the node
// announces no volumes, so no app with volumes is placed on it.
func prepareVolumesDir(dir string, log *slog.Logger) string {
	if err := agent.PrepareVolumesDir(dir); err != nil {
		log.Warn("volumes disabled", "dir", dir, "err", err)
		return ""
	}
	return dir
}

// loadMasterKey loads the secrets master key. A cluster initialized before
// secrets existed gets a new key; otherwise the key must be the one recorded
// in the state database, so a lost or swapped key file is caught at start
// instead of producing secrets nobody can decrypt.
func loadMasterKey(ctx context.Context, st store.Store, dataDir string, log *slog.Logger) (*secrets.Keyring, error) {
	path := filepath.Join(dataDir, fileMasterKey)
	recorded, err := st.GetMeta(ctx, metaMasterKey)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	keys, err := secrets.LoadKeyFile(path)
	if errors.Is(err, fs.ErrNotExist) && recorded == "" {
		if err := secrets.GenerateKeyFile(path); err != nil {
			return nil, fmt.Errorf("master key: %w", err)
		}
		log.Warn("created a new secrets master key; back it up with the state database", "path", path)
		keys, err = secrets.LoadKeyFile(path)
	}
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("master key %s is missing; restore it from a backup (key id %s)", path, recorded)
		}
		return nil, fmt.Errorf("master key: %w", err)
	}
	switch recorded {
	case keys.ID():
	case "":
		if err := st.SetMeta(ctx, metaMasterKey, keys.ID()); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("master key %s (id %s) is not the key this cluster's secrets use (id %s); restore the right key", path, keys.ID(), recorded)
	}
	return keys, nil
}

// errStandBy ends a term without failing: the server may not lead yet.
var errStandBy = errors.New("not ready to lead")

// leadReady reports whether this server may lead (ADR 0012). A binary that
// knows a newer state schema than the cluster uses waits until every
// server knows it, so servers still on the old version keep leading during
// a rolling upgrade and the migration runs only once none of them is left.
// State written by a newer binary is an error: downgrades are refused.
func leadReady(ctx context.Context, st *store.Etcd, mine int) (bool, []string, error) {
	stored, err := st.StoredSchema(ctx)
	if err != nil {
		return false, nil, err
	}
	switch {
	case stored > mine:
		return false, nil, fmt.Errorf("the state was written by a newer Armada (schema %d, this binary knows %d); run the newer version (downgrades are not supported)", stored, mine)
	case stored == mine:
		return true, nil, nil
	}
	servers, err := st.ListServers(ctx)
	if err != nil {
		return false, nil, err
	}
	var old []string
	for _, s := range servers {
		if s.Schema < mine {
			old = append(old, s.Name)
		}
	}
	return len(old) == 0, old, nil
}

// leadReadyPoll is how often a server waiting to lead checks again.
var leadReadyPoll = 5 * time.Second

// waitLeadReady blocks until leadReady allows this server to lead.
func waitLeadReady(ctx context.Context, st *store.Etcd, log *slog.Logger) error {
	var waiting string
	for {
		ok, old, err := leadReady(ctx, st, store.SchemaVersion())
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if w := strings.Join(old, ","); w != waiting {
			waiting = w
			log.Warn("standing by: the state migrates to this version's schema once these servers are upgraded", "servers", old)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(leadReadyPoll):
		}
	}
}

// upgradeState runs at the start of a term, on the store fenced to it:
// it checks again that this server may lead and migrates the state.
func upgradeState(ctx context.Context, st *store.Etcd, log *slog.Logger) error {
	ok, _, err := leadReady(ctx, st, store.SchemaVersion())
	if err != nil {
		return err
	}
	if !ok {
		return errStandBy
	}
	from, err := st.Migrate(ctx)
	if err != nil {
		return err
	}
	if to := store.SchemaVersion(); from != to {
		log.Info("state migrated", "from_schema", from, "to_schema", to)
	}
	return nil
}

// writeMachineServers keeps clientconfig.ServersPath current for client
// configs on this machine. Only the agent of the machine's own data
// directory, run as root, writes it; failing only warns.
func writeMachineServers(dataDir string, servers []string, log *slog.Logger) {
	if os.Geteuid() != 0 || filepath.Clean(dataDir) != defaultDataDir || len(servers) == 0 {
		return
	}
	if err := clientconfig.WriteMachineServers(servers); err != nil {
		log.Warn("write the control plane list for clients", "err", err)
	}
}
