// Package dnsserver is the node-local resolver for app containers. It
// answers <app>.internal with the node's internal ingress address and
// forwards every other query to the host's upstream resolvers. It listens
// only on the container bridge gateway and answers only clients on that
// bridge.
package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/spec"
)

const (
	// ttl is short so scaling and removing apps show up quickly.
	ttl            = 5
	forwardTimeout = 2 * time.Second
	zone           = "internal."
)

// Config configures a Server.
type Config struct {
	// Addr is where the server listens and what <app>.internal resolves to:
	// the bridge gateway, where the internal ingress frontend listens.
	Addr netip.Addr
	// Port defaults to 53; tests use another one.
	Port uint16
	// Clients is the only source range answered (the bridge subnet).
	Clients netip.Prefix
	// Upstreams are ip:port resolvers for names outside .internal.
	Upstreams []string
	// UnknownWait is how long a lookup of an internal name from an
	// address the client map does not hold waits for the map to learn it
	// (default 3s; see awaitClient).
	UnknownWait time.Duration
	// StartWait is how long a lookup of an internal name waits for the
	// first SetNames (default 10s; see awaitClient).
	StartWait time.Duration
	Logger    *slog.Logger
}

// Server is the node-local DNS server.
type Server struct {
	cfg   Config
	log   *slog.Logger
	names atomic.Pointer[map[string]bool]
	// named is set by the first SetNames: until then the server does not
	// know which names exist.
	named atomic.Bool
	// clients maps the node's container addresses to their app IDs; nil
	// answers every name to every client.
	clients atomic.Pointer[map[netip.Addr]string]

	pc net.PacketConn
	l  net.Listener

	// inflight bounds concurrent upstream queries, so a busy or hostile
	// container cannot exhaust the agent's sockets.
	inflight chan struct{}

	// perClient counts each client address's forwarded queries in flight
	// and its open TCP connections, so one container cannot take every
	// slot of the node from the containers of other spaces.
	mu        sync.Mutex
	perClient map[netip.Addr]int
	perConn   map[netip.Addr]int
	// learned is closed, and replaced, whenever SetClients or SetNames
	// runs.
	learned chan struct{}
}

const (
	// maxInflight is the number of queries forwarded at the same time;
	// beyond it clients get SERVFAIL and retry.
	maxInflight = 128
	// maxInflightPerClient is one client address's share of maxInflight:
	// a client past it gets SERVFAIL without taking a node slot.
	maxInflightPerClient = 16
	// maxConnsPerClient bounds one client address's open TCP connections;
	// further connections are closed at once.
	maxConnsPerClient = 16
	// defaultUnknownWait covers the time between a container's start and
	// the agent telling the server its address (Config.UnknownWait).
	defaultUnknownWait = 3 * time.Second
	// defaultStartWait covers an agent's start until its first proxy
	// configuration, which waits for the leader: when the leader itself
	// restarts, an election comes first (Config.StartWait).
	defaultStartWait = 10 * time.Second
)

// New validates cfg. The listen address must be private.
func New(cfg Config) (*Server, error) {
	if !cfg.Addr.IsValid() || !netutil.IsPrivate(cfg.Addr) {
		return nil, fmt.Errorf("dns: listen address %s must be a private IP", cfg.Addr)
	}
	if !cfg.Clients.IsValid() {
		return nil, errors.New("dns: client range is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 53
	}
	if cfg.UnknownWait == 0 {
		cfg.UnknownWait = defaultUnknownWait
	}
	if cfg.StartWait == 0 {
		cfg.StartWait = defaultStartWait
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	self := netip.AddrPortFrom(cfg.Addr, cfg.Port).String()
	var ups []string
	for _, u := range cfg.Upstreams {
		// Forwarding to ourselves would loop.
		if u != self {
			ups = append(ups, u)
		}
	}
	cfg.Upstreams = ups
	s := &Server{cfg: cfg, log: cfg.Logger.With("component", "dns"), inflight: make(chan struct{}, maxInflight),
		perClient: map[netip.Addr]int{}, perConn: map[netip.Addr]int{}, learned: make(chan struct{})}
	s.names.Store(&map[string]bool{})
	return s, nil
}

// Address returns the nameserver address for containers.
func (s *Server) Address() string { return s.cfg.Addr.String() }

// SetNames replaces the set of names (apps, and <label>--<app> for
// revision labels) that resolve under .internal.
func (s *Server) SetNames(apps []string) {
	m := make(map[string]bool, len(apps))
	for _, a := range apps {
		m[a] = true
	}
	s.names.Store(&m)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.named.Store(true)
	close(s.learned)
	s.learned = make(chan struct{})
}

// SetClients maps the addresses of the node's containers to their app IDs.
// From then on a container resolves only the names of its own space
// (ADR 0026), and an address not in the map resolves no internal name.
func (s *Server) SetClients(clients map[netip.Addr]string) {
	m := make(map[netip.Addr]string, len(clients))
	for a, app := range clients {
		m[a] = app
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients.Store(&m)
	close(s.learned)
	s.learned = make(chan struct{})
}

// awaitClient holds a lookup of an internal name until the server can
// answer it: from a container the client map does not hold yet, until the
// map learns it or UnknownWait passes (a container runs before the agent
// hears of its address); and before the first SetNames, until it comes or
// StartWait passes (an agent that just started, with its containers still
// running, has not received its configuration yet). Either would otherwise
// get NXDOMAIN and fail at once. Each client holds at most
// maxInflightPerClient lookups; past that, and for the server's own
// address, the answer comes at once.
func (s *Server) awaitClient(client netip.Addr) {
	if !client.IsValid() || client == s.cfg.Addr || s.answerable(client) {
		return
	}
	if !s.take(s.perClient, client, maxInflightPerClient) {
		return
	}
	defer s.release(s.perClient, client)
	wait := s.cfg.UnknownWait
	if !s.named.Load() {
		wait = s.cfg.StartWait
	}
	timeout := time.NewTimer(wait)
	defer timeout.Stop()
	for {
		// The channel first: a SetClients or SetNames after the check
		// closes it.
		s.mu.Lock()
		learned := s.learned
		s.mu.Unlock()
		if s.answerable(client) {
			return
		}
		select {
		case <-learned:
		case <-timeout.C:
			return
		}
	}
}

// answerable reports whether the server knows the names and the client.
func (s *Server) answerable(client netip.Addr) bool {
	return s.named.Load() && s.known(client)
}

// known reports whether the client map holds client; with no map, every
// client is.
func (s *Server) known(client netip.Addr) bool {
	clients := s.clients.Load()
	if clients == nil {
		return true
	}
	_, ok := (*clients)[client]
	return ok
}

// Listen opens the UDP and TCP sockets, so a caller learns about a busy
// port before relying on the server.
func (s *Server) Listen() error {
	addr := netip.AddrPortFrom(s.cfg.Addr, s.cfg.Port).String()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("dns: %w", err)
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		_ = pc.Close()
		return fmt.Errorf("dns: %w", err)
	}
	s.pc, s.l = pc, &clientListener{Listener: l, s: s}
	return nil
}

// Run serves UDP and TCP until ctx is cancelled, calling Listen first if
// needed.
func (s *Server) Run(ctx context.Context) error {
	if s.pc == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	addr := netip.AddrPortFrom(s.cfg.Addr, s.cfg.Port).String()
	pc, l := s.pc, s.l
	var err error
	var started sync.WaitGroup
	started.Add(2)
	servers := []*dns.Server{
		{PacketConn: pc, Handler: s, ReadTimeout: 5 * time.Second, NotifyStartedFunc: started.Done},
		{Listener: l, Handler: s, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, NotifyStartedFunc: started.Done},
	}
	var wg sync.WaitGroup
	errc := make(chan error, len(servers))
	for _, srv := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errc <- srv.ActivateAndServe()
		}()
	}
	// Shutdown only works on a started server.
	started.Wait()
	s.log.Info("internal DNS listening", "addr", addr, "upstreams", s.cfg.Upstreams)
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	for _, srv := range servers {
		_ = srv.Shutdown()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if !s.allowed(w.RemoteAddr()) {
		// Not a container on this node: no answer at all, so the server
		// cannot be used as an open resolver or reflector.
		return
	}
	if req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 || req.Response {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeNotImplemented)
		_ = w.WriteMsg(resp)
		return
	}
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	if name == zone || strings.HasSuffix(name, "."+zone) {
		client := remoteIP(w.RemoteAddr())
		s.awaitClient(client)
		_ = w.WriteMsg(s.answer(req, q, name, client))
		return
	}
	// The client's own share first, so a client past it never holds a
	// node slot another client could use.
	client := remoteIP(w.RemoteAddr())
	if !s.take(s.perClient, client, maxInflightPerClient) {
		s.fail(w, req)
		return
	}
	defer s.release(s.perClient, client)
	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		s.fail(w, req)
		return
	}
	_ = w.WriteMsg(s.forward(req, w.RemoteAddr().Network()))
}

func (s *Server) fail(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeServerFailure)
	_ = w.WriteMsg(resp)
}

// take counts one more use by client in m unless it already has limit.
func (s *Server) take(m map[netip.Addr]int, client netip.Addr, limit int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m[client] >= limit {
		return false
	}
	m[client]++
	return true
}

func (s *Server) release(m map[netip.Addr]int, client netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m[client]--; m[client] <= 0 {
		delete(m, client)
	}
}

// clientListener closes a TCP connection at once when its client address
// already has maxConnsPerClient open.
type clientListener struct {
	net.Listener
	s *Server
}

func (l *clientListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := remoteIP(c.RemoteAddr())
		if !l.s.take(l.s.perConn, ip, maxConnsPerClient) {
			_ = c.Close()
			continue
		}
		return &clientConn{Conn: c, s: l.s, ip: ip}, nil
	}
}

type clientConn struct {
	net.Conn
	s    *Server
	ip   netip.Addr
	once sync.Once
}

func (c *clientConn) Close() error {
	c.once.Do(func() { c.s.release(c.s.perConn, c.ip) })
	return c.Conn.Close()
}

func (s *Server) allowed(a net.Addr) bool {
	ip := remoteIP(a)
	return ip.IsValid() && s.cfg.Clients.Contains(ip)
}

func remoteIP(a net.Addr) netip.Addr {
	var ip netip.Addr
	switch v := a.(type) {
	case *net.UDPAddr:
		ip, _ = netip.AddrFromSlice(v.IP)
	case *net.TCPAddr:
		ip, _ = netip.AddrFromSlice(v.IP)
	}
	return ip.Unmap()
}

// sees reports whether the container at client may resolve host (an app ID
// or <label>--<app ID>): always without a client map, else only within its
// own space.
func (s *Server) sees(client netip.Addr, host string) bool {
	clients := s.clients.Load()
	if clients == nil {
		return true
	}
	app, ok := (*clients)[client]
	if !ok {
		return false
	}
	if _, id, labelled := strings.Cut(host, "--"); labelled {
		host = id
	}
	mine, _, ok1 := spec.SplitAppID(app)
	theirs, _, ok2 := spec.SplitAppID(host)
	return ok1 && ok2 && mine == theirs
}

// answer resolves a name in the internal zone authoritatively.
func (s *Server) answer(req *dns.Msg, q dns.Question, name string, client netip.Addr) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	app := strings.TrimSuffix(name, "."+zone)
	if !spec.ValidHostName(app) || !(*s.names.Load())[app] || !s.sees(client, app) {
		resp.Rcode = dns.RcodeNameError
		return resp
	}
	if q.Qclass == dns.ClassINET && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY) {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   s.cfg.Addr.AsSlice(),
		})
	}
	// Other types of a known name: an empty answer (NODATA).
	return resp
}

// forward relays a query to the first upstream that answers.
func (s *Server) forward(req *dns.Msg, network string) *dns.Msg {
	c := &dns.Client{Net: network, Timeout: forwardTimeout}
	for _, up := range s.cfg.Upstreams {
		resp, _, err := c.Exchange(req, up)
		if err == nil && resp != nil {
			resp.Id = req.Id
			return resp
		}
		s.log.Debug("upstream DNS failed", "upstream", up, "err", err)
	}
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeServerFailure)
	return resp
}

// HostUpstreams reads the host's resolvers from a resolv.conf file.
func HostUpstreams(path string) ([]string, error) {
	cc, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, srv := range cc.Servers {
		out = append(out, net.JoinHostPort(srv, cc.Port))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no nameservers in %s", path)
	}
	return out, nil
}
