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
	Logger    *slog.Logger
}

// Server is the node-local DNS server.
type Server struct {
	cfg   Config
	log   *slog.Logger
	names atomic.Pointer[map[string]bool]

	pc net.PacketConn
	l  net.Listener

	// inflight bounds concurrent upstream queries, so a busy or hostile
	// container cannot exhaust the agent's sockets.
	inflight chan struct{}
}

// maxInflight is the number of queries forwarded at the same time; beyond
// it clients get SERVFAIL and retry.
const maxInflight = 128

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
	s := &Server{cfg: cfg, log: cfg.Logger.With("component", "dns"), inflight: make(chan struct{}, maxInflight)}
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
	s.pc, s.l = pc, l
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
		_ = w.WriteMsg(s.answer(req, q, name))
		return
	}
	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(resp)
		return
	}
	_ = w.WriteMsg(s.forward(req, w.RemoteAddr().Network()))
}

func (s *Server) allowed(a net.Addr) bool {
	var ip netip.Addr
	switch v := a.(type) {
	case *net.UDPAddr:
		ip, _ = netip.AddrFromSlice(v.IP)
	case *net.TCPAddr:
		ip, _ = netip.AddrFromSlice(v.IP)
	}
	return ip.IsValid() && s.cfg.Clients.Contains(ip.Unmap())
}

// answer resolves a name in the internal zone authoritatively.
func (s *Server) answer(req *dns.Msg, q dns.Question, name string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	app := strings.TrimSuffix(name, "."+zone)
	if strings.Contains(app, ".") || !spec.ValidHostName(app) || !(*s.names.Load())[app] {
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
