package dnsserver

import (
	"context"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// freePort is a port free for both UDP and TCP on 127.0.0.1: the resolver
// binds both, and on a busy machine a port free for UDP can be one of TCP's
// ephemeral ports.
func freePort(t *testing.T) uint16 {
	t.Helper()
	for range 50 {
		l, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.LocalAddr().(*net.UDPAddr).Port
		tl, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		_ = l.Close()
		if err != nil {
			continue
		}
		_ = tl.Close()
		return uint16(port)
	}
	t.Fatal("no port free for both UDP and TCP")
	return 0
}

// upstream answers every A query with 192.0.2.7.
func upstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.7")})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func start(t *testing.T, clients string, upstreams ...string) (*Server, string) {
	t.Helper()
	return startWith(t, Config{}, clients, upstreams...)
}

// startWith is start with the settings of base the tests choose.
func startWith(t *testing.T, base Config, clients string, upstreams ...string) (*Server, string) {
	t.Helper()
	// The port is bound before anything is asked: a free port can be taken by
	// another parallel test's server between freePort and the bind, and that
	// server would answer in this one's place.
	var (
		s    *Server
		port uint16
	)
	for attempt := 0; ; attempt++ {
		port = freePort(t)
		var err error
		cfg := base
		cfg.Addr, cfg.Port, cfg.Clients, cfg.Upstreams = netip.MustParseAddr("127.0.0.1"), port, netip.MustParsePrefix(clients), upstreams
		if s, err = New(cfg); err != nil {
			t.Fatal(err)
		}
		if err = s.Listen(); err == nil {
			break
		} else if attempt == 9 {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String()
	// Wait until it answers.
	for range 50 {
		if _, _, err := (&dns.Client{Timeout: 100 * time.Millisecond}).Exchange(query("x.internal.", dns.TypeA), addr); err == nil || clients != "127.0.0.0/8" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return s, addr
}

func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	return m
}

func ask(t *testing.T, addr, network, name string, qtype uint16) *dns.Msg {
	t.Helper()
	r, _, err := (&dns.Client{Net: network, Timeout: time.Second}).Exchange(query(name, qtype), addr)
	if err != nil {
		t.Fatalf("%s %s: %v", network, name, err)
	}
	return r
}

func TestInternalNames(t *testing.T) {
	t.Parallel()
	s, addr := start(t, "127.0.0.0/8")
	s.SetNames([]string{"shop-api", "web", "canary--web", "api.staging", "canary--api.staging"})

	for _, name := range []string{"canary--web.internal.", "api.staging.internal.", "canary--api.staging.internal."} {
		if r := ask(t, addr, "udp", name, dns.TypeA); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
			t.Errorf("%s: %v", name, r)
		}
	}
	for _, network := range []string{"udp", "tcp"} {
		r := ask(t, addr, network, "Shop-API.internal.", dns.TypeA)
		if r.Rcode != dns.RcodeSuccess || !r.Authoritative || len(r.Answer) != 1 {
			t.Fatalf("%s: %v", network, r)
		}
		if a := r.Answer[0].(*dns.A); a.A.String() != "127.0.0.1" || a.Hdr.Ttl != ttl {
			t.Errorf("%s: answer %v", network, a)
		}
	}
	if r := ask(t, addr, "udp", "web.internal.", dns.TypeAAAA); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Errorf("AAAA of a known name = %v", r)
	}
	for _, name := range []string{"ghost.internal.", "a.web.internal.", "api.internal.", "x.api.staging.internal.", "api.default.internal.", "internal.", "bad_name.internal.", "old--web.internal.", "a--b--c.internal.", "--web.internal."} {
		if r := ask(t, addr, "udp", name, dns.TypeA); r.Rcode != dns.RcodeNameError {
			t.Errorf("%s: rcode %s", name, dns.RcodeToString[r.Rcode])
		}
	}
	s.SetNames(nil)
	if r := ask(t, addr, "udp", "web.internal.", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Error("removed app still resolves")
	}
}

func TestForwarding(t *testing.T) {
	t.Parallel()
	dead := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), freePort(t)).String()
	_, addr := start(t, "127.0.0.0/8", dead, upstream(t))
	r := ask(t, addr, "udp", "example.com.", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.0.2.7" {
		t.Errorf("forwarded answer = %v", r)
	}

	_, noUp := start(t, "127.0.0.0/8")
	if r := ask(t, noUp, "udp", "example.com.", dns.TypeA); r.Rcode != dns.RcodeServerFailure {
		t.Errorf("without upstreams: %s", dns.RcodeToString[r.Rcode])
	}
}

func TestRefusesForeignClients(t *testing.T) {
	t.Parallel()
	s, addr := start(t, "172.17.0.0/16", upstream(t))
	s.SetNames([]string{"web"})
	// A client outside the bridge gets no reply at all.
	if r, _, err := (&dns.Client{Timeout: 300 * time.Millisecond}).Exchange(query("web.internal.", dns.TypeA), addr); err == nil {
		t.Errorf("foreign client got %v", r)
	}
}

func TestRejectsOddQueries(t *testing.T) {
	t.Parallel()
	_, addr := start(t, "127.0.0.0/8")
	m := query("web.internal.", dns.TypeA)
	m.Opcode = dns.OpcodeUpdate
	r, _, err := (&dns.Client{Timeout: time.Second}).Exchange(m, addr)
	if err != nil || r.Rcode != dns.RcodeNotImplemented {
		t.Errorf("update = %v, %v", r, err)
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	for name, cfg := range map[string]Config{
		"public address": {Addr: netip.MustParseAddr("8.8.8.8"), Clients: netip.MustParsePrefix("172.17.0.0/16")},
		"no address":     {Clients: netip.MustParsePrefix("172.17.0.0/16")},
		"no clients":     {Addr: netip.MustParseAddr("172.17.0.1")},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s, err := New(Config{Addr: netip.MustParseAddr("172.17.0.1"), Clients: netip.MustParsePrefix("172.17.0.0/16"), Upstreams: []string{"172.17.0.1:53", "10.0.0.1:53"}})
	if err != nil || len(s.cfg.Upstreams) != 1 || s.cfg.Upstreams[0] != "10.0.0.1:53" {
		t.Errorf("self not dropped from upstreams: %v %v", s.cfg.Upstreams, err)
	}
}

func TestHostUpstreams(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "resolv.conf")
	_ = os.WriteFile(p, []byte("# comment\nnameserver 127.0.0.53\nnameserver 10.0.0.2\noptions edns0\n"), 0o600)
	got, err := HostUpstreams(p)
	if err != nil || len(got) != 2 || got[0] != "127.0.0.53:53" || got[1] != "10.0.0.2:53" {
		t.Errorf("HostUpstreams = %v, %v", got, err)
	}
	_ = os.WriteFile(p, []byte("search example\n"), 0o600)
	if _, err := HostUpstreams(p); err == nil {
		t.Error("empty resolv.conf accepted")
	}
}

func TestForwardingIsBounded(t *testing.T) {
	t.Parallel()
	s, addr := start(t, "127.0.0.0/8", upstream(t))
	// Occupy every slot: further forwards fail fast instead of piling up.
	for range cap(s.inflight) {
		s.inflight <- struct{}{}
	}
	if r := ask(t, addr, "udp", "example.com.", dns.TypeA); r.Rcode != dns.RcodeServerFailure {
		t.Errorf("forward beyond the limit: %s", dns.RcodeToString[r.Rcode])
	}
	// Internal names never need an upstream and keep working.
	s.SetNames([]string{"web"})
	if r := ask(t, addr, "udp", "web.internal.", dns.TypeA); r.Rcode != dns.RcodeSuccess {
		t.Errorf("internal name under load: %s", dns.RcodeToString[r.Rcode])
	}
	for range cap(s.inflight) {
		<-s.inflight
	}
	if r := ask(t, addr, "udp", "example.com.", dns.TypeA); r.Rcode != dns.RcodeSuccess {
		t.Errorf("forward after release: %s", dns.RcodeToString[r.Rcode])
	}
}

// askFrom queries addr from the loopback address from.
func askFrom(t *testing.T, addr, network, from, name string) *dns.Msg {
	t.Helper()
	local := net.Addr(&net.UDPAddr{IP: net.ParseIP(from)})
	if network == "tcp" {
		local = &net.TCPAddr{IP: net.ParseIP(from)}
	}
	c := &dns.Client{Net: network, Timeout: time.Second, Dialer: &net.Dialer{LocalAddr: local, Timeout: time.Second}}
	r, _, err := c.Exchange(query(name, dns.TypeA), addr)
	if err != nil {
		t.Fatalf("%s %s from %s: %v", network, name, from, err)
	}
	return r
}

func TestForwardingSharePerClient(t *testing.T) {
	t.Parallel()
	s, addr := start(t, "127.0.0.0/8", upstream(t))
	noisy := netip.MustParseAddr("127.0.0.2")
	// The noisy client holds its whole share, as with slow upstream names.
	s.mu.Lock()
	s.perClient[noisy] = maxInflightPerClient
	s.mu.Unlock()
	if r := askFrom(t, addr, "udp", "127.0.0.2", "example.com."); r.Rcode != dns.RcodeServerFailure {
		t.Errorf("forward beyond the client's share: %s", dns.RcodeToString[r.Rcode])
	}
	// Refusing it took no node slot, and another client still resolves.
	if n := len(s.inflight); n != 0 {
		t.Errorf("over-limit client holds %d node slots", n)
	}
	if r := askFrom(t, addr, "udp", "127.0.0.3", "example.com."); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Errorf("other client: %s %v", dns.RcodeToString[r.Rcode], r.Answer)
	}
	s.mu.Lock()
	s.perClient[noisy] = 0
	s.mu.Unlock()
	if r := askFrom(t, addr, "udp", "127.0.0.2", "example.com."); r.Rcode != dns.RcodeSuccess {
		t.Errorf("after release: %s", dns.RcodeToString[r.Rcode])
	}
	// Counts return to zero once queries finish. A slot is released after
	// the answer is written, so the client can see the answer first.
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		left := maps.Clone(s.perClient)
		s.mu.Unlock()
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("counts left: %v", left)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestTCPConnectionsPerClient(t *testing.T) {
	t.Parallel()
	s, addr := start(t, "127.0.0.0/8", upstream(t))
	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			_ = c.Close()
		}
	})
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.4")}}
	for range maxConnsPerClient {
		c, err := d.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	// The next connection of that client is closed at once.
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("connection past the client's bound was kept open")
	}
	// Another client is unaffected (the test upstream answers UDP only).
	s.SetNames([]string{"web"})
	if r := askFrom(t, addr, "tcp", "127.0.0.5", "web.internal."); r.Rcode != dns.RcodeSuccess {
		t.Errorf("other client over TCP: %s", dns.RcodeToString[r.Rcode])
	}
	s.mu.Lock()
	n := s.perConn[netip.MustParseAddr("127.0.0.4")]
	s.mu.Unlock()
	if n != maxConnsPerClient {
		t.Errorf("open connections counted %d, want %d", n, maxConnsPerClient)
	}
}

func TestOwnSpaceOnly(t *testing.T) {
	t.Parallel()
	s, addr := start(t, "127.0.0.0/8")
	s.SetNames([]string{"web", "api", "web.shop", "canary--web.shop", "db.blog"})
	resolves := func(name string) bool {
		t.Helper()
		return ask(t, addr, "udp", name, dns.TypeA).Rcode == dns.RcodeSuccess
	}
	// No client map yet: every name resolves, as on nodes without the
	// cluster network.
	if !resolves("db.blog.internal.") {
		t.Fatal("without clients, a space name does not resolve")
	}
	// The test client is 127.0.0.1: a container of web.shop.
	s.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.1"): "web.shop"})
	for name, want := range map[string]bool{
		"web.shop.internal.":         true,
		"canary--web.shop.internal.": true,
		"web.internal.":              false, // the default space's
		"api.internal.":              false,
		"db.blog.internal.":          false, // another space's
	} {
		if got := resolves(name); got != want {
			t.Errorf("%s resolves = %t, want %t", name, got, want)
		}
	}
	// A container of the default space resolves only default names.
	s.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.1"): "api"})
	if !resolves("web.internal.") || resolves("web.shop.internal.") {
		t.Error("default container: wrong names")
	}
	// An address the agent does not know resolves no internal name.
	s.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.9"): "api"})
	if resolves("web.internal.") {
		t.Error("unknown client resolved an internal name")
	}
}

// A container's first lookups wait for the agent to tell the server its
// address, so a container that calls an app at once does not fail;
// an address the agent never names still resolves nothing (ADR 0026).
func TestNewContainerWaitsToBeKnown(t *testing.T) {
	t.Parallel()
	s, addr := startWith(t, Config{UnknownWait: 300 * time.Millisecond}, "127.0.0.0/8")
	s.SetNames([]string{"web"})
	s.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.6"): "api"})
	done := make(chan *dns.Msg, 1)
	go func() { done <- askFrom(t, addr, "udp", "127.0.0.7", "web.internal.") }()
	time.Sleep(50 * time.Millisecond)
	// Another container is learned first: the lookup keeps waiting.
	s.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.6"): "api", netip.MustParseAddr("127.0.0.8"): "api"})
	time.Sleep(50 * time.Millisecond)
	select {
	case r := <-done:
		t.Fatalf("answered before the container was known: %v", r)
	default:
	}
	s.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.6"): "api", netip.MustParseAddr("127.0.0.7"): "web"})
	if r := <-done; r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Errorf("new container's first lookup: %v", r)
	}
	// Never learned: NXDOMAIN once the wait is over.
	begin := time.Now()
	if r := askFrom(t, addr, "udp", "127.0.0.9", "web.internal."); r.Rcode != dns.RcodeNameError {
		t.Errorf("unknown client: %v", r)
	}
	if took := time.Since(begin); took < 250*time.Millisecond {
		t.Errorf("unknown client answered after %s, before the wait", took)
	}
	// Known clients and names outside .internal never wait.
	begin = time.Now()
	if r := askFrom(t, addr, "udp", "127.0.0.6", "web.internal."); r.Rcode != dns.RcodeSuccess || time.Since(begin) > 200*time.Millisecond {
		t.Errorf("known client: %v after %s", r, time.Since(begin))
	}
	s.mu.Lock()
	n := s.perClient[netip.MustParseAddr("127.0.0.9")]
	s.mu.Unlock()
	if n != 0 {
		t.Errorf("waits left counted: %d", n)
	}
}

// An agent that just started has not received its configuration: lookups
// of internal names wait for the first SetNames instead of failing.
func TestLookupsWaitForFirstNames(t *testing.T) {
	t.Parallel()
	s, addr := startWith(t, Config{UnknownWait: 50 * time.Millisecond, StartWait: 2 * time.Second}, "127.0.0.0/8")
	done := make(chan *dns.Msg, 1)
	go func() { done <- askFrom(t, addr, "udp", "127.0.0.7", "web.internal.") }()
	// Past UnknownWait: the start wait is the longer one.
	time.Sleep(200 * time.Millisecond)
	select {
	case r := <-done:
		t.Fatalf("answered before the first names: %v", r)
	default:
	}
	s.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.7"): "api"})
	time.Sleep(50 * time.Millisecond)
	select {
	case r := <-done:
		t.Fatalf("answered with clients but no names: %v", r)
	default:
	}
	s.SetNames([]string{"web"})
	if r := <-done; r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Errorf("lookup held for the first names: %v", r)
	}

	// Never configured: NXDOMAIN once StartWait is over.
	s2, addr2 := startWith(t, Config{StartWait: 300 * time.Millisecond}, "127.0.0.0/8")
	begin := time.Now()
	if r := askFrom(t, addr2, "udp", "127.0.0.7", "web.internal."); r.Rcode != dns.RcodeNameError {
		t.Errorf("unconfigured server: %v", r)
	}
	if took := time.Since(begin); took < 250*time.Millisecond {
		t.Errorf("answered after %s, before the start wait", took)
	}
	s2.mu.Lock()
	n := s2.perClient[netip.MustParseAddr("127.0.0.7")]
	s2.mu.Unlock()
	if n != 0 {
		t.Errorf("waits left counted: %d", n)
	}
}
