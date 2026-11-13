package dnsserver

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return uint16(l.LocalAddr().(*net.UDPAddr).Port)
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
		if s, err = New(Config{Addr: netip.MustParseAddr("127.0.0.1"), Port: port, Clients: netip.MustParsePrefix(clients), Upstreams: upstreams}); err != nil {
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
