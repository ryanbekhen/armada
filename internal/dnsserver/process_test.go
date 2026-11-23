package dnsserver

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The tests of armada-dns run the program built from dns/ (make dns) and
// set ARMADA_DNS_BIN to it, like the conformance tests of armada-log. They
// ask it what the tests of the Go server ask, so both answer alike.

// procs runs units as plain child processes.
type procs struct {
	mu    sync.Mutex
	units map[string]*exec.Cmd
}

func (l *procs) Start(_ context.Context, unit string, argv []string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.units == nil {
		l.units = map[string]*exec.Cmd{}
	}
	l.units[unit] = cmd
	go func() { _ = cmd.Wait() }()
	return nil
}

func (l *procs) Stop(_ context.Context, unit string) error {
	l.mu.Lock()
	cmd := l.units[unit]
	delete(l.units, unit)
	l.mu.Unlock()
	if cmd != nil {
		_ = cmd.Process.Kill()
	}
	return nil
}

// crash ends unit's process the way a crash would: its manager still
// lists it until asked.
func (l *procs) crash(unit string) {
	l.mu.Lock()
	cmd := l.units[unit]
	delete(l.units, unit)
	l.mu.Unlock()
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

func (l *procs) Units(context.Context) ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for u := range l.units {
		out = append(out, u)
	}
	slices.Sort(out)
	return out, nil
}

func (l *procs) stopAll() {
	units, _ := l.Units(context.Background())
	for _, u := range units {
		_ = l.Stop(context.Background(), u)
	}
}

func dnsBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("ARMADA_DNS_BIN")
	if bin == "" {
		t.Skip("ARMADA_DNS_BIN is not set (make dns)")
	}
	return bin
}

// startProc runs armada-dns on a free loopback port answering 127.0.0.0/8
// (or clients), with the settings of base.
func startProc(t *testing.T, base ProcessConfig, clients string, upstreams ...string) (*Process, string, *procs) {
	t.Helper()
	l := &procs{}
	t.Cleanup(l.stopAll)
	return startProcWith(t, l, base, clients, upstreams...)
}

func startProcWith(t *testing.T, l *procs, base ProcessConfig, clients string, upstreams ...string) (*Process, string, *procs) {
	t.Helper()
	cfg := base
	cfg.Bin, cfg.Launcher = dnsBin(t), l
	if cfg.Addr == (netip.Addr{}) {
		cfg.Addr, cfg.Port = netip.MustParseAddr("127.0.0.1"), freePort(t)
	}
	if cfg.Dir == "" {
		cfg.Dir = t.TempDir()
	}
	cfg.Clients, cfg.Upstreams = netip.MustParsePrefix(clients), upstreams
	p, err := StartProcess(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p, netip.AddrPortFrom(cfg.Addr, cfg.Port).String(), l
}

func TestProcessInternalNames(t *testing.T) {
	t.Parallel()
	p, addr, _ := startProc(t, ProcessConfig{}, "127.0.0.0/8")
	p.SetNames([]string{"shop-api", "web", "canary--web", "api.staging", "canary--api.staging"})
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
		if a := r.Answer[0].(*dns.A); a.A.String() != "127.0.0.1" || a.Hdr.Ttl != ttl || a.Hdr.Name != "Shop-API.internal." {
			t.Errorf("%s: answer %v", network, a)
		}
	}
	if r := ask(t, addr, "udp", "web.internal.", dns.TypeAAAA); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Errorf("AAAA of a known name = %v", r)
	}
	for _, name := range []string{"ghost.internal.", "a.web.internal.", "api.internal.", "x.api.staging.internal.", "api.default.internal.", "internal.", "bad_name.internal.", "old--web.internal.", "a--b--c.internal.", "--web.internal.", `web\.x.internal.`} {
		if r := ask(t, addr, "udp", name, dns.TypeA); r.Rcode != dns.RcodeNameError {
			t.Errorf("%s: rcode %s", name, dns.RcodeToString[r.Rcode])
		}
	}
	p.SetNames(nil)
	if r := ask(t, addr, "udp", "web.internal.", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Error("removed app still resolves")
	}
}

func TestProcessForwarding(t *testing.T) {
	t.Parallel()
	dead := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), freePort(t)).String()
	_, addr, _ := startProc(t, ProcessConfig{}, "127.0.0.0/8", dead, upstream(t))
	r := ask(t, addr, "udp", "example.com.", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.0.2.7" {
		t.Errorf("forwarded answer = %v", r)
	}
	_, noUp, _ := startProc(t, ProcessConfig{}, "127.0.0.0/8")
	if r := ask(t, noUp, "udp", "example.com.", dns.TypeA); r.Rcode != dns.RcodeServerFailure || len(r.Question) != 1 {
		t.Errorf("without upstreams: %v", r)
	}
}

func TestProcessRefusesForeignClients(t *testing.T) {
	t.Parallel()
	p, addr, _ := startProc(t, ProcessConfig{}, "172.17.0.0/16", upstream(t))
	p.SetNames([]string{"web"})
	for _, network := range []string{"udp", "tcp"} {
		c := &dns.Client{Net: network, Timeout: 300 * time.Millisecond}
		if r, _, err := c.Exchange(query("web.internal.", dns.TypeA), addr); err == nil {
			t.Errorf("%s: foreign client got %v", network, r)
		}
	}
	// Not even an error to a malformed message.
	m := query("web.internal.", dns.TypeA)
	m.Opcode = dns.OpcodeUpdate
	if r, _, err := (&dns.Client{Timeout: 300 * time.Millisecond}).Exchange(m, addr); err == nil {
		t.Errorf("foreign client got %v", r)
	}
}

func TestProcessRejectsOddQueries(t *testing.T) {
	t.Parallel()
	_, addr, _ := startProc(t, ProcessConfig{}, "127.0.0.0/8")
	m := query("web.internal.", dns.TypeA)
	m.Opcode = dns.OpcodeUpdate
	r, _, err := (&dns.Client{Timeout: time.Second}).Exchange(m, addr)
	if err != nil || r.Rcode != dns.RcodeNotImplemented {
		t.Errorf("update = %v, %v", r, err)
	}
	m = query("web.internal.", dns.TypeA)
	m.Question = append(m.Question, m.Question[0])
	r, _, err = (&dns.Client{Timeout: time.Second}).Exchange(m, addr)
	if err != nil || r.Rcode != dns.RcodeFormatError {
		t.Errorf("two questions = %v, %v", r, err)
	}
}

func TestProcessOwnSpaceOnly(t *testing.T) {
	t.Parallel()
	p, addr, _ := startProc(t, ProcessConfig{}, "127.0.0.0/8")
	p.SetNames([]string{"web", "api", "web.shop", "canary--web.shop", "db.blog"})
	resolves := func(name string) bool {
		t.Helper()
		return ask(t, addr, "udp", name, dns.TypeA).Rcode == dns.RcodeSuccess
	}
	if !resolves("db.blog.internal.") {
		t.Fatal("without clients, a space name does not resolve")
	}
	p.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.1"): "web.shop"})
	for name, want := range map[string]bool{
		"web.shop.internal.":         true,
		"canary--web.shop.internal.": true,
		"web.internal.":              false,
		"api.internal.":              false,
		"db.blog.internal.":          false,
	} {
		if got := resolves(name); got != want {
			t.Errorf("%s resolves = %t, want %t", name, got, want)
		}
	}
	p.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.1"): "api"})
	if !resolves("web.internal.") || resolves("web.shop.internal.") {
		t.Error("default container: wrong names")
	}
	p.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.9"): "api"})
	if resolves("web.internal.") {
		t.Error("unknown client resolved an internal name")
	}
}

func TestProcessNewContainerWaitsToBeKnown(t *testing.T) {
	t.Parallel()
	p, addr, _ := startProc(t, ProcessConfig{UnknownWait: 300 * time.Millisecond}, "127.0.0.0/8")
	p.SetNames([]string{"web"})
	p.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.6"): "api"})
	for _, network := range []string{"udp", "tcp"} {
		done := make(chan *dns.Msg, 1)
		go func() { done <- askFrom(t, addr, network, "127.0.0.7", "web.internal.") }()
		time.Sleep(50 * time.Millisecond)
		p.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.6"): "api", netip.MustParseAddr("127.0.0.8"): "api"})
		time.Sleep(50 * time.Millisecond)
		select {
		case r := <-done:
			t.Fatalf("%s: answered before the container was known: %v", network, r)
		default:
		}
		p.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.6"): "api", netip.MustParseAddr("127.0.0.7"): "web"})
		if r := <-done; r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
			t.Errorf("%s: new container's first lookup: %v", network, r)
		}
		p.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.6"): "api"})
	}
	begin := time.Now()
	if r := askFrom(t, addr, "udp", "127.0.0.9", "web.internal."); r.Rcode != dns.RcodeNameError {
		t.Errorf("unknown client: %v", r)
	}
	if took := time.Since(begin); took < 250*time.Millisecond {
		t.Errorf("unknown client answered after %s, before the wait", took)
	}
	begin = time.Now()
	if r := askFrom(t, addr, "udp", "127.0.0.6", "web.internal."); r.Rcode != dns.RcodeSuccess || time.Since(begin) > 200*time.Millisecond {
		t.Errorf("known client: %v after %s", r, time.Since(begin))
	}
}

func TestProcessLookupsWaitForFirstNames(t *testing.T) {
	t.Parallel()
	p, addr, _ := startProc(t, ProcessConfig{UnknownWait: 50 * time.Millisecond, StartWait: 2 * time.Second}, "127.0.0.0/8")
	done := make(chan *dns.Msg, 1)
	go func() { done <- askFrom(t, addr, "udp", "127.0.0.7", "web.internal.") }()
	time.Sleep(200 * time.Millisecond)
	select {
	case r := <-done:
		t.Fatalf("answered before the first names: %v", r)
	default:
	}
	p.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.7"): "api"})
	time.Sleep(50 * time.Millisecond)
	select {
	case r := <-done:
		t.Fatalf("answered with clients but no names: %v", r)
	default:
	}
	p.SetNames([]string{"web"})
	if r := <-done; r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Errorf("lookup held for the first names: %v", r)
	}

	_, addr2, _ := startProc(t, ProcessConfig{StartWait: 300 * time.Millisecond}, "127.0.0.0/8")
	begin := time.Now()
	if r := askFrom(t, addr2, "udp", "127.0.0.7", "web.internal."); r.Rcode != dns.RcodeNameError {
		t.Errorf("unconfigured server: %v", r)
	}
	if took := time.Since(begin); took < 250*time.Millisecond {
		t.Errorf("answered after %s, before the start wait", took)
	}
}

// slowUpstream never answers names starting with "slow" and answers every
// other A query with 192.0.2.7.
func slowUpstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if strings.HasPrefix(r.Question[0].Name, "slow") {
			return
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.7")})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestProcessForwardingSharePerClient(t *testing.T) {
	t.Parallel()
	_, addr, _ := startProc(t, ProcessConfig{}, "127.0.0.0/8", slowUpstream(t))
	// The noisy client fills its share with names the upstream never
	// answers (each waits out the forward timeout).
	raw, err := (&net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.2")}}).Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	co := &dns.Conn{Conn: raw}
	for range maxInflightPerClient {
		if err := co.WriteMsg(query("slow.example.", dns.TypeA)); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	begin := time.Now()
	if r := askFrom(t, addr, "udp", "127.0.0.2", "example.com."); r.Rcode != dns.RcodeServerFailure || time.Since(begin) > time.Second {
		t.Errorf("forward beyond the client's share: %s after %s", dns.RcodeToString[r.Rcode], time.Since(begin))
	}
	if r := askFrom(t, addr, "udp", "127.0.0.3", "example.com."); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Errorf("other client: %s %v", dns.RcodeToString[r.Rcode], r.Answer)
	}
	// Once the slow ones time out, the noisy client resolves again.
	time.Sleep(forwardTimeout + 200*time.Millisecond)
	if r := askFrom(t, addr, "udp", "127.0.0.2", "example.com."); r.Rcode != dns.RcodeSuccess {
		t.Errorf("after release: %s", dns.RcodeToString[r.Rcode])
	}
}

func TestProcessTCPConnectionsPerClient(t *testing.T) {
	t.Parallel()
	p, addr, _ := startProc(t, ProcessConfig{}, "127.0.0.0/8", upstream(t))
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
	time.Sleep(100 * time.Millisecond)
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("connection past the client's bound was kept open")
	}
	p.SetNames([]string{"web"})
	if r := askFrom(t, addr, "tcp", "127.0.0.5", "web.internal."); r.Rcode != dns.RcodeSuccess {
		t.Errorf("other client over TCP: %s", dns.RcodeToString[r.Rcode])
	}
}

// A new armadad with another armada-dns (an upgrade) takes over from the
// running one without a lookup going unanswered, and the new process
// knows what the old one knew before the agent says anything.
func TestProcessHandOver(t *testing.T) {
	t.Parallel()
	l := &procs{}
	t.Cleanup(l.stopAll)
	dir := t.TempDir()
	port := freePort(t)
	base := ProcessConfig{Addr: netip.MustParseAddr("127.0.0.1"), Port: port, Dir: dir, UnknownWait: 300 * time.Millisecond}
	up := upstream(t)
	old, addr, _ := startProcWith(t, l, base, "127.0.0.0/8", up)
	old.SetNames([]string{"web", "web.shop"})
	old.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.1"): "api.shop"})

	stop := make(chan struct{})
	var failures, asked int
	var wg sync.WaitGroup
	wg.Go(func() {
		c := &dns.Client{Timeout: time.Second}
		for {
			select {
			case <-stop:
				return
			default:
			}
			r, _, err := c.Exchange(query("web.shop.internal.", dns.TypeA), addr)
			asked++
			if err != nil || r.Rcode != dns.RcodeSuccess {
				failures++
			}
		}
	})
	time.Sleep(100 * time.Millisecond)
	next := base
	next.UnknownWait = 400 * time.Millisecond // other settings, another unit
	p, _, _ := startProcWith(t, l, next, "127.0.0.0/8", up)
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
	if p.Unit() == old.Unit() {
		t.Fatal("same unit for other settings")
	}
	if units, _ := l.Units(context.Background()); !slices.Equal(units, []string{p.Unit()}) {
		t.Errorf("units after the hand-over: %v", units)
	}
	if failures > 0 || asked < 10 {
		t.Errorf("%d of %d lookups failed during the hand-over", failures, asked)
	}
	// The space rule came along: a default-space name stays hidden.
	if r := ask(t, addr, "udp", "web.internal.", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Errorf("client map lost in the hand-over: %v", r)
	}
	// The same settings again (armadad restarting) find the running one.
	again, _, _ := startProcWith(t, l, next, "127.0.0.0/8", up)
	if units, _ := l.Units(context.Background()); again.Unit() != p.Unit() || len(units) != 1 {
		t.Errorf("restart started another unit: %v", units)
	}
}

// A process that exits is started again and told everything the agent
// said.
func TestProcessKeep(t *testing.T) {
	t.Parallel()
	p, addr, l := startProc(t, ProcessConfig{}, "127.0.0.0/8")
	p.SetNames([]string{"web"})
	p.SetClients(map[netip.Addr]string{netip.MustParseAddr("127.0.0.1"): "api"})
	l.crash(p.Unit())
	// Started again (systemd does it), it answers from what it saved,
	// before the agent says anything.
	if err := p.ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := ask(t, addr, "udp", "web.internal.", dns.TypeA); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Errorf("restarted, before the agent: %v", r)
	}
	l.crash(p.Unit())
	p.keep(context.Background())
	if r := ask(t, addr, "udp", "web.internal.", dns.TypeA); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Errorf("after a restart: %v", r)
	}
	if units, _ := l.Units(context.Background()); len(units) != 1 {
		t.Errorf("units: %v", units)
	}
}

func TestStartProcessChecks(t *testing.T) {
	t.Parallel()
	for name, cfg := range map[string]ProcessConfig{
		"public address": {Addr: netip.MustParseAddr("8.8.8.8"), Clients: netip.MustParsePrefix("172.17.0.0/16")},
		"IPv6 address":   {Addr: netip.MustParseAddr("fd00::1"), Clients: netip.MustParsePrefix("172.17.0.0/16")},
		"no clients":     {Addr: netip.MustParseAddr("172.17.0.1")},
		"no program":     {Addr: netip.MustParseAddr("172.17.0.1"), Clients: netip.MustParsePrefix("172.17.0.0/16"), Bin: "/nonexistent/armada-dns"},
	} {
		cfg.Launcher, cfg.Dir = &procs{}, t.TempDir()
		if _, err := StartProcess(context.Background(), cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
