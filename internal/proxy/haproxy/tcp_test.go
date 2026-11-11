package haproxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/proxy"
)

// tcpConfig has internal TCP apps (ADR 0039): one port shared by two
// projects, one app that allows only some callers, and an HTTP app next to
// them.
func tcpConfig() proxy.Config {
	return proxy.Config{
		Backends: []proxy.Backend{
			{Name: "db", LocalFirst: true, Servers: []proxy.Server{
				{Name: "db-r1-a", Address: "10.120.0.5:5432"},
				{Name: "db-r1-b", Address: "10.120.1.4:5432"},
			}},
			{Name: "db.staging", LocalFirst: true, Servers: []proxy.Server{{Name: "db.staging-r1-a", Address: "10.120.1.6:5432"}}},
			{Name: "cache.staging", Servers: []proxy.Server{{Name: "cache.staging-r1-a", Address: "10.120.0.7:6379"}}},
			{Name: "web", LocalFirst: true, HealthPath: "/ready", Servers: []proxy.Server{{Name: "web-r1-a", Address: "10.120.0.8:8080"}}},
		},
		Rules: []proxy.Rule{{Host: "web.internal", PathPrefix: "/", Backend: "web", Internal: true}},
		TCP: []proxy.TCPRoute{
			{Port: 5432, Backend: "db"},
			{Port: 5432, Backend: "db.staging"},
			{Port: 6379, Backend: "cache.staging", Allow: []string{"cache.staging", "api.staging"}},
		},
	}
}

func TestRenderTCPGolden(t *testing.T) {
	t.Parallel()
	cfg, opts := tcpConfig(), callersOptions()
	golden(t, "tcp.cfg", render(cfg, assignLayout(nil, cfg, opts.node()), opts))
}

var bindLine = regexp.MustCompile(`(?m)^    bind (\S+)`)

// Rule 4: TCP listeners bind only to the bridge gateway, never to every
// address or the private IP, and each one checks its caller.
func TestRenderTCPBindsOnlyTheGateway(t *testing.T) {
	t.Parallel()
	cfg, opts := tcpConfig(), callersOptions()
	out := string(render(cfg, assignLayout(nil, cfg, opts.node()), opts))
	want := map[string]bool{":80": true, ":443": true, "10.0.0.2:8404": true, "10.120.0.1:80": true, "10.120.0.1:5432": true, "10.120.0.1:6379": true}
	for _, m := range bindLine.FindAllStringSubmatch(out, -1) {
		if !want[m[1]] {
			t.Errorf("unexpected bind %q", m[1])
		}
		delete(want, m[1])
	}
	if len(want) > 0 {
		t.Errorf("missing binds: %v", want)
	}
	for _, port := range []string{"5432", "6379"} {
		s := out[strings.Index(out, "frontend tcp_"+port+"\n"):]
		s = s[:strings.Index(s, "\n\n")]
		if !strings.Contains(s, "tcp-request connection reject unless { var(sess.route) -m found }") {
			t.Errorf("tcp_%s does not refuse unknown callers:\n%s", port, s)
		}
		if strings.Contains(s, "default_backend") {
			t.Errorf("tcp_%s has a default backend:\n%s", port, s)
		}
	}
	// The caller's project picks the backend, and allow narrows it.
	for _, line := range []string{
		"tcp-request connection set-var(sess.route) str(be_db) if { var(sess.cproj) -m str default }\n",
		"tcp-request connection set-var(sess.route) str(be_db.staging) if { var(sess.cproj) -m str staging }\n",
		"tcp-request connection set-var(sess.route) str(be_cache.staging) if { var(sess.cproj) -m str staging } { var(sess.capp) -m str cache.staging api.staging }\n",
	} {
		if !strings.Contains(out, line) {
			t.Errorf("missing %q", line)
		}
	}
	// TCP backends come after the TCP defaults, HTTP ones before.
	def := strings.Index(out, "defaults tcp\n")
	if def < 0 || strings.Index(out, "backend be_db\n") < def || strings.Index(out, "backend be_web\n") > def {
		t.Errorf("sections out of order:\n%s", out)
	}
	if strings.Contains(out, "frontend internal") && strings.Contains(out[strings.Index(out, "frontend internal"):def], "be_db") {
		t.Error("the HTTP internal frontend routes to a TCP backend")
	}
}

// Without a subnet the node does not know its callers: no TCP listener, but
// the backends stay for the Runtime API's slots.
func TestRenderTCPNeedsCallers(t *testing.T) {
	t.Parallel()
	cfg := tcpConfig()
	opts := renderOptions{PrivateIP: "10.0.0.2", InternalIP: "172.17.0.1"}
	out := string(render(cfg, assignLayout(nil, cfg, opts.node()), opts))
	if strings.Contains(out, "frontend tcp_") {
		t.Error("TCP listeners without caller checks")
	}
	if !strings.Contains(out, "backend be_db\n") {
		t.Error("TCP backend missing")
	}
	// A port another program has gets no listener.
	opts = callersOptions()
	opts.BusyTCP = []int{5432}
	out = string(render(cfg, assignLayout(nil, cfg, opts.node()), opts))
	if strings.Contains(out, "frontend tcp_5432") || !strings.Contains(out, "frontend tcp_6379") {
		t.Errorf("busy port:\n%s", out)
	}
}

func TestValidateTCP(t *testing.T) {
	t.Parallel()
	if err := tcpConfig().Validate(); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	for name, mutate := range map[string]func(c *proxy.Config){
		"reserved port":       func(c *proxy.Config) { c.TCP[0].Port = 53 },
		"port 80":             func(c *proxy.Config) { c.TCP[0].Port = 80 },
		"port zero":           func(c *proxy.Config) { c.TCP[0].Port = 0 },
		"port too large":      func(c *proxy.Config) { c.TCP[0].Port = 65536 },
		"unknown backend":     func(c *proxy.Config) { c.TCP[0].Backend = "nope" },
		"injected backend":    func(c *proxy.Config) { c.TCP[0].Backend = "db }\n    server x 1.2.3.4:5" },
		"label backend":       func(c *proxy.Config) { c.Backends[0].Name = "canary--db"; c.TCP[0].Backend = "canary--db" },
		"http backend":        func(c *proxy.Config) { c.TCP[0].Backend = "web"; c.Backends[3].HealthPath = "" },
		"health path":         func(c *proxy.Config) { c.Backends[0].HealthPath = "/h" },
		"wake":                func(c *proxy.Config) { c.Backends[0].Wake = true },
		"timeout":             func(c *proxy.Config) { c.Backends[0].TimeoutSeconds = 10 },
		"sticky":              func(c *proxy.Config) { c.Backends[0].Sticky = true },
		"two of one project":  func(c *proxy.Config) { c.TCP[2].Port = 5432 },
		"backend twice":       func(c *proxy.Config) { c.TCP = append(c.TCP, proxy.TCPRoute{Port: 6000, Backend: "db"}) },
		"caller elsewhere":    func(c *proxy.Config) { c.TCP[2].Allow = []string{"api"} },
		"injected caller":     func(c *proxy.Config) { c.TCP[2].Allow = []string{"api.staging }  or { always_true"} },
		"caller with newline": func(c *proxy.Config) { c.TCP[2].Allow = []string{"api.staging\nbind :1"} },
	} {
		c := tcpConfig()
		mutate(&c)
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// FuzzRenderTCP renders a TCP route from arbitrary names and ports, and
// checks that anything accepted stays on the gateway and names exactly its
// caller.
func FuzzRenderTCP(f *testing.F) {
	f.Add("db.shop", "api.shop", 5432)
	f.Add("db", "api", 1)
	f.Add("db.shop", "api.shop }  or { always_true", 6379)
	f.Add("db\nbind :1", "x.shop", 22)
	f.Fuzz(func(t *testing.T, name, caller string, port int) {
		cfg := proxy.Config{
			Backends: []proxy.Backend{{Name: name, Servers: []proxy.Server{{Name: "r", Address: "10.120.0.5:5432"}}}},
			TCP:      []proxy.TCPRoute{{Port: port, Backend: name, Allow: []string{caller}}},
		}
		if cfg.Validate() != nil {
			return
		}
		opts := callersOptions()
		out := render(cfg, assignLayout(nil, cfg, opts.node()), opts)
		if out == nil {
			t.Fatal("valid config refused")
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Count(line, "{") != strings.Count(line, "}") {
				t.Fatalf("unbalanced ACL braces in %q", line)
			}
			if strings.HasPrefix(line, "    bind ") && line != "    bind :80" && !strings.HasPrefix(line, "    bind :443 ") &&
				line != "    bind 10.0.0.2:8404" && line != "    bind 10.120.0.1:80" && line != fmt.Sprintf("    bind 10.120.0.1:%d", port) {
				t.Fatalf("unexpected bind %q", line)
			}
			if strings.Contains(line, "sess.capp) -m str") && !strings.HasSuffix(line, "-m str "+caller+" }") {
				t.Fatalf("caller check %q does not name exactly %q", line, caller)
			}
		}
	})
}

// procLine writes a socket as /proc/net/tcp does: 32-bit words of the
// address in the host's byte order.
func procLine(ap netip.AddrPort, state string) string {
	raw := ap.Addr().AsSlice()
	var hexAddr string
	for i := 0; i < len(raw); i += 4 {
		hexAddr += fmt.Sprintf("%08X", binary.NativeEndian.Uint32(raw[i:]))
	}
	return fmt.Sprintf("   0: %s:%04X 00000000:0000 %s 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0", hexAddr, ap.Port(), state)
}

func TestParseListeners(t *testing.T) {
	t.Parallel()
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	want := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.53:53"), netip.MustParseAddrPort("10.120.0.1:5432"), netip.MustParseAddrPort("[::]:6379"), netip.MustParseAddrPort("0.0.0.0:22")}
	in := header
	for _, ap := range want {
		in += procLine(ap, "0A") + "\n"
	}
	in += procLine(netip.MustParseAddrPort("10.0.0.2:40000"), "01") + "\n" // established, not listening
	in += procLine(netip.MustParseAddrPort("[::ffff:10.0.0.9]:7000"), "0A") + "\n"
	got, err := parseListeners([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, netip.MustParseAddrPort("10.0.0.9:7000"))
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if _, err := parseListeners([]byte(header + "   0: XYZ:0035 00000000:0000 0A\n")); err == nil {
		t.Error("bad address accepted")
	}
}

func TestBusyTCP(t *testing.T) {
	t.Parallel()
	cfg := tcpConfig()
	gw := netip.MustParseAddr("10.120.0.1")
	ls := []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:22"), netip.MustParseAddrPort("10.120.0.1:5432"), netip.MustParseAddrPort("10.0.0.2:6379")}
	// Someone else on the gateway, a listener on another address only.
	if got := busyTCP(cfg, gw, ls, nil); !slices.Equal(got, []int{5432}) {
		t.Errorf("busy = %v", got)
	}
	// HAProxy's own listener.
	if got := busyTCP(cfg, gw, ls, []int{5432}); len(got) != 0 {
		t.Errorf("busy = %v", got)
	}
	// Every address: busy whoever holds the gateway.
	ls = append(ls, netip.MustParseAddrPort("[::]:6379"))
	if got := busyTCP(cfg, gw, ls, []int{5432, 6379}); !slices.Equal(got, []int{6379}) {
		t.Errorf("busy = %v", got)
	}
}

// A port another program listens on gets no listener, so the reload does not
// fail; once it is free the next pass reloads with it.
func TestApplyBusyTCP(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "haproxy")
	listeners := []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:5432")}
	e, a := &fakeEngine{}, &fakeAPI{}
	d, err := New(Config{Dir: dir, PrivateIP: "10.0.0.2", InternalIP: "10.120.0.1", Subnet: "10.120.0.0/24", Engine: e, API: a,
		Listeners: func() ([]netip.AddrPort, error) { return listeners, nil }})
	if err != nil {
		t.Fatal(err)
	}
	cfg := tcpConfig()
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	read := func() string {
		b, err := os.ReadFile(filepath.Join(etcDir(dir), configFile))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if out := read(); strings.Contains(out, "frontend tcp_5432") || !strings.Contains(out, "frontend tcp_6379") {
		t.Fatalf("busy port rendered:\n%s", out)
	}
	if !slices.Equal(d.held, []int{6379}) {
		t.Errorf("held = %v", d.held)
	}
	// Free now, and HAProxy's own listener on 6379 is not someone else's.
	listeners = []netip.AddrPort{netip.MustParseAddrPort("10.120.0.1:6379")}
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if out := read(); !strings.Contains(out, "frontend tcp_5432") || !strings.Contains(out, "frontend tcp_6379") || e.reloads != 1 {
		t.Errorf("after the port was freed (%d reloads):\n%s", e.reloads, out)
	}
	// A new driver knows the ports of the running configuration.
	d2, err := New(Config{Dir: dir, PrivateIP: "10.0.0.2", InternalIP: "10.120.0.1", Subnet: "10.120.0.0/24", Engine: e, API: a,
		Listeners: func() ([]netip.AddrPort, error) { return listeners, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(d2.held, []int{5432, 6379}) {
		t.Errorf("held after restart = %v", d2.held)
	}
}
