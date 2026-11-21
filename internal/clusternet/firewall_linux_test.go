package clusternet

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Containers cannot reach a peer's tunnel port, the tunnel lets out no
// packet from outside the cluster, and no packet claiming this node's
// containers enters but from the bridge or the node itself.
func TestForwardRulesRefuseSpoofing(t *testing.T) {
	t.Parallel()
	p, err := parse(config(np("a", "10.0.0.1", "10.120.0.0/24"), np("b", "10.0.0.2", "10.120.1.0/24"), np("c", "10.0.0.3", "10.120.2.0/24")), "a", self)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, r := range spoofRules(p) {
		lines = append(lines, strings.Join(r, " "))
	}
	for _, want := range []string{
		"-d 10.0.0.2/32 -i armada0 -p udp -m udp --dport 4789 -j DROP",
		"-d 10.0.0.3/32 -i armada0 -p udp -m udp --dport 4789 -j DROP",
		"-s 10.120.0.0/24 -i lo -j RETURN",
		"-s 10.120.0.0/24 ! -i armada0 -j DROP",
		"! -s 10.120.0.0/16 -i armada-net -j DROP",
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("%q missing:\n%s", want, strings.Join(lines, "\n"))
		}
	}
	// The node itself, over loopback, passes before the drop of its subnet
	// from anywhere but the bridge.
	if lo, drop := slices.Index(lines, "-s 10.120.0.0/24 -i lo -j RETURN"), slices.Index(lines, "-s 10.120.0.0/24 ! -i armada0 -j DROP"); lo > drop {
		t.Errorf("loopback after the drop:\n%s", strings.Join(lines, "\n"))
	}
	p.mode = ModeWireGuard
	if r := spoofRules(p); !slices.Contains(r[0], "51820") {
		t.Errorf("wireguard: %v", r[0])
	}

	// Another node guards its own subnet, in either mode, and never names
	// a peer's: those arrive through the tunnel.
	p, err = parse(config(np("a", "10.0.0.1", "10.120.0.0/24"), np("b", "10.0.0.2", "10.120.1.0/24")), "b", netip.MustParseAddr("10.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	p.mode = ModeWireGuard
	var b []string
	for _, r := range spoofRules(p) {
		b = append(b, strings.Join(r, " "))
	}
	if !slices.Contains(b, "-s 10.120.1.0/24 ! -i armada0 -j DROP") || !slices.Contains(b, "-s 10.120.1.0/24 -i lo -j RETURN") {
		t.Errorf("node b does not guard its subnet:\n%s", strings.Join(b, "\n"))
	}
	for _, l := range b {
		if strings.Contains(l, "10.120.0.0/24") {
			t.Errorf("node b names a peer's subnet: %q", l)
		}
	}
}

// While a switch runs (ADR 0050), both tunnels and both ports are guarded,
// forwarded, and clamped; without one, the rules are those of one tunnel.
func TestSwitchRules(t *testing.T) {
	t.Parallel()
	c := config(np("a", "10.0.0.1", "10.120.0.0/24"), np("b", "10.0.0.2", "10.120.1.0/24"))
	p, err := parse(c, "a", self)
	if err != nil {
		t.Fatal(err)
	}
	if got := forwardRules(tunnels(p), nil); len(got) != 5 || got[2][1] != Interface {
		t.Errorf("one tunnel: %v", got)
	}
	if got := mssRules(tunnels(p)); len(got) != 1 {
		t.Errorf("one tunnel: %v", got)
	}
	c.SwitchTo, c.SwitchStep = ModeWireGuard, SwitchPrepare
	if p, err = parse(c, "a", self); err != nil {
		t.Fatal(err)
	}
	join := func(rules [][]string) []string {
		var out []string
		for _, r := range rules {
			out = append(out, strings.Join(r, " "))
		}
		return out
	}
	spoof := join(spoofRules(p))
	for _, want := range []string{
		"-d 10.0.0.2/32 -i armada0 -p udp -m udp --dport 4789 -j DROP",
		"-d 10.0.0.2/32 -i armada0 -p udp -m udp --dport 51820 -j DROP",
		"! -s 10.120.0.0/16 -i armada-net -j DROP",
		"! -s 10.120.0.0/16 -i armada-next -j DROP",
	} {
		if !slices.Contains(spoof, want) {
			t.Errorf("%q missing:\n%s", want, strings.Join(spoof, "\n"))
		}
	}
	fwd := join(forwardRules(tunnels(p), nil))
	for _, want := range []string{
		"-i armada-next -o armada0 -j ACCEPT",
		"-i armada0 -o armada-next -j ACCEPT",
		"-i armada-net -j DROP",
		"-i armada-next -j DROP",
	} {
		if !slices.Contains(fwd, want) {
			t.Errorf("%q missing:\n%s", want, strings.Join(fwd, "\n"))
		}
	}
	// Accepting into the bridge comes before any drop of the tunnels.
	if slices.Index(fwd, "-i armada-next -o armada0 -j ACCEPT") > slices.Index(fwd, "-i armada-net -j DROP") {
		t.Errorf("drop before accept:\n%s", strings.Join(fwd, "\n"))
	}
	if got := join(mssRules(tunnels(p))); !slices.Contains(got, "-o armada-next -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu") {
		t.Errorf("mss: %v", got)
	}
}

// A relay forwards between the subnets of the pairs it relays for, both
// ways and between any two tunnels, before the tunnels' drops (ADR 0050).
func TestForwardRulesRelay(t *testing.T) {
	t.Parallel()
	pair := [2]netip.Prefix{netip.MustParsePrefix("10.120.1.0/24"), netip.MustParsePrefix("10.120.4.0/24")}
	got := forwardRules([]string{Interface, SiteInterface}, [][2]netip.Prefix{pair})
	if len(got) < 8 {
		t.Fatalf("rules %v", got)
	}
	want := []string{"-s", "10.120.4.0/24", "-d", "10.120.1.0/24", "-i", Interface, "-o", SiteInterface, "-j", "ACCEPT"}
	if !slices.ContainsFunc(got[:8], func(r []string) bool { return slices.Equal(r, want) }) {
		t.Errorf("missing %v in %v", want, got[:8])
	}
	for _, r := range got[:8] {
		if r[len(r)-1] != "ACCEPT" {
			t.Errorf("relay rule %v", r)
		}
	}
}

// RotateKey replaces network.key with a new private file and the key the
// devices take on the next Apply.
func TestNetRotateKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "network.key")
	old, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	n, err := New(Config{Node: "a", PrivateIP: self, Key: old, KeyPath: path})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := n.RotateKey()
	if err != nil || pub == old.Public() || n.cfg.Key.Public() != pub {
		t.Fatalf("rotate: %q %v", pub, err)
	}
	again, err := LoadOrCreateKey(path)
	if err != nil || again.Public() != pub {
		t.Fatalf("file holds %v, %v", again.Public(), err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, %v", fi.Mode(), err)
	}
	if _, err := (&Net{}).RotateKey(); err == nil {
		t.Error("rotation without a key file accepted")
	}
}
