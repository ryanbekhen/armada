package clusternet

import (
	"net/netip"
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
