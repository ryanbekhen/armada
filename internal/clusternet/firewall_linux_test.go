package clusternet

import (
	"slices"
	"strings"
	"testing"
)

// Containers cannot reach a peer's tunnel port, and the tunnel lets out no
// packet claiming this node's containers or an address outside the cluster.
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
		"-s 10.120.0.0/24 -i armada-net -j DROP",
		"! -s 10.120.0.0/16 -i armada-net -j DROP",
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("%q missing:\n%s", want, strings.Join(lines, "\n"))
		}
	}
	p.mode = ModeWireGuard
	if r := spoofRules(p); !slices.Contains(r[0], "51820") {
		t.Errorf("wireguard: %v", r[0])
	}
}
