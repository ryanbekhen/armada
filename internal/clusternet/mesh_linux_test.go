package clusternet

import (
	"slices"
	"strings"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// In the mesh mode, mesh addresses exist only on the tunnel, containers
// never reach a peer's WireGuard port at its endpoint, and peers reach this
// node's mesh address, nothing more.
func TestMeshRules(t *testing.T) {
	t.Parallel()
	p, err := parse(meshConfig(
		meshPeer(t, "a", "10.121.0.1", "10.120.0.0/24", "203.0.113.1"),
		meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "203.0.113.2"),
	), "a", meshSelf)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, r := range spoofRules(p) {
		lines = append(lines, strings.Join(r, " "))
	}
	want := []string{
		"-d 203.0.113.2/32 -i armada0 -p udp -m udp --dport 51820 -j DROP",
		"-d 10.121.0.0/16 -i lo -j RETURN",
		"-d 10.121.0.0/16 ! -i armada-net -j DROP",
		"-s 10.121.0.0/16 ! -i armada-net -j DROP",
		"-s 10.121.0.0/16 -i armada-net -j RETURN",
		"! -s 10.120.0.0/16 -i armada-net -j DROP",
	}
	last := -1
	for _, w := range want {
		i := slices.Index(lines, w)
		if i < 0 || i < last {
			t.Fatalf("%q missing or out of order:\n%s", w, strings.Join(lines, "\n"))
		}
		last = i
	}
	if got := meshRules(p); len(got) != 2 || strings.Join(got[0], " ") != "-s 10.121.0.0/16 -d 10.121.0.1/32 -j ACCEPT" || strings.Join(got[1], " ") != "-j RETURN" {
		t.Errorf("mesh rules %v", got)
	}
	// Other modes have none of this.
	p, err = parse(&armadav1.NetworkConfig{Mode: ModePlain, ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{np("a", "10.0.0.1", "10.120.0.0/24")}}, "a", self)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range spoofRules(p) {
		if strings.Contains(strings.Join(r, " "), "10.121.") {
			t.Errorf("plain mode names the mesh: %v", r)
		}
	}
}
