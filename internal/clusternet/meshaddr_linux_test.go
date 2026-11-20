package clusternet

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// Mesh addresses in a plain cluster exist only on the WireGuard interface
// of other sites (ADR 0050): the raw chain drops them anywhere else.
func TestMeshAddressRules(t *testing.T) {
	t.Parallel()
	cfg := &armadav1.NetworkConfig{Mode: ModePlain, ClusterCidr: "10.120.0.0/16", MeshCidr: "10.122.0.0/16", Peers: []*armadav1.NetworkPeer{
		sitePeer(t, "a", "10.0.0.1", "10.120.0.0/24", "203.0.113.1", ""),
		sitePeer(t, "m", "10.122.0.1", "10.120.2.0/24", "203.0.113.3", "cloud"),
	}}
	for _, from := range []struct {
		node string
		ip   string
	}{{"a", "10.0.0.1"}, {"m", "10.122.0.1"}} {
		p, err := parse(cfg, from.node, netip.MustParseAddr(from.ip))
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, r := range spoofRules(p) {
			lines = append(lines, strings.Join(r, " "))
		}
		for _, want := range []string{
			"-d 10.122.0.0/16 -i lo -j RETURN",
			"-d 10.122.0.0/16 ! -i armada-wg -j DROP",
			"-s 10.122.0.0/16 ! -i armada-wg -j DROP",
		} {
			if !slices.Contains(lines, want) {
				t.Errorf("from %s: %q missing:\n%s", from.node, want, strings.Join(lines, "\n"))
			}
		}
		// The peer's own address is let through on the tunnel first.
		other := "10.122.0.1/32"
		if from.node == "m" {
			other = "10.0.0.1/32"
		}
		if ret, drop := slices.Index(lines, "-s "+other+" -i armada-wg -j RETURN"), slices.Index(lines, "-s 10.122.0.0/16 ! -i armada-wg -j DROP"); ret < 0 || ret > drop {
			t.Errorf("from %s: peer return at %d, range drop at %d", from.node, ret, drop)
		}
	}
}
