//go:build integration && linux

package clusternet

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/encoding/protojson"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// The Go side of comparing armada-node net firewall apply with the agent on
// the kernel: the requests armada-node reads (Config, Node, PrivateIP, Key,
// Local), applied one after another as Net.Apply applies the firewall and
// the isolation tables, then, with ARMADA_FIREWALL_REMOVE=1, Remove's
// firewall part. Run it as root in its own network namespace, then compare
// `nft -j list ruleset` and `iptables-save` with armada-node's namespace:
//
//	go test -c -tags integration ./internal/clusternet -o t
//	ip netns add fw-go
//	ARMADA_FIREWALL_REQUESTS=a.json,b.json ip netns exec fw-go ./t -test.run IntegrationFirewallFromRequests
func TestIntegrationFirewallFromRequests(t *testing.T) {
	files := os.Getenv("ARMADA_FIREWALL_REQUESTS")
	if files == "" {
		t.Skip("ARMADA_FIREWALL_REQUESTS is not set")
	}
	var n *Net
	for _, f := range strings.Split(files, ",") {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var req struct {
			Config    json.RawMessage
			Node      string
			PrivateIP netip.Addr
			Key       string
			Local     map[netip.Addr]string
		}
		if err := json.Unmarshal(b, &req); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		cfg := &armadav1.NetworkConfig{}
		if err := protojson.Unmarshal(req.Config, cfg); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var key wgtypes.Key
		if req.Key != "" {
			if key, err = wgtypes.ParseKey(req.Key); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
		}
		if n == nil {
			if n, err = New(Config{Node: req.Node, PrivateIP: req.PrivateIP, Key: PrivateKey{k: key}}); err != nil {
				t.Fatal(err)
			}
		}
		p, err := n.plan(cfg)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if err := n.firewall(p); err != nil {
			t.Fatalf("%s: firewall: %v", f, err)
		}
		if err := n.isolate(buildPolicy(p, req.Local)); err != nil {
			t.Fatalf("%s: isolation: %v", f, err)
		}
	}
	if os.Getenv("ARMADA_FIREWALL_REMOVE") == "1" {
		errs := append([]error{removeIsolation()}, removeFirewall(iptables)...)
		if err := errors.Join(errs...); err != nil {
			t.Fatal(err)
		}
	}
}
