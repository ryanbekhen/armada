package containerd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"

	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// BridgeOf returns the bridge network for subnet: the gateway is the
// subnet's first address.
func BridgeOf(subnet netip.Prefix) (runtime.Bridge, error) {
	subnet = subnet.Masked()
	if !subnet.Addr().Is4() || subnet.Bits() > 28 || subnet.Bits() < 8 {
		return runtime.Bridge{}, fmt.Errorf("container subnet %s: need an IPv4 prefix between /8 and /28", subnet)
	}
	gw := subnet.Addr().Next()
	if !netutil.IsPrivate(gw) {
		return runtime.Bridge{}, fmt.Errorf("container subnet %s is not private", subnet)
	}
	return runtime.Bridge{Gateway: gw, Subnet: subnet}, nil
}

// bridgeMAC is the fixed hardware address of the bridge with gateway gw: a
// locally administered unicast address holding the gateway's IPv4 bytes,
// so it stays the same across restarts. Without a fixed address the
// kernel gives the bridge the lowest address of its ports, which changes
// as containers come and go, and containers keep sending to the old one
// until their ARP entry for the gateway expires.
func bridgeMAC(gw netip.Addr) net.HardwareAddr {
	b := gw.As4()
	return net.HardwareAddr{0x02, 0x41, b[0], b[1], b[2], b[3]}
}

// cniConfig renders the plugin chain: a bridge with NAT for egress,
// host-local addresses kept on tmpfs (namespaces do not survive a reboot
// either), portmap for published ports, and firewall rules that let the
// traffic through a restrictive FORWARD policy.
func cniConfig(b runtime.Bridge, ipamDir string) ([]byte, error) {
	conf := map[string]any{
		"cniVersion": "1.0.0",
		"name":       "armada",
		"plugins": []any{
			map[string]any{
				"type":        "bridge",
				"bridge":      embedded.BridgeName,
				"isGateway":   true,
				"ipMasq":      true,
				"hairpinMode": true,
				"ipam": map[string]any{
					"type":   "host-local",
					"ranges": [][]map[string]string{{{"subnet": b.Subnet.String(), "gateway": b.Gateway.String()}}},
					// The default route via the gateway: egress, and replies to
					// connections DNAT'd from the node's private IP.
					"routes":  []map[string]string{{"dst": "0.0.0.0/0"}},
					"dataDir": ipamDir,
				},
			},
			map[string]any{"type": "portmap", "capabilities": map[string]bool{"portMappings": true}, "snat": true},
			map[string]any{"type": "firewall"},
		},
	}
	return json.Marshal(conf)
}

// portMappings is the portmap plugin's runtime argument.
func portMappings(pm *portMapping) []map[string]any {
	if pm == nil {
		return nil
	}
	return []map[string]any{{
		"hostPort": pm.HostPort, "containerPort": pm.ContainerPort, "protocol": "tcp", "hostIP": pm.HostIP,
	}}
}
