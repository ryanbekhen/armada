package containerd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

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
// either), portmap for published ports, firewall rules that let the
// traffic through a restrictive FORWARD policy, and, with shape, the
// bandwidth plugin, which limits what a container sends when its runtime
// arguments carry a rate and does nothing otherwise. An mtu above 0 sets
// the MTU of the bridge and of each container's interface.
func cniConfig(b runtime.Bridge, ipamDir string, mtu int, shape bool) ([]byte, error) {
	bridge := map[string]any{
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
	}
	if mtu > 0 {
		bridge["mtu"] = mtu
	}
	plugins := []any{
		bridge,
		map[string]any{"type": "portmap", "capabilities": map[string]bool{"portMappings": true}, "snat": true},
		map[string]any{"type": "firewall"},
	}
	if shape {
		plugins = append(plugins, map[string]any{"type": "bandwidth", "capabilities": map[string]bool{"bandwidth": true}})
	}
	conf := map[string]any{
		"cniVersion": "1.0.0",
		"name":       "armada",
		"plugins":    plugins,
	}
	return json.Marshal(conf)
}

// bandwidthArgs is the bandwidth plugin's runtime argument for a limit of
// egress bits per second (nil without one). Traffic the container sends
// enters the node on its veth, where the plugin redirects it to an ifb
// device with a token bucket filter; the burst is 100 ms of traffic.
// Ingress stays unlimited.
func bandwidthArgs(egress int64) map[string]any {
	if egress <= 0 {
		return nil
	}
	return map[string]any{"egressRate": egress, "egressBurst": max(egress/10, 1)}
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

// shapingModules are the kernel modules the bandwidth plugin's egress limit
// uses: an ingress qdisc on the container's veth, a u32 filter with a
// mirred action to an ifb device, and a token bucket filter on it.
var shapingModules = []string{"ifb", "sch_ingress", "cls_u32", "act_mirred", "sch_tbf"}

// kernelShapes reports whether the kernel of release under root has every
// shaping module, loaded, built in, or loadable (the kernel loads them on
// first use).
func kernelShapes(root, release string) bool {
	missing := map[string]bool{}
	for _, m := range shapingModules {
		if _, err := os.Stat(filepath.Join(root, "sys/module", m)); err != nil {
			missing[m] = true
		}
	}
	if len(missing) == 0 {
		return true
	}
	if release == "" || strings.ContainsAny(release, "/\x00") {
		return false
	}
	dir := filepath.Join(root, "lib/modules", release)
	for _, list := range []string{"modules.builtin", "modules.dep"} {
		f, err := os.Open(filepath.Join(dir, list)) //nolint:gosec // a fixed name under the kernel's module directory
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			// "kernel/net/sched/sch_tbf.ko.xz: ..." or "kernel/drivers/net/ifb.ko"
			path, _, _ := strings.Cut(sc.Text(), ":")
			name, _, _ := strings.Cut(filepath.Base(path), ".ko")
			delete(missing, strings.ReplaceAll(name, "-", "_"))
		}
		_ = f.Close()
	}
	return len(missing) == 0
}

// executable reports whether path is a regular file anyone may run.
func executable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}
