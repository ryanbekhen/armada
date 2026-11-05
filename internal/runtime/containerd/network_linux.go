//go:build linux

package containerd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/containerd/containerd/v2/pkg/netns"
	"github.com/containernetworking/cni/libcni"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/vishvananda/netlink"

	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

type cniNetwork struct {
	bridge   runtime.Bridge
	mtu      int
	cni      *libcni.CNIConfig
	conf     *libcni.NetworkConfigList // without the bandwidth plugin
	shaped   *libcni.NetworkConfigList // with it
	plugin   string                    // path of the bandwidth plugin
	kernel   bool                      // the kernel has the shaping modules
	netnsDir string

	mu    sync.Mutex
	ready bool
}

func newNetwork(p embedded.Paths, subnet netip.Prefix, mtu int) (network, error) {
	b, err := BridgeOf(subnet)
	if err != nil {
		return nil, err
	}
	confs := make([]*libcni.NetworkConfigList, 2)
	for i, shape := range []bool{false, true} {
		raw, err := cniConfig(b, filepath.Join(p.CNI(), "ipam"), mtu, shape)
		if err != nil {
			return nil, err
		}
		if confs[i], err = libcni.ConfListFromBytes(raw); err != nil {
			return nil, err
		}
	}
	return &cniNetwork{
		bridge:   b,
		mtu:      mtu,
		cni:      libcni.NewCNIConfigWithCacheDir([]string{filepath.Join(p.Bin(), embedded.DirCNI)}, filepath.Join(p.CNI(), "cache"), nil),
		conf:     confs[0],
		shaped:   confs[1],
		plugin:   filepath.Join(p.Bin(), embedded.DirCNI, "bandwidth"),
		kernel:   kernelShapes("/", kernelRelease()),
		netnsDir: p.NetNS(),
	}, nil
}

func (n *cniNetwork) Bridge() runtime.Bridge { return n.bridge }

// chain returns the plugin chain, with the bandwidth plugin only while its
// binary exists: the runtime extracts the binaries when it starts, which
// may be after the driver is created, and a chain naming a missing plugin
// would fail every container start (a --bin-dir without it).
func (n *cniNetwork) chain() (*libcni.NetworkConfigList, bool) {
	if executable(n.plugin) {
		return n.shaped, true
	}
	return n.conf, false
}

func (n *cniNetwork) CanShape() bool {
	_, plugin := n.chain()
	return plugin && n.kernel
}

func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Ensure creates the bridge up front so the gateway address exists before
// the first container: internal DNS and ingress bind to it.
func (n *cniNetwork) Ensure(context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ready {
		return nil
	}
	link, err := netlink.LinkByName(embedded.BridgeName)
	var nf netlink.LinkNotFoundError
	if errors.As(err, &nf) {
		br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: embedded.BridgeName}}
		if err := netlink.LinkAdd(br); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create bridge %s: %w", embedded.BridgeName, err)
		}
		link, err = netlink.LinkByName(embedded.BridgeName)
	}
	if err != nil {
		return fmt.Errorf("bridge %s: %w", embedded.BridgeName, err)
	}
	if _, ok := link.(*netlink.Bridge); !ok {
		return fmt.Errorf("%s exists and is not a bridge", embedded.BridgeName)
	}
	want := &netlink.Addr{IPNet: &net.IPNet{
		IP:   n.bridge.Gateway.AsSlice(),
		Mask: net.CIDRMask(n.bridge.Subnet.Bits(), 32),
	}}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	have := false
	for _, a := range addrs {
		if a.IPNet.String() == want.IPNet.String() {
			have = true
			continue
		}
		// A bridge left from another subnet setting would route wrongly.
		return fmt.Errorf("bridge %s has address %s, want %s; remove it with `ip link delete %s`",
			embedded.BridgeName, a.IPNet, want.IPNet, embedded.BridgeName)
	}
	if !have {
		if err := netlink.AddrAdd(link, want); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("address bridge %s: %w", embedded.BridgeName, err)
		}
	}
	// A fixed address: otherwise the bridge takes its ports' addresses as
	// containers come and go (see bridgeMAC).
	mac := bridgeMAC(n.bridge.Gateway)
	assigned, _ := os.ReadFile(filepath.Join("/sys/class/net", embedded.BridgeName, "addr_assign_type"))
	if link.Attrs().HardwareAddr.String() != mac.String() || strings.TrimSpace(string(assigned)) != addrAssignSet {
		if err := netlink.LinkSetHardwareAddr(link, mac); err != nil {
			return fmt.Errorf("set address of bridge %s: %w", embedded.BridgeName, err)
		}
	}
	if n.mtu > 0 && link.Attrs().MTU != n.mtu {
		if err := netlink.LinkSetMTU(link, n.mtu); err != nil {
			return fmt.Errorf("set MTU of bridge %s: %w", embedded.BridgeName, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	n.ready = true
	return nil
}

// addrAssignSet is NET_ADDR_SET in addr_assign_type: the address was set
// by hand, and the kernel no longer changes it.
const addrAssignSet = "3"

func (n *cniNetwork) runtimeConf(id, path string, pm *portMapping, egress int64) *libcni.RuntimeConf {
	rt := &libcni.RuntimeConf{ContainerID: id, NetNS: path, IfName: "eth0", CapabilityArgs: map[string]any{}}
	if m := portMappings(pm); m != nil {
		rt.CapabilityArgs["portMappings"] = m
	}
	if bw := bandwidthArgs(egress); bw != nil {
		rt.CapabilityArgs["bandwidth"] = bw
	}
	return rt
}

func (n *cniNetwork) Setup(ctx context.Context, id string, pm *portMapping, egress int64) (string, string, error) {
	conf, plugin := n.chain()
	if egress > 0 && (!plugin || !n.kernel) {
		return "", "", errors.New("this node cannot limit egress bandwidth")
	}
	if err := os.MkdirAll(n.netnsDir, 0o700); err != nil {
		return "", "", err
	}
	ns, err := netns.NewNetNS(n.netnsDir)
	if err != nil {
		return "", "", fmt.Errorf("network namespace: %w", err)
	}
	res, err := n.cni.AddNetworkList(ctx, conf, n.runtimeConf(id, ns.GetPath(), pm, egress))
	if err != nil {
		_ = n.cni.DelNetworkList(context.WithoutCancel(ctx), conf, n.runtimeConf(id, ns.GetPath(), pm, 0))
		_ = ns.Remove()
		return "", "", err
	}
	r, err := types100.NewResultFromResult(res)
	if err == nil && len(r.IPs) == 0 {
		err = errors.New("no IP address assigned")
	}
	if err != nil {
		_ = n.Teardown(context.WithoutCancel(ctx), id, ns.GetPath(), pm)
		return "", "", fmt.Errorf("network result: %w", err)
	}
	return ns.GetPath(), r.IPs[0].Address.IP.String(), nil
}

func (n *cniNetwork) Teardown(ctx context.Context, id, path string, pm *portMapping) error {
	nsPath := path
	if _, err := os.Stat(path); path == "" || err != nil {
		// Gone (e.g. after a reboot): plugins still release the address
		// and NAT rules.
		nsPath = ""
	}
	// The bandwidth plugin removes the container's ifb device by its ID;
	// it needs no rate to do so.
	conf, _ := n.chain()
	if err := n.cni.DelNetworkList(ctx, conf, n.runtimeConf(id, nsPath, pm, 0)); err != nil {
		return err
	}
	if nsPath != "" {
		if err := netns.LoadNetNS(nsPath).Remove(); err != nil {
			return err
		}
	}
	return nil
}
