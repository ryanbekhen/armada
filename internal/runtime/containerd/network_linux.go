//go:build linux

package containerd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/containerd/containerd/v2/pkg/netns"
	"github.com/containernetworking/cni/libcni"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/vishvananda/netlink"

	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// cniPlugins is the part of the plugin runner the network uses (a fake in
// tests).
type cniPlugins interface {
	AddNetworkList(ctx context.Context, net *libcni.NetworkConfigList, rt *libcni.RuntimeConf) (cnitypes.Result, error)
	DelNetworkList(ctx context.Context, net *libcni.NetworkConfigList, rt *libcni.RuntimeConf) error
	GetNetworkListCachedResult(net *libcni.NetworkConfigList, rt *libcni.RuntimeConf) (cnitypes.Result, error)
}

type cniNetwork struct {
	bridge   runtime.Bridge
	mtu      int
	cni      cniPlugins
	conf     *libcni.NetworkConfigList
	netnsDir string
	// forget deletes the connection tracking entries of an address the
	// plugins gave back (forgetConnections; a fake in tests).
	forget func(netip.Addr) error

	mu    sync.Mutex
	ready bool
}

func newNetwork(p embedded.Paths, subnet netip.Prefix, mtu int) (network, error) {
	b, err := BridgeOf(subnet)
	if err != nil {
		return nil, err
	}
	raw, err := cniConfig(b, filepath.Join(p.CNI(), "ipam"), mtu)
	if err != nil {
		return nil, err
	}
	conf, err := libcni.ConfListFromBytes(raw)
	if err != nil {
		return nil, err
	}
	return &cniNetwork{
		bridge:   b,
		mtu:      mtu,
		cni:      libcni.NewCNIConfigWithCacheDir([]string{filepath.Join(p.Bin(), embedded.DirCNI)}, filepath.Join(p.CNI(), "cache"), nil),
		conf:     conf,
		netnsDir: p.NetNS(),
		forget:   forgetConnections,
	}, nil
}

func (n *cniNetwork) Bridge() runtime.Bridge { return n.bridge }

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
	// Before the link is up, so it never gets a link-local address.
	if err := embedded.DisableIPv6(embedded.BridgeName); err != nil {
		return err
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

func (n *cniNetwork) runtimeConf(id, path string, pm *portMapping) *libcni.RuntimeConf {
	rt := &libcni.RuntimeConf{ContainerID: id, NetNS: path, IfName: "eth0", CapabilityArgs: map[string]any{}}
	if m := portMappings(pm); m != nil {
		rt.CapabilityArgs["portMappings"] = m
	}
	return rt
}

func (n *cniNetwork) Setup(ctx context.Context, id string, pm *portMapping) (string, string, error) {
	if err := os.MkdirAll(n.netnsDir, 0o700); err != nil {
		return "", "", err
	}
	ns, err := netns.NewNetNS(n.netnsDir)
	if err != nil {
		return "", "", fmt.Errorf("network namespace: %w", err)
	}
	res, err := n.cni.AddNetworkList(ctx, n.conf, n.runtimeConf(id, ns.GetPath(), pm))
	if err != nil {
		_ = n.cni.DelNetworkList(context.WithoutCancel(ctx), n.conf, n.runtimeConf(id, ns.GetPath(), pm))
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

// SetupAt attaches the network namespace at path, which the caller made,
// as id, with no port, and returns its address.
func (n *cniNetwork) SetupAt(ctx context.Context, id, path string) (string, error) {
	res, err := n.cni.AddNetworkList(ctx, n.conf, n.runtimeConf(id, path, nil))
	if err != nil {
		_ = n.cni.DelNetworkList(context.WithoutCancel(ctx), n.conf, n.runtimeConf(id, path, nil))
		return "", err
	}
	return resultIP(res)
}

// Address returns the address SetupAt gave id in the namespace at path,
// from the plugins' cache, which lives as long as the namespace does.
func (n *cniNetwork) Address(id, path string) (string, error) {
	res, err := n.cni.GetNetworkListCachedResult(n.conf, n.runtimeConf(id, path, nil))
	if err != nil {
		return "", err
	}
	if res == nil {
		return "", errors.New("no cached network result")
	}
	return resultIP(res)
}

func resultIP(res cnitypes.Result) (string, error) {
	r, err := types100.NewResultFromResult(res)
	if err != nil {
		return "", fmt.Errorf("network result: %w", err)
	}
	if len(r.IPs) == 0 {
		return "", errors.New("network result: no IP address assigned")
	}
	return r.IPs[0].Address.IP.String(), nil
}

func (n *cniNetwork) Teardown(ctx context.Context, id, path string, pm *portMapping) error {
	nsPath := path
	if _, err := os.Stat(path); path == "" || err != nil {
		// Gone (e.g. after a reboot): plugins still release the address
		// and NAT rules.
		nsPath = ""
	}
	// The address, read before the plugins drop their cache with it.
	addr := n.cachedAddr(id, nsPath, pm)
	if err := n.cni.DelNetworkList(ctx, n.conf, n.runtimeConf(id, nsPath, pm)); err != nil {
		return err
	}
	n.forgetAddr(id, addr)
	if nsPath != "" {
		if err := netns.LoadNetNS(nsPath).Remove(); err != nil {
			return err
		}
	}
	return nil
}

// cachedAddr returns the IPv4 address the plugins' cache holds for id, or
// the zero address when there is none.
func (n *cniNetwork) cachedAddr(id, path string, pm *portMapping) netip.Addr {
	res, err := n.cni.GetNetworkListCachedResult(n.conf, n.runtimeConf(id, path, pm))
	if err != nil || res == nil {
		return netip.Addr{}
	}
	ip, err := resultIP(res)
	if err != nil {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return netip.Addr{}
	}
	return a
}

// forgetAddr deletes the connection tracking entries of an address the
// plugins just gave back. The address can go to a container of another
// space next, and an entry its peer keeps refreshing would hand that
// peer's flow to the new owner past the isolation rules, which accept
// established connections first (ADR 0026). With the entries gone, the
// peer's next packet is new and checked again. A failure is logged, never
// returned: the address is released either way.
func (n *cniNetwork) forgetAddr(id string, addr netip.Addr) {
	if !addr.IsValid() || n.forget == nil {
		return
	}
	if err := n.forget(addr); err != nil {
		slog.Warn("connection tracking entries of a released container address were not all deleted",
			"container", id, "address", addr, "err", err)
	}
}

// forgetConnections deletes every IPv4 connection tracking entry of the
// host's network namespace whose original source or destination, or reply
// source or destination, is addr (the reply side catches connections
// DNAT'd to the container from a published port).
func forgetConnections(addr netip.Addr) error {
	filters, err := connFilters(addr)
	if err != nil {
		return err
	}
	// A dump the kernel interrupts (the table changed while it was read,
	// as it does on a busy node) may have missed entries: read it again.
	for try := 1; ; try++ {
		_, err = netlink.ConntrackDeleteFilters(netlink.ConntrackTable, netlink.FAMILY_V4, filters...)
		if !errors.Is(err, netlink.ErrDumpInterrupted) || try == conntrackDumpTries {
			return err
		}
	}
}

// conntrackDumpTries bounds how often forgetConnections reads the
// connection table when the kernel interrupts the dump.
const conntrackDumpTries = 5

// connFilters match an entry when any of its four addresses is addr.
func connFilters(addr netip.Addr) ([]netlink.CustomConntrackFilter, error) {
	ip := net.IP(addr.AsSlice())
	types := []netlink.ConntrackFilterType{netlink.ConntrackOrigSrcIP, netlink.ConntrackOrigDstIP, netlink.ConntrackReplyAnyIP}
	filters := make([]netlink.CustomConntrackFilter, 0, len(types))
	for _, t := range types {
		f := &netlink.ConntrackFilter{}
		if err := f.AddIP(t, ip); err != nil {
			return nil, err
		}
		filters = append(filters, f)
	}
	return filters, nil
}
