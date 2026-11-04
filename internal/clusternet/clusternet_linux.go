//go:build linux

package clusternet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// vni is the VXLAN network identifier of Armada's tunnel.
const vni = 7027

// Firewall chains Armada owns.
const (
	chainIn  = "ARMADA-NET-IN"
	chainFwd = "ARMADA-NET-FWD"
)

// Net is the cluster network on a Linux node.
type Net struct {
	cfg Config
	log *slog.Logger

	mu   sync.Mutex
	last string // summary of the last applied plan, to log changes once
}

// New returns the node's cluster network. Nothing changes on the host until
// Apply.
func New(cfg Config) (*Net, error) {
	if !cfg.PrivateIP.Is4() {
		return nil, fmt.Errorf("cluster network: private IP %s is not IPv4", cfg.PrivateIP)
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Net{cfg: cfg, log: log}, nil
}

// Apply makes the tunnel, routes, and firewall rules match cfg. The
// firewall comes first, so the tunnel never accepts packets from anyone but
// the current peers.
func (n *Net) Apply(_ context.Context, cfg *armadav1.NetworkConfig) error {
	p, err := parse(cfg, n.cfg.Node, n.cfg.PrivateIP)
	if err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.firewall(p); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	uplink, mtu, err := UplinkOf(n.cfg.PrivateIP)
	if err != nil {
		return err
	}
	link, err := n.device(p, uplink, TunnelMTU(mtu))
	if err != nil {
		return err
	}
	if err := n.peers(p, link); err != nil {
		return err
	}
	summary := fmt.Sprintf("%s %d", p.self.subnet, len(p.peers))
	if summary != n.last {
		n.log.Info("cluster network applied", "subnet", p.self.subnet, "peers", len(p.peers), "mtu", TunnelMTU(mtu))
		n.last = summary
	}
	return nil
}

// UplinkOf returns the interface that holds ip and its MTU.
func UplinkOf(ip netip.Addr) (netlink.Link, int, error) {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, 0, err
	}
	for _, a := range addrs {
		if got, ok := netip.AddrFromSlice(a.IP); ok && got.Unmap() == ip {
			link, err := netlink.LinkByIndex(a.LinkIndex)
			if err != nil {
				return nil, 0, err
			}
			mtu := link.Attrs().MTU
			if mtu < MinUplinkMTU {
				return nil, 0, fmt.Errorf("the interface of %s (%s) has MTU %d, below %d", ip, link.Attrs().Name, mtu, MinUplinkMTU)
			}
			return link, mtu, nil
		}
	}
	return nil, 0, fmt.Errorf("no interface holds the private IP %s", ip)
}

// device creates or repairs the VXLAN interface.
func (n *Net) device(p plan, uplink netlink.Link, mtu int) (netlink.Link, error) {
	want := &netlink.Vxlan{
		LinkAttrs:    netlink.LinkAttrs{Name: Interface, MTU: mtu, HardwareAddr: vtepMAC(p.self.subnet)},
		VxlanId:      vni,
		VtepDevIndex: uplink.Attrs().Index,
		SrcAddr:      n.cfg.PrivateIP.AsSlice(),
		Port:         VXLANPort,
		Learning:     false,
	}
	link, err := netlink.LinkByName(Interface)
	var nf netlink.LinkNotFoundError
	switch {
	case errors.As(err, &nf):
	case err != nil:
		return nil, err
	default:
		v, ok := link.(*netlink.Vxlan)
		if !ok || v.VxlanId != want.VxlanId || v.Port != want.Port || v.Learning || v.VtepDevIndex != want.VtepDevIndex || !v.SrcAddr.Equal(want.SrcAddr) {
			n.log.Info("replacing the cluster network interface", "interface", Interface)
			if err := netlink.LinkDel(link); err != nil {
				return nil, fmt.Errorf("remove %s: %w", Interface, err)
			}
			link = nil
		}
	}
	if link == nil {
		if err := netlink.LinkAdd(want); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create %s: %w", Interface, err)
		}
		if link, err = netlink.LinkByName(Interface); err != nil {
			return nil, err
		}
	}
	if link.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return nil, fmt.Errorf("set MTU of %s: %w", Interface, err)
		}
	}
	if link.Attrs().HardwareAddr.String() != want.HardwareAddr.String() {
		if err := netlink.LinkSetHardwareAddr(link, want.HardwareAddr); err != nil {
			return nil, fmt.Errorf("set address of %s: %w", Interface, err)
		}
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: vtepAddr(p.self.subnet).AsSlice(), Mask: net.CIDRMask(32, 32)}}
	have, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	for _, a := range have {
		if !a.IP.Equal(addr.IP) {
			if err := netlink.AddrDel(link, &a); err != nil {
				return nil, err
			}
		}
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return nil, fmt.Errorf("address %s: %w", Interface, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, err
	}
	return link, nil
}

// peers installs, for each peer, the forwarding entry (its tunnel end's
// hardware address on its private IP), the neighbour entry (its tunnel
// address on that hardware address), and the route to its subnet, and
// removes entries for nodes that left.
func (n *Net) peers(p plan, link netlink.Link) error {
	idx := link.Attrs().Index
	wantRoutes := map[netip.Prefix]bool{}
	wantNeigh := map[netip.Addr]bool{}
	wantFDB := map[string]bool{}
	for _, pe := range p.peers {
		mac, gw := vtepMAC(pe.subnet), vtepAddr(pe.subnet)
		if err := netlink.NeighSet(&netlink.Neigh{
			LinkIndex: idx, Family: syscall.AF_BRIDGE, Flags: netlink.NTF_SELF, State: netlink.NUD_PERMANENT,
			IP: pe.ip.AsSlice(), HardwareAddr: mac,
		}); err != nil {
			return fmt.Errorf("forwarding entry for %s: %w", pe.node, err)
		}
		if err := netlink.NeighSet(&netlink.Neigh{
			LinkIndex: idx, Family: netlink.FAMILY_V4, State: netlink.NUD_PERMANENT,
			IP: gw.AsSlice(), HardwareAddr: mac,
		}); err != nil {
			return fmt.Errorf("neighbour entry for %s: %w", pe.node, err)
		}
		if err := netlink.RouteReplace(&netlink.Route{
			LinkIndex: idx, Dst: prefixNet(pe.subnet), Gw: gw.AsSlice(), Flags: int(netlink.FLAG_ONLINK),
		}); err != nil {
			return fmt.Errorf("route to %s (%s): %w", pe.node, pe.subnet, err)
		}
		wantRoutes[pe.subnet], wantNeigh[gw], wantFDB[mac.String()] = true, true, true
	}

	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.Dst == nil {
			continue
		}
		dst, ok := netip.AddrFromSlice(r.Dst.IP)
		ones, _ := r.Dst.Mask.Size()
		if ok && !wantRoutes[netip.PrefixFrom(dst.Unmap(), ones)] && r.Protocol != netlink.RouteProtocol(syscall.RTPROT_KERNEL) {
			if err := netlink.RouteDel(&r); err != nil {
				return fmt.Errorf("remove route %s: %w", r.Dst, err)
			}
		}
	}
	neighs, err := netlink.NeighList(idx, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, ne := range neighs {
		ip, ok := netip.AddrFromSlice(ne.IP)
		if ok && !wantNeigh[ip.Unmap()] {
			if err := netlink.NeighDel(&ne); err != nil {
				return fmt.Errorf("remove neighbour %s: %w", ne.IP, err)
			}
		}
	}
	fdb, err := netlink.NeighList(idx, syscall.AF_BRIDGE)
	if err != nil {
		return err
	}
	for _, ne := range fdb {
		if ne.HardwareAddr != nil && !wantFDB[ne.HardwareAddr.String()] && ne.State&netlink.NUD_PERMANENT != 0 {
			if err := netlink.NeighDel(&ne); err != nil {
				return fmt.Errorf("remove forwarding entry %s: %w", ne.HardwareAddr, err)
			}
		}
	}
	return nil
}

func prefixNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// firewall lets the tunnel's port on the private IP accept packets only
// from the current peers, forwards decapsulated traffic only to and from
// the container bridge, and keeps traffic between containers of different
// nodes out of masquerading, so a replica sees the caller's address.
func (n *Net) firewall(p plan) error {
	ipt := iptables
	if err := ipt.chain("filter", chainIn); err != nil {
		return err
	}
	rules := [][]string{}
	for _, pe := range p.peers {
		rules = append(rules, []string{"-s", pe.ip.String() + "/32", "-j", "ACCEPT"})
	}
	rules = append(rules, []string{"-j", "DROP"})
	if err := ipt.fill("filter", chainIn, rules); err != nil {
		return err
	}
	if err := ipt.first("filter", "INPUT", "-d", n.cfg.PrivateIP.String()+"/32", "-p", "udp", "--dport", strconv.Itoa(VXLANPort), "-j", chainIn); err != nil {
		return err
	}
	if err := ipt.chain("filter", chainFwd); err != nil {
		return err
	}
	if err := ipt.fill("filter", chainFwd, [][]string{
		{"-i", Interface, "-o", embedded.BridgeName, "-j", "ACCEPT"},
		{"-i", embedded.BridgeName, "-o", Interface, "-j", "ACCEPT"},
		// Nothing that arrives through the tunnel is routed anywhere else.
		{"-i", Interface, "-j", "DROP"},
	}); err != nil {
		return err
	}
	if err := ipt.first("filter", "FORWARD", "-j", chainFwd); err != nil {
		return err
	}
	// Ahead of the container runtime's masquerading.
	return ipt.first("nat", "POSTROUTING", "-o", Interface, "-j", "RETURN")
}

// iptablesCmd runs the iptables tool the container networking plugins use.
type iptablesCmd struct{ bin string }

var iptables = iptablesCmd{bin: "iptables"}

func (c iptablesCmd) run(args ...string) error {
	out, err := exec.Command(c.bin, append([]string{"-w", "5"}, args...)...).CombinedOutput() //nolint:gosec // fixed tool; arguments are validated addresses and constants
	if err != nil {
		return fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// chain creates a chain if it does not exist.
func (c iptablesCmd) chain(table, name string) error {
	if c.run("-t", table, "-L", name, "-n") == nil {
		return nil
	}
	return c.run("-t", table, "-N", name)
}

// fill replaces a chain's rules, unless they already match.
func (c iptablesCmd) fill(table, name string, rules [][]string) error {
	out, err := exec.Command(c.bin, "-w", "5", "-t", table, "-S", name).Output() //nolint:gosec // see run
	if err == nil {
		want := []string{"-N " + name}
		for _, r := range rules {
			want = append(want, "-A "+name+" "+strings.Join(r, " "))
		}
		if slices.Equal(strings.Split(strings.TrimSpace(string(out)), "\n"), want) {
			return nil
		}
	}
	if err := c.run("-t", table, "-F", name); err != nil {
		return err
	}
	for _, r := range rules {
		if err := c.run(append([]string{"-t", table, "-A", name}, r...)...); err != nil {
			return err
		}
	}
	return nil
}

// first makes sure a rule is in a built-in chain, inserting it at the top
// when it is missing.
func (c iptablesCmd) first(table, chain string, rule ...string) error {
	if c.run(append([]string{"-t", table, "-C", chain}, rule...)...) == nil {
		return nil
	}
	return c.run(append([]string{"-t", table, "-I", chain, "1"}, rule...)...)
}

// ContainerMTU is the MTU for the bridge and containers on a node whose
// private IP is ip.
func ContainerMTU(ip netip.Addr) (int, error) {
	_, mtu, err := UplinkOf(ip)
	if err != nil {
		return 0, err
	}
	return TunnelMTU(mtu), nil
}

// Diagnose reports, for armada doctor, whether the node's uplink leaves
// room for the tunnel and whether the tunnel is up with its peers.
func Diagnose(ip netip.Addr) []Check {
	var out []Check
	add := func(name string, level int, format string, args ...any) {
		out = append(out, Check{Name: name, Level: level, Detail: fmt.Sprintf(format, args...)})
	}
	uplink, mtu, err := UplinkOf(ip)
	if err != nil {
		add("network-mtu", CheckFail, "%v", err)
		return out
	}
	add("network-mtu", CheckOK, "%s has MTU %d; the tunnel and containers use %d", uplink.Attrs().Name, mtu, TunnelMTU(mtu))
	link, err := netlink.LinkByName(Interface)
	var nf netlink.LinkNotFoundError
	switch {
	case errors.As(err, &nf):
		if _, err := os.Stat("/sys/module/vxlan"); err != nil {
			if _, err := exec.Command("modprobe", "-n", "vxlan").CombinedOutput(); err != nil {
				add("network", CheckFail, "the kernel has no VXLAN support (modprobe vxlan fails); the cluster network needs it")
				return out
			}
		}
		add("network", CheckWarn, "%s is not set up yet; the agent creates it once connected", Interface)
		return out
	case err != nil:
		add("network", CheckFail, "inspect %s: %v", Interface, err)
		return out
	}
	if _, ok := link.(*netlink.Vxlan); !ok || link.Attrs().OperState == netlink.OperDown {
		add("network", CheckFail, "%s is not an up VXLAN interface; restart the agent to recreate it", Interface)
		return out
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		add("network", CheckWarn, "list routes of %s: %v", Interface, err)
		return out
	}
	peers := 0
	for _, r := range routes {
		if r.Dst != nil && r.Gw != nil {
			peers++
		}
	}
	add("network", CheckOK, "%s routes %d other node subnet(s) over VXLAN (UDP %d on %s, open it to the other nodes)", Interface, peers, VXLANPort, ip)
	return out
}

// Remove takes the cluster network off the node: the tunnel interface, with
// its routes and entries, and the firewall rules. It is for a node that has
// left the cluster.
func Remove() error {
	var errs []error
	if link, err := netlink.LinkByName(Interface); err == nil {
		if err := netlink.LinkDel(link); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", Interface, err))
		}
	}
	ipt := iptables
	for _, r := range [][]string{
		{"filter", "FORWARD", "-j", chainFwd},
		{"nat", "POSTROUTING", "-o", Interface, "-j", "RETURN"},
	} {
		for ipt.run(append([]string{"-t", r[0], "-D", r[1]}, r[2:]...)...) == nil {
		}
	}
	// The INPUT rule names the private IP; drop every rule that jumps to
	// the chain.
	if out, err := exec.Command(ipt.bin, "-w", "5", "-S", "INPUT").Output(); err == nil { //nolint:gosec // see run
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "-A INPUT ") && strings.HasSuffix(line, "-j "+chainIn) {
				errs = append(errs, ipt.run(append([]string{"-D", "INPUT"}, strings.Fields(strings.TrimPrefix(line, "-A INPUT "))...)...))
			}
		}
	}
	for _, c := range []string{chainIn, chainFwd} {
		if ipt.run("-L", c, "-n") == nil {
			errs = append(errs, ipt.run("-F", c), ipt.run("-X", c))
		}
	}
	return errors.Join(errs...)
}
