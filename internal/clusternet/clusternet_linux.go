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
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/device"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

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
	// isolated is the last isolation policy applied, to rebuild the tables
	// only when it changes (or they went missing).
	isolated *policy
	// user is the userspace WireGuard device, when the kernel has none; it
	// lives as long as the agent.
	user *userDevice
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
func (n *Net) Apply(_ context.Context, cfg *armadav1.NetworkConfig, local map[netip.Addr]string) error {
	p, err := parse(cfg, n.cfg.Node, n.cfg.PrivateIP)
	if err != nil {
		return err
	}
	if p.mode == ModeWireGuard && n.cfg.Key.IsZero() {
		return errors.New("the wireguard mode needs the node's key")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.firewall(p); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	if err := n.isolate(buildPolicy(p, local)); err != nil {
		return fmt.Errorf("isolation: %w", err)
	}
	uplink, uplinkMTU, err := UplinkOf(n.cfg.PrivateIP)
	if err != nil {
		return err
	}
	mtu := TunnelMTU(p.mode, uplinkMTU)
	if p.mode == ModeWireGuard {
		err = n.wireguard(p, mtu)
	} else {
		err = n.vxlan(p, uplink, mtu)
	}
	if err != nil {
		return err
	}
	summary := fmt.Sprintf("%s %s %d", p.mode, p.self.subnet, len(p.peers))
	if summary != n.last {
		n.log.Info("cluster network applied", "mode", p.mode, "subnet", p.self.subnet, "peers", len(p.peers), "mtu", mtu)
		n.last = summary
	}
	return nil
}

// isolate applies pol unless it is what the tables already hold.
func (n *Net) isolate(pol policy) error {
	if n.isolated != nil && reflect.DeepEqual(*n.isolated, pol) {
		if ok, err := hasIsolation(); err == nil && ok {
			return nil
		}
	}
	if n.isolated != nil && sameFrame(*n.isolated, pol) {
		if ok, err := hasIsolation(); err == nil && ok {
			err := updateIsolation(*n.isolated, pol)
			if err == nil {
				n.isolated = &pol
				return nil
			}
			n.log.Warn("update the isolation rules; rebuilding them", "err", err)
		}
	}
	if err := isolate(pol); err != nil {
		n.isolated = nil
		return err
	}
	n.isolated = &pol
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

// existing returns the tunnel interface, or nil when there is none.
func existing() (netlink.Link, error) {
	link, err := netlink.LinkByName(Interface)
	var nf netlink.LinkNotFoundError
	if errors.As(err, &nf) {
		return nil, nil
	}
	return link, err
}

// setUp gives the tunnel interface its MTU and the node's tunnel address,
// removes any other address, and brings it up.
func setUp(link netlink.Link, p plan, mtu int) error {
	if link.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("set MTU of %s: %w", Interface, err)
		}
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: vtepAddr(p.self.subnet).AsSlice(), Mask: net.CIDRMask(32, 32)}}
	have, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, a := range have {
		if !a.IP.Equal(addr.IP) {
			if err := netlink.AddrDel(link, &a); err != nil {
				return err
			}
		}
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("address %s: %w", Interface, err)
	}
	return netlink.LinkSetUp(link)
}

// syncRoutes installs a route to each peer's subnet through link, via the
// peer's tunnel end when via is set, and removes routes to nodes that left.
func syncRoutes(link netlink.Link, p plan, via bool) error {
	idx := link.Attrs().Index
	want := map[netip.Prefix]bool{}
	for _, pe := range p.peers {
		r := &netlink.Route{LinkIndex: idx, Dst: prefixNet(pe.subnet), Scope: netlink.SCOPE_LINK}
		if via {
			r.Scope, r.Gw, r.Flags = netlink.SCOPE_UNIVERSE, vtepAddr(pe.subnet).AsSlice(), int(netlink.FLAG_ONLINK)
		}
		if err := netlink.RouteReplace(r); err != nil {
			return fmt.Errorf("route to %s (%s): %w", pe.node, pe.subnet, err)
		}
		want[pe.subnet] = true
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
		if ok && !want[netip.PrefixFrom(dst.Unmap(), ones)] && r.Protocol != netlink.RouteProtocol(syscall.RTPROT_KERNEL) {
			if err := netlink.RouteDel(&r); err != nil {
				return fmt.Errorf("remove route %s: %w", r.Dst, err)
			}
		}
	}
	return nil
}

// port is the tunnel's UDP port in a mode.
func port(mode string) int {
	if mode == ModeWireGuard {
		return WireGuardPort
	}
	return VXLANPort
}

// firewall lets the tunnel's port accept packets only on the private IP and
// only from the current peers (kernel WireGuard listens on every address),
// forwards decapsulated traffic only to and from the container bridge, and
// keeps traffic between containers of different nodes out of masquerading,
// so a replica sees the caller's address.
func (n *Net) firewall(p plan) error {
	ipt := iptables
	if err := ipt.chain("filter", chainIn); err != nil {
		return err
	}
	rules := [][]string{}
	for _, pe := range p.peers {
		rules = append(rules, []string{"-s", pe.ip.String() + "/32", "-d", n.cfg.PrivateIP.String() + "/32", "-j", "ACCEPT"})
	}
	rules = append(rules, []string{"-j", "DROP"})
	if err := ipt.fill("filter", chainIn, rules); err != nil {
		return err
	}
	if err := ipt.only("INPUT", chainIn, "-p", "udp", "-m", "udp", "--dport", strconv.Itoa(port(p.mode)), "-j", chainIn); err != nil {
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
		// Containers are reached from other machines only through the
		// tunnel: a machine on the private network that routes the node's
		// subnet through its private IP gets nowhere. Replies, traffic
		// between containers, and ports published before the node joined
		// (DNAT) still pass.
		{"-i", embedded.BridgeName, "-o", embedded.BridgeName, "-j", "RETURN"},
		{"-o", embedded.BridgeName, "-m", "conntrack", "--ctstate", "NEW", "-m", "conntrack", "!", "--ctstate", "DNAT", "-j", "DROP"},
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

// jumps returns the rules of a built-in filter chain that jump to target,
// as arguments for -D.
func (c iptablesCmd) jumps(chain, target string) [][]string {
	out, err := exec.Command(c.bin, "-w", "5", "-S", chain).Output() //nolint:gosec // see run
	if err != nil {
		return nil
	}
	var rules [][]string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "-A "+chain+" ") && strings.HasSuffix(line, "-j "+target) {
			rules = append(rules, strings.Fields(strings.TrimPrefix(line, "-A "+chain+" ")))
		}
	}
	return rules
}

// only makes rule the one rule of a built-in filter chain that jumps to
// target, at the top, and removes other jumps to it (from an older port).
func (c iptablesCmd) only(chain, target string, rule ...string) error {
	for _, r := range c.jumps(chain, target) {
		if !slices.Equal(r, rule) {
			if err := c.run(append([]string{"-D", chain}, r...)...); err != nil {
				return err
			}
		}
	}
	return c.first("filter", chain, rule...)
}

// ContainerMTU is the MTU for the bridge and containers on a node of a
// cluster network in mode whose private IP is ip.
func ContainerMTU(mode string, ip netip.Addr) (int, error) {
	_, mtu, err := UplinkOf(ip)
	if err != nil {
		return 0, err
	}
	return TunnelMTU(mode, mtu), nil
}

// Diagnose reports, for armada doctor, whether the node's uplink leaves
// room for the tunnel and whether the tunnel is up with its peers.
func Diagnose(mode string, ip netip.Addr) []Check {
	return append(diagnoseTunnel(mode, ip), diagnoseIsolation())
}

// diagnoseIsolation reports whether the tables that keep apps and projects
// apart are in place.
func diagnoseIsolation() Check {
	c := Check{Name: "isolation", Level: CheckOK, Detail: "the nftables tables that keep apps and projects apart are in place"}
	switch ok, err := hasIsolation(); {
	case err != nil:
		c.Level, c.Detail = CheckFail, fmt.Sprintf("nftables is not usable (%v); the kernel needs nf_tables to keep apps and projects apart", err)
	case !ok:
		c.Level, c.Detail = CheckWarn, "the nftables tables that keep apps and projects apart are not set up yet; the agent creates them once connected"
	}
	return c
}

func diagnoseTunnel(mode string, ip netip.Addr) []Check {
	var out []Check
	add := func(name string, level int, format string, args ...any) {
		out = append(out, Check{Name: name, Level: level, Detail: fmt.Sprintf(format, args...)})
	}
	uplink, mtu, err := UplinkOf(ip)
	if err != nil {
		add("network-mtu", CheckFail, "%v", err)
		return out
	}
	add("network-mtu", CheckOK, "%s has MTU %d; the tunnel and containers use %d", uplink.Attrs().Name, mtu, TunnelMTU(mode, mtu))
	if mode == ModeWireGuard {
		return append(out, diagnoseWireGuard(ip)...)
	}
	link, err := existing()
	switch {
	case err != nil:
		add("network", CheckFail, "inspect %s: %v", Interface, err)
		return out
	case link == nil:
		if !kernelHas("vxlan") {
			add("network", CheckFail, "the kernel has no VXLAN support (modprobe vxlan fails); the cluster network needs it")
			return out
		}
		add("network", CheckWarn, "%s is not set up yet; the agent creates it once connected", Interface)
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

// kernelHas reports whether the kernel has a module loaded, built in, or
// available to load.
func kernelHas(module string) bool {
	if _, err := os.Stat("/sys/module/" + module); err == nil {
		return true
	}
	return exec.Command("modprobe", "-n", module).Run() == nil //nolint:gosec // fixed module names
}

// Remove takes the cluster network off the node: the tunnel interface, with
// its routes and entries, and the firewall rules. It is for a node that has
// left the cluster.
func Remove() error {
	var errs []error
	if link, err := existing(); err == nil && link != nil {
		if err := netlink.LinkDel(link); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", Interface, err))
		}
	}
	if err := removeIsolation(); err != nil {
		errs = append(errs, fmt.Errorf("remove the isolation tables: %w", err))
	}
	ipt := iptables
	for _, r := range [][]string{
		{"filter", "FORWARD", "-j", chainFwd},
		{"nat", "POSTROUTING", "-o", Interface, "-j", "RETURN"},
	} {
		for ipt.run(append([]string{"-t", r[0], "-D", r[1]}, r[2:]...)...) == nil {
		}
	}
	for _, r := range ipt.jumps("INPUT", chainIn) {
		errs = append(errs, ipt.run(append([]string{"-D", "INPUT"}, r...)...))
	}
	for _, c := range []string{chainIn, chainFwd} {
		if ipt.run("-L", c, "-n") == nil {
			errs = append(errs, ipt.run("-F", c), ipt.run("-X", c))
		}
	}
	// The control socket a userspace WireGuard device leaves behind.
	if err := os.Remove(userSocket); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// deviceLogger sends the userspace WireGuard device's errors to the log.
func deviceLogger(log *slog.Logger) *device.Logger {
	return &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf:   func(format string, args ...any) { log.Warn("wireguard: " + fmt.Sprintf(format, args...)) },
	}
}
