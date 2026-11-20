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
	// chainPre (raw table) drops forged tunnel traffic, and this node's
	// container addresses arriving anywhere but on the bridge, before
	// anything else sees it: the container networking plugins accept
	// containers' packets in FORWARD ahead of chainFwd.
	chainPre = "ARMADA-NET-PRE"
	// chainMesh accepts what the mesh mode's peers send to this node's
	// mesh address through the tunnel (ADR 0049).
	chainMesh = "ARMADA-NET-MESH"
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
	p, err := n.plan(cfg)
	if err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.firewall(p); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	if err := n.isolate(buildPolicy(p, local)); err != nil {
		return fmt.Errorf("isolation: %w", err)
	}
	if err := n.tunnel(p); err != nil {
		return err
	}
	if p.mode == ModeMesh && n.cfg.MeshCache != "" {
		if err := saveMeshCache(n.cfg.MeshCache, cfg); err != nil {
			n.log.Warn("keep the mesh's peer list", "err", err)
		}
	}
	return nil
}

// Up brings the mesh mode's tunnel up before the control plane can send a
// peer list: the API and etcd listen on mesh addresses (ADR 0049). With
// cfg (from init or the join answer) it uses that list and keeps it in
// Config.MeshCache; without, the list Apply last kept, doing nothing when
// there is none. Isolation waits for the first Apply.
func (n *Net) Up(cfg *armadav1.NetworkConfig) error {
	if n.cfg.MeshCache == "" {
		return errors.New("the mesh mode needs a place to keep its peer list")
	}
	given := cfg != nil
	if !given {
		var err error
		if cfg, err = loadMeshCache(n.cfg.MeshCache); err != nil || cfg == nil {
			return err
		}
	}
	p, err := n.plan(cfg)
	if err != nil {
		return fmt.Errorf("mesh peer list: %w", err)
	}
	if p.mode != ModeMesh {
		return fmt.Errorf("network mode %q is not the mesh", p.mode)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.firewall(p); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	if err := n.tunnel(p); err != nil {
		return err
	}
	if given {
		return saveMeshCache(n.cfg.MeshCache, cfg)
	}
	return nil
}

// plan validates cfg for this node.
func (n *Net) plan(cfg *armadav1.NetworkConfig) (plan, error) {
	p, err := parse(cfg, n.cfg.Node, n.cfg.PrivateIP)
	if err != nil {
		return plan{}, err
	}
	if encrypted(p.mode) && n.cfg.Key.IsZero() {
		return plan{}, fmt.Errorf("the %s mode needs the node's key", p.mode)
	}
	return p, nil
}

// tunnel sets up the tunnel interface, its peers, and its routes.
func (n *Net) tunnel(p plan) error {
	uplink, uplinkMTU, err := uplinkFor(p.mode, n.cfg.PrivateIP, n.cfg.Endpoint)
	if err != nil {
		return err
	}
	mtu := TunnelMTU(p.mode, uplinkMTU)
	if encrypted(p.mode) {
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

// uplinkFor returns the interface the tunnel's packets leave by, and its
// MTU: the one holding the private IP, or in the mesh mode (where the
// private IP is on the tunnel itself) the one holding the endpoint, else,
// behind one-to-one NAT, the one the route to the endpoint takes.
func uplinkFor(mode string, ip, endpoint netip.Addr) (netlink.Link, int, error) {
	if mode != ModeMesh {
		return UplinkOf(ip)
	}
	if !endpoint.IsValid() {
		return nil, 0, errors.New("the mesh mode needs the node's endpoint")
	}
	if link, mtu, err := UplinkOf(endpoint); err == nil {
		return link, mtu, nil
	}
	routes, err := netlink.RouteGet(endpoint.AsSlice())
	if err != nil {
		return nil, 0, fmt.Errorf("no route towards the endpoint %s: %w", endpoint, err)
	}
	if len(routes) == 0 {
		return nil, 0, fmt.Errorf("no route towards the endpoint %s", endpoint)
	}
	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return nil, 0, err
	}
	mtu := link.Attrs().MTU
	if link.Attrs().Name == Interface || link.Attrs().Name == "lo" {
		return nil, 0, fmt.Errorf("the route towards the endpoint %s leaves by %s, not an uplink", endpoint, link.Attrs().Name)
	}
	if mtu < MinUplinkMTU {
		return nil, 0, fmt.Errorf("the uplink %s has MTU %d, below %d", link.Attrs().Name, mtu, MinUplinkMTU)
	}
	return link, mtu, nil
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

// setUp gives the tunnel interface its MTU and the node's tunnel address
// (and in the mesh mode its mesh address), removes any other address, and
// brings it up.
func setUp(link netlink.Link, p plan, mtu int) error {
	if link.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("set MTU of %s: %w", Interface, err)
		}
	}
	addrs := []*netlink.Addr{{IPNet: &net.IPNet{IP: vtepAddr(p.self.subnet).AsSlice(), Mask: net.CIDRMask(32, 32)}}}
	if p.mode == ModeMesh {
		addrs = append(addrs, &netlink.Addr{IPNet: &net.IPNet{IP: p.self.ip.AsSlice(), Mask: net.CIDRMask(32, 32)}})
	}
	have, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, a := range have {
		if !slices.ContainsFunc(addrs, func(w *netlink.Addr) bool { return a.IP.Equal(w.IP) }) {
			if err := netlink.AddrDel(link, &a); err != nil {
				return err
			}
		}
	}
	for _, a := range addrs {
		if err := netlink.AddrReplace(link, a); err != nil {
			return fmt.Errorf("address %s: %w", Interface, err)
		}
	}
	return netlink.LinkSetUp(link)
}

// syncRoutes installs a route to each peer's subnet through link, via the
// peer's tunnel end when via is set, and in the mesh mode one to each peer's
// mesh address, from this node's; it removes routes to nodes that left.
func syncRoutes(link netlink.Link, p plan, via bool) error {
	idx := link.Attrs().Index
	want := map[netip.Prefix]bool{}
	for _, pe := range p.peers {
		if p.mode == ModeMesh {
			dst := netip.PrefixFrom(pe.ip, 32)
			r := &netlink.Route{LinkIndex: idx, Dst: prefixNet(dst), Scope: netlink.SCOPE_LINK, Src: p.self.ip.AsSlice()}
			if err := netlink.RouteReplace(r); err != nil {
				return fmt.Errorf("route to %s (%s): %w", pe.node, pe.ip, err)
			}
			want[dst] = true
		}
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
	if encrypted(mode) {
		return WireGuardPort
	}
	return VXLANPort
}

// firewall lets the tunnel's port accept packets only on the private IP and
// only from the current peers (kernel WireGuard listens on every address),
// or in the mesh mode from anywhere (peers' public addresses change, and
// WireGuard answers nothing that does not authenticate) with the peers'
// mesh traffic to this node's mesh address accepted too; it forwards
// decapsulated traffic only to and from the container bridge, and keeps
// traffic between containers of different nodes out of masquerading, so a
// replica sees the caller's address.
func (n *Net) firewall(p plan) error {
	ipt := iptables
	if err := ipt.chain("filter", chainIn); err != nil {
		return err
	}
	rules := [][]string{}
	if p.mode == ModeMesh {
		rules = append(rules, []string{"-j", "ACCEPT"})
	} else {
		for _, pe := range p.peers {
			rules = append(rules, []string{"-s", pe.ip.String() + "/32", "-d", n.cfg.PrivateIP.String() + "/32", "-j", "ACCEPT"})
		}
		rules = append(rules, []string{"-j", "DROP"})
	}
	if err := ipt.fill("filter", chainIn, rules); err != nil {
		return err
	}
	if err := ipt.only("INPUT", chainIn, "-p", "udp", "-m", "udp", "--dport", strconv.Itoa(port(p.mode)), "-j", chainIn); err != nil {
		return err
	}
	if p.mode == ModeMesh {
		if err := ipt.chain("filter", chainMesh); err != nil {
			return err
		}
		if err := ipt.fill("filter", chainMesh, meshRules(p)); err != nil {
			return err
		}
		if err := ipt.only("INPUT", chainMesh, "-i", Interface, "-j", chainMesh); err != nil {
			return err
		}
	}
	if err := ipt.chain("filter", chainFwd); err != nil {
		return err
	}
	if err := ipt.fill("filter", chainFwd, forwardRules()); err != nil {
		return err
	}
	if err := ipt.first("filter", "FORWARD", "-j", chainFwd); err != nil {
		return err
	}
	if err := ipt.chain("raw", chainPre); err != nil {
		return err
	}
	if err := ipt.fill("raw", chainPre, spoofRules(p)); err != nil {
		return err
	}
	if err := ipt.first("raw", "PREROUTING", "-j", chainPre); err != nil {
		return err
	}
	// Ahead of the container runtime's masquerading.
	return ipt.first("nat", "POSTROUTING", "-o", Interface, "-j", "RETURN")
}

// forwardRules are ARMADA-NET-FWD's rules.
func forwardRules() [][]string {
	return [][]string{
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
	}
}

// meshRules are ARMADA-NET-MESH's rules: the mesh mode's peers reach this
// node's mesh address (the API, etcd, HTTP-01 forwarding, metrics), as
// machines on a private network reach a private IP. WireGuard allows each
// peer only its own mesh address and subnet as sources.
func meshRules(p plan) [][]string {
	return [][]string{
		{"-s", p.mesh.String(), "-d", p.self.ip.String() + "/32", "-j", "ACCEPT"},
		{"-j", "RETURN"},
	}
}

// spoofRules are ARMADA-NET-PRE's rules, written as iptables -S prints them
// so that fill finds them unchanged.
func spoofRules(p plan) [][]string {
	var rules [][]string
	// A container never sends to a peer's tunnel port: masqueraded to the
	// node's address, its packets would pass the peer's ARMADA-NET-IN, and
	// the frame inside, with any source address it likes, would come out of
	// the peer's tunnel as if another node's container had sent it, past
	// the isolation of spaces.
	for _, pe := range p.peers {
		to := pe.ip
		if p.mode == ModeMesh {
			to = pe.endpoint
		}
		rules = append(rules, []string{"-d", to.String() + "/32", "-i", embedded.BridgeName, "-p", "udp", "-m", "udp", "--dport", strconv.Itoa(port(p.mode)), "-j", "DROP"})
	}
	if p.mode == ModeMesh {
		mesh := p.mesh.String()
		rules = append(rules,
			// Mesh addresses exist only on the tunnel: nothing else, a
			// machine on the provider's network routing the range to this
			// node or a container included, reaches them or claims one. The
			// node itself talks to its own mesh address over loopback.
			[]string{"-d", mesh, "-i", "lo", "-j", "RETURN"},
			[]string{"-d", mesh, "!", "-i", Interface, "-j", "DROP"},
			[]string{"-s", mesh, "!", "-i", Interface, "-j", "DROP"},
			// The peers' own traffic, which WireGuard has authenticated.
			[]string{"-s", mesh, "-i", Interface, "-j", "RETURN"},
		)
	}
	sub := p.self.subnet.String()
	return append(rules,
		// This node's subnet arrives only from its own containers, on the
		// bridge, or from the node itself (its gateway and tunnel
		// addresses), over loopback. Anything else claiming it, from the
		// tunnel or forged by a machine on the private network that routes
		// the subnet to this node, is dropped: the DNS server, the internal
		// frontend, and the isolation rules take an address in the subnet
		// for one of this node's containers.
		[]string{"-s", sub, "-i", "lo", "-j", "RETURN"},
		[]string{"-s", sub, "!", "-i", embedded.BridgeName, "-j", "DROP"},
		// What comes out of the tunnel is from another node's containers or
		// that node itself (its tunnel address): never from outside the
		// cluster's range.
		[]string{"!", "-s", p.cidr.String(), "-i", Interface, "-j", "DROP"},
	)
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
// cluster network in mode whose private IP is ip (and, in the mesh mode,
// whose endpoint is endpoint).
func ContainerMTU(mode string, ip, endpoint netip.Addr) (int, error) {
	_, mtu, err := uplinkFor(mode, ip, endpoint)
	if err != nil {
		return 0, err
	}
	return TunnelMTU(mode, mtu), nil
}

// Diagnose reports, for armadad doctor, whether the node's uplink leaves
// room for the tunnel and whether the tunnel is up with its peers.
func Diagnose(mode string, ip, endpoint netip.Addr) []Check {
	return append(diagnoseTunnel(mode, ip, endpoint), diagnoseIsolation())
}

// diagnoseIsolation reports whether the tables that keep apps and spaces
// apart are in place.
func diagnoseIsolation() Check {
	c := Check{Name: "isolation", Level: CheckOK, Detail: "the nftables tables that keep apps and spaces apart are in place"}
	switch ok, err := hasIsolation(); {
	case err != nil:
		c.Level, c.Detail = CheckFail, fmt.Sprintf("nftables is not usable (%v); the kernel needs nf_tables to keep apps and spaces apart", err)
	case !ok:
		c.Level, c.Detail = CheckWarn, "the nftables tables that keep apps and spaces apart are not set up yet; the agent creates them once connected"
	default:
		// The tables filter IPv4 only; the bridge must have no IPv6.
		if off, err := embedded.IPv6Off(embedded.BridgeName); err != nil || !off {
			c.Level, c.Detail = CheckFail, fmt.Sprintf("IPv6 is on for %s, so containers can reach this machine's IPv6 listeners past the firewall; restart the agent, which turns it off", embedded.BridgeName)
		}
	}
	return c
}

func diagnoseTunnel(mode string, ip, endpoint netip.Addr) []Check {
	var out []Check
	add := func(name string, level int, format string, args ...any) {
		out = append(out, Check{Name: name, Level: level, Detail: fmt.Sprintf(format, args...)})
	}
	uplink, mtu, err := uplinkFor(mode, ip, endpoint)
	if err != nil {
		add("network-mtu", CheckFail, "%v", err)
		return out
	}
	add("network-mtu", CheckOK, "%s has MTU %d; the tunnel and containers use %d", uplink.Attrs().Name, mtu, TunnelMTU(mode, mtu))
	if encrypted(mode) {
		return append(out, diagnoseWireGuard(mode, ip)...)
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
		{"raw", "PREROUTING", "-j", chainPre},
		{"nat", "POSTROUTING", "-o", Interface, "-j", "RETURN"},
	} {
		for ipt.run(append([]string{"-t", r[0], "-D", r[1]}, r[2:]...)...) == nil {
		}
	}
	for _, c := range []string{chainIn, chainMesh} {
		for _, r := range ipt.jumps("INPUT", c) {
			errs = append(errs, ipt.run(append([]string{"-D", "INPUT"}, r...)...))
		}
	}
	for _, c := range []string{chainIn, chainMesh, chainFwd} {
		if ipt.run("-L", c, "-n") == nil {
			errs = append(errs, ipt.run("-F", c), ipt.run("-X", c))
		}
	}
	if ipt.run("-t", "raw", "-L", chainPre, "-n") == nil {
		errs = append(errs, ipt.run("-t", "raw", "-F", chainPre), ipt.run("-t", "raw", "-X", chainPre))
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
