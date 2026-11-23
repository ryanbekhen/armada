//go:build linux

package clusternet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
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
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

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
	// chainMSS (mangle table) clamps the MSS of TCP connections leaving
	// through the tunnel to its MTU, so containers created with a larger
	// MTU, before a switch to the wireguard mode (ADR 0050), keep working.
	chainMSS = "ARMADA-NET-MSS"
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
	// sw is this node's side of a switch between modes (ADR 0050).
	sw switchState
	// wgSince is when each WireGuard peer, by key, was first configured,
	// so a peer just added is not reported unreachable (UnreachablePeers).
	wgSince map[wgtypes.Key]wgPeerSeen
	// nextClean is set once the firewall rules of a finished switch's
	// interface are known to be gone; siteClean, those of SiteInterface
	// once no peer is in another site.
	nextClean, siteClean bool
	// prog is what passes through armada-node keep (program_linux.go).
	prog programRun
	// goApply is Go's own pass of Apply; tests replace it.
	goApply func(cfg *armadav1.NetworkConfig, local map[netip.Addr]string) error
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
	n := &Net{cfg: cfg, log: log}
	n.goApply = n.applyGo
	return n, nil
}

// Apply makes the tunnel, routes, and firewall rules match cfg. The
// firewall comes first, so the tunnel never accepts packets from anyone but
// the current peers. With Config.Program, armada-node does the pass, and Go
// only when it fails.
func (n *Net) Apply(ctx context.Context, cfg *armadav1.NetworkConfig, local map[netip.Addr]string) error {
	if done, err := n.viaProgram(ctx, "apply", cfg, local); done {
		return err
	}
	return n.goApply(cfg, local)
}

// applyGo is Apply in Go.
func (n *Net) applyGo(cfg *armadav1.NetworkConfig, local map[netip.Addr]string) error {
	p, err := n.plan(cfg)
	if err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.takeOver()
	if err := n.firewall(p); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	if err := n.isolate(buildPolicy(p, local)); err != nil {
		return fmt.Errorf("isolation: %w", err)
	}
	err = n.tunnel(p)
	n.track(p, err)
	if err != nil {
		return err
	}
	n.seePeers(p, time.Now())
	switch {
	case n.cfg.MeshCache == "":
	case p.mode == ModeMesh || len(p.remote()) > 0:
		// The tunnels to the mesh, or to other sites, come up from it
		// before the control plane when the machine starts.
		if err := saveMeshCache(n.cfg.MeshCache, cfg); err != nil {
			n.log.Warn("keep the peer list", "err", err)
		}
	default:
		if err := RemoveMeshCache(n.cfg.MeshCache); err != nil {
			n.log.Warn("remove the peer list", "err", err)
		}
	}
	return nil
}

// Up brings the tunnels up before the control plane can send a peer list:
// in the mesh mode the API and etcd listen on mesh addresses (ADR 0049),
// and nodes of other sites reach the control plane only through them (ADR
// 0050). With
// cfg (from init or the join answer) it uses that list and keeps it in
// Config.MeshCache; without, the list Apply last kept, doing nothing when
// there is none. Isolation waits for the first Apply.
func (n *Net) Up(cfg *armadav1.NetworkConfig) error {
	if done, err := n.viaProgram(context.Background(), "up", cfg, nil); done {
		return err
	}
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
		return fmt.Errorf("peer list: %w", err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.takeOver()
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
	if (encrypted(p.mode) || encrypted(p.switchTo)) && n.cfg.Key.IsZero() {
		return plan{}, fmt.Errorf("the %s mode needs the node's key", ModeWireGuard)
	}
	return p, nil
}

// routeSet is which routes a transport's interface carries.
type routeSet int

const (
	// routesAll: a route to every peer's subnet (and mesh address).
	routesAll routeSet = iota
	// routesProbe: only a route to every peer's tunnel address, which the
	// probe of a switch's prepare step pings (ADR 0050).
	routesProbe
	// routesNone: no routes; the interface still takes what peers send.
	routesNone
)

// tunnel sets up the tunnel interface, its peers, and its routes. During a
// switch between modes (ADR 0050) the target transport runs beside the
// current one on Next: in the prepare step with only the probe's routes, in
// the move step with every route. The interface that takes the routes is
// set up first, so the routes move without a gap.
func (n *Net) tunnel(p plan) error {
	if !p.switching() {
		if err := n.finishSwitch(p.mode); err != nil {
			return err
		}
		// A plain cluster reaches other sites over SiteInterface, set up
		// first so a peer that moved site takes its routes along.
		all := p
		if p.mode == ModePlain {
			if err := n.sites(p); err != nil {
				return err
			}
			if p.meshed {
				// No private network to run VXLAN over: every peer is
				// on SiteInterface.
				return n.dropVXLAN(p)
			}
			all = p.only(p.local())
		} else if err := n.sites(p.only(nil)); err != nil {
			// Interface carries every peer, on the same port.
			return err
		}
		mtu, err := n.transport(all, p.mode, Interface, routesAll)
		if err != nil {
			return err
		}
		remote := len(p.remote())
		summary := fmt.Sprintf("%s %s %d %d", p.mode, p.self.subnet, len(p.peers), remote)
		if summary != n.last {
			n.log.Info("cluster network applied", "mode", p.mode, "subnet", p.self.subnet, "peers", len(p.peers), "other_sites", remote, "mtu", mtu)
			n.last = summary
		}
		return nil
	}
	if p.step == SwitchMove {
		if _, err := n.transport(p, p.switchTo, Next, routesAll); err != nil {
			return err
		}
		_, err := n.transport(p, p.mode, Interface, routesNone)
		return err
	}
	if _, err := n.transport(p, p.mode, Interface, routesAll); err != nil {
		return err
	}
	_, err := n.transport(p, p.switchTo, Next, routesProbe)
	return err
}

// dropVXLAN removes Interface from a plain cluster's node with a mesh
// address (ADR 0050), whose peers are all on SiteInterface.
func (n *Net) dropVXLAN(p plan) error {
	summary := fmt.Sprintf("%s %s meshed %d", p.mode, p.self.subnet, len(p.peers))
	if summary != n.last {
		n.log.Info("cluster network applied", "mode", p.mode, "subnet", p.self.subnet, "peers", len(p.peers), "mesh_address", p.self.ip)
		n.last = summary
	}
	link, err := linkNamed(Interface)
	if err != nil || link == nil {
		return err
	}
	return n.delLink(link)
}

// sites sets up SiteInterface for a plain cluster's peers in other sites
// (ADR 0050), or removes it when there are none.
func (n *Net) sites(p plan) error {
	remote := p.remote()
	if len(remote) == 0 {
		link, err := linkNamed(SiteInterface)
		if err != nil || link == nil {
			return err
		}
		n.log.Info("no node in another site; removing their interface", "interface", SiteInterface)
		return n.delLink(link)
	}
	_, err := n.transport(p.only(remote), ModeWireGuard, SiteInterface, routesAll)
	return err
}

// transport sets up mode's transport on the interface name with the routes
// r asks for, and returns its MTU.
func (n *Net) transport(p plan, mode, name string, r routeSet) (int, error) {
	uplink, uplinkMTU, _, err := uplinkFor(mode, n.cfg.PrivateIP, n.cfg.Endpoint)
	if err != nil {
		return 0, err
	}
	if encrypted(mode) {
		// Packets to other sites leave by the route to their endpoints,
		// whose interface may take less than the private network's.
		uplinkMTU = min(uplinkMTU, remoteUplinkMTU(p.remote(), uplinkMTU))
	}
	if n.cfg.UplinkMTU > 0 {
		uplinkMTU = min(uplinkMTU, n.cfg.UplinkMTU)
	}
	mtu := TunnelMTU(mode, uplinkMTU)
	if encrypted(mode) {
		err = n.wireguard(p, mode, name, mtu, r)
	} else {
		err = n.vxlan(p, name, uplink, mtu, r)
	}
	return mtu, err
}

// finishSwitch ends what a switch left on the node (ADR 0050): Next, when
// it carries mode, takes the place of Interface; otherwise (a switch given
// up during its prepare step) it goes. Renaming takes the interface down
// for a moment, and the caller sets it up again with its routes.
func (n *Net) finishSwitch(mode string) error {
	next, err := linkNamed(Next)
	if err != nil || next == nil {
		return err
	}
	cur, err := linkNamed(Interface)
	if err != nil {
		return err
	}
	if !n.carries(next, mode) || cur != nil && n.carries(cur, mode) {
		n.log.Info("removing the interface of a switch that did not happen", "interface", Next)
		return n.delLink(next)
	}
	if cur != nil {
		if err := n.delLink(cur); err != nil {
			return err
		}
	}
	if err := netlink.LinkSetDown(next); err != nil {
		return fmt.Errorf("take %s down: %w", Next, err)
	}
	if err := netlink.LinkSetName(next, Interface); err != nil {
		return fmt.Errorf("rename %s to %s: %w", Next, Interface, err)
	}
	n.log.Info("cluster network switched", "mode", mode)
	return nil
}

// remoteUplinkMTU returns the smallest MTU of the interfaces the routes to
// peers' endpoints leave by, or def when there are none.
func remoteUplinkMTU(peers []peer, def int) int {
	mtu := def
	for _, pe := range peers {
		routes, err := netlink.RouteGet(pe.endpoint.AsSlice())
		if err != nil || len(routes) == 0 {
			continue
		}
		link, err := netlink.LinkByIndex(routes[0].LinkIndex)
		if err != nil {
			continue
		}
		switch name := link.Attrs().Name; {
		case name == Interface || name == Next || name == SiteInterface || name == "lo":
		case link.Attrs().MTU >= MinUplinkMTU:
			mtu = min(mtu, link.Attrs().MTU)
		}
	}
	return mtu
}

// carries reports whether link is the transport of mode.
func (n *Net) carries(link netlink.Link, mode string) bool {
	switch link.(type) {
	case *netlink.Wireguard:
		return encrypted(mode)
	case *netlink.Vxlan:
		return !encrypted(mode)
	}
	return encrypted(mode) && link.Attrs().Name == Interface && n.user != nil
}

// delLink removes an interface, closing the userspace device that holds
// it.
func (n *Net) delLink(link netlink.Link) error {
	name := link.Attrs().Name
	if name == Interface && n.user != nil {
		n.user.close()
		n.user = nil
		if l, err := linkNamed(name); err != nil || l == nil {
			return err
		}
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("remove %s: %w", name, err)
	}
	return nil
}

// uplinkFor returns the interface the tunnel's packets leave by, and its
// MTU: the one holding the private IP, or in the mesh mode (where the
// private IP is on the tunnel itself) the one holding the endpoint, else,
// behind one-to-one NAT, the one the route to the endpoint takes. A node
// of a plain or wireguard cluster whose address is a mesh address (ADR
// 0050), held by a tunnel interface or by none, finds it the same way and
// reports meshed.
func uplinkFor(mode string, ip, endpoint netip.Addr) (link netlink.Link, mtu int, meshed bool, err error) {
	if mode != ModeMesh {
		link, mtu, err := UplinkOf(ip)
		if err == nil && !tunnelName(link.Attrs().Name) || !endpoint.IsValid() {
			return link, mtu, false, err
		}
		if err == nil || errors.Is(err, errNoUplink) {
			link, mtu, err := endpointUplink(endpoint)
			return link, mtu, err == nil, err
		}
		return nil, 0, false, err
	}
	link, mtu, err = endpointUplink(endpoint)
	return link, mtu, false, err
}

// tunnelName reports whether name is one of Armada's tunnel interfaces.
func tunnelName(name string) bool {
	return name == Interface || name == Next || name == SiteInterface
}

// endpointUplink returns the interface holding the endpoint, else the one
// the route to it takes, and its MTU.
func endpointUplink(endpoint netip.Addr) (netlink.Link, int, error) {
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
	if name := link.Attrs().Name; name == Interface || name == Next || name == SiteInterface || name == "lo" {
		return nil, 0, fmt.Errorf("the route towards the endpoint %s leaves by %s, not an uplink", endpoint, link.Attrs().Name)
	}
	if mtu < MinUplinkMTU {
		return nil, 0, fmt.Errorf("the uplink %s has MTU %d, below %d", link.Attrs().Name, mtu, MinUplinkMTU)
	}
	return link, mtu, nil
}

// isolate applies pol unless it is what the tables already hold.
func (n *Net) isolate(pol policy) error {
	has := func() bool {
		ok, err := hasIsolation()
		return err == nil && ok
	}
	switch isolationAction(n.isolated, pol, has) {
	case isolationKeep:
		return nil
	case isolationUpdate:
		err := updateIsolation(*n.isolated, pol)
		if err == nil {
			n.isolated = &pol
			return nil
		}
		n.log.Warn("update the isolation rules; rebuilding them", "err", err)
	}
	if err := isolate(pol); err != nil {
		n.isolated = nil
		return err
	}
	n.isolated = &pol
	return nil
}

// What Net.isolate does with a policy.
const (
	isolationKeep    = "keep"    // the tables already hold it
	isolationUpdate  = "update"  // change them in place, rebuilding them when that fails
	isolationRebuild = "rebuild" // build them again
)

// isolationAction is Net.isolate's choice for pol after prev, with has
// reporting whether the tables exist (asked only when it matters).
func isolationAction(prev *policy, pol policy, has func() bool) string {
	if prev != nil && reflect.DeepEqual(*prev, pol) && has() {
		return isolationKeep
	}
	if prev != nil && sameFrame(*prev, pol) && has() {
		return isolationUpdate
	}
	return isolationRebuild
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
	return nil, 0, fmt.Errorf("%w %s", errNoUplink, ip)
}

// errNoUplink: no interface holds the address.
var errNoUplink = errors.New("no interface holds the private IP")

// linkNamed returns the interface name, or nil when there is none.
func linkNamed(name string) (netlink.Link, error) {
	link, err := netlink.LinkByName(name)
	var nf netlink.LinkNotFoundError
	if errors.As(err, &nf) {
		return nil, nil
	}
	return link, err
}

// setUp gives the tunnel interface its MTU and the node's tunnel address
// (and its mesh address, in the mesh mode or when it has one, ADR 0050),
// removes any other address, and
// brings it up.
func setUp(link netlink.Link, p plan, mtu int) error {
	if link.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("set MTU of %s: %w", link.Attrs().Name, err)
		}
	}
	addrs := []*netlink.Addr{{IPNet: &net.IPNet{IP: vtepAddr(p.self.subnet).AsSlice(), Mask: net.CIDRMask(32, 32)}}}
	if p.mode == ModeMesh || p.meshed {
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
			return fmt.Errorf("address %s: %w", link.Attrs().Name, err)
		}
	}
	return netlink.LinkSetUp(link)
}

// syncRoutes installs a route to each peer's subnet through link, via the
// peer's tunnel end when via is set, and in the mesh mode, or for a peer of
// another site, one to each peer's node address, from this node's; it removes routes to nodes that left. With
// routesProbe it installs only a route to each peer's tunnel end, and with
// routesNone none.
func syncRoutes(link netlink.Link, p plan, via bool, set routeSet) error {
	idx := link.Attrs().Index
	want := map[netip.Prefix]bool{}
	for _, w := range wantRoutes(p, via, set) {
		r := &netlink.Route{LinkIndex: idx, Dst: prefixNet(w.dst), Scope: netlink.SCOPE_LINK}
		if w.src.IsValid() {
			r.Src = w.src.AsSlice()
		}
		if w.via.IsValid() {
			r.Scope, r.Gw, r.Flags = netlink.SCOPE_UNIVERSE, w.via.AsSlice(), int(netlink.FLAG_ONLINK)
		}
		if err := netlink.RouteReplace(r); err != nil {
			return fmt.Errorf("route to %s (%s): %w", w.node, w.what, err)
		}
		want[w.dst] = true
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

// wantedRoute is one route syncRoutes installs.
type wantedRoute struct {
	node string
	dst  netip.Prefix
	// via is the peer's tunnel end, on link (VXLAN); src, this node's
	// address for a route to a peer's node address.
	via, src netip.Addr
	// what is the destination as errors name it.
	what string
}

// wantRoutes are the routes syncRoutes installs, in order.
func wantRoutes(p plan, via bool, set routeSet) []wantedRoute {
	var out []wantedRoute
	if set == routesNone {
		return out
	}
	for _, pe := range p.peers {
		if set == routesProbe {
			dst := netip.PrefixFrom(vtepAddr(pe.subnet), 32)
			out = append(out, wantedRoute{node: pe.node, dst: dst, what: dst.String()})
			continue
		}
		if p.mode == ModeMesh || pe.remote {
			out = append(out, wantedRoute{node: pe.node, dst: netip.PrefixFrom(pe.ip, 32), src: p.self.ip, what: pe.ip.String()})
		}
		// The peer's own subnet, and those of nodes behind NAT reached
		// through it, a relay (ADR 0050).
		for _, dst := range append([]netip.Prefix{pe.subnet}, pe.carried...) {
			w := wantedRoute{node: pe.node, dst: dst, what: dst.String()}
			if via {
				w.via = vtepAddr(pe.subnet)
			}
			out = append(out, w)
		}
	}
	return out
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
	remote := len(p.remote()) > 0
	if err := ipt.fill("filter", chainIn, inputRules(p, n.cfg.PrivateIP)); err != nil {
		return err
	}
	if err := ipt.only("INPUT", chainIn, inputJump(p)...); err != nil {
		return err
	}
	if p.mode == ModeMesh || remote {
		if err := ipt.chain("filter", chainMesh); err != nil {
			return err
		}
		if err := ipt.fill("filter", chainMesh, meshRules(p)); err != nil {
			return err
		}
		if err := ipt.only("INPUT", chainMesh, "-i", wgInterface(p), "-j", chainMesh); err != nil {
			return err
		}
	} else {
		for _, r := range ipt.jumps("INPUT", chainMesh) {
			if err := ipt.run(append([]string{"-D", "INPUT"}, r...)...); err != nil {
				return err
			}
		}
	}
	if err := ipt.chain("filter", chainFwd); err != nil {
		return err
	}
	if err := ipt.fill("filter", chainFwd, forwardRules(tunnels(p), p.relaying)); err != nil {
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
	if err := ipt.chain("mangle", chainMSS); err != nil {
		return err
	}
	if err := ipt.fill("mangle", chainMSS, mssRules(tunnels(p))); err != nil {
		return err
	}
	if err := ipt.first("mangle", "FORWARD", "-j", chainMSS); err != nil {
		return err
	}
	// Ahead of the container runtime's masquerading.
	for _, name := range tunnels(p) {
		if err := ipt.first("nat", "POSTROUTING", "-o", name, "-j", "RETURN"); err != nil {
			return err
		}
	}
	if p.switching() {
		n.nextClean = false
	} else if !n.nextClean {
		for ipt.run("-t", "nat", "-D", "POSTROUTING", "-o", Next, "-j", "RETURN") == nil {
		}
		n.nextClean = true
	}
	if slices.Contains(tunnels(p), SiteInterface) {
		n.siteClean = false
	} else if !n.siteClean {
		for ipt.run("-t", "nat", "-D", "POSTROUTING", "-o", SiteInterface, "-j", "RETURN") == nil {
		}
		n.siteClean = true
	}
	return nil
}

// inputRules are ARMADA-NET-IN's rules for a node at privateIP.
func inputRules(p plan, privateIP netip.Addr) [][]string {
	if p.mode == ModeMesh {
		return [][]string{{"-j", "ACCEPT"}}
	}
	rules := [][]string{}
	for _, pe := range p.local() {
		rules = append(rules, []string{"-s", pe.ip.String() + "/32", "-d", privateIP.String() + "/32", "-j", "ACCEPT"})
	}
	if len(p.remote()) > 0 {
		// Other sites' endpoints change, and WireGuard answers
		// nothing that does not authenticate (ADR 0050).
		rules = append(rules, []string{"-p", "udp", "-m", "udp", "--dport", strconv.Itoa(WireGuardPort), "-j", "ACCEPT"})
	}
	return append(rules, []string{"-j", "DROP"})
}

// inputJump is the INPUT rule that sends the tunnels' port (or both ports)
// to ARMADA-NET-IN.
func inputJump(p plan) []string {
	if p.switching() || p.mode == ModePlain && len(p.remote()) > 0 {
		return []string{"-p", "udp", "-m", "multiport", "--dports", strconv.Itoa(VXLANPort) + "," + strconv.Itoa(WireGuardPort), "-j", chainIn}
	}
	return []string{"-p", "udp", "-m", "udp", "--dport", strconv.Itoa(port(p.mode)), "-j", chainIn}
}

// tunnels are the interfaces packets between nodes come and go by: Next
// too while a switch runs, and SiteInterface while a plain cluster's node
// has peers in other sites (ADR 0050).
func tunnels(p plan) []string {
	switch {
	case p.switching():
		return []string{Interface, Next}
	case p.mode == ModePlain && len(p.remote()) > 0:
		return []string{Interface, SiteInterface}
	}
	return []string{Interface}
}

// wgInterface is the interface WireGuard peers' traffic comes out of:
// SiteInterface in a plain cluster, Interface otherwise.
func wgInterface(p plan) string {
	if p.mode == ModePlain {
		return SiteInterface
	}
	return Interface
}

// mssRules are ARMADA-NET-MSS's rules, written as iptables -S prints them.
func mssRules(tunnels []string) [][]string {
	var rules [][]string
	for _, name := range tunnels {
		rules = append(rules, []string{"-o", name, "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"})
	}
	return rules
}

// forwardRules are ARMADA-NET-FWD's rules for the tunnel interfaces. A
// relay (ADR 0050) also forwards between the subnets of each pair of nodes
// behind NAT it relays for, from any tunnel to any tunnel: a pair's ends
// may be on the private network's transport or on WireGuard.
func forwardRules(tunnels []string, relaying [][2]netip.Prefix) [][]string {
	var rules [][]string
	for _, pair := range relaying {
		for _, in := range tunnels {
			for _, out := range tunnels {
				for _, dir := range [][2]netip.Prefix{pair, {pair[1], pair[0]}} {
					rules = append(rules, []string{"-s", dir[0].String(), "-d", dir[1].String(), "-i", in, "-o", out, "-j", "ACCEPT"})
				}
			}
		}
	}
	for _, name := range tunnels {
		rules = append(rules,
			[]string{"-i", name, "-o", embedded.BridgeName, "-j", "ACCEPT"},
			[]string{"-i", embedded.BridgeName, "-o", name, "-j", "ACCEPT"})
	}
	for _, name := range tunnels {
		// Nothing that arrives through the tunnel is routed anywhere else.
		rules = append(rules, []string{"-i", name, "-j", "DROP"})
	}
	return append(rules, [][]string{
		// Containers are reached from other machines only through the
		// tunnel: a machine on the private network that routes the node's
		// subnet through its private IP gets nowhere. Replies, traffic
		// between containers, and ports published before the node joined
		// (DNAT) still pass.
		{"-i", embedded.BridgeName, "-o", embedded.BridgeName, "-j", "RETURN"},
		{"-o", embedded.BridgeName, "-m", "conntrack", "--ctstate", "NEW", "-m", "conntrack", "!", "--ctstate", "DNAT", "-j", "DROP"},
	}...)
}

// meshRules are ARMADA-NET-MESH's rules: the mesh mode's peers reach this
// node's mesh address (the API, etcd, HTTP-01 forwarding, metrics), as
// machines on a private network reach a private IP, and so do peers of
// other sites this node's private IP (ADR 0050). WireGuard allows each
// peer only its own node address and subnet as sources.
func meshRules(p plan) [][]string {
	var rules [][]string
	if p.mode == ModeMesh {
		rules = append(rules, []string{"-s", p.mesh.String(), "-d", p.self.ip.String() + "/32", "-j", "ACCEPT"})
	} else {
		for _, pe := range p.remote() {
			rules = append(rules, []string{"-s", pe.ip.String() + "/32", "-d", p.self.ip.String() + "/32", "-j", "ACCEPT"})
		}
	}
	return append(rules, []string{"-j", "RETURN"})
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
	ports := []int{port(p.mode)}
	if p.switching() {
		ports = append(ports, port(p.switchTo))
	}
	for _, pe := range p.peers {
		to, peerPorts := pe.ip, ports
		if p.mode == ModeMesh || pe.remote {
			to, peerPorts = pe.endpoint, []int{WireGuardPort}
		}
		if !to.IsValid() {
			// Behind NAT (ADR 0050): no address of its own to send to.
			continue
		}
		for _, port := range peerPorts {
			rules = append(rules, []string{"-d", to.String() + "/32", "-i", embedded.BridgeName, "-p", "udp", "-m", "udp", "--dport", strconv.Itoa(port), "-j", "DROP"})
		}
	}
	if p.mode != ModeMesh {
		// A node of another site is reached only through WireGuard, which
		// allows each peer only its own addresses: nothing else claims one
		// (ADR 0050).
		dev := wgInterface(p)
		for _, pe := range p.remote() {
			ip := pe.ip.String() + "/32"
			rules = append(rules,
				[]string{"-s", ip, "!", "-i", dev, "-j", "DROP"},
				[]string{"-s", ip, "-i", dev, "-j", "RETURN"})
		}
		if p.mesh.IsValid() {
			// Mesh addresses of nodes with no private network exist only
			// on WireGuard, as in the mesh mode below.
			mesh := p.mesh.String()
			rules = append(rules,
				[]string{"-d", mesh, "-i", "lo", "-j", "RETURN"},
				[]string{"-d", mesh, "!", "-i", dev, "-j", "DROP"},
				[]string{"-s", mesh, "!", "-i", dev, "-j", "DROP"})
		}
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
	rules = append(rules,
		// This node's subnet arrives only from its own containers, on the
		// bridge, or from the node itself (its gateway and tunnel
		// addresses), over loopback. Anything else claiming it, from the
		// tunnel or forged by a machine on the private network that routes
		// the subnet to this node, is dropped: the DNS server, the internal
		// frontend, and the isolation rules take an address in the subnet
		// for one of this node's containers.
		[]string{"-s", sub, "-i", "lo", "-j", "RETURN"},
		[]string{"-s", sub, "!", "-i", embedded.BridgeName, "-j", "DROP"},
	)
	for _, name := range tunnels(p) {
		// What comes out of the tunnel is from another node's containers or
		// that node itself (its tunnel address): never from outside the
		// cluster's range.
		rules = append(rules, []string{"!", "-s", p.cidr.String(), "-i", name, "-j", "DROP"})
	}
	return rules
}

// iptablesCmd runs the iptables tool the container networking plugins use.
type iptablesCmd struct {
	bin string
	// fake stands for the tool in tests: it gets the arguments the tool
	// would and returns its output.
	fake func(args []string) ([]byte, error)
}

var iptables = iptablesCmd{bin: "iptables"}

// exec runs the tool with args, returning its standard output, or with
// combined its standard output and error together.
func (c iptablesCmd) exec(combined bool, args ...string) ([]byte, error) {
	if c.fake != nil {
		return c.fake(args)
	}
	cmd := exec.Command(c.bin, args...) //nolint:gosec // fixed tool; arguments are validated addresses and constants
	if combined {
		return cmd.CombinedOutput()
	}
	return cmd.Output()
}

func (c iptablesCmd) run(args ...string) error {
	out, err := c.exec(true, append([]string{"-w", "5"}, args...)...)
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
	out, err := c.exec(false, "-w", "5", "-t", table, "-S", name)
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
	out, err := c.exec(false, "-w", "5", "-S", chain)
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
func ContainerMTU(mode string, ip, endpoint netip.Addr, uplinkMTU int) (int, error) {
	_, mtu, meshed, err := uplinkFor(mode, ip, endpoint)
	if err != nil {
		return 0, err
	}
	if uplinkMTU > 0 {
		mtu = min(mtu, uplinkMTU)
	}
	if meshed {
		// Every packet to another node goes over WireGuard (ADR 0050).
		mode = ModeWireGuard
	}
	return TunnelMTU(mode, mtu), nil
}

// Diagnose reports, for armadad doctor, whether the node's uplink leaves
// room for the tunnel and whether the tunnel is up with its peers.
func Diagnose(mode string, ip, endpoint netip.Addr, sites Sites) []Check {
	out := diagnoseTunnel(mode, ip, endpoint)
	if c, ok := diagnoseSites(sites, ip); ok {
		out = append(out, c)
	}
	if c, ok := diagnoseRelay(sites, ip); ok {
		out = append(out, c)
	}
	return append(out, diagnoseIsolation())
}

// Sites is what doctor needs to look at the node's peers in other sites:
// the peer list the node keeps while it has one (Config.MeshCache) and its
// own name.
type Sites struct {
	Cache string
	Node  string
}

// diagnoseSites warns when a peer of another site has a node address inside
// one of this machine's local networks (ADR 0050). ok is false while the
// node keeps no peer list or has no peer in another site.
func diagnoseSites(s Sites, ip netip.Addr) (Check, bool) {
	c := Check{Name: "sites", Level: CheckOK}
	if s.Cache == "" {
		return c, false
	}
	cfg, err := loadMeshCache(s.Cache)
	switch {
	case err != nil:
		c.Level, c.Detail = CheckWarn, fmt.Sprintf("read the peer list: %v", err)
		return c, true
	case cfg == nil:
		return c, false
	}
	p, err := parse(cfg, s.Node, ip)
	if err != nil {
		c.Level, c.Detail = CheckWarn, fmt.Sprintf("the peer list in %s does not parse: %v; the agent writes it again once connected", s.Cache, err)
		return c, true
	}
	remote := 0
	for _, pe := range p.peers {
		if pe.remote {
			remote++
		}
	}
	if remote == 0 {
		return c, false
	}
	locals, err := localPrefixes()
	if err != nil {
		c.Level, c.Detail = CheckWarn, fmt.Sprintf("list this machine's addresses: %v", err)
		return c, true
	}
	if bad := shadowed(p, locals); len(bad) > 0 {
		c.Level = CheckWarn
		c.Detail = fmt.Sprintf("%d node(s) of other sites have an address inside this machine's local networks: %s; this machine reaches those addresses through the tunnel, so a host on the local network at the same address is unreachable from it (join such a node again with --no-private-ip to give it a mesh address)", len(bad), strings.Join(bad, "; "))
		return c, true
	}
	c.Detail = fmt.Sprintf("%d node(s) in other sites, none inside this machine's local networks", remote)
	return c, true
}

// diagnoseRelay reports how a node behind NAT reaches the nodes behind NAT
// of other sites, and what a relay forwards (ADR 0050). ok is false when
// neither applies.
func diagnoseRelay(s Sites, ip netip.Addr) (Check, bool) {
	c := Check{Name: "relay", Level: CheckOK}
	if s.Cache == "" {
		return c, false
	}
	cfg, err := loadMeshCache(s.Cache)
	if err != nil || cfg == nil {
		return c, false
	}
	p, err := parse(cfg, s.Node, ip)
	if err != nil {
		return c, false
	}
	return relayCheck(p)
}

// relayCheck is what diagnoseRelay says of a parsed peer list.
func relayCheck(p plan) (Check, bool) {
	c := Check{Name: "relay", Level: CheckOK}
	switch {
	case len(p.unreachable) > 0:
		c.Level = CheckFail
		c.Detail = fmt.Sprintf("this node is behind NAT and cannot reach %d node(s) behind NAT: %s; their sites and this one have no relay (a ready node with an endpoint)", len(p.unreachable), strings.Join(p.unreachable, ", "))
	case len(p.relayed) > 0:
		var via []string
		for _, pe := range p.peers {
			if len(pe.carried) > 0 {
				via = append(via, fmt.Sprintf("%d through %s", len(pe.carried), pe.node))
			}
		}
		c.Detail = fmt.Sprintf("this node is behind NAT and reaches %d node(s) behind NAT in other sites through relays: %s", len(p.relayed), strings.Join(via, ", "))
	case p.self.nat:
		c.Detail = "this node is behind NAT; it reaches every node of another site directly"
	case p.self.relay:
		c.Detail = fmt.Sprintf("this node relays its site's traffic between nodes behind NAT: %d pair(s)", len(p.relaying))
	default:
		return c, false
	}
	return c, true
}

// localPrefixes are the IPv4 networks on the machine's interfaces, leaving
// out loopback and Armada's own.
func localPrefixes() ([]localPrefix, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	var out []localPrefix
	for _, l := range links {
		a := l.Attrs()
		switch a.Name {
		case Interface, Next, SiteInterface, embedded.BridgeName:
			continue
		}
		if a.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			return nil, fmt.Errorf("addresses of %s: %w", a.Name, err)
		}
		for _, ad := range addrs {
			if ad.IPNet == nil {
				continue
			}
			ap, ok := netip.AddrFromSlice(ad.IP.To4())
			if !ok {
				continue
			}
			bits, _ := ad.Mask.Size()
			out = append(out, localPrefix{dev: a.Name, prefix: netip.PrefixFrom(ap, bits)})
		}
	}
	return out, nil
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
	uplink, mtu, meshed, err := uplinkFor(mode, ip, endpoint)
	if err != nil {
		add("network-mtu", CheckFail, "%v", err)
		return out
	}
	tunnelMode := mode
	if meshed {
		tunnelMode = ModeWireGuard
	}
	add("network-mtu", CheckOK, "%s has MTU %d; the tunnel and containers use %d", uplink.Attrs().Name, mtu, TunnelMTU(tunnelMode, mtu))
	if next, err := linkNamed(Next); err == nil && next != nil {
		add("network-switch", CheckWarn, "%s is up: the cluster network is switching modes (armada cluster status shows how far)", Next)
	}
	if encrypted(mode) || meshed {
		// A node with a mesh address reaches every peer over WireGuard
		// (ADR 0050).
		return append(out, diagnoseWireGuard(mode, ip, meshed)...)
	}
	link, err := linkNamed(Interface)
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
	// Peers in other sites go over WireGuard on SiteInterface (ADR 0050),
	// which exists only while there are some.
	if wg, err := linkNamed(SiteInterface); err == nil && wg != nil {
		for _, c := range diagnoseWireGuard(mode, ip, true) {
			if c.Name == "network" {
				c.Name = "network-sites"
			}
			out = append(out, c)
		}
	}
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
	for _, name := range []string{Interface, Next, SiteInterface} {
		if link, err := linkNamed(name); err == nil && link != nil {
			if err := netlink.LinkDel(link); err != nil {
				errs = append(errs, fmt.Errorf("remove %s: %w", name, err))
			}
		}
	}
	if err := removeIsolation(); err != nil {
		errs = append(errs, fmt.Errorf("remove the isolation tables: %w", err))
	}
	errs = append(errs, removeFirewall(iptables)...)
	// The control socket a userspace WireGuard device leaves behind.
	if err := os.Remove(userSocket); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// removeFirewall removes the iptables rules and chains of the cluster
// network, returning what failed (nil entries included).
func removeFirewall(ipt iptablesCmd) []error {
	var errs []error
	for _, r := range [][]string{
		{"filter", "FORWARD", "-j", chainFwd},
		{"raw", "PREROUTING", "-j", chainPre},
		{"nat", "POSTROUTING", "-o", Interface, "-j", "RETURN"},
		{"nat", "POSTROUTING", "-o", Next, "-j", "RETURN"},
		{"nat", "POSTROUTING", "-o", SiteInterface, "-j", "RETURN"},
		{"mangle", "FORWARD", "-j", chainMSS},
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
	if ipt.run("-t", "mangle", "-L", chainMSS, "-n") == nil {
		errs = append(errs, ipt.run("-t", "mangle", "-F", chainMSS), ipt.run("-t", "mangle", "-X", chainMSS))
	}
	return errs
}

// deviceLogger sends the userspace WireGuard device's errors to the log.
func deviceLogger(log *slog.Logger) *device.Logger {
	return &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf:   func(format string, args ...any) { log.Warn("wireguard: " + fmt.Sprintf(format, args...)) },
	}
}

// wgPeerSeen is a WireGuard peer's node and when it was first configured.
type wgPeerSeen struct {
	node  string
	since time.Time
}

// seePeers records the WireGuard peers of p, keeping when each was first
// seen: every peer in the wireguard and mesh modes, and those of other
// sites (and relayed ones' relays) in plain.
func (n *Net) seePeers(p plan, now time.Time) {
	next := map[wgtypes.Key]wgPeerSeen{}
	for _, pe := range p.peers {
		if pe.key == (wgtypes.Key{}) || !encrypted(p.mode) && !pe.remote {
			continue
		}
		seen, ok := n.wgSince[pe.key]
		if !ok || seen.node != pe.node {
			seen = wgPeerSeen{node: pe.node, since: now}
		}
		next[pe.key] = seen
	}
	n.wgSince = next
}

// WireGuardUserspace reports whether the node's WireGuard runs in userspace
// inside the agent, because the kernel has none (ADR 0025).
func (n *Net) WireGuardUserspace() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.user != nil
}

// UnreachablePeers returns the nodes whose WireGuard peer has had no
// handshake for staleHandshake although it was configured longer ago
// (ADR 0025), sorted, at most 32; nil while a switch runs or nothing is
// on WireGuard.
func (n *Net) UnreachablePeers() []string {
	n.mu.Lock()
	since := maps.Clone(n.wgSince)
	switching := n.sw.to != ""
	user := n.user != nil
	n.mu.Unlock()
	if switching || len(since) == 0 {
		return nil
	}
	if peers, done := n.unreachableViaProgram(since, user); done {
		return peers
	}
	c, err := wgctrl.New()
	if err != nil {
		return nil
	}
	defer func() { _ = c.Close() }()
	return unreachable(c, since, time.Now())
}

// unreachable lists the peers of Interface and SiteInterface known in
// since that are stale at now.
func unreachable(c *wgctrl.Client, since map[wgtypes.Key]wgPeerSeen, now time.Time) []string {
	var devs []*wgtypes.Device
	for _, name := range []string{Interface, SiteInterface} {
		if d, err := c.Device(name); err == nil {
			devs = append(devs, d)
		}
	}
	return stalePeers(devs, since, now)
}

// stalePeers is unreachable on devices already read.
func stalePeers(devs []*wgtypes.Device, since map[wgtypes.Key]wgPeerSeen, now time.Time) []string {
	var out []string
	for _, d := range devs {
		for _, pe := range d.Peers {
			seen, ok := since[pe.PublicKey]
			if !ok || now.Sub(seen.since) <= staleHandshake {
				continue
			}
			if pe.LastHandshakeTime.IsZero() || now.Sub(pe.LastHandshakeTime) > staleHandshake {
				out = append(out, seen.node)
			}
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

// RotateKey replaces the node's WireGuard key with a new one in
// Config.KeyPath and returns its public half (armada node rotate-key, ADR
// 0025). The devices take it on the next Apply, which follows once the
// control plane has the new public key.
func (n *Net) RotateKey() (string, error) {
	if n.cfg.KeyPath == "" {
		return "", errors.New("the node's key file is unknown")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if pub, done, err := n.rotateViaProgram(); done {
		return pub, err
	}
	k, err := RotateKey(n.cfg.KeyPath)
	if err != nil {
		return "", err
	}
	n.cfg.Key = k
	n.log.Info("made a new network key")
	return k.Public(), nil
}
