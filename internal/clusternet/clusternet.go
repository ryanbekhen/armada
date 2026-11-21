// Package clusternet routes the cluster network's node subnets between
// nodes (ADR 0025). In the plain mode every node has a VXLAN interface on
// its private IP, with static forwarding entries for its peers and a route
// for each peer's subnet; nothing is learned from the network. In the
// wireguard mode the interface is a WireGuard device whose peers are the
// other nodes, each allowed exactly its own subnet. In the mesh mode (ADR
// 0049) the WireGuard peers are reached at their public addresses, and each
// node's private IP is a mesh address that only the tunnel carries.
package clusternet

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/spec"
)

const (
	// Interface is the tunnel interface on every node.
	Interface = "armada-net"
	// SiteInterface carries a plain cluster's traffic to nodes of other
	// sites, over WireGuard between their endpoints (ADR 0050); in the
	// wireguard and mesh modes Interface carries every peer.
	SiteInterface = "armada-wg"
	// Next holds the target transport while the cluster switches between
	// the plain and wireguard modes (ADR 0050); once the switch is done it
	// takes Interface's place.
	Next = "armada-next"
	// VXLANPort is the UDP port of the plain mode, on the private IP.
	VXLANPort = 4789
	// VXLANOverhead is what VXLAN adds to each packet over IPv4: outer IP,
	// UDP, and VXLAN headers and the inner Ethernet header.
	VXLANOverhead = 50
	// WireGuardPort is the UDP port of the wireguard mode.
	WireGuardPort = 51820
	// WireGuardOverhead is what WireGuard adds to each packet, counted for
	// IPv6 underlays as WireGuard's own default does.
	WireGuardOverhead = 80
	// MinUplinkMTU leaves containers at least the IPv4 minimum of 576
	// bytes, with room to spare for the encapsulation.
	MinUplinkMTU = 1280
	// subnetBits is the prefix length of a node subnet.
	subnetBits = 24
	// maxPeers bounds the peer list a node accepts.
	maxPeers = 4096
)

// Cluster network modes.
const (
	ModePlain     = "plain"
	ModeWireGuard = "wireguard"
	ModeMesh      = "mesh"
)

// Steps of a switch between the plain and wireguard modes (ADR 0050).
const (
	// SwitchPrepare brings the target transport up beside the current one,
	// with the peers but without routes.
	SwitchPrepare = "prepare"
	// SwitchMove routes over the target transport, keeping the current one
	// up for nodes that have not moved yet.
	SwitchMove = "move"
)

// encrypted reports whether a mode runs over WireGuard.
func encrypted(mode string) bool { return mode == ModeWireGuard || mode == ModeMesh }

// Config describes the node.
type Config struct {
	// Node is the node's name; its own entry in the peer list is skipped.
	Node string
	// PrivateIP is where the tunnel listens and peers reach the node; in
	// the mesh mode, the node's mesh address.
	PrivateIP netip.Addr
	// Endpoint is the node's public address in the mesh mode: its interface
	// (or, behind one-to-one NAT, the default route's) is the uplink.
	Endpoint netip.Addr
	// MeshCache is where the mesh mode keeps the last peer list it applied,
	// so the tunnel comes up before the control plane (Up).
	MeshCache string
	// UplinkMTU, when set, is the largest packet the machine's line to
	// other nodes carries, below its interface's MTU (PPPoE lines behind
	// NAT, ADR 0050); tunnels and containers take their overhead from it.
	UplinkMTU int
	// Key is the node's own key (LoadOrCreateKey); the wireguard mode needs
	// it.
	Key    PrivateKey
	Logger *slog.Logger
}

// peer is one other node.
type peer struct {
	node   string
	ip     netip.Addr
	subnet netip.Prefix
	key    wgtypes.Key // zero until the node has announced one
	// endpoint is the public address of the mesh mode, and of a peer in
	// another site (ADR 0050).
	endpoint netip.Addr
	// site is the node's site, "" for the first (ADR 0050).
	site string
	// remote marks a peer in another site than this node, or one of a pair
	// with a mesh address: reached over WireGuard at its endpoint, and
	// allowed its node address too.
	remote bool
	// nat marks a node behind NAT (ADR 0050): it has no endpoint, and a
	// peer reaches it only once it has sent a packet; relay, its site's
	// relay between nodes behind NAT.
	nat, relay bool
	// carried are the subnets of nodes behind NAT this node reaches
	// through this peer, its relay (ADR 0050): WireGuard allows them on
	// the relay's entry, and routes take them there.
	carried []netip.Prefix
}

// plan is a validated network configuration.
type plan struct {
	mode string
	cidr netip.Prefix
	// mesh is the range of the nodes' mesh addresses: in the mesh mode, and
	// in the others once a node without a private network holds one (ADR
	// 0050).
	mesh netip.Prefix
	// meshed marks this node's address as a mesh address in a plain or
	// wireguard cluster: it has no private network, holds the address on
	// its WireGuard interface, and reaches every peer there (ADR 0050).
	meshed bool
	// switchTo and step describe a switch to another mode under way (ADR
	// 0050); switchTo is empty while none runs.
	switchTo string
	step     string
	self     peer
	peers    []peer // every node but this one, in the order received
	// relayed are the peers this node reaches only through a relay (ADR
	// 0050), listed in their relay's carried; they are not in peers.
	relayed []peer
	// unreachable are the nodes behind NAT this node, behind NAT too,
	// cannot reach: their sites have no relay (ADR 0050).
	unreachable []string
	// relaying are the pairs of subnets this node, a relay, forwards
	// between (ADR 0050).
	relaying [][2]netip.Prefix
	// endpoints maps the cluster's container addresses to their app IDs.
	endpoints map[netip.Addr]string
	// isolateDefault isolates the default space like the others.
	isolateDefault bool
	// tcpPorts are the ports of internal TCP apps, sorted (ADR 0039).
	tcpPorts []uint16
}

// parse validates what the control plane sent. It never trusts the server
// with anything that ends up in routes or firewall rules: names, addresses
// and subnets are checked here again.
func parse(cfg *armadav1.NetworkConfig, self string, selfIP netip.Addr) (plan, error) {
	if cfg.GetMode() != ModePlain && cfg.GetMode() != ModeWireGuard && cfg.GetMode() != ModeMesh {
		return plan{}, fmt.Errorf("cluster network mode %q is not supported by this agent", cfg.GetMode())
	}
	cidr, err := netip.ParsePrefix(cfg.GetClusterCidr())
	if err != nil || !cidr.Addr().Is4() || cidr.Masked() != cidr || !cidr.Addr().IsPrivate() || cidr.Bits() < 8 || cidr.Bits() > subnetBits {
		return plan{}, fmt.Errorf("invalid cluster CIDR %q", cfg.GetClusterCidr())
	}
	var mesh netip.Prefix
	if cfg.GetMode() == ModeMesh || cfg.GetMeshCidr() != "" {
		if mesh, err = CheckMeshCIDR(cfg.GetMeshCidr()); err != nil {
			return plan{}, err
		}
		if mesh.Overlaps(cidr) {
			return plan{}, fmt.Errorf("mesh CIDR %s overlaps the cluster CIDR %s", mesh, cidr)
		}
	}
	if len(cfg.GetPeers()) > maxPeers {
		return plan{}, fmt.Errorf("%d peers: at most %d", len(cfg.GetPeers()), maxPeers)
	}
	p := plan{mode: cfg.GetMode(), cidr: cidr, mesh: mesh, isolateDefault: cfg.GetIsolateDefault()}
	if p.switchTo, p.step, err = parseSwitch(cfg); err != nil {
		return plan{}, err
	}
	if p.endpoints, err = parseEndpoints(cfg.GetEndpoints(), cidr); err != nil {
		return plan{}, err
	}
	if p.tcpPorts, err = parseTCPPorts(cfg.GetTcpPorts()); err != nil {
		return plan{}, err
	}
	ips, subnets, names, keys := map[netip.Addr]bool{}, map[netip.Prefix]bool{}, map[string]bool{}, map[wgtypes.Key]bool{}
	found := false
	for _, pp := range cfg.GetPeers() {
		if err := spec.ValidateName(pp.GetNode()); err != nil {
			return plan{}, fmt.Errorf("peer name %q: %w", pp.GetNode(), err)
		}
		ip, err := netutil.CheckNodeIP(pp.GetPrivateIp())
		if err != nil {
			return plan{}, fmt.Errorf("peer %s: %w", pp.GetNode(), err)
		}
		sub, err := netip.ParsePrefix(pp.GetSubnet())
		if err != nil || sub.Bits() != subnetBits || sub.Masked() != sub || !cidr.Contains(sub.Addr()) {
			return plan{}, fmt.Errorf("peer %s: subnet %q is not a /%d of %s", pp.GetNode(), pp.GetSubnet(), subnetBits, cidr)
		}
		if cidr.Contains(ip) {
			return plan{}, fmt.Errorf("peer %s: private IP %s is inside the cluster CIDR", pp.GetNode(), ip)
		}
		if p.mode == ModeMesh && !mesh.Contains(ip) {
			return plan{}, fmt.Errorf("peer %s: mesh address %s is outside the mesh CIDR %s", pp.GetNode(), ip, mesh)
		}
		if names[pp.GetNode()] || ips[ip] || subnets[sub] {
			return plan{}, fmt.Errorf("peer %s: duplicate name, address, or subnet", pp.GetNode())
		}
		names[pp.GetNode()], ips[ip], subnets[sub] = true, true, true
		pe := peer{node: pp.GetNode(), ip: ip, subnet: sub, site: pp.GetSite(), nat: pp.GetBehindNat(), relay: pp.GetRelay()}
		if pe.nat && pe.relay {
			return plan{}, fmt.Errorf("peer %s: a node behind NAT cannot relay", pp.GetNode())
		}
		if pe.site != "" {
			if err := spec.CheckLabelValue(pe.site); err != nil {
				return plan{}, fmt.Errorf("peer %s: site: %w", pp.GetNode(), err)
			}
		}
		if pp.GetEndpoint() != "" && !pe.nat {
			ep, err := netutil.CheckEndpoint(pp.GetEndpoint())
			if err != nil {
				return plan{}, fmt.Errorf("peer %s: %w", pp.GetNode(), err)
			}
			if cidr.Contains(ep) || mesh.Contains(ep) {
				return plan{}, fmt.Errorf("peer %s: endpoint %s is inside the cluster's own ranges", pp.GetNode(), ep)
			}
			pe.endpoint = ep
		}
		if pp.GetPublicKey() != "" {
			k, err := wgtypes.ParseKey(pp.GetPublicKey())
			if err != nil || k == (wgtypes.Key{}) {
				return plan{}, fmt.Errorf("peer %s: invalid public key", pp.GetNode())
			}
			if keys[k] {
				return plan{}, fmt.Errorf("peer %s: duplicate public key", pp.GetNode())
			}
			keys[k], pe.key = true, k
		}
		if pe.node == self {
			if ip != selfIP {
				return plan{}, fmt.Errorf("the control plane lists this node at %s, not %s", ip, selfIP)
			}
			p.self, found = pe, true
			continue
		}
		p.peers = append(p.peers, pe)
	}
	if !found {
		return plan{}, errors.New("this node is not in the cluster network's peer list")
	}
	// Peers of other sites are reached over WireGuard at their endpoints
	// (ADR 0050); the mesh reaches every peer that way already. So is
	// every pair one of whose nodes has a mesh address: it has no private
	// network to reach the other by.
	p.meshed = p.mode != ModeMesh && mesh.Contains(p.self.ip)
	kept := p.peers[:0]
	for _, pe := range p.peers {
		pe.remote = p.mode != ModeMesh && (pe.site != p.self.site || p.meshed || mesh.Contains(pe.ip))
		wg := encrypted(p.mode) || pe.remote
		switch {
		case wg && pe.key == (wgtypes.Key{}):
			// Not connected since it joined: it has no key to reach it by
			// yet, and comes in with the next list. (Switching from plain,
			// the VXLAN side keeps it; the WireGuard side skips it.)
			continue
		case (p.mode == ModeMesh || pe.remote) && !pe.endpoint.IsValid() && !pe.nat:
			// Nowhere to send its packets yet. (A node behind NAT sends
			// first, and WireGuard learns where it is.)
			continue
		}
		kept = append(kept, pe)
	}
	p.peers = kept
	p.relayThrough()
	if p.switching() && len(p.remote()) > 0 {
		return plan{}, errors.New("a cluster with more than one site cannot switch its network mode")
	}
	return p, nil
}

// public reports whether a pair is reached over WireGuard between
// endpoints rather than over a private network: in the mesh mode, between
// sites, and with a mesh address on either side (ADR 0050).
func (p plan) public(a, b peer) bool {
	return p.mode == ModeMesh || a.site != b.site || p.mesh.Contains(a.ip) || p.mesh.Contains(b.ip)
}

// pairRelay returns the relay of the pair a and b, two nodes behind NAT that
// cannot reach each other (ADR 0050): the relay of the site of the two that
// sorts first, else of the other, else (both sites behind NAT) of the site
// that sorts first of all those with one. Both ends and the relay work it
// out alike, so both directions take one path, which the relay's
// connection tracking needs.
func pairRelay(relays map[string]peer, a, b peer) (peer, bool) {
	first, second := min(a.site, b.site), max(a.site, b.site)
	if r, ok := relays[first]; ok {
		return r, true
	}
	if r, ok := relays[second]; ok {
		return r, true
	}
	if len(relays) == 0 {
		return peer{}, false
	}
	return relays[slices.Min(slices.Collect(maps.Keys(relays)))], true
}

// relayThrough moves the peers behind NAT this node, itself behind NAT,
// cannot reach directly into their relay's carried (ADR 0050), dropping
// those with no relay, and lists the pairs this node relays between when
// it is a relay.
func (p *plan) relayThrough() {
	relays := map[string]peer{}
	for _, pe := range append([]peer{p.self}, p.peers...) {
		// The leader picks relays with an endpoint and a key; the check
		// keeps a relay this node could not reach out of the paths.
		if pe.relay && pe.endpoint.IsValid() && pe.key != (wgtypes.Key{}) {
			relays[pe.site] = pe
		}
	}
	if p.self.nat {
		carried := map[string][]netip.Prefix{}
		kept := p.peers[:0]
		for _, pe := range p.peers {
			if !pe.nat || !p.public(p.self, pe) {
				kept = append(kept, pe)
				continue
			}
			if r, ok := pairRelay(relays, p.self, pe); ok {
				carried[r.node] = append(carried[r.node], pe.subnet)
				p.relayed = append(p.relayed, pe)
			} else {
				p.unreachable = append(p.unreachable, pe.node)
			}
		}
		p.peers = kept
		for i := range p.peers {
			p.peers[i].carried = carried[p.peers[i].node]
		}
		return
	}
	if !p.self.relay {
		return
	}
	for i, a := range p.peers {
		for _, b := range p.peers[i+1:] {
			if !a.nat || !b.nat || !p.public(a, b) {
				continue
			}
			if r, ok := pairRelay(relays, a, b); ok && r.node == p.self.node {
				p.relaying = append(p.relaying, [2]netip.Prefix{a.subnet, b.subnet})
			}
		}
	}
}

// local returns the peers in this node's site.
func (p plan) local() []peer {
	var out []peer
	for _, pe := range p.peers {
		if !pe.remote {
			out = append(out, pe)
		}
	}
	return out
}

// remote returns the peers in other sites (ADR 0050).
func (p plan) remote() []peer {
	var out []peer
	for _, pe := range p.peers {
		if pe.remote {
			out = append(out, pe)
		}
	}
	return out
}

// only returns p with only the given peers.
func (p plan) only(peers []peer) plan {
	p.peers = peers
	return p
}

// parseSwitch validates a switch between modes (ADR 0050): only between
// plain and wireguard, in one of the two steps.
func parseSwitch(cfg *armadav1.NetworkConfig) (to, step string, err error) {
	to, step = cfg.GetSwitchTo(), cfg.GetSwitchStep()
	if to == "" {
		if step != "" {
			return "", "", fmt.Errorf("switch step %q without a target mode", step)
		}
		return "", "", nil
	}
	mode := cfg.GetMode()
	if mode != ModePlain && mode != ModeWireGuard || to != ModePlain && to != ModeWireGuard || to == mode {
		return "", "", fmt.Errorf("cannot switch the cluster network from %q to %q", mode, to)
	}
	if step != SwitchPrepare && step != SwitchMove {
		return "", "", fmt.Errorf("unknown switch step %q", step)
	}
	return to, step, nil
}

// switching reports whether a switch between modes is under way.
func (p plan) switching() bool { return p.switchTo != "" }

// vtepAddr is the address of a node's end of the tunnel: its subnet's
// network address, which the bridge never hands to a container.
func vtepAddr(subnet netip.Prefix) netip.Addr { return subnet.Masked().Addr() }

// vtepMAC is the fixed hardware address of a node's tunnel end, derived
// from its subnet, so peers know it without asking: a locally administered
// unicast address holding the subnet's address bytes.
func vtepMAC(subnet netip.Prefix) net.HardwareAddr {
	b := vtepAddr(subnet).As4()
	return net.HardwareAddr{0x02, 0x42, b[0], b[1], b[2], b[3]}
}

// TunnelMTU is the MTU for the tunnel, the bridge, and containers on a
// node whose uplink has the given MTU.
func TunnelMTU(mode string, uplink int) int {
	if encrypted(mode) {
		return uplink - WireGuardOverhead
	}
	return uplink - VXLANOverhead
}

// CheckMeshCIDR validates the range of a mesh cluster's node addresses: a
// private IPv4 prefix from /8 to /24 in canonical form.
func CheckMeshCIDR(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	switch {
	case err != nil || !p.Addr().Is4():
		return netip.Prefix{}, fmt.Errorf("invalid mesh CIDR %q: want an IPv4 prefix", s)
	case p.Masked() != p:
		return netip.Prefix{}, fmt.Errorf("mesh CIDR %s is not in canonical form (want %s)", p, p.Masked())
	case p.Bits() < 8 || p.Bits() > 24:
		return netip.Prefix{}, fmt.Errorf("mesh CIDR %s: the prefix must be from /8 to /24", p)
	case !p.Addr().IsPrivate():
		return netip.Prefix{}, fmt.Errorf("mesh CIDR %s is not a private range", p)
	}
	return p, nil
}

// InternetProbe stands in for the endpoint of a node behind NAT (ADR 0050)
// wherever the endpoint finds the uplink: the route to an address on the
// internet is where its packets to other sites leave. Nothing is sent to
// it, and it is never announced.
var InternetProbe = netip.MustParseAddr("1.1.1.1")

// Check levels of Diagnose.
const (
	CheckOK = iota
	CheckWarn
	CheckFail
)

// Check is one result of Diagnose.
type Check struct {
	Name   string
	Level  int
	Detail string
}

// localPrefix is a network on one of the machine's own interfaces.
type localPrefix struct {
	dev    string
	prefix netip.Prefix
}

// shadowed lists the peers of other sites whose node address lies in one of
// the machine's local networks (ADR 0050): the route to the peer through
// the tunnel hides a host at that address on the local network.
func shadowed(p plan, locals []localPrefix) []string {
	var out []string
	for _, pe := range p.peers {
		if !pe.remote {
			continue
		}
		for _, l := range locals {
			if l.prefix.Bits() < 32 && l.prefix.Contains(pe.ip) {
				site := pe.site
				if site == "" {
					site = "the first site"
				}
				out = append(out, fmt.Sprintf("%s (%s) at %s is inside %s on %s", pe.node, site, pe.ip, l.prefix.Masked(), l.dev))
				break
			}
		}
	}
	return out
}
