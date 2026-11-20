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
	"net"
	"net/netip"

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
		pe := peer{node: pp.GetNode(), ip: ip, subnet: sub, site: pp.GetSite()}
		if pe.site != "" {
			if err := spec.CheckLabelValue(pe.site); err != nil {
				return plan{}, fmt.Errorf("peer %s: site: %w", pp.GetNode(), err)
			}
		}
		if pp.GetEndpoint() != "" {
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
		case (p.mode == ModeMesh || pe.remote) && !pe.endpoint.IsValid():
			// Nowhere to send its packets yet.
			continue
		}
		kept = append(kept, pe)
	}
	p.peers = kept
	if p.switching() && len(p.remote()) > 0 {
		return plan{}, errors.New("a cluster with more than one site cannot switch its network mode")
	}
	return p, nil
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
