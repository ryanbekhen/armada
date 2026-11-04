// Package clusternet routes the cluster network's node subnets between
// nodes (ADR 0027). In the plain mode every node has a VXLAN interface on
// its private IP, with static forwarding entries for its peers and a route
// for each peer's subnet; nothing is learned from the network.
package clusternet

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/spec"
)

const (
	// Interface is the tunnel interface on every node.
	Interface = "armada-net"
	// VXLANPort is the UDP port of the plain mode, on the private IP.
	VXLANPort = 4789
	// VXLANOverhead is what VXLAN adds to each packet over IPv4: outer IP,
	// UDP, and VXLAN headers and the inner Ethernet header.
	VXLANOverhead = 50
	// MinUplinkMTU leaves containers at least the IPv4 minimum of 576
	// bytes, with room to spare for the encapsulation.
	MinUplinkMTU = 1280
	// subnetBits is the prefix length of a node subnet.
	subnetBits = 24
	// maxPeers bounds the peer list a node accepts.
	maxPeers = 4096
)

// ModePlain is the cluster network mode this package implements.
const ModePlain = "plain"

// Config describes the node.
type Config struct {
	// Node is the node's name; its own entry in the peer list is skipped.
	Node string
	// PrivateIP is where the tunnel listens and peers reach the node.
	PrivateIP netip.Addr
	Logger    *slog.Logger
}

// peer is one other node.
type peer struct {
	node   string
	ip     netip.Addr
	subnet netip.Prefix
}

// plan is a validated network configuration.
type plan struct {
	cidr  netip.Prefix
	self  peer
	peers []peer // every node but this one, in the order received
}

// parse validates what the control plane sent. It never trusts the server
// with anything that ends up in routes or firewall rules: names, addresses
// and subnets are checked here again.
func parse(cfg *armadav1.NetworkConfig, self string, selfIP netip.Addr) (plan, error) {
	if cfg.GetMode() != ModePlain {
		return plan{}, fmt.Errorf("cluster network mode %q is not supported by this agent", cfg.GetMode())
	}
	cidr, err := netip.ParsePrefix(cfg.GetClusterCidr())
	if err != nil || !cidr.Addr().Is4() || cidr.Masked() != cidr || !cidr.Addr().IsPrivate() || cidr.Bits() < 8 || cidr.Bits() > subnetBits {
		return plan{}, fmt.Errorf("invalid cluster CIDR %q", cfg.GetClusterCidr())
	}
	if len(cfg.GetPeers()) > maxPeers {
		return plan{}, fmt.Errorf("%d peers: at most %d", len(cfg.GetPeers()), maxPeers)
	}
	p := plan{cidr: cidr}
	ips, subnets, names := map[netip.Addr]bool{}, map[netip.Prefix]bool{}, map[string]bool{}
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
		if names[pp.GetNode()] || ips[ip] || subnets[sub] {
			return plan{}, fmt.Errorf("peer %s: duplicate name, address, or subnet", pp.GetNode())
		}
		names[pp.GetNode()], ips[ip], subnets[sub] = true, true, true
		pe := peer{node: pp.GetNode(), ip: ip, subnet: sub}
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
	return p, nil
}

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
func TunnelMTU(uplink int) int { return uplink - VXLANOverhead }

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
