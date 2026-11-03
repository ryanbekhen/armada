package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Network modes (ADR 0027).
const (
	// NetworkPlain routes the cluster CIDR between nodes over VXLAN on the
	// private network, unencrypted.
	NetworkPlain = "plain"
	// NetworkWireGuard routes it over WireGuard.
	NetworkWireGuard = "wireguard"
)

// NodeSubnetBits is the prefix length of each node's container subnet.
const NodeSubnetBits = 24

// Network is the cluster network (ADR 0027). Clusters created before it
// have none and keep one bridge subnet on every node.
type Network struct {
	Mode        string
	ClusterCIDR netip.Prefix
}

// CheckClusterCIDR validates a cluster CIDR: a private IPv4 prefix from /12
// to /20 in canonical form, so that it holds at least 16 node subnets.
func CheckClusterCIDR(p netip.Prefix) error {
	switch {
	case !p.IsValid() || !p.Addr().Is4():
		return errors.New("cluster CIDR must be an IPv4 prefix")
	case p.Masked() != p:
		return fmt.Errorf("cluster CIDR %s is not in canonical form (want %s)", p, p.Masked())
	case p.Bits() < 12 || p.Bits() > 20:
		return fmt.Errorf("cluster CIDR %s: the prefix must be from /12 to /20", p)
	case !p.Addr().IsPrivate():
		return fmt.Errorf("cluster CIDR %s is not a private range", p)
	}
	return nil
}

type networkRec struct {
	Mode        string `json:"mode"`
	ClusterCIDR string `json:"clusterCidr"`
}

const keyNetwork = "network"

func (t *etx) network() (Network, bool, error) {
	var r networkRec
	ok, err := t.get(keyNetwork, &r)
	if err != nil || !ok {
		return Network{}, false, err
	}
	p, err := netip.ParsePrefix(r.ClusterCIDR)
	if err != nil {
		return Network{}, false, fmt.Errorf("decode %s: cluster CIDR: %w", keyNetwork, err)
	}
	return Network{Mode: r.Mode, ClusterCIDR: p}, true, nil
}

// GetNetwork returns the cluster network, or ErrNotFound for a cluster
// that has none.
func (s *Etcd) GetNetwork(ctx context.Context) (Network, error) {
	var out Network
	err := s.view(ctx, func(t *etx) error {
		n, ok, err := t.network()
		if err == nil && !ok {
			return notFoundf("cluster network")
		}
		out = n
		return err
	})
	return out, err
}

// InitNetwork records the cluster network. It can be set only once, and
// only before any node exists, so that every node gets a subnet.
func (s *Etcd) InitNetwork(ctx context.Context, n Network) error {
	if n.Mode != NetworkPlain && n.Mode != NetworkWireGuard {
		return fmt.Errorf("unknown network mode %q", n.Mode)
	}
	if err := CheckClusterCIDR(n.ClusterCIDR); err != nil {
		return err
	}
	return s.tx(ctx, func(t *etx) error {
		if _, ok, err := t.network(); err != nil {
			return err
		} else if ok {
			return fmt.Errorf("the cluster network is already set: %w", ErrConflict)
		}
		nodes, err := t.list(pfxNodes)
		if err != nil {
			return err
		}
		if len(nodes) > 0 {
			return fmt.Errorf("the cluster already has nodes: %w", ErrPrecondition)
		}
		return t.put(keyNetwork, networkRec{Mode: n.Mode, ClusterCIDR: n.ClusterCIDR.String()})
	})
}

// newNodeNetwork checks a new node's private IP against the cluster network
// and returns the subnet to give it: the lowest node subnet no other node
// holds. It returns "" when the cluster has no network.
func (t *etx) newNodeNetwork(privateIP string) (string, error) {
	n, ok, err := t.network()
	if err != nil || !ok {
		return "", err
	}
	if ip, err := netip.ParseAddr(privateIP); err == nil && n.ClusterCIDR.Contains(ip) {
		return "", fmt.Errorf("private IP %s is inside the cluster CIDR %s: %w", privateIP, n.ClusterCIDR, ErrPrecondition)
	}
	used := map[string]bool{}
	err = listInto(t, pfxNodes, func(_ string, r nodeRec) error {
		if r.Subnet != "" {
			used[r.Subnet] = true
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sub, err := freeSubnet(n.ClusterCIDR, used)
	if err != nil {
		return "", err
	}
	return sub.String(), nil
}

// freeSubnet returns the first /NodeSubnetBits of cidr not in used.
func freeSubnet(cidr netip.Prefix, used map[string]bool) (netip.Prefix, error) {
	count := uint32(1) << (NodeSubnetBits - cidr.Bits())
	base := cidr.Addr().As4()
	start := binary.BigEndian.Uint32(base[:])
	for i := range count {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], start+i<<(32-NodeSubnetBits))
		p := netip.PrefixFrom(netip.AddrFrom4(b), NodeSubnetBits)
		if !used[p.String()] {
			return p, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("the cluster CIDR %s has no free node subnet (%d nodes): %w", cidr, count, ErrPrecondition)
}

// networkDetail is the audit detail of a node with a subnet.
func networkDetail(ip, subnet string) string {
	return strings.TrimSuffix(ip+", subnet "+subnet, ", subnet ")
}
