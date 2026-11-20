package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Network modes (ADR 0025).
const (
	// NetworkPlain routes the cluster CIDR between nodes over VXLAN on the
	// private network, unencrypted.
	NetworkPlain = "plain"
	// NetworkWireGuard routes it over WireGuard.
	NetworkWireGuard = "wireguard"
	// NetworkMesh routes it, and everything else between nodes, over
	// WireGuard between the nodes' public addresses; each node's private IP
	// is a mesh address (ADR 0049).
	NetworkMesh = "mesh"
)

// NodeSubnetBits is the prefix length of each node's container subnet.
const NodeSubnetBits = 24

// Network is the cluster network (ADR 0025). Clusters created before it
// have none and keep one bridge subnet on every node.
type Network struct {
	Mode        string
	ClusterCIDR netip.Prefix
	// IsolateDefault keeps the default space's containers away from the
	// platform, as every other space's always are (ADR 0026).
	IsolateDefault bool
	// MeshCIDR is the range of the nodes' mesh addresses in the mesh mode.
	MeshCIDR netip.Prefix
	// Switch is a switch to another mode under way (ADR 0050), nil while
	// none runs.
	Switch *NetworkSwitch
}

// NetworkSwitch is a switch of a running cluster between the plain and
// wireguard modes (ADR 0050).
type NetworkSwitch struct {
	// To is the target mode.
	To string
	// Step is SwitchPrepare or SwitchMove.
	Step string
	// Since is when the step began.
	Since time.Time
}

// Steps of a network switch (ADR 0050).
const (
	// SwitchPrepare: every node brings the target transport up beside the
	// current one.
	SwitchPrepare = "prepare"
	// SwitchMove: every node routes over the target transport.
	SwitchMove = "move"
)

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
	Mode           string `json:"mode"`
	ClusterCIDR    string `json:"clusterCidr"`
	IsolateDefault bool   `json:"isolateDefault,omitempty"`
	MeshCIDR       string `json:"meshCidr,omitempty"`
	// Switch is ignored by binaries that do not know it: their nodes stay
	// on (or go back to) Mode.
	Switch *networkSwitchRec `json:"switch,omitempty"`
}

type networkSwitchRec struct {
	To    string    `json:"to"`
	Step  string    `json:"step"`
	Since time.Time `json:"since"`
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
	n := Network{Mode: r.Mode, ClusterCIDR: p, IsolateDefault: r.IsolateDefault}
	if r.Switch != nil {
		n.Switch = &NetworkSwitch{To: r.Switch.To, Step: r.Switch.Step, Since: r.Switch.Since}
	}
	if r.MeshCIDR != "" {
		if n.MeshCIDR, err = netip.ParsePrefix(r.MeshCIDR); err != nil {
			return Network{}, false, fmt.Errorf("decode %s: mesh CIDR: %w", keyNetwork, err)
		}
	}
	return n, true, nil
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
	if n.Mode != NetworkPlain && n.Mode != NetworkWireGuard && n.Mode != NetworkMesh {
		return fmt.Errorf("unknown network mode %q", n.Mode)
	}
	if err := CheckClusterCIDR(n.ClusterCIDR); err != nil {
		return err
	}
	rec := networkRec{Mode: n.Mode, ClusterCIDR: n.ClusterCIDR.String()}
	switch {
	case n.Mode != NetworkMesh && n.MeshCIDR.IsValid():
		return fmt.Errorf("a mesh CIDR needs the mesh network mode")
	case n.Mode == NetworkMesh:
		if err := CheckMeshCIDR(n.MeshCIDR); err != nil {
			return err
		}
		if n.MeshCIDR.Overlaps(n.ClusterCIDR) {
			return fmt.Errorf("mesh CIDR %s overlaps the cluster CIDR %s", n.MeshCIDR, n.ClusterCIDR)
		}
		rec.MeshCIDR = n.MeshCIDR.String()
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
		return t.put(keyNetwork, rec)
	})
}

// SetDefaultIsolation turns network isolation of the default space on or
// off (ADR 0026). It needs the cluster network, which enforces it.
func (s *Etcd) SetDefaultIsolation(ctx context.Context, on bool, actor string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var r networkRec
		ok, err := t.get(keyNetwork, &r)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("network isolation needs the cluster network (armadad init --cluster-cidr): %w", ErrPrecondition)
		}
		if r.IsolateDefault == on {
			return nil
		}
		r.IsolateDefault = on
		if err := t.put(keyNetwork, r); err != nil {
			return err
		}
		return t.audit(now, actor, "space.set", "default", fmt.Sprintf("network isolation %t", on))
	})
}

// StartNetworkSwitch begins switching a running cluster to mode to (ADR
// 0050): only between plain and wireguard, and only while no switch runs
// (ErrConflict). Asking for the current mode during a switch's prepare step
// gives the switch up; once its nodes move, it finishes.
func (s *Etcd) StartNetworkSwitch(ctx context.Context, to, actor string) error {
	if to != NetworkPlain && to != NetworkWireGuard {
		return fmt.Errorf("a running cluster switches only to %s or %s, not %q: %w", NetworkPlain, NetworkWireGuard, to, ErrPrecondition)
	}
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var r networkRec
		ok, err := t.get(keyNetwork, &r)
		if err != nil {
			return err
		}
		switch {
		case !ok:
			return fmt.Errorf("the cluster has no cluster network to switch: %w", ErrPrecondition)
		case r.Mode == NetworkMesh:
			return fmt.Errorf("a mesh cluster cannot switch its network mode: its nodes' addresses depend on it: %w", ErrPrecondition)
		case r.Switch != nil && to == r.Mode && r.Switch.Step == SwitchPrepare:
			r.Switch = nil
			if err := t.put(keyNetwork, r); err != nil {
				return err
			}
			return t.audit(now, actor, "network.switch", "network", "gave up the switch to "+to+"; staying on "+r.Mode)
		case r.Switch != nil:
			return fmt.Errorf("the network is switching to %s (%s step): %w", r.Switch.To, r.Switch.Step, ErrConflict)
		case to == r.Mode:
			return nil
		}
		var away []string
		if err := listInto(t, pfxNodes, func(_ string, n nodeRec) error {
			if n.Site != "" {
				away = append(away, n.ID)
			}
			return nil
		}); err != nil {
			return err
		}
		if len(away) > 0 {
			return fmt.Errorf("nodes in another site reach the others over WireGuard whatever the mode, and a switch moves only one site's: move them back first (armada node site NODE --clear): %s: %w", strings.Join(away, ", "), ErrPrecondition)
		}
		r.Switch = &networkSwitchRec{To: to, Step: SwitchPrepare, Since: now}
		if err := t.put(keyNetwork, r); err != nil {
			return err
		}
		return t.audit(now, actor, "network.switch", "network", "switching from "+r.Mode+" to "+to)
	})
}

// AdvanceNetworkSwitch takes a switch to to from the step from to the next
// (ADR 0050): prepare to move, and move to done, where the cluster's mode
// becomes to. It returns ErrConflict when the switch is no longer at that
// step, so a pass acting on what it read earlier changes nothing.
func (s *Etcd) AdvanceNetworkSwitch(ctx context.Context, to, from string) error {
	now := s.now()
	return s.tx(ctx, func(t *etx) error {
		var r networkRec
		ok, err := t.get(keyNetwork, &r)
		if err != nil {
			return err
		}
		if !ok || r.Switch == nil || r.Switch.To != to || r.Switch.Step != from {
			return fmt.Errorf("the network switch is not at %s %s: %w", to, from, ErrConflict)
		}
		switch from {
		case SwitchPrepare:
			r.Switch = &networkSwitchRec{To: to, Step: SwitchMove, Since: now}
		case SwitchMove:
			r.Mode, r.Switch = to, nil
		default:
			return fmt.Errorf("unknown switch step %q", from)
		}
		return t.put(keyNetwork, r)
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
	ip, err := netip.ParseAddr(privateIP)
	if err == nil && n.ClusterCIDR.Contains(ip) {
		return "", fmt.Errorf("private IP %s is inside the cluster CIDR %s: %w", privateIP, n.ClusterCIDR, ErrPrecondition)
	}
	if n.Mode == NetworkMesh && (err != nil || !n.MeshCIDR.Contains(ip)) {
		return "", fmt.Errorf("a mesh node's address %s must be in the mesh CIDR %s: %w", privateIP, n.MeshCIDR, ErrPrecondition)
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

// CheckMeshCIDR validates the range of a mesh cluster's node addresses: a
// private IPv4 prefix from /8 to /24 in canonical form (ADR 0049).
func CheckMeshCIDR(p netip.Prefix) error {
	switch {
	case !p.IsValid() || !p.Addr().Is4():
		return errors.New("mesh CIDR must be an IPv4 prefix")
	case p.Masked() != p:
		return fmt.Errorf("mesh CIDR %s is not in canonical form (want %s)", p, p.Masked())
	case p.Bits() < 8 || p.Bits() > 24:
		return fmt.Errorf("mesh CIDR %s: the prefix must be from /8 to /24", p)
	case !p.Addr().IsPrivate():
		return fmt.Errorf("mesh CIDR %s is not a private range", p)
	}
	return nil
}

// freeMeshAddress returns the lowest host address of mesh not in used,
// leaving out the network and broadcast addresses.
func freeMeshAddress(mesh netip.Prefix, used map[netip.Addr]bool) (netip.Addr, error) {
	b := mesh.Addr().As4()
	binary.BigEndian.PutUint32(b[:], binary.BigEndian.Uint32(b[:])|(uint32(1)<<(32-mesh.Bits())-1))
	last := netip.AddrFrom4(b)
	for a := mesh.Addr().Next(); a.IsValid() && a.Less(last); a = a.Next() {
		if !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("the mesh CIDR %s has no free address: %w", mesh, ErrPrecondition)
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
