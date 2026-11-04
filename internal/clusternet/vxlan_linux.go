//go:build linux

package clusternet

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/vishvananda/netlink"
)

// vni is the VXLAN network identifier of Armada's tunnel.
const vni = 7027

// vxlan creates or repairs the VXLAN interface and its peers.
func (n *Net) vxlan(p plan, uplink netlink.Link, mtu int) error {
	link, err := n.vxlanDevice(p, uplink, mtu)
	if err != nil {
		return err
	}
	if err := vxlanPeers(p, link); err != nil {
		return err
	}
	return syncRoutes(link, p, true)
}

func (n *Net) vxlanDevice(p plan, uplink netlink.Link, mtu int) (netlink.Link, error) {
	want := &netlink.Vxlan{
		LinkAttrs:    netlink.LinkAttrs{Name: Interface, MTU: mtu, HardwareAddr: vtepMAC(p.self.subnet)},
		VxlanId:      vni,
		VtepDevIndex: uplink.Attrs().Index,
		SrcAddr:      n.cfg.PrivateIP.AsSlice(),
		Port:         VXLANPort,
		Learning:     false,
	}
	link, err := existing()
	if err != nil {
		return nil, err
	}
	if link != nil {
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
	if link.Attrs().HardwareAddr.String() != want.HardwareAddr.String() {
		if err := netlink.LinkSetHardwareAddr(link, want.HardwareAddr); err != nil {
			return nil, fmt.Errorf("set address of %s: %w", Interface, err)
		}
	}
	return link, setUp(link, p, mtu)
}

// vxlanPeers installs, for each peer, the forwarding entry (its tunnel
// end's hardware address on its private IP) and the neighbour entry (its
// tunnel address on that hardware address), and removes entries for nodes
// that left.
func vxlanPeers(p plan, link netlink.Link) error {
	idx := link.Attrs().Index
	wantNeigh := map[string]bool{}
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
		wantNeigh[gw.String()], wantFDB[mac.String()] = true, true
	}
	neighs, err := netlink.NeighList(idx, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, ne := range neighs {
		if !wantNeigh[ne.IP.String()] {
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
