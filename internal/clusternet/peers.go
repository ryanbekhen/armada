package clusternet

import (
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// keepalive keeps every pair's session up while idle, so that the first
// packet after a quiet spell does not wait for a handshake and armada
// doctor can tell a peer that answers from one that does not.
const keepalive = 25 * time.Second

func prefixNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// peerChanges returns the configuration that turns device d into one with
// key and peers, or nil when it already is.
func peerChanges(d *wgtypes.Device, key wgtypes.Key, peers []peer) *wgtypes.Config {
	var cfg wgtypes.Config
	changed := false
	if d.PrivateKey != key {
		cfg.PrivateKey, changed = &key, true
	}
	if d.ListenPort != WireGuardPort {
		port := WireGuardPort
		cfg.ListenPort, changed = &port, true
	}
	have := map[wgtypes.Key]wgtypes.Peer{}
	for _, pe := range d.Peers {
		have[pe.PublicKey] = pe
	}
	want := map[wgtypes.Key]bool{}
	for _, pe := range peers {
		want[pe.key] = true
		ep := &net.UDPAddr{IP: pe.ip.AsSlice(), Port: WireGuardPort}
		allowed := *prefixNet(pe.subnet)
		if h, ok := have[pe.key]; ok && h.Endpoint != nil && h.Endpoint.String() == ep.String() &&
			len(h.AllowedIPs) == 1 && h.AllowedIPs[0].String() == allowed.String() && h.PersistentKeepaliveInterval == keepalive {
			continue
		}
		ka := keepalive
		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
			PublicKey: pe.key, Endpoint: ep, ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{allowed},
			PersistentKeepaliveInterval: &ka,
		})
	}
	for k := range have {
		if !want[k] {
			cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{PublicKey: k, Remove: true})
		}
	}
	if !changed && len(cfg.Peers) == 0 {
		return nil
	}
	return &cfg
}
