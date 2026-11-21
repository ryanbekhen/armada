package clusternet

import (
	"net"
	"net/netip"
	"slices"
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
// key and peers, or nil when it already is. In the mesh mode, and for a
// peer of another site, a peer is reached at its endpoint and is also
// allowed its node address; an endpoint
// WireGuard has moved (roaming, from the peer's authenticated packets) is
// kept while its handshake is fresh at now, so a peer behind NAT or with a
// changed address keeps working before the control plane hears of it.
func peerChanges(d *wgtypes.Device, key wgtypes.Key, mode string, peers []peer, now time.Time) *wgtypes.Config {
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
		target, allowed := pe.ip, []net.IPNet{*prefixNet(pe.subnet)}
		// A mesh peer, or a peer of another site (ADR 0050), is reached at
		// its public endpoint and also carries its node address.
		public := mode == ModeMesh || pe.remote
		if public {
			target = pe.endpoint
			allowed = []net.IPNet{*prefixNet(netip.PrefixFrom(pe.ip, 32)), *prefixNet(pe.subnet)}
		}
		// A relay's entry also carries the nodes behind NAT reached
		// through it (ADR 0050).
		for _, c := range pe.carried {
			allowed = append(allowed, *prefixNet(c))
		}
		h, ok := have[pe.key]
		var ep *net.UDPAddr
		var keep bool
		if public && !target.IsValid() {
			// A node behind NAT (ADR 0050): only WireGuard knows where it
			// is, from its packets.
			keep = ok
		} else {
			ep = &net.UDPAddr{IP: target.AsSlice(), Port: WireGuardPort}
			keep = ok && h.Endpoint != nil && (h.Endpoint.String() == ep.String() ||
				public && !h.LastHandshakeTime.IsZero() && now.Sub(h.LastHandshakeTime) <= staleHandshake)
		}
		if keep && sameNets(h.AllowedIPs, allowed) && h.PersistentKeepaliveInterval == keepalive {
			continue
		}
		ka := keepalive
		pc := wgtypes.PeerConfig{
			PublicKey: pe.key, ReplaceAllowedIPs: true, AllowedIPs: allowed,
			PersistentKeepaliveInterval: &ka,
		}
		if ep != nil {
			pc.Endpoint = ep
		}
		if keep {
			pc.Endpoint = nil
		}
		cfg.Peers = append(cfg.Peers, pc)
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

// staleHandshake is how old a peer's last handshake may be before doctor
// reports it, and before the mesh mode stops trusting a roamed endpoint:
// sessions are renewed every two minutes while they carry traffic, which
// the keepalive provides.
const staleHandshake = 3 * time.Minute

// sameNets compares two lists of networks as sets: the kernel lists a
// peer's allowed addresses in its own order.
func sameNets(a, b []net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	as, bs := make([]string, len(a)), make([]string, len(b))
	for i := range a {
		as[i], bs[i] = a[i].String(), b[i].String()
	}
	slices.Sort(as)
	slices.Sort(bs)
	return slices.Equal(as, bs)
}
