package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"maps"
	"slices"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

// buildNetwork returns the cluster network every agent applies (ADR 0025):
// the mode, the cluster CIDR, and every node that has a subnet. It returns
// nil for a cluster without a network.
func (s *Server) buildNetwork(ctx context.Context, nodes []store.Node, replicas []store.Replica) (*armadav1.NetworkConfig, error) {
	n, err := s.store.GetNetwork(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cfg := &armadav1.NetworkConfig{Mode: n.Mode, ClusterCidr: n.ClusterCIDR.String(), IsolateDefault: n.IsolateDefault}
	if n.MeshCIDR.IsValid() {
		cfg.MeshCidr = n.MeshCIDR.String()
	}
	if n.Switch != nil {
		cfg.SwitchTo, cfg.SwitchStep = n.Switch.To, n.Switch.Step
	}
	relays := s.siteRelays(nodes)
	subnets := map[string]string{}
	for _, node := range nodes {
		if node.Subnet == "" {
			continue
		}
		subnets[node.ID] = node.Subnet
		cfg.Peers = append(cfg.Peers, &armadav1.NetworkPeer{Node: node.ID, PrivateIp: node.PrivateIP, Subnet: node.Subnet, PublicKey: node.NetworkKey, Endpoint: node.Endpoint, Site: node.Site,
			BehindNat: node.BehindNAT, Relay: relays[node.Site] == node.ID})
	}
	cfg.Endpoints = networkEndpoints(replicas, subnets)
	return cfg, nil
}

// tcpPorts returns the ports the nodes' proxies listen on for internal TCP
// apps (ADR 0039), sorted: the firewall opens them on the bridge gateway to
// containers of isolated spaces.
func tcpPorts(px *armadav1.ProxyConfig) []uint32 {
	var out []uint32
	for _, r := range px.GetTcpRoutes() {
		out = append(out, r.GetPort())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// networkEndpoints lists the container address of every replica whose
// node has a subnet, with its app ID, for the firewalls that keep apps and
// spaces apart (ADR 0026). An address two replicas claim (one of them
// stale) is left out: no node lets it reach anything until it is clear.
func networkEndpoints(replicas []store.Replica, subnets map[string]string) []*armadav1.NetworkEndpoint {
	apps := map[string]string{}
	clash := map[string]bool{}
	for _, r := range replicas {
		if r.IP == "" || r.Done || !validReplicaIP(r.IP, subnets[r.NodeID]) {
			continue
		}
		if a, ok := apps[r.IP]; ok && a != r.App {
			clash[r.IP] = true
		}
		apps[r.IP] = r.App
	}
	out := make([]*armadav1.NetworkEndpoint, 0, len(apps))
	for _, ip := range slices.Sorted(maps.Keys(apps)) {
		if !clash[ip] {
			out = append(out, &armadav1.NetworkEndpoint{Address: ip, App: apps[ip]})
		}
	}
	return out
}

// networkMode is the cluster network's mode for join responses; empty in a
// cluster without one.
func (s *Server) networkMode(ctx context.Context) (string, error) {
	n, err := s.store.GetNetwork(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return n.Mode, err
}

// fileNetworkKeyHint names the node's key file in messages to operators.
const fileNetworkKeyHint = "network.key in the data directory"

// validNetworkKey reports whether s is a WireGuard public key: 32 bytes in
// standard base64, not all zero.
func validNetworkKey(s string) bool {
	if len(s) != 44 {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32 && !bytes.Equal(b, make([]byte, 32))
}

// siteRelays picks the relay of every site once a node is behind NAT (ADR
// 0050): a node of the site that can relay (relayCandidate), the one an
// admin chose when it can, else the one a rendezvous hash of the site and
// node names ranks first, so the choice stays put as other nodes come and
// go. Every site with a candidate gets one: nodes behind NAT in two sites
// with none use another site's. A cluster with no node behind NAT has
// none.
func (s *Server) siteRelays(nodes []store.Node) map[string]string {
	if !slices.ContainsFunc(nodes, func(n store.Node) bool { return n.BehindNAT && n.Subnet != "" }) {
		return nil
	}
	out := map[string]string{}
	best := map[string][]byte{}
	pinned := map[string]bool{}
	now := s.now()
	for _, n := range nodes {
		if !s.relayCandidate(n, now) {
			continue
		}
		h := sha256.Sum256([]byte(n.Site + "\x00" + n.ID))
		switch {
		case n.Relay && (!pinned[n.Site] || n.ID < out[n.Site]):
			// The store keeps one choice per site; were there more, the
			// lowest ID would win whatever the order of nodes.
			out[n.Site], pinned[n.Site] = n.ID, true
		case pinned[n.Site]:
		case best[n.Site] == nil || bytes.Compare(h[:], best[n.Site]) > 0:
			out[n.Site], best[n.Site] = n.ID, h[:]
		}
	}
	return out
}

// relayCandidate reports whether a node can relay its site's traffic: it
// has a subnet, a key, and an endpoint, is not behind NAT, is connected
// (not lost), and is not cordoned.
func (s *Server) relayCandidate(n store.Node, now time.Time) bool {
	return n.Subnet != "" && n.NetworkKey != "" && n.Endpoint != "" && !n.BehindNAT &&
		!n.Cordoned && n.State == store.NodeReady && !nodeLost(n, now, s.nodeLostTimeout)
}
