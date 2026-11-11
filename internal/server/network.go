package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"maps"
	"slices"

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
	subnets := map[string]string{}
	for _, node := range nodes {
		if node.Subnet == "" {
			continue
		}
		subnets[node.ID] = node.Subnet
		cfg.Peers = append(cfg.Peers, &armadav1.NetworkPeer{Node: node.ID, PrivateIp: node.PrivateIP, Subnet: node.Subnet, PublicKey: node.NetworkKey})
	}
	cfg.Endpoints = networkEndpoints(replicas, subnets)
	return cfg, nil
}

// tcpPorts returns the ports the nodes' proxies listen on for internal TCP
// apps (ADR 0039), sorted: the firewall opens them on the bridge gateway to
// containers of isolated projects.
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
// projects apart (ADR 0026). An address two replicas claim (one of them
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
