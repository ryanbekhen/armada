package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

// buildNetwork returns the cluster network every agent applies (ADR 0027):
// the mode, the cluster CIDR, and every node that has a subnet. It returns
// nil for a cluster without a network.
func (s *Server) buildNetwork(ctx context.Context, nodes []store.Node) (*armadav1.NetworkConfig, error) {
	n, err := s.store.GetNetwork(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cfg := &armadav1.NetworkConfig{Mode: n.Mode, ClusterCidr: n.ClusterCIDR.String()}
	for _, node := range nodes {
		if node.Subnet == "" {
			continue
		}
		cfg.Peers = append(cfg.Peers, &armadav1.NetworkPeer{Node: node.ID, PrivateIp: node.PrivateIP, Subnet: node.Subnet, PublicKey: node.NetworkKey})
	}
	return cfg, nil
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
