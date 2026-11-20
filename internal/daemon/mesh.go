package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/clusternet"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/store"
)

// fileMeshCache is where a mesh node keeps the last peer list it applied
// (ADR 0049); it is learned again from the control plane, so it is not
// backed up.
const fileMeshCache = "mesh.json"

// meshConfig is the clusternet configuration of a node of a cluster
// network, with what the mesh mode needs.
func meshConfig(dataDir string, ac *agentConfig, key clusternet.PrivateKey, log *slog.Logger) (clusternet.Config, error) {
	ip, err := netip.ParseAddr(ac.PrivateIP)
	if err != nil {
		return clusternet.Config{}, fmt.Errorf("%s: private IP: %w", fileAgent, err)
	}
	// The endpoint also finds the uplink of a node whose address is a mesh
	// address in a plain or wireguard cluster (ADR 0050).
	return clusternet.Config{Node: ac.NodeID, PrivateIP: ip, Key: key, Logger: log.With("component", "network"),
		MeshCache: filepath.Join(dataDir, fileMeshCache), Endpoint: ac.endpoint()}, nil
}

// upMesh brings a mesh node's tunnel up before etcd or the agent reach
// mesh addresses (ADR 0049): from cfg (init's or the join answer's peer
// list) or, when nil, the list the node last applied. A node of another
// cluster network brings its tunnels up from that list too when it keeps
// one, which it does while peers are in other sites (ADR 0050): they reach
// the control plane only through them. Tests replace it.
var upMesh = func(dataDir string, ac *agentConfig, cfg *armadav1.NetworkConfig, log *slog.Logger) error {
	switch {
	case ac.Network == "":
		return nil
	case ac.Network != store.NetworkMesh:
		if _, err := os.Stat(filepath.Join(dataDir, fileMeshCache)); cfg == nil && err != nil {
			return nil
		}
	}
	given := cfg != nil
	key, err := clusternet.LoadOrCreateKey(filepath.Join(dataDir, fileNetworkKey))
	if err != nil {
		return fmt.Errorf("cluster network key: %w", err)
	}
	c, err := meshConfig(dataDir, ac, key, log)
	if err != nil {
		return err
	}
	if cfg == nil && ac.Network == store.NetworkMesh {
		if _, err := os.Stat(c.MeshCache); errors.Is(err, fs.ErrNotExist) {
			// No peer list (a restored or rebuilt node): come up alone, so
			// etcd and the API can listen; the control plane sends the
			// peers, and the node's new key, once it answers.
			cfg = alone(ac, key.Public())
		}
	}
	n, err := clusternet.New(c)
	if err != nil {
		return err
	}
	if err := n.Up(cfg); err != nil {
		if ac.Network != store.NetworkMesh && !given {
			// The private network still reaches this site's nodes; the
			// agent applies the network again once connected.
			log.Warn("bring the tunnels to other sites up", "err", err)
			return nil
		}
		return fmt.Errorf("cluster network: %w", err)
	}
	return nil
}

// alone is a mesh network with only this node in it.
func alone(ac *agentConfig, key string) *armadav1.NetworkConfig {
	return &armadav1.NetworkConfig{
		Mode: store.NetworkMesh, ClusterCidr: ac.ClusterCIDR, MeshCidr: ac.MeshCIDR,
		Peers: []*armadav1.NetworkPeer{{Node: ac.NodeID, PrivateIp: ac.PrivateIP, Subnet: ac.ContainerSubnet, PublicKey: key, Endpoint: ac.Endpoint}},
	}
}

// resolveEndpoint returns a mesh node's endpoint: --endpoint, or the
// machine's only public IPv4 address.
func resolveEndpoint(flag string) (netip.Addr, error) {
	if flag == "" {
		return netutil.DetectEndpoint()
	}
	return netutil.CheckEndpoint(flag)
}

// meshJoinAddr reports whether a join address is a mesh cluster's: a join
// listener on a public address exists only there (ADR 0049).
func meshJoinAddr(addr string) (bool, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || ap.Port() == 0 {
		return false, fmt.Errorf("join address %q: want IP:PORT", addr)
	}
	if netutil.IsPrivate(ap.Addr()) {
		return false, netutil.CheckPrivateListen(addr)
	}
	if _, err := netutil.CheckEndpoint(ap.Addr().Unmap().String()); err != nil {
		return false, fmt.Errorf("join address: %w", err)
	}
	return true, nil
}

// meshJoinListen moves a mesh server's join listener from its mesh address
// to its endpoint, on the same port.
func meshJoinListen(joinAddr string, endpoint netip.Addr) (string, error) {
	ap, err := netip.ParseAddrPort(joinAddr)
	if err != nil {
		return "", fmt.Errorf("join listener %q: %w", joinAddr, err)
	}
	if !endpoint.IsValid() {
		return "", fmt.Errorf("%s: a mesh node needs its endpoint", fileAgent)
	}
	return netip.AddrPortFrom(endpoint, ap.Port()).String(), nil
}

// joinMesh is a machine's side of joining over a public join address: the
// cluster is a mesh (ADR 0049), or the machine is in another site than the
// leader (ADR 0050). It sends its WireGuard key and endpoint, and its
// private IP when it has one, which only the second uses.
type joinMesh struct {
	on       bool
	endpoint netip.Addr
	key      string
}

// prepareJoin works out how a machine joins addr: its private IP, or over
// a public address its endpoint and, when it has one and noPrivateIP is
// unset, its private IP. ip is invalid when a public join sends none.
func prepareJoin(cmd interface{ Changed(string) bool }, addr, privateIP, endpoint string, noPrivateIP bool) (netip.Addr, joinMesh, error) {
	public, err := meshJoinAddr(addr)
	if err != nil {
		return netip.Addr{}, joinMesh{}, err
	}
	if noPrivateIP && cmd.Changed("private-ip") {
		return netip.Addr{}, joinMesh{}, errors.New("--private-ip and --no-private-ip exclude each other")
	}
	if !public {
		if cmd.Changed("endpoint") {
			return netip.Addr{}, joinMesh{}, errors.New("--endpoint is for joins over a public address (mesh clusters, and machines of another site than the leader's)")
		}
		if noPrivateIP {
			return netip.Addr{}, joinMesh{}, errors.New("--no-private-ip is for joins over a public address: machines of another site than the leader's")
		}
		ip, err := resolvePrivateIP(privateIP)
		return ip, joinMesh{}, err
	}
	ep, err := resolveEndpoint(endpoint)
	if err != nil {
		return netip.Addr{}, joinMesh{}, err
	}
	var ip netip.Addr
	switch {
	case noPrivateIP:
	case cmd.Changed("private-ip"):
		if ip, err = resolvePrivateIP(privateIP); err != nil {
			return netip.Addr{}, joinMesh{}, err
		}
	default:
		if found, err := resolvePrivateIP(""); err == nil {
			ip = found
		}
	}
	return ip, joinMesh{on: true, endpoint: ep}, nil
}

// loadKey makes or reads the machine's WireGuard key for a mesh join.
func (j *joinMesh) loadKey(dataDir string) error {
	if !j.on {
		return nil
	}
	key, err := clusternet.LoadOrCreateKey(filepath.Join(dataDir, fileNetworkKey))
	if err != nil {
		return fmt.Errorf("cluster network key: %w", err)
	}
	j.key = key.Public()
	return nil
}

// address returns the machine's address from the join answer: its private
// IP, or the mesh address the cluster gave it: a mesh cluster's, or a plain
// or wireguard cluster's for a machine that sent no private IP (ADR 0050).
func (j joinMesh) address(ip netip.Addr, mode, meshIP string) (netip.Addr, error) {
	if mode == store.NetworkMesh && !j.on {
		return netip.Addr{}, fmt.Errorf("the cluster's network mode is %q, which does not match a join at this address", mode)
	}
	if mode != store.NetworkMesh && meshIP == "" {
		if !ip.IsValid() {
			return netip.Addr{}, errors.New("the cluster gave this machine, which sent no private IP, no mesh address")
		}
		return ip, nil
	}
	if ip.IsValid() && mode != store.NetworkMesh {
		return netip.Addr{}, fmt.Errorf("the cluster gave this machine a mesh address although it joined with its private IP %s", ip)
	}
	a, err := netutil.CheckNodeIP(meshIP)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("mesh address from the cluster: %w", err)
	}
	return a, nil
}

// ipString is ip as text, or "" when it is unset (a mesh join).
func ipString(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}
