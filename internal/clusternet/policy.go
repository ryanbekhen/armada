package clusternet

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
)

// maxEndpoints bounds the container addresses a node accepts.
const maxEndpoints = 1 << 16

// parseEndpoints validates the container addresses the control plane sent.
// An address must be a container address of a node subnet of the cluster
// CIDR and its app a valid ID. An address listed twice is left out, so it
// reaches nothing until the control plane agrees with itself.
func parseEndpoints(eps []*armadav1.NetworkEndpoint, cidr netip.Prefix) (map[netip.Addr]string, error) {
	if len(eps) > maxEndpoints {
		return nil, fmt.Errorf("%d container addresses: at most %d", len(eps), maxEndpoints)
	}
	out := make(map[netip.Addr]string, len(eps))
	clash := map[netip.Addr]bool{}
	for _, e := range eps {
		a, err := netip.ParseAddr(e.GetAddress())
		if err != nil || !containerAddr(a, cidr) {
			return nil, fmt.Errorf("invalid container address %q", e.GetAddress())
		}
		if !spec.ValidAppID(e.GetApp()) {
			return nil, fmt.Errorf("container address %s: invalid app %q", a, e.GetApp())
		}
		if _, dup := out[a]; dup {
			clash[a] = true
		}
		out[a] = e.GetApp()
	}
	for a := range clash {
		delete(out, a)
	}
	return out, nil
}

// containerAddr reports whether a is an address the bridge of a node
// subnet of cidr can give a container: not the subnet's network address
// (the node's tunnel end), gateway, or broadcast address.
func containerAddr(a netip.Addr, cidr netip.Prefix) bool {
	if !a.Is4() || a.Zone() != "" || !cidr.Contains(a) {
		return false
	}
	host := a.As4()[3]
	return host != 0 && host != 1 && host != 255
}

// policy is what the firewall that keeps apps and projects apart is built
// from (ADR 0026).
type policy struct {
	cidr    netip.Prefix
	subnet  netip.Prefix // this node's
	gateway netip.Addr   // this node's bridge
	// apps are the app IDs with a known address, sorted, and members their
	// addresses, sorted. Traffic from one container straight to another
	// passes only between members of the same app.
	apps    []string
	members map[string][]netip.Addr
	// open are this node's containers that are not isolated from the
	// platform (the default project's, unless it is isolated). Every other
	// address of the node subnet, known or not, is isolated.
	open []netip.Addr
	// nodes are the private addresses of every node.
	nodes []netip.Addr
}

// buildPolicy merges the cluster's container addresses with this node's
// own, which local overrides for the node subnet: they are known before
// the control plane hears of them. With local nil, the node's containers
// are not in its subnet and the list from the control plane is used as is.
func buildPolicy(p plan, local map[netip.Addr]string) policy {
	pol := policy{
		cidr:    p.cidr,
		subnet:  p.self.subnet,
		gateway: p.self.subnet.Masked().Addr().Next(),
		members: map[string][]netip.Addr{},
	}
	eps := make(map[netip.Addr]string, len(p.endpoints)+len(local))
	for a, app := range p.endpoints {
		if local == nil || !p.self.subnet.Contains(a) {
			eps[a] = app
		}
	}
	for a, app := range local {
		if p.self.subnet.Contains(a) && containerAddr(a, p.cidr) && spec.ValidAppID(app) {
			eps[a] = app
		}
	}
	for _, a := range slices.SortedFunc(maps.Keys(eps), netip.Addr.Compare) {
		app := eps[a]
		pol.members[app] = append(pol.members[app], a)
		if !p.self.subnet.Contains(a) {
			continue
		}
		if project, _, _ := spec.SplitAppID(app); project == spec.DefaultProject && !p.isolateDefault {
			pol.open = append(pol.open, a)
		}
	}
	pol.apps = slices.Sorted(maps.Keys(pol.members))
	pol.nodes = append(pol.nodes, p.self.ip)
	for _, pe := range p.peers {
		pol.nodes = append(pol.nodes, pe.ip)
	}
	slices.SortFunc(pol.nodes, netip.Addr.Compare)
	return pol
}
