// Package netutil enforces that internal services only listen on private
// network addresses.
package netutil

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ErrPublicAddress is returned when an internal service would be exposed on a
// public or unspecified address.
var ErrPublicAddress = errors.New("address is not private")

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// IsPrivate reports whether addr is suitable for internal services: RFC 1918,
// IPv6 ULA, loopback, or carrier-grade NAT (used by some provider VPCs).
// Addresses with an IPv6 zone are never accepted: a zone can hold arbitrary
// bytes, including newlines, that would end up in generated configuration.
func IsPrivate(addr netip.Addr) bool {
	if addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	return addr.IsPrivate() || addr.IsLoopback() || cgnat.Contains(addr)
}

// CheckPrivateIP validates a bare IP address for internal use. Only the
// canonical form is accepted, so the string can be used verbatim.
func CheckPrivateIP(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid IP address %q", s)
	}
	if addr.Unmap().String() != s {
		return netip.Addr{}, fmt.Errorf("IP address %q is not in canonical form (want %s)", s, addr.Unmap())
	}
	if !IsPrivate(addr) {
		return netip.Addr{}, fmt.Errorf("%s: %w; internal services must bind to a private (VPC) or loopback address", s, ErrPublicAddress)
	}
	return addr.Unmap(), nil
}

// CheckNodeIP validates the private IP a remote node registers with: private
// and canonical like CheckPrivateIP, and additionally not loopback, so a
// node cannot point other nodes' proxies at their own local services.
func CheckNodeIP(s string) (netip.Addr, error) {
	addr, err := CheckPrivateIP(s)
	if err != nil {
		return netip.Addr{}, err
	}
	if addr.IsLoopback() {
		return netip.Addr{}, fmt.Errorf("%s: a node IP must not be a loopback address", s)
	}
	return addr, nil
}

// CheckPrivateListen validates a host:port listen address for internal use.
// Unspecified addresses such as 0.0.0.0 and [::] are rejected.
func CheckPrivateListen(hostport string) error {
	ap, err := netip.ParseAddrPort(hostport)
	if err != nil {
		return fmt.Errorf("listen address %q must be ip:port: %w", hostport, err)
	}
	_, err = CheckPrivateIP(ap.Addr().String())
	return err
}

// DetectPrivateIP returns the first private, non-loopback IPv4 address of an
// interface that is up.
func DetectPrivateIP() (netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return netip.Addr{}, err
	}
	var addrs []net.Addr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || virtualInterface(iface.Name) {
			continue
		}
		a, err := iface.Addrs()
		if err != nil {
			continue
		}
		addrs = append(addrs, a...)
	}
	if ip, ok := firstPrivateIPv4(addrs); ok {
		return ip, nil
	}
	return netip.Addr{}, errors.New("no private IPv4 address found; pass --private-ip")
}

func firstPrivateIPv4(addrs []net.Addr) (netip.Addr, bool) {
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() && !ip.IsLoopback() && IsPrivate(ip) {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// virtualInterface reports container and VM bridges, whose addresses are
// private but reachable from every container: never a node's VPC address.
func virtualInterface(name string) bool {
	for _, p := range []string{"docker", "br-", "veth", "cni", "flannel", "virbr", "lxc", "lxd", "podman", "tun", "tap", "wg", "armada"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
