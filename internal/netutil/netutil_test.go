package netutil

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestCheckPrivateIP(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"10.0.0.2", "172.16.5.1", "192.168.1.10", "127.0.0.1", "::1", "fd00::1", "100.64.1.1"} {
		if _, err := CheckPrivateIP(s); err != nil {
			t.Errorf("CheckPrivateIP(%q) = %v", s, err)
		}
	}
	for _, s := range []string{"0.0.0.0", "::", "8.8.8.8", "172.32.0.1", "100.128.0.1", "2001:db8::1"} {
		if _, err := CheckPrivateIP(s); !errors.Is(err, ErrPublicAddress) {
			t.Errorf("CheckPrivateIP(%q) = %v, want ErrPublicAddress", s, err)
		}
	}
	// Invalid or ambiguous: zones (which may carry any bytes, even
	// newlines), non-canonical spellings.
	for _, s := range []string{"not-an-ip", "fd00::1%eth0", "fd00::1%x\n    global x", "::ffff:10.0.0.1", "fd00:0::1", "010.0.0.1", " 10.0.0.1"} {
		if _, err := CheckPrivateIP(s); err == nil || errors.Is(err, ErrPublicAddress) {
			t.Errorf("CheckPrivateIP(%q) = %v, want invalid", s, err)
		}
	}
	if IsPrivate(netip.MustParseAddr("fd00::1%eth0")) {
		t.Error("an address with a zone counts as private")
	}
}

func TestCheckNodeIP(t *testing.T) {
	t.Parallel()
	if _, err := CheckNodeIP("10.0.0.2"); err != nil {
		t.Error(err)
	}
	for _, s := range []string{"127.0.0.1", "127.0.0.2", "::1", "8.8.8.8", "fd00::1%x"} {
		if _, err := CheckNodeIP(s); err == nil {
			t.Errorf("CheckNodeIP(%q) accepted", s)
		}
	}
}

func TestVirtualInterface(t *testing.T) {
	t.Parallel()
	for _, n := range []string{"docker0", "br-1a2b", "veth12ab", "cni0", "virbr0", "wg0", "armada0"} {
		if !virtualInterface(n) {
			t.Errorf("%s not treated as virtual", n)
		}
	}
	for _, n := range []string{"eth0", "ens3", "enp1s0", "eth1"} {
		if virtualInterface(n) {
			t.Errorf("%s treated as virtual", n)
		}
	}
}

func TestCheckPrivateListen(t *testing.T) {
	t.Parallel()

	if err := CheckPrivateListen("10.0.0.2:7443"); err != nil {
		t.Error(err)
	}
	if err := CheckPrivateListen("[fd00::1]:7443"); err != nil {
		t.Error(err)
	}
	for _, s := range []string{"0.0.0.0:7443", "[::]:7443", "1.2.3.4:7443"} {
		if err := CheckPrivateListen(s); !errors.Is(err, ErrPublicAddress) {
			t.Errorf("CheckPrivateListen(%q) = %v", s, err)
		}
	}
	for _, s := range []string{":7443", "localhost:7443", "10.0.0.1"} {
		if err := CheckPrivateListen(s); err == nil {
			t.Errorf("CheckPrivateListen(%q) accepted", s)
		}
	}
}

func TestOnePrivateIPv4(t *testing.T) {
	t.Parallel()

	mk := func(name, s string) ifaceAddr {
		_, n, _ := net.ParseCIDR(s)
		n.IP = net.ParseIP(s[:strings.IndexByte(s, '/')])
		return ifaceAddr{name, n}
	}
	got, err := onePrivateIPv4([]ifaceAddr{
		mk("eth0", "8.8.8.8/24"), mk("eth0", "fd00::1/64"), {"eth1", &net.IPAddr{IP: net.ParseIP("10.9.9.9")}}, mk("eth1", "10.0.0.2/24"),
	})
	if err != nil || got != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("one private address: %v, %v", got, err)
	}
	if _, err := onePrivateIPv4([]ifaceAddr{mk("eth0", "8.8.8.8/24")}); err == nil || !strings.Contains(err.Error(), "no private IPv4") {
		t.Errorf("public only: %v", err)
	}
	_, err = onePrivateIPv4([]ifaceAddr{mk("ens4", "10.0.0.5/24"), mk("tailscale0", "100.101.2.3/32")})
	if err == nil || !strings.Contains(err.Error(), "10.0.0.5 on ens4, 100.101.2.3 on tailscale0") || !strings.Contains(err.Error(), "--private-ip") {
		t.Errorf("several: %v", err)
	}
}

func TestDetectPrivateIPDoesNotReturnPublic(t *testing.T) {
	t.Parallel()

	ip, err := DetectPrivateIP()
	if err != nil {
		t.Skipf("no single private address on this machine: %v", err)
	}
	if !IsPrivate(ip) || ip.IsLoopback() {
		t.Errorf("DetectPrivateIP() = %v", ip)
	}
}
