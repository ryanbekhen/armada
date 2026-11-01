package netutil

import (
	"errors"
	"net"
	"net/netip"
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

func TestFirstPrivateIPv4(t *testing.T) {
	t.Parallel()

	mk := func(s string) net.Addr {
		_, n, _ := net.ParseCIDR(s)
		n.IP = net.ParseIP(s[:len(s)-3])
		return n
	}
	got, ok := firstPrivateIPv4([]net.Addr{
		mk("8.8.8.8/24"), mk("127.0.0.1/8"), &net.IPAddr{IP: net.ParseIP("10.9.9.9")}, mk("10.0.0.2/24"), mk("192.168.1.2/24"),
	})
	if !ok || got != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("firstPrivateIPv4 = %v, %v", got, ok)
	}
	if _, ok := firstPrivateIPv4([]net.Addr{mk("8.8.8.8/24")}); ok {
		t.Error("public-only interface list returned an address")
	}
}

func TestDetectPrivateIPDoesNotReturnPublic(t *testing.T) {
	t.Parallel()

	ip, err := DetectPrivateIP()
	if err != nil {
		t.Skipf("no private interface on this machine: %v", err)
	}
	if !IsPrivate(ip) || ip.IsLoopback() {
		t.Errorf("DetectPrivateIP() = %v", ip)
	}
}
