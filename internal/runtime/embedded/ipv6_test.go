package embedded

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDisableIPv6(t *testing.T) {
	dir := t.TempDir()
	old := ipv6Conf
	ipv6Conf = dir
	t.Cleanup(func() { ipv6Conf = old })

	// A link without IPv6 settings in a kernel that has IPv6 is not off.
	if off, err := IPv6Off(BridgeName); err == nil || off {
		t.Errorf("missing link: off = %v, err = %v", off, err)
	}
	if err := DisableIPv6(BridgeName); err != nil {
		t.Errorf("missing link: %v", err)
	}
	conf := filepath.Join(dir, BridgeName)
	if err := os.MkdirAll(conf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conf, "disable_ipv6"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if off, err := IPv6Off(BridgeName); err != nil || off {
		t.Errorf("before: off = %v, err = %v", off, err)
	}
	if err := DisableIPv6(BridgeName); err != nil {
		t.Fatal(err)
	}
	if off, err := IPv6Off(BridgeName); err != nil || !off {
		t.Errorf("after: off = %v, err = %v", off, err)
	}

	// A kernel without IPv6 has nothing to turn off.
	ipv6Conf = filepath.Join(dir, "none")
	if off, err := IPv6Off(BridgeName); err != nil || !off {
		t.Errorf("no IPv6: off = %v, err = %v", off, err)
	}
	if err := DisableIPv6(BridgeName); err != nil {
		t.Errorf("no IPv6: %v", err)
	}
}
