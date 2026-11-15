package embedded

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ipv6Conf is where the kernel keeps each interface's IPv6 settings.
var ipv6Conf = "/proc/sys/net/ipv6/conf"

// DisableIPv6 turns IPv6 off on the bridge link. Containers get only IPv4
// addresses, and the space isolation firewall filters only IPv4: with IPv6
// on, the bridge would have a link-local address through which every
// container reaches the host's IPv6 listeners (T13). A kernel without IPv6
// has nothing to turn off.
func DisableIPv6(link string) error {
	p := filepath.Join(ipv6Conf, link, "disable_ipv6")
	if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := os.WriteFile(p, []byte("1\n"), 0o600); err != nil {
		return fmt.Errorf("turn IPv6 off on %s: %w", link, err)
	}
	return nil
}

// IPv6Off reports whether link has IPv6 turned off (or the kernel has none).
func IPv6Off(link string) (bool, error) {
	b, err := os.ReadFile(filepath.Join(ipv6Conf, link, "disable_ipv6")) //nolint:gosec // a kernel setting of a link Armada names
	if errors.Is(err, fs.ErrNotExist) {
		if _, err := os.Stat(ipv6Conf); errors.Is(err, fs.ErrNotExist) {
			return true, nil
		}
		return false, fmt.Errorf("%s has no IPv6 settings", link)
	}
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(b)) == "1", nil
}
