package haproxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ryanbekhen/armada/internal/proxy"
)

// procListeners returns the TCP sockets listening on the node, from
// /proc/net/tcp and /proc/net/tcp6. HAProxy runs on the host network, so
// these are the addresses its listeners compete with.
func procListeners() ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f) //nolint:gosec // fixed paths
		if errors.Is(err, os.ErrNotExist) && f == "/proc/net/tcp6" {
			continue // IPv6 is off
		}
		if err != nil {
			return nil, err
		}
		ls, err := parseListeners(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, ls...)
	}
	return out, nil
}

// tcpListen is the state of a listening socket in /proc/net/tcp.
const tcpListen = "0A"

// parseListeners reads the listening sockets of a /proc/net/tcp or tcp6
// table. Addresses are written as 32-bit words in the host's byte order.
func parseListeners(b []byte) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	sc := bufio.NewScanner(bytes.NewReader(b))
	first := true
	for sc.Scan() {
		if first {
			first = false // the header
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != tcpListen {
			continue
		}
		host, port, ok := strings.Cut(fields[1], ":")
		if !ok {
			return nil, fmt.Errorf("invalid address %q", fields[1])
		}
		p, err := strconv.ParseUint(port, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", port)
		}
		raw, err := hex.DecodeString(host)
		if err != nil || (len(raw) != 4 && len(raw) != 16) {
			return nil, fmt.Errorf("invalid address %q", host)
		}
		for i := 0; i < len(raw); i += 4 {
			binary.NativeEndian.PutUint32(raw[i:], binary.BigEndian.Uint32(raw[i:]))
		}
		a, _ := netip.AddrFromSlice(raw)
		out = append(out, netip.AddrPortFrom(a.Unmap(), uint16(p)))
	}
	return out, sc.Err()
}

// busyTCP returns the TCP ports of cfg another program listens on where a
// listener on the gateway would collide: on every address, or on the gateway
// itself while the running HAProxy does not hold the port. HAProxy would fail
// to bind them, and the whole reload with them (ADR 0039). held are the
// ports the running HAProxy listens on.
func busyTCP(cfg proxy.Config, gateway netip.Addr, listeners []netip.AddrPort, held []int) []int {
	var busy []int
	for _, port := range cfg.TCPPorts() {
		for _, l := range listeners {
			if int(l.Port()) != port {
				continue
			}
			if a := l.Addr(); a.IsUnspecified() || (a == gateway && !slices.Contains(held, port)) {
				busy = append(busy, port)
				break
			}
		}
	}
	return busy
}

var tcpFrontendLine = regexp.MustCompile(`(?m)^frontend tcp_([0-9]+)$`)

// heldTCP returns the ports of the TCP listeners in a rendered
// configuration.
func heldTCP(content []byte) []int {
	var out []int
	for _, m := range tcpFrontendLine.FindAllSubmatch(content, -1) {
		if p, err := strconv.Atoi(string(m[1])); err == nil {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}
