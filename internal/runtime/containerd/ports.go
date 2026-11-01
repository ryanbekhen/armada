package containerd

import (
	"errors"
	"math/rand/v2"
	"net"
	"strconv"
)

// Host ports for published container ports come from this range, below
// the kernel's default ephemeral range.
const (
	portMin = 20000
	portMax = 32767
)

// pickPort returns a free port on hostIP: not used by another container
// and not bound by a host process.
func pickPort(hostIP string, used map[int]bool, free func(hostIP string, port int) bool) (int, error) {
	n := portMax - portMin + 1
	start := rand.IntN(n) //nolint:gosec // spreads ports, not a secret
	for i := range n {
		p := portMin + (start+i)%n
		if !used[p] && free(hostIP, p) {
			return p, nil
		}
	}
	return 0, errors.New("no free host port")
}

// portFree reports whether nothing on the host listens on hostIP:port.
// Published ports are NAT rules, not sockets, so this only finds host
// processes; used covers containers.
func portFree(hostIP string, port int) bool {
	l, err := net.Listen("tcp", net.JoinHostPort(hostIP, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}
