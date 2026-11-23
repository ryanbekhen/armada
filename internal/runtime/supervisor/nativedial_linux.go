package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// nativeDial is what `runtime dial` reads.
type nativeDial struct {
	Dir       string `json:"dir,omitempty"`
	ShimDir   string `json:"shimDir,omitempty"`
	ID        string `json:"id,omitempty"`
	Proc      string `json:"proc,omitempty"`
	Netns     string `json:"netns,omitempty"`
	Kind      string `json:"kind"`
	IP        string `json:"ip"`
	Family    int    `json:"family"`
	Port      uint16 `json:"port"`
	V6Only    bool   `json:"v6only"`
	TimeoutMs int64  `json:"timeoutMs,omitempty"`
}

// dialPlan works out what Go's dialer does with network and address: the
// socket's kind and family, and IPV6_V6ONLY. ok is false for what Go
// dials itself: a port that is not a number, an address with a zone, or
// a family the network does not take (Go's dialer words that error).
func dialPlan(network, address string) (nativeDial, net.Addr, bool) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || ap.Addr().Zone() != "" || network == "" {
		return nativeDial{}, nil, false
	}
	d := nativeDial{Port: ap.Port()}
	var raddr net.Addr
	switch network {
	case "tcp", "tcp4", "tcp6":
		d.Kind, raddr = "tcp", net.TCPAddrFromAddrPort(ap)
	case "udp", "udp4", "udp6":
		d.Kind, raddr = "udp", net.UDPAddrFromAddrPort(ap)
	default:
		return nativeDial{}, nil, false
	}
	ip := ap.Addr()
	is4 := ip.Is4() || ip.Is4In6()
	switch network[len(network)-1] {
	case '4':
		if !is4 {
			return nativeDial{}, nil, false
		}
		d.Family = 4
	case '6':
		if is4 {
			return nativeDial{}, nil, false
		}
		d.Family, d.V6Only = 6, true
	default:
		d.Family = 6
		if is4 {
			d.Family = 4
		}
	}
	if d.Family == 4 {
		d.IP = ip.Unmap().String()
	} else {
		d.IP = ip.String()
	}
	return d, raddr, true
}

// NativeDial dials address from a network namespace through armada-node,
// as the driver's dialIn does: container id's (netnsPath empty, its
// process found under procRoot) or the one pinned at netnsPath (a
// sandbox). handled is false when Go must dial itself: the node is not
// on armada-node, the address is one Go's dialer handles alone, the call
// failed (logged once per distinct failure), or the container's shim
// needs what Go does about a shim that is gone.
func (s *Store) NativeDial(ctx context.Context, id, netnsPath, procRoot, network, address string) (conn net.Conn, handled bool, err error) {
	n := s.Native
	if n == nil {
		return nil, false, nil
	}
	req, raddr, ok := dialPlan(network, address)
	if !ok {
		return nil, false, nil
	}
	if netnsPath != "" {
		req.Netns = netnsPath
	} else {
		req.Dir, req.ShimDir, req.ID, req.Proc = s.Bundles.Dir, s.Shims.Dir, id, procRoot
	}
	req.TimeoutMs = timeoutMs(ctx)
	conn, handled, err = n.dial(ctx, req, network, raddr)
	if ctx.Err() != nil && !handled {
		// dialIn returns the context's error once it ends.
		return nil, true, ctx.Err()
	}
	if !handled {
		return nil, false, nil
	}
	if err != nil {
		var nsErr *nsError
		if errors.As(err, &nsErr) {
			if netnsPath != "" {
				return nil, true, fmt.Errorf("sandbox namespace: %w", nsErr.errno)
			}
			return nil, true, fmt.Errorf("container network namespace: %w", nsErr.errno)
		}
	}
	return conn, true, err
}

// nsError is a namespace that could not be opened.
type nsError struct{ errno syscall.Errno }

func (e *nsError) Error() string { return e.errno.Error() }

// dial runs `runtime dial` and takes the connection it sends back.
func (n *Native) dial(ctx context.Context, req nativeDial, network string, raddr net.Addr) (net.Conn, bool, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		n.fallback("dial", programError{fmt.Errorf("socketpair: %w", err)})
		return nil, false, nil
	}
	mine, theirs := os.NewFile(uintptr(fds[0]), "dial"), os.NewFile(uintptr(fds[1]), "dial")
	defer mine.Close()
	b, err := n.execFiles(ctx, true, req, []*os.File{theirs}, "runtime", "dial")
	_ = theirs.Close()
	if err != nil {
		if ctx.Err() == nil {
			n.fallback("dial", err)
		}
		return nil, false, nil
	}
	var a struct {
		Connected bool    `json:"connected"`
		NotFound  bool    `json:"notFound"`
		Redo      *string `json:"redo"`
		Netns     *int    `json:"netns"`
		Setns     *int    `json:"setns"`
		Op        string  `json:"op"`
		Errno     int     `json:"errno"`
		Timeout   bool    `json:"timeout"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		n.fallback("dial", programError{fmt.Errorf("unreadable answer: %w", err)})
		return nil, false, nil
	}
	opErr := func(err error) error {
		return &net.OpError{Op: "dial", Net: network, Addr: raddr, Err: err}
	}
	switch {
	case a.Connected:
		conn, err := receiveConn(mine)
		if err != nil {
			n.fallback("dial", programError{err})
			return nil, false, nil
		}
		n.fallback("dial", nil)
		return conn, true, nil
	case a.Redo != nil:
		n.fallback("dial", nil)
		n.mu.Lock()
		n.standIn("dial")
		n.mu.Unlock()
		return nil, false, nil
	case a.NotFound:
		n.fallback("dial", nil)
		return nil, true, runtime.ErrNotFound
	case a.Netns != nil:
		n.fallback("dial", nil)
		return nil, true, &nsError{syscall.Errno(*a.Netns)}
	case a.Setns != nil:
		n.fallback("dial", nil)
		return nil, true, syscall.Errno(*a.Setns)
	case a.Op != "":
		n.fallback("dial", nil)
		return nil, true, opErr(os.NewSyscallError(a.Op, syscall.Errno(a.Errno)))
	case a.Timeout:
		n.fallback("dial", nil)
		if err := ctx.Err(); err != nil {
			return nil, true, err
		}
		return nil, true, opErr(os.ErrDeadlineExceeded)
	}
	n.fallback("dial", programError{fmt.Errorf("unreadable answer: %s", b)})
	return nil, false, nil
}

// receiveConn takes the connected socket armada-node sent on c.
func receiveConn(c *os.File) (net.Conn, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(int(c.Fd()), buf, oob, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("receive the connection: %w", err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		return nil, errors.New("receive the connection: no descriptor")
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
		return nil, errors.New("receive the connection: no descriptor")
	}
	f := os.NewFile(uintptr(fds[0]), "conn")
	defer f.Close()
	return net.FileConn(f)
}
