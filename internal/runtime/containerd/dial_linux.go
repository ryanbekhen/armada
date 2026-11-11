//go:build linux

package containerd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	goruntime "runtime"

	"github.com/vishvananda/netns"

	"github.com/ryanbekhen/armada/internal/runtime"
)

var _ runtime.ContainerDialer = (*Driver)(nil)

// DialContainer dials address from the network namespace of the running
// container id (ADR 0034). The socket is created on a thread switched into
// that namespace and keeps it afterwards, so the connection has exactly the
// container's routes and firewall. Only IP addresses are dialled: a name
// would be resolved, and a second address tried, on other threads.
func (d *Driver) DialContainer(ctx context.Context, id, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return nil, fmt.Errorf("dial from a container: %q is not an IP address", host)
	}
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
	default:
		return nil, fmt.Errorf("dial from a container: network %q", network)
	}
	c, err := d.client.LoadContainer(d.ctx(ctx), id)
	if err != nil {
		return nil, notFound(err)
	}
	t, err := c.Task(d.ctx(ctx), nil)
	if err != nil {
		return nil, notFound(err)
	}
	target, err := netns.GetFromPid(int(t.Pid()))
	if err != nil {
		return nil, fmt.Errorf("container network namespace: %w", err)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		defer target.Close()
		goruntime.LockOSThread()
		orig, err := netns.Get()
		if err != nil {
			goruntime.UnlockOSThread()
			done <- result{err: err}
			return
		}
		defer orig.Close()
		if err := netns.Set(target); err != nil {
			goruntime.UnlockOSThread()
			done <- result{err: err}
			return
		}
		var dl net.Dialer
		conn, err := dl.DialContext(ctx, network, address)
		if serr := netns.Set(orig); serr != nil {
			// The thread stays locked and ends with this goroutine, so no
			// other goroutine runs in the container's namespace.
			if conn != nil {
				_ = conn.Close()
			}
			done <- result{err: errors.Join(err, serr)}
			return
		}
		goruntime.UnlockOSThread()
		done <- result{conn: conn, err: err}
	}()
	select {
	case r := <-done:
		return r.conn, r.err
	case <-ctx.Done():
		go func() {
			if r := <-done; r.conn != nil {
				_ = r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}
