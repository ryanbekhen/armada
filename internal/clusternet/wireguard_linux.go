//go:build linux

package clusternet

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// staleHandshake is how old a peer's last handshake may be before doctor
// reports it: sessions are renewed every two minutes while they carry
// traffic, which the keepalive provides.
const staleHandshake = 3 * time.Minute

// wireguard creates or repairs the WireGuard interface, its peers, and the
// routes to their subnets.
func (n *Net) wireguard(p plan, mtu int) error {
	link, err := n.wgDevice(mtu)
	if err != nil {
		return err
	}
	if err := setUp(link, p, mtu); err != nil {
		return err
	}
	if err := n.wgPeers(p); err != nil {
		return err
	}
	return syncRoutes(link, p, false)
}

// wgDevice returns the WireGuard interface, creating it in the kernel, or
// in userspace inside the agent when the kernel has no WireGuard.
func (n *Net) wgDevice(mtu int) (netlink.Link, error) {
	link, err := existing()
	if err != nil {
		return nil, err
	}
	if link != nil {
		if _, ok := link.(*netlink.Wireguard); ok || n.user != nil {
			return link, nil
		}
		n.log.Info("replacing the cluster network interface", "interface", Interface)
		if err := netlink.LinkDel(link); err != nil {
			return nil, fmt.Errorf("remove %s: %w", Interface, err)
		}
	}
	if n.user != nil {
		// The userspace device's interface went away: start it again.
		n.user.close()
		n.user = nil
	}
	err = netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: Interface, MTU: mtu}})
	switch {
	case err == nil:
	case errors.Is(err, unix.EOPNOTSUPP):
		u, err := startUserDevice(mtu, n.log)
		if err != nil {
			return nil, fmt.Errorf("the kernel has no WireGuard, and the userspace device failed: %w", err)
		}
		n.user = u
		n.log.Warn("the kernel has no WireGuard; it runs in userspace inside the agent, which is markedly slower")
	default:
		return nil, fmt.Errorf("create %s: %w", Interface, err)
	}
	return netlink.LinkByName(Interface)
}

// userSocket is where the userspace device serves its control socket.
const userSocket = "/var/run/wireguard/" + Interface + ".sock"

// userDevice is WireGuard in userspace, serving the usual control socket
// (root only) so the agent and armadad doctor configure and read it as they
// do the kernel's.
type userDevice struct {
	dev  *device.Device
	uapi net.Listener
}

func startUserDevice(mtu int, log *slog.Logger) (*userDevice, error) {
	t, err := tun.CreateTUN(Interface, mtu)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(t, conn.NewDefaultBind(), deviceLogger(log))
	f, err := ipc.UAPIOpen(Interface)
	if err != nil {
		dev.Close()
		return nil, err
	}
	l, err := ipc.UAPIListen(Interface, f)
	if err != nil {
		dev.Close()
		return nil, err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go dev.IpcHandle(c)
		}
	}()
	if err := dev.Up(); err != nil {
		_ = l.Close()
		dev.Close()
		return nil, err
	}
	return &userDevice{dev: dev, uapi: l}, nil
}

func (u *userDevice) close() {
	_ = u.uapi.Close()
	u.dev.Close()
}

// wgPeers gives the device the node's key and port and one peer per other
// node, allowed exactly that node's subnet. It changes only what differs,
// so sessions survive every pass.
func (n *Net) wgPeers(p plan) error {
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	d, err := c.Device(Interface)
	if err != nil {
		return fmt.Errorf("read %s: %w", Interface, err)
	}
	cfg := peerChanges(d, n.cfg.Key.k, p.peers)
	if cfg == nil {
		return nil
	}
	if err := c.ConfigureDevice(Interface, *cfg); err != nil {
		return fmt.Errorf("configure %s: %w", Interface, err)
	}
	return nil
}

// diagnoseWireGuard reports whether the kernel has WireGuard and whether
// every peer has a recent handshake.
func diagnoseWireGuard(ip netip.Addr) []Check {
	var out []Check
	add := func(name string, level int, format string, args ...any) {
		out = append(out, Check{Name: name, Level: level, Detail: fmt.Sprintf(format, args...)})
	}
	if kernelHas("wireguard") {
		add("wireguard", CheckOK, "the kernel has WireGuard")
	} else {
		add("wireguard", CheckWarn, "the kernel has no WireGuard: the agent runs it in userspace, which is markedly slower; install a kernel with WireGuard")
	}
	c, err := wgctrl.New()
	if err != nil {
		add("network", CheckFail, "WireGuard control: %v", err)
		return out
	}
	defer func() { _ = c.Close() }()
	d, err := c.Device(Interface)
	if err != nil {
		add("network", CheckWarn, "%s is not set up yet; the agent creates it once connected", Interface)
		return out
	}
	now := time.Now()
	var stale []string
	for _, pe := range d.Peers {
		if pe.LastHandshakeTime.IsZero() || now.Sub(pe.LastHandshakeTime) > staleHandshake {
			ep := "no endpoint"
			if pe.Endpoint != nil {
				ep = pe.Endpoint.IP.String()
			}
			stale = append(stale, ep)
		}
	}
	slices.Sort(stale)
	if len(stale) > 0 {
		add("network", CheckFail, "%d of %d peer(s) have no recent handshake: %v; allow UDP %d between the nodes", len(stale), len(d.Peers), stale, WireGuardPort)
		return out
	}
	add("network", CheckOK, "%s (%s) has a recent handshake with all %d peer(s) (UDP %d on %s, open it to the other nodes)", Interface, d.Type, len(d.Peers), WireGuardPort, ip)
	return out
}
