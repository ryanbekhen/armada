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
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wireguard creates or repairs the WireGuard interface name, its peers,
// and the routes r asks for. Only the wireguard mode's own interface may
// fall back to the userspace device: the mesh must be up before the agent,
// and a switch's target interface is renamed when the switch is done
// (ADR 0050), which the userspace device's control socket would not follow.
func (n *Net) wireguard(p plan, mode, name string, mtu int, r routeSet) error {
	link, err := n.wgDevice(name, mtu, mode == ModeWireGuard && name == Interface)
	if err != nil {
		return err
	}
	if err := setUp(link, p, mtu); err != nil {
		return err
	}
	if err := n.wgPeers(name, mode, p.peers); err != nil {
		return err
	}
	return syncRoutes(link, p, false, r)
}

// errNoKernelWireGuard is the mesh mode's refusal of the userspace device:
// the mesh must be up before the agent that would hold it runs.
var errNoKernelWireGuard = errors.New("the kernel has no WireGuard, which the mesh network mode needs (the userspace device lives inside the agent, and the mesh must be up before it starts); use a kernel with WireGuard (Linux 5.6 or later)")

// errSwitchNeedsKernel refuses a switch to the wireguard mode on a node
// without the kernel's WireGuard (ADR 0050).
var errSwitchNeedsKernel = errors.New("the kernel has no WireGuard, which switching a running cluster to the wireguard mode needs; use a kernel with WireGuard (Linux 5.6 or later), or remove this node first")

// wgDevice returns the WireGuard interface name, creating it in the kernel,
// or, when user allows it, in userspace inside the agent when the kernel
// has no WireGuard.
func (n *Net) wgDevice(name string, mtu int, user bool) (netlink.Link, error) {
	link, err := linkNamed(name)
	if err != nil {
		return nil, err
	}
	if link != nil {
		if _, ok := link.(*netlink.Wireguard); ok || name == Interface && n.user != nil {
			return link, nil
		}
		n.log.Info("replacing the cluster network interface", "interface", name)
		if err := n.delLink(link); err != nil {
			return nil, err
		}
	}
	if name == Interface && n.user != nil {
		// The userspace device's interface went away: start it again.
		n.user.close()
		n.user = nil
	}
	err = netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: mtu}})
	switch {
	case err == nil:
	case errors.Is(err, unix.EOPNOTSUPP) && name == Next:
		return nil, errSwitchNeedsKernel
	case errors.Is(err, unix.EOPNOTSUPP) && !user:
		return nil, errNoKernelWireGuard
	case errors.Is(err, unix.EOPNOTSUPP):
		u, err := startUserDevice(mtu, n.log)
		if err != nil {
			return nil, fmt.Errorf("the kernel has no WireGuard, and the userspace device failed: %w", err)
		}
		n.user = u
		n.log.Warn("the kernel has no WireGuard; it runs in userspace inside the agent, which is markedly slower")
	default:
		return nil, fmt.Errorf("create %s: %w", name, err)
	}
	return netlink.LinkByName(name)
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

// wgPeers gives the device name the node's key and port and one peer per
// other node with a key, allowed exactly that node's subnet. It changes
// only what differs, so sessions survive every pass.
func (n *Net) wgPeers(name, mode string, peers []peer) error {
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	d, err := c.Device(name)
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	keyed := slices.DeleteFunc(slices.Clone(peers), func(pe peer) bool { return pe.key == wgtypes.Key{} })
	cfg := peerChanges(d, n.cfg.Key.k, mode, keyed, time.Now())
	if cfg == nil {
		return nil
	}
	if err := c.ConfigureDevice(name, *cfg); err != nil {
		return fmt.Errorf("configure %s: %w", name, err)
	}
	return nil
}

// diagnoseWireGuard reports whether the kernel has WireGuard and whether
// every peer has a recent handshake.
func diagnoseWireGuard(mode string, ip netip.Addr) []Check {
	var out []Check
	add := func(name string, level int, format string, args ...any) {
		out = append(out, Check{Name: name, Level: level, Detail: fmt.Sprintf(format, args...)})
	}
	switch {
	case kernelHas("wireguard"):
		add("wireguard", CheckOK, "the kernel has WireGuard")
	case mode == ModeMesh:
		add("wireguard", CheckFail, "%v", errNoKernelWireGuard)
		return out
	default:
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
	if mode == ModeMesh {
		add("network", CheckOK, "%s (%s) has a recent handshake with all %d peer(s) (UDP %d, open it to every address)", Interface, d.Type, len(d.Peers), WireGuardPort)
		return out
	}
	add("network", CheckOK, "%s (%s) has a recent handshake with all %d peer(s) (UDP %d on %s, open it to the other nodes)", Interface, d.Type, len(d.Peers), WireGuardPort, ip)
	return out
}
