package clusternet

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/mdlayher/genetlink"
	mdnetlink "github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The kernel side of armada-node net apply (node/src/net/rtnl.rs,
// wgnl.rs) is compared with this package's without root: the netlink
// messages Go's libraries send for each call the agent makes, captured
// before they reach the kernel, against what armada-node encodes for the
// same call; what both read of this machine's interfaces, addresses,
// routes, and neighbour entries; and what both make of a WireGuard
// device's answer. Applying them is compared as root by
// TestIntegrationNetParity.

// captureRoute runs f on a netlink handle whose routing socket sends to a
// socket of the test's instead of the kernel (a NETLINK_USERSOCK pair,
// where unprivileged processes may send each other messages), and returns
// what it sent as hex with the sequence number and port ID zeroed. The
// test's socket answers, which the library refuses as not the kernel's, so
// a call ends after its first request.
func captureRoute(t *testing.T, f func(h *netlink.Handle) error) []string {
	t.Helper()
	cfd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_USERSOCK)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(cfd) }()
	if err := unix.Bind(cfd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptTimeval(cfd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5}); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(cfd)
	if err != nil {
		t.Fatal(err)
	}
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	us, err := nl.Subscribe(unix.NETLINK_USERSOCK)
	if err != nil {
		t.Fatal(err)
	}
	// The handle's socket, and where it sends, are unexported.
	lsa := reflect.ValueOf(us).Elem().FieldByName("lsa")
	(*unix.SockaddrNetlink)(unsafe.Pointer(lsa.UnsafeAddr())).Pid = sa.(*unix.SockaddrNetlink).Pid
	socks := reflect.ValueOf(h).Elem().FieldByName("sockets")
	(*(*map[int]*nl.SocketHandle)(unsafe.Pointer(socks.UnsafeAddr())))[unix.NETLINK_ROUTE] = &nl.SocketHandle{Socket: us}
	if err := h.SetSocketTimeout(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	called := make(chan error, 1)
	go func() { called <- f(h) }()
	var out []string
	buf := make([]byte, 1<<16)
	n, from, err := unix.Recvfrom(cfd, buf, 0)
	if err != nil {
		t.Fatalf("no message sent: %v", err)
	}
	msgs, err := splitMessages(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		clear(m[8:16])
		if typ := binary.NativeEndian.Uint16(m[4:]); typ >= unix.RTM_NEWNEIGH && typ <= unix.RTM_GETNEIGH && len(m) >= 20 {
			// Go sends its Ndmsg struct's padding as it finds it in
			// memory; the kernel ignores it.
			clear(m[17:20])
		}
		out = append(out, hex.EncodeToString(m))
	}
	ack := make([]byte, 36)
	binary.NativeEndian.PutUint32(ack, 36)
	binary.NativeEndian.PutUint16(ack[4:], unix.NLMSG_ERROR)
	copy(ack[8:12], buf[8:12])
	_ = unix.Sendto(cfd, ack, 0, from)
	if err := <-called; err == nil {
		t.Fatal("the call took the test's answer for the kernel's")
	}
	return out
}

// splitMessages splits a datagram into its messages.
func splitMessages(b []byte) ([][]byte, error) {
	var out [][]byte
	for len(b) >= unix.NLMSG_HDRLEN {
		l := int(binary.NativeEndian.Uint32(b))
		if l < unix.NLMSG_HDRLEN || l > len(b) {
			return nil, unix.EINVAL
		}
		out = append(out, slices.Clone(b[:l]))
		b = b[min(len(b), (l+3)&^3):]
	}
	return out, nil
}

// wgCapture is a WireGuard client of wgctrl's whose generic netlink
// connection answers from the test, and what it sent.
type wgCapture struct {
	c      *wgctrl.Client
	family uint16
	sent   []string
	// reply answers a request; nil acknowledges it.
	reply func(req mdnetlink.Message) []mdnetlink.Message
}

func newWGCapture(t *testing.T) *wgCapture {
	t.Helper()
	c, err := wgctrl.New()
	if err != nil {
		t.Skipf("wgctrl: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	w := &wgCapture{c: c}
	cs := reflect.ValueOf(c).Elem().FieldByName("cs")
	for i := range cs.Len() {
		e := cs.Index(i).Elem()
		if e.Type().String() != "*wglinux.Client" {
			continue
		}
		w.family = uint16(e.Elem().FieldByName("family").FieldByName("ID").Uint())
		f := e.Elem().FieldByName("c")
		conn := genetlink.NewConn(nltest.Dial(w.answer))
		reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(reflect.ValueOf(conn))
		return w
	}
	t.Skip("the kernel has no WireGuard family here")
	return nil
}

// answer records what the client sends and answers it.
func (w *wgCapture) answer(reqs []mdnetlink.Message) ([]mdnetlink.Message, error) {
	for _, m := range reqs {
		b, err := m.MarshalBinary()
		if err != nil {
			return nil, err
		}
		clear(b[8:16])
		w.sent = append(w.sent, hex.EncodeToString(b))
	}
	req := reqs[0]
	if w.reply != nil {
		out := w.reply(req)
		for i := range out {
			out[i].Header.Sequence, out[i].Header.PID = req.Header.Sequence, req.Header.PID
		}
		return nltest.Multipart(out)
	}
	return []mdnetlink.Message{{Header: mdnetlink.Header{Type: mdnetlink.Error, Sequence: req.Header.Sequence, PID: req.Header.PID}, Data: make([]byte, 4)}}, nil
}

// rtCall is one call of the agent's, as Go makes it and as armada-node
// net netlink encode reads it.
type rtCall struct {
	name string
	call func(h *netlink.Handle) error
	rust map[string]any
}

func ipNet(s string) *net.IPNet {
	p := netip.MustParsePrefix(s)
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func ip4(s string) net.IP { return netip.MustParseAddr(s).AsSlice() }

// rtCalls are the calls vxlan_linux.go, wireguard_linux.go,
// clusternet_linux.go, and switch_linux.go make, with the arguments they
// pass (and, for deletes, what the kernel answers a listing with).
func rtCalls() []rtCall {
	link := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 7, Name: Interface}}
	mac := vtepMAC(netip.MustParsePrefix("10.120.1.0/24"))
	addrJSON := func(a *netlink.Addr) map[string]any {
		ones, _ := a.Mask.Size()
		if a.Peer != nil {
			ones, _ = a.Peer.Mask.Size()
		}
		m := map[string]any{"IP": a.IP.String(), "Prefixlen": ones, "Flags": a.Flags, "Scope": a.Scope,
			"Valid": a.ValidLft, "Preferred": a.PreferedLft, "Label": a.Label}
		if a.Broadcast != nil {
			m["Broadcast"] = a.Broadcast.String()
		}
		if a.Peer != nil {
			m["Peer"] = a.Peer.IP.String()
		}
		return m
	}
	routeJSON := func(r *netlink.Route) map[string]any {
		m := map[string]any{"Family": r.Family, "Oif": r.LinkIndex, "Priority": r.Priority, "Table": r.Table,
			"Protocol": int(r.Protocol), "Scope": int(r.Scope), "Type": r.Type, "Flags": r.Flags, "Tos": r.Tos}
		if r.Dst != nil {
			ones, _ := r.Dst.Mask.Size()
			m["Dst"] = r.Dst.IP.String() + "/" + itoa(ones)
		}
		if r.Src != nil {
			m["Src"] = r.Src.String()
		}
		if r.Gw != nil {
			m["Gw"] = r.Gw.String()
		}
		return m
	}
	neighJSON := func(n *netlink.Neigh) map[string]any {
		m := map[string]any{"Index": n.LinkIndex, "Family": n.Family, "State": n.State, "Type": n.Type, "Flags": n.Flags,
			"IP": n.IP.String(), "FlagsExt": n.FlagsExt, "Vlan": n.Vlan, "VNI": n.VNI, "Master": n.MasterIndex}
		if n.HardwareAddr != nil {
			m["MAC"] = n.HardwareAddr.String()
		}
		return m
	}
	vx := &netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: Interface, MTU: 1450, HardwareAddr: mac}, VxlanId: vni,
		VtepDevIndex: 2, SrcAddr: ip4("10.0.0.1"), Port: VXLANPort, Learning: false}
	hostAddr := &netlink.Addr{IPNet: ipNet("10.120.1.0/32")}
	readAddr := &netlink.Addr{IPNet: ipNet("10.120.9.0/32"), Flags: 0x80, ValidLft: 0xffffffff, PreferedLft: 0xffffffff}
	wideAddr := &netlink.Addr{IPNet: ipNet("10.99.0.1/24"), Broadcast: ip4("10.99.0.255"), Label: "eth0", Flags: 0x480, Scope: 0}
	peerAddr := &netlink.Addr{IPNet: ipNet("10.99.0.1/32"), Peer: ipNet("10.99.0.2/24")}
	via := &netlink.Route{LinkIndex: 7, Dst: ipNet("10.120.2.0/24"), Scope: netlink.SCOPE_UNIVERSE, Gw: ip4("10.120.2.0"), Flags: int(netlink.FLAG_ONLINK)}
	onLink := &netlink.Route{LinkIndex: 7, Dst: ipNet("10.99.0.3/32"), Scope: netlink.SCOPE_LINK, Src: ip4("10.99.0.1")}
	probe := &netlink.Route{LinkIndex: 7, Dst: ipNet("10.120.2.0/32"), Scope: netlink.SCOPE_LINK}
	stale := &netlink.Route{Family: 2, LinkIndex: 7, Dst: ipNet("10.120.5.0/24"), Gw: ip4("10.120.5.0"), Table: 254,
		Protocol: 3, Scope: netlink.SCOPE_UNIVERSE, Type: 1, Flags: 4}
	staleDefault := &netlink.Route{Family: 2, LinkIndex: 7, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Gw: ip4("10.120.5.1"), Table: 254, Protocol: 4, Type: 1, Priority: 100}
	highTable := &netlink.Route{Family: 2, LinkIndex: 7, Dst: ipNet("10.120.6.0/24"), Table: 300, Protocol: 3, Scope: netlink.SCOPE_LINK, Type: 1, Src: ip4("10.99.0.1")}
	fdb := &netlink.Neigh{LinkIndex: 7, Family: unix.AF_BRIDGE, Flags: netlink.NTF_SELF, State: netlink.NUD_PERMANENT,
		IP: ip4("10.0.0.2"), HardwareAddr: mac}
	neigh := &netlink.Neigh{LinkIndex: 7, Family: netlink.FAMILY_V4, State: netlink.NUD_PERMANENT, IP: ip4("10.120.2.0"), HardwareAddr: mac}
	readFDB := &netlink.Neigh{LinkIndex: 7, Family: unix.AF_BRIDGE, Flags: netlink.NTF_SELF, State: netlink.NUD_PERMANENT | netlink.NUD_NOARP,
		Type: 1, IP: ip4("10.0.0.9"), HardwareAddr: mac, Vlan: 3, VNI: 7027, MasterIndex: 4, FlagsExt: 1}
	return []rtCall{
		{"LinkByName", func(h *netlink.Handle) error { _, err := h.LinkByName(Interface); return err },
			map[string]any{"Op": "LinkByName", "Name": Interface}},
		{"LinkByName long", func(h *netlink.Handle) error { _, err := h.LinkByName("an-interface-name-past-15"); return err },
			map[string]any{"Op": "LinkByName", "Name": "an-interface-name-past-15"}},
		{"LinkByIndex", func(h *netlink.Handle) error { _, err := h.LinkByIndex(7); return err },
			map[string]any{"Op": "LinkByIndex", "Index": 7}},
		{"LinkList", func(h *netlink.Handle) error { _, err := h.LinkList(); return err },
			map[string]any{"Op": "LinkList"}},
		{"LinkAdd vxlan", func(h *netlink.Handle) error { return h.LinkAdd(vx) },
			map[string]any{"Op": "AddVxlan", "Name": Interface, "MTU": 1450, "MAC": mac.String(), "VNI": vni, "Link": 2, "Local": "10.0.0.1", "Port": VXLANPort}},
		{"LinkAdd vxlan learning", func(h *netlink.Handle) error {
			return h.LinkAdd(&netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: Next}, VxlanId: vni, Learning: true})
		}, map[string]any{"Op": "AddVxlan", "Name": Next, "MTU": 0, "VNI": vni, "Port": 0, "Learning": true}},
		{"LinkAdd wireguard", func(h *netlink.Handle) error {
			return h.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: SiteInterface, MTU: 1420}})
		}, map[string]any{"Op": "AddWireguard", "Name": SiteInterface, "MTU": 1420}},
		{"LinkDel", func(h *netlink.Handle) error { return h.LinkDel(link) }, map[string]any{"Op": "LinkDel", "Index": 7}},
		{"LinkSetMTU", func(h *netlink.Handle) error { return h.LinkSetMTU(link, 1370) }, map[string]any{"Op": "SetMTU", "Index": 7, "MTU": 1370}},
		{"LinkSetUp", func(h *netlink.Handle) error { return h.LinkSetUp(link) }, map[string]any{"Op": "SetUp", "Index": 7}},
		{"LinkSetDown", func(h *netlink.Handle) error { return h.LinkSetDown(link) }, map[string]any{"Op": "SetDown", "Index": 7}},
		{"LinkSetName", func(h *netlink.Handle) error { return h.LinkSetName(link, Interface) }, map[string]any{"Op": "SetName", "Index": 7, "Name": Interface}},
		{"LinkSetHardwareAddr", func(h *netlink.Handle) error { return h.LinkSetHardwareAddr(link, mac) },
			map[string]any{"Op": "SetMAC", "Index": 7, "MAC": mac.String()}},
		{"AddrList", func(h *netlink.Handle) error { _, err := h.AddrList(nil, netlink.FAMILY_V4); return err },
			map[string]any{"Op": "AddrList", "Family": unix.AF_INET}},
		{"AddrReplace", func(h *netlink.Handle) error { return h.AddrReplace(link, hostAddr) },
			map[string]any{"Op": "AddrReplace", "Index": 7, "Addr": addrJSON(hostAddr)}},
		{"AddrReplace wide", func(h *netlink.Handle) error { return h.AddrReplace(link, &netlink.Addr{IPNet: ipNet("10.99.0.1/24")}) },
			map[string]any{"Op": "AddrReplace", "Index": 7, "Addr": map[string]any{"IP": "10.99.0.1", "Prefixlen": 24}}},
		{"AddrDel read", func(h *netlink.Handle) error { return h.AddrDel(link, readAddr) },
			map[string]any{"Op": "AddrDel", "Index": 7, "Addr": addrJSON(readAddr)}},
		{"AddrDel wide", func(h *netlink.Handle) error { return h.AddrDel(link, wideAddr) },
			map[string]any{"Op": "AddrDel", "Index": 7, "Addr": addrJSON(wideAddr)}},
		{"AddrDel peer", func(h *netlink.Handle) error { return h.AddrDel(link, peerAddr) },
			map[string]any{"Op": "AddrDel", "Index": 7, "Addr": addrJSON(peerAddr)}},
		{"RouteReplace via", func(h *netlink.Handle) error { return h.RouteReplace(via) },
			map[string]any{"Op": "RouteReplace", "Route": routeJSON(via)}},
		{"RouteReplace node", func(h *netlink.Handle) error { return h.RouteReplace(onLink) },
			map[string]any{"Op": "RouteReplace", "Route": routeJSON(onLink)}},
		{"RouteReplace probe", func(h *netlink.Handle) error { return h.RouteReplace(probe) },
			map[string]any{"Op": "RouteReplace", "Route": routeJSON(probe)}},
		{"RouteDel", func(h *netlink.Handle) error { return h.RouteDel(stale) },
			map[string]any{"Op": "RouteDel", "Route": routeJSON(stale)}},
		{"RouteDel default", func(h *netlink.Handle) error { return h.RouteDel(staleDefault) },
			map[string]any{"Op": "RouteDel", "Route": map[string]any{"Family": 2, "Dst": "0.0.0.0/0", "Gw": "10.120.5.1", "Oif": 7,
				"Table": 254, "Protocol": 4, "Type": 1, "Priority": 100}}},
		{"RouteDel table", func(h *netlink.Handle) error { return h.RouteDel(highTable) },
			map[string]any{"Op": "RouteDel", "Route": routeJSON(highTable)}},
		{"RouteList", func(h *netlink.Handle) error { _, err := h.RouteList(link, netlink.FAMILY_V4); return err },
			map[string]any{"Op": "RouteList", "Family": unix.AF_INET, "Index": 7}},
		{"RouteGet", func(h *netlink.Handle) error { _, err := h.RouteGet(ip4("203.0.113.9")); return err },
			map[string]any{"Op": "RouteGet", "Dst": "203.0.113.9"}},
		{"NeighSet forwarding", func(h *netlink.Handle) error { return h.NeighSet(fdb) },
			map[string]any{"Op": "NeighSet", "Neigh": neighJSON(fdb)}},
		{"NeighSet neighbour", func(h *netlink.Handle) error { return h.NeighSet(neigh) },
			map[string]any{"Op": "NeighSet", "Neigh": neighJSON(neigh)}},
		{"NeighDel read", func(h *netlink.Handle) error { return h.NeighDel(readFDB) },
			map[string]any{"Op": "NeighDel", "Neigh": neighJSON(readFDB)}},
		{"NeighList", func(h *netlink.Handle) error { _, err := h.NeighList(7, netlink.FAMILY_V4); return err },
			map[string]any{"Op": "NeighList", "Family": unix.AF_INET, "Index": 7}},
		{"NeighList bridge", func(h *netlink.Handle) error { _, err := h.NeighList(7, unix.AF_BRIDGE); return err },
			map[string]any{"Op": "NeighList", "Family": unix.AF_BRIDGE, "Index": 7}},
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// encodeNode asks armada-node for the messages of calls.
func encodeNode(t *testing.T, bin string, calls []map[string]any) [][]string {
	t.Helper()
	in, err := json.Marshal(calls)
	if err != nil {
		t.Fatal(err)
	}
	out, err := runNode(t, bin, in, "net", "netlink", "encode")
	if err != nil {
		t.Fatal(err)
	}
	var got [][]string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(calls) {
		t.Fatalf("armada-node answered %d calls of %d", len(got), len(calls))
	}
	return got
}

// armada-node must send the routing messages vishvananda/netlink sends for
// every call the agent makes. CI sets ARMADA_NODE_BIN (make node).
func TestArmadaNodeRouteMessagesMatchGo(t *testing.T) {
	bin := nodeBin(t)
	calls := rtCalls()
	var rust []map[string]any
	for _, c := range calls {
		rust = append(rust, c.rust)
	}
	got := encodeNode(t, bin, rust)
	for i, c := range calls {
		want := captureRoute(t, c.call)
		if !slices.Equal(got[i], want) {
			t.Errorf("%s:\n armada-node: %v\n Go:          %v", c.name, got[i], want)
		}
	}
}

// wgConfigJSON writes a wgtypes.Config as armada-node net netlink reads it.
func wgConfigJSON(cfg wgtypes.Config) map[string]any {
	m := map[string]any{}
	if cfg.PrivateKey != nil {
		m["PrivateKey"] = cfg.PrivateKey.String()
	}
	if cfg.ListenPort != nil {
		m["ListenPort"] = *cfg.ListenPort
	}
	peers := []map[string]any{}
	for _, p := range cfg.Peers {
		pm := map[string]any{"PublicKey": p.PublicKey.String(), "Remove": p.Remove, "ReplaceAllowedIPs": p.ReplaceAllowedIPs}
		if p.Endpoint != nil {
			pm["Endpoint"] = p.Endpoint.String()
		}
		if p.PersistentKeepaliveInterval != nil {
			pm["Keepalive"] = int(*p.PersistentKeepaliveInterval / time.Second)
		}
		ips := []string{}
		for _, n := range p.AllowedIPs {
			ips = append(ips, n.String())
		}
		pm["AllowedIPs"] = ips
		peers = append(peers, pm)
	}
	m["Peers"] = peers
	return m
}

// armada-node must send the generic netlink messages wgctrl sends: the
// family lookup, reading a device, and setting one, a large configuration
// split into batches as wgctrl splits it.
func TestArmadaNodeWireGuardMessagesMatchGo(t *testing.T) {
	bin := nodeBin(t)
	w := newWGCapture(t)
	key, peer, gone := newKey(t), newKey(t).PublicKey(), newKey(t).PublicKey()
	port := WireGuardPort
	ka := keepalive
	small := wgtypes.Config{PrivateKey: &key, ListenPort: &port, Peers: []wgtypes.PeerConfig{
		{PublicKey: peer, Endpoint: &net.UDPAddr{IP: ip4("203.0.113.2"), Port: WireGuardPort}, ReplaceAllowedIPs: true,
			AllowedIPs: []net.IPNet{*ipNet("10.99.0.2/32"), *ipNet("10.120.2.0/24")}, PersistentKeepaliveInterval: &ka},
		{PublicKey: gone, Remove: true},
	}}
	only := wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: peer, ReplaceAllowedIPs: true,
		AllowedIPs: []net.IPNet{*ipNet("10.120.2.0/24")}, PersistentKeepaliveInterval: &ka}}}
	large := wgtypes.Config{ListenPort: &port}
	for i := range 40 {
		pc := wgtypes.PeerConfig{PublicKey: newKey(t).PublicKey(), ReplaceAllowedIPs: true, PersistentKeepaliveInterval: &ka,
			Endpoint: &net.UDPAddr{IP: net.IPv4(10, 0, 1, byte(i)).To4(), Port: WireGuardPort}}
		ips := 1
		if i == 3 {
			ips = 300 // a relay carrying many subnets
		}
		for j := range ips {
			pc.AllowedIPs = append(pc.AllowedIPs, *ipNet(netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 120, byte(j), 0}), 24).String()))
		}
		large.Peers = append(large.Peers, pc)
	}
	type wgCase struct {
		name string
		do   func() error
		rust map[string]any
	}
	cases := []wgCase{
		{"GetFamily", func() error {
			_, err := genetlink.NewConn(nltest.Dial(func(reqs []mdnetlink.Message) ([]mdnetlink.Message, error) {
				if _, err := w.answer(reqs); err != nil {
					return nil, err
				}
				return nltest.Error(int(unix.ENOENT), reqs)
			})).GetFamily("wireguard")
			return err
		}, map[string]any{"Op": "WgFamily"}},
		{"Device", func() error { _, err := w.c.Device(Interface); return err },
			map[string]any{"Op": "WgGet", "Family": w.family, "Name": Interface}},
		{"ConfigureDevice", func() error { return w.c.ConfigureDevice(Interface, small) },
			map[string]any{"Op": "WgSet", "Family": w.family, "Name": Interface, "Config": wgConfigJSON(small)}},
		{"ConfigureDevice one peer", func() error { return w.c.ConfigureDevice(SiteInterface, only) },
			map[string]any{"Op": "WgSet", "Family": w.family, "Name": SiteInterface, "Config": wgConfigJSON(only)}},
		{"ConfigureDevice batches", func() error { return w.c.ConfigureDevice(Interface, large) },
			map[string]any{"Op": "WgSet", "Family": w.family, "Name": Interface, "Config": wgConfigJSON(large)}},
	}
	var rust []map[string]any
	for _, c := range cases {
		rust = append(rust, c.rust)
	}
	got := encodeNode(t, bin, rust)
	for i, c := range cases {
		w.sent = nil
		w.reply = func(req mdnetlink.Message) []mdnetlink.Message {
			if req.Header.Flags&mdnetlink.Dump == 0 {
				return []mdnetlink.Message{{Header: mdnetlink.Header{Type: mdnetlink.Error}, Data: make([]byte, 4)}}
			}
			return []mdnetlink.Message{{Header: mdnetlink.Header{Type: mdnetlink.Done}, Data: make([]byte, 4)}}
		}
		_ = c.do()
		if !slices.Equal(got[i], w.sent) {
			t.Errorf("%s:\n armada-node: %v\n Go:          %v", c.name, got[i], w.sent)
		}
	}
}

// deviceAnswer is a WireGuard device dump as the kernel writes it: the
// device in the first message, then more peers, one of them continued
// from the first message.
func deviceAnswer(t *testing.T, key wgtypes.Key, peers []wgtypes.Key) [][]byte {
	t.Helper()
	peer := func(ae *mdnetlink.AttributeEncoder, k wgtypes.Key, ep *net.UDPAddr, handshake time.Time, ips ...string) {
		ae.Bytes(unix.WGPEER_A_PUBLIC_KEY, k[:])
		ae.Bytes(unix.WGPEER_A_PRESHARED_KEY, make([]byte, 32))
		if ep != nil {
			var sa []byte
			if ep.IP.To4() != nil {
				sa = make([]byte, 16)
				binary.NativeEndian.PutUint16(sa, unix.AF_INET)
				copy(sa[4:], ep.IP.To4())
			} else {
				sa = make([]byte, 28)
				binary.NativeEndian.PutUint16(sa, unix.AF_INET6)
				copy(sa[8:], ep.IP.To16())
			}
			binary.BigEndian.PutUint16(sa[2:], uint16(ep.Port))
			ae.Bytes(unix.WGPEER_A_ENDPOINT, sa)
		}
		ae.Uint16(unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, 25)
		ts := make([]byte, 16)
		if !handshake.IsZero() {
			binary.NativeEndian.PutUint64(ts, uint64(handshake.Unix()))
			binary.NativeEndian.PutUint64(ts[8:], uint64(handshake.Nanosecond()))
		}
		ae.Bytes(unix.WGPEER_A_LAST_HANDSHAKE_TIME, ts)
		ae.Uint64(unix.WGPEER_A_RX_BYTES, 1234)
		ae.Uint64(unix.WGPEER_A_TX_BYTES, 5678)
		ae.Nested(unix.WGPEER_A_ALLOWEDIPS, func(nae *mdnetlink.AttributeEncoder) error {
			for i, s := range ips {
				p := netip.MustParsePrefix(s)
				nae.Nested(uint16(i), func(x *mdnetlink.AttributeEncoder) error {
					if p.Addr().Is4() {
						x.Uint16(unix.WGALLOWEDIP_A_FAMILY, unix.AF_INET)
					} else {
						x.Uint16(unix.WGALLOWEDIP_A_FAMILY, unix.AF_INET6)
					}
					x.Bytes(unix.WGALLOWEDIP_A_IPADDR, p.Addr().AsSlice())
					x.Uint8(unix.WGALLOWEDIP_A_CIDR_MASK, uint8(p.Bits()))
					return nil
				})
			}
			return nil
		})
		ae.Uint32(unix.WGPEER_A_PROTOCOL_VERSION, 1)
	}
	at := time.Unix(1_800_000_000, 500)
	first := mdnetlink.NewAttributeEncoder()
	first.Uint32(unix.WGDEVICE_A_IFINDEX, 7)
	first.String(unix.WGDEVICE_A_IFNAME, Interface)
	first.Bytes(unix.WGDEVICE_A_PRIVATE_KEY, key[:])
	pub := key.PublicKey()
	first.Bytes(unix.WGDEVICE_A_PUBLIC_KEY, pub[:])
	first.Uint16(unix.WGDEVICE_A_LISTEN_PORT, WireGuardPort)
	first.Uint32(unix.WGDEVICE_A_FWMARK, 0)
	first.Nested(unix.WGDEVICE_A_PEERS, func(nae *mdnetlink.AttributeEncoder) error {
		nae.Nested(0, func(ae *mdnetlink.AttributeEncoder) error {
			peer(ae, peers[0], &net.UDPAddr{IP: ip4("203.0.113.2"), Port: WireGuardPort}, at, "10.99.0.2/32", "10.120.2.0/24")
			return nil
		})
		nae.Nested(1, func(ae *mdnetlink.AttributeEncoder) error {
			peer(ae, peers[1], nil, time.Time{}, "10.120.3.0/24")
			return nil
		})
		return nil
	})
	more := mdnetlink.NewAttributeEncoder()
	more.String(unix.WGDEVICE_A_IFNAME, Interface)
	more.Nested(unix.WGDEVICE_A_PEERS, func(nae *mdnetlink.AttributeEncoder) error {
		nae.Nested(0, func(ae *mdnetlink.AttributeEncoder) error {
			peer(ae, peers[1], nil, time.Time{}, "10.120.4.0/24")
			return nil
		})
		nae.Nested(1, func(ae *mdnetlink.AttributeEncoder) error {
			peer(ae, peers[2], &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 40000}, at, "fd00::/64")
			return nil
		})
		return nil
	})
	var out [][]byte
	for _, ae := range []*mdnetlink.AttributeEncoder{first, more} {
		b, err := ae.Encode()
		if err != nil {
			t.Fatal(err)
		}
		g, err := (genetlink.Message{Header: genetlink.Header{Command: unix.WG_CMD_GET_DEVICE, Version: 1}, Data: b}).MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, g)
	}
	return out
}

// armada-node must read a WireGuard device's answer as wgctrl reads it:
// the keys, port, and every peer's endpoint, allowed IPs (merged across
// messages), keepalive, and last handshake.
func TestArmadaNodeWireGuardDeviceMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	w := newWGCapture(t)
	key := newKey(t)
	peers := []wgtypes.Key{newKey(t).PublicKey(), newKey(t).PublicKey(), newKey(t).PublicKey()}
	answer := deviceAnswer(t, key, peers)
	w.reply = func(mdnetlink.Message) []mdnetlink.Message {
		var out []mdnetlink.Message
		for _, b := range answer {
			out = append(out, mdnetlink.Message{Header: mdnetlink.Header{Type: mdnetlink.HeaderType(w.family)}, Data: b})
		}
		return append(out, mdnetlink.Message{Header: mdnetlink.Header{Type: mdnetlink.Done}, Data: make([]byte, 4)})
	}
	d, err := w.c.Device(Interface)
	if err != nil {
		t.Fatal(err)
	}
	type peerOut struct {
		PublicKey     string
		Endpoint      string
		AllowedIPs    []string
		Keepalive     int64
		LastHandshake int64
	}
	want := struct {
		PrivateKey string
		ListenPort int
		Peers      []peerOut
	}{PrivateKey: d.PrivateKey.String(), ListenPort: d.ListenPort, Peers: []peerOut{}}
	for _, p := range d.Peers {
		po := peerOut{PublicKey: p.PublicKey.String(), AllowedIPs: []string{}, Keepalive: int64(p.PersistentKeepaliveInterval / time.Second)}
		if p.Endpoint != nil {
			po.Endpoint = p.Endpoint.String()
		}
		for _, n := range p.AllowedIPs {
			po.AllowedIPs = append(po.AllowedIPs, n.String())
		}
		if !p.LastHandshakeTime.IsZero() {
			po.LastHandshake = p.LastHandshakeTime.Unix()
		}
		want.Peers = append(want.Peers, po)
	}
	var hexes []string
	for _, b := range answer {
		hexes = append(hexes, hex.EncodeToString(b))
	}
	in, err := json.Marshal(hexes)
	if err != nil {
		t.Fatal(err)
	}
	got, err := runNode(t, bin, in, "net", "netlink", "wg-parse")
	if err != nil {
		t.Fatal(err)
	}
	if w := canonicalJSON(want); string(got) != string(w) {
		t.Fatalf("armada-node and wgctrl read the device differently:\n armada-node: %s\n wgctrl:      %s", got, w)
	}
}

// The readings armada-node net netlink show prints.
type shownLink struct {
	Index int
	Name  string
	MTU   int
	MAC   string
	Kind  string
	Oper  int
	Vxlan *struct {
		ID       int
		Link     int
		Local    string
		Port     int
		Learning bool
	}
}

type shown struct {
	Links  []shownLink
	Addrs  []map[string]any
	Routes []map[string]any
	Neighs []map[string]any
}

// armada-node must read this machine's interfaces, IPv4 addresses, main
// table IPv4 routes, and lasting neighbour and forwarding entries as
// vishvananda/netlink reads them (no root needed to read them).
func TestArmadaNodeRouteReadingsMatchGo(t *testing.T) {
	bin := nodeBin(t)
	var got shown
	read := func() {
		out, err := runNode(t, bin, nil, "net", "netlink", "show")
		if err != nil {
			t.Fatal(err)
		}
		got = shown{}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatal(err)
		}
	}
	read()
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatal(err)
	}
	var want []shownLink
	for _, l := range links {
		a := l.Attrs()
		kind := l.Type()
		switch kind {
		case "device":
			kind = ""
		case "tuntap":
			kind = "tun"
		}
		sl := shownLink{Index: a.Index, Name: a.Name, MTU: a.MTU, MAC: a.HardwareAddr.String(), Kind: kind, Oper: int(a.OperState)}
		if v, ok := l.(*netlink.Vxlan); ok {
			sl.Vxlan = &struct {
				ID       int
				Link     int
				Local    string
				Port     int
				Learning bool
			}{v.VxlanId, v.VtepDevIndex, v.SrcAddr.String(), v.Port, v.Learning}
			if v.SrcAddr == nil {
				sl.Vxlan.Local = ""
			}
		}
		want = append(want, sl)
	}
	if g, w := canonicalJSON(got.Links), canonicalJSON(want); string(g) != string(w) {
		t.Errorf("links:\n armada-node: %s\n Go:          %s", g, w)
	}
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	var wantAddrs []map[string]any
	for _, a := range addrs {
		ones, _ := a.Mask.Size()
		if a.Peer != nil {
			ones, _ = a.Peer.Mask.Size()
		}
		m := map[string]any{"Index": a.LinkIndex, "Family": unix.AF_INET, "IP": a.IP.String(), "Prefixlen": ones, "Peer": "", "Broadcast": "",
			"Label": a.Label, "Flags": a.Flags, "Scope": a.Scope, "Valid": uint32(a.ValidLft), "Preferred": uint32(a.PreferedLft)}
		if a.Peer != nil {
			m["Peer"] = a.Peer.IP.String()
		}
		if a.Broadcast != nil {
			m["Broadcast"] = a.Broadcast.String()
		}
		wantAddrs = append(wantAddrs, m)
	}
	// Lifetimes count down between the two readings.
	mask := func(v []map[string]any) []map[string]any {
		for _, m := range v {
			for _, k := range []string{"Valid", "Preferred"} {
				if n, ok := m[k].(float64); ok && n != 0xffffffff {
					m[k] = "counting"
				}
				if n, ok := m[k].(uint32); ok && n != 0xffffffff {
					m[k] = "counting"
				}
			}
		}
		return v
	}
	if g, w := canonicalJSON(mask(got.Addrs)), canonicalJSON(mask(roundTrip(t, wantAddrs))); string(g) != string(w) {
		t.Errorf("addresses:\n armada-node: %s\n Go:          %s", g, w)
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	var wantRoutes []map[string]any
	for _, r := range routes {
		m := map[string]any{"Family": r.Family, "Dst": "", "Src": "", "Gw": "", "Oif": r.LinkIndex, "Priority": r.Priority, "Table": r.Table,
			"Protocol": int(r.Protocol), "Scope": int(r.Scope), "Type": r.Type, "Flags": r.Flags, "Tos": r.Tos}
		if r.Dst != nil {
			ones, _ := r.Dst.Mask.Size()
			m["Dst"] = r.Dst.IP.String() + "/" + itoa(ones)
		}
		if r.Src != nil {
			m["Src"] = r.Src.String()
		}
		if r.Gw != nil {
			m["Gw"] = r.Gw.String()
		}
		wantRoutes = append(wantRoutes, m)
	}
	if g, w := canonicalJSON(got.Routes), canonicalJSON(roundTrip(t, wantRoutes)); string(g) != string(w) {
		t.Errorf("routes:\n armada-node: %s\n Go:          %s", g, w)
	}
	var wantNeighs []map[string]any
	for _, fam := range []int{netlink.FAMILY_V4, unix.AF_BRIDGE} {
		ns, err := netlink.NeighList(0, fam)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range ns {
			m := map[string]any{"Index": n.LinkIndex, "Family": n.Family, "State": n.State, "Type": n.Type, "Flags": n.Flags,
				"IP": "", "MAC": n.HardwareAddr.String(), "LLIP": "", "FlagsExt": n.FlagsExt, "Vlan": n.Vlan, "VNI": n.VNI, "Master": n.MasterIndex}
			if len(n.IP) > 0 {
				m["IP"] = n.IP.String()
			}
			if n.LLIPAddr != nil {
				m["LLIP"] = n.LLIPAddr.String()
			}
			wantNeighs = append(wantNeighs, m)
		}
	}
	// Only lasting entries: the others change state between readings.
	lasting := func(v []map[string]any) []string {
		var out []string
		for _, m := range v {
			if st, _ := m["State"].(float64); int(st)&(netlink.NUD_PERMANENT|netlink.NUD_NOARP) != 0 {
				out = append(out, string(canonicalJSON(m)))
			}
		}
		slices.Sort(out)
		return out
	}
	if g, w := lasting(got.Neighs), lasting(roundTrip(t, wantNeighs)); !slices.Equal(g, w) {
		t.Errorf("neighbour entries:\n armada-node: %s\n Go:          %s", strings.Join(g, "\n"), strings.Join(w, "\n"))
	}
}

// roundTrip passes v through JSON, so numbers compare as armada-node's do.
func roundTrip(t *testing.T, v []map[string]any) []map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
