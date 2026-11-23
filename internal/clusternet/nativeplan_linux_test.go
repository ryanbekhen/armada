package clusternet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// netCase is one input of armada-node net plan (node/src/net): a network
// configuration seen from one node, with what the kernel would report.
type netCase struct {
	name      string
	cfg       *armadav1.NetworkConfig
	node      string
	ip        netip.Addr
	key       wgtypes.Key // the node's private key; zero for none
	local     map[netip.Addr]string
	locals    []localPrefix
	uplinkMTU int
	lineMTU   int
	remoteMTU int
	now       time.Time
	devices   map[string]*wgtypes.Device
	since     map[wgtypes.Key]wgPeerSeen
	staleDevs []*wgtypes.Device // with since, the input of stalePeers
}

// What armada-node net plan reads, as node/src/net/mod.rs documents it.
type netPlanRequest struct {
	Config    json.RawMessage
	Node      string
	PrivateIP netip.Addr
	Key       string
	Local     map[netip.Addr]string
	Locals    []netLocalIn
	UplinkMTU int
	LineMTU   int
	RemoteMTU int
	Now       int64
	Devices   map[string]netDeviceIn
	Stale     *netStaleIn
}

type netLocalIn struct{ Dev, Prefix string }

type netDeviceIn struct {
	PrivateKey string
	ListenPort int
	Peers      []netDevicePeerIn
}

type netDevicePeerIn struct {
	PublicKey     string
	Endpoint      string
	AllowedIPs    []string
	Keepalive     int64
	LastHandshake int64
}

type netStaleIn struct {
	Since   []netSeenIn
	Devices [][]netDevicePeerIn
}

type netSeenIn struct {
	Key   string
	Node  string
	Since int64
}

func keyText(k wgtypes.Key) string {
	if k == (wgtypes.Key{}) {
		return ""
	}
	return k.String()
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func devicePeerIn(pe wgtypes.Peer) netDevicePeerIn {
	in := netDevicePeerIn{PublicKey: pe.PublicKey.String(), AllowedIPs: []string{},
		Keepalive: int64(pe.PersistentKeepaliveInterval / time.Second), LastHandshake: unixOrZero(pe.LastHandshakeTime)}
	if pe.Endpoint != nil {
		in.Endpoint = pe.Endpoint.String()
	}
	for _, n := range pe.AllowedIPs {
		in.AllowedIPs = append(in.AllowedIPs, n.String())
	}
	return in
}

func (c netCase) request(t *testing.T) []byte {
	t.Helper()
	cfg, err := protojson.Marshal(c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := netPlanRequest{Config: cfg, Node: c.node, PrivateIP: c.ip, Key: keyText(c.key), Local: c.local,
		UplinkMTU: c.uplinkMTU, LineMTU: c.lineMTU, RemoteMTU: c.remoteMTU, Now: c.now.Unix()}
	for _, l := range c.locals {
		req.Locals = append(req.Locals, netLocalIn{Dev: l.dev, Prefix: l.prefix.String()})
	}
	if len(c.devices) > 0 {
		req.Devices = map[string]netDeviceIn{}
		for name, d := range c.devices {
			in := netDeviceIn{PrivateKey: keyText(d.PrivateKey), ListenPort: d.ListenPort}
			for _, pe := range d.Peers {
				in.Peers = append(in.Peers, devicePeerIn(pe))
			}
			req.Devices[name] = in
		}
	}
	if c.since != nil {
		req.Stale = &netStaleIn{}
		for k, s := range c.since {
			req.Stale.Since = append(req.Stale.Since, netSeenIn{Key: k.String(), Node: s.node, Since: s.since.Unix()})
		}
		for _, d := range c.staleDevs {
			var peers []netDevicePeerIn
			for _, pe := range d.Peers {
				peers = append(peers, devicePeerIn(pe))
			}
			req.Stale.Devices = append(req.Stale.Devices, peers)
		}
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The answer, as node/src/net/mod.rs writes it; every list is [] when
// empty, never null, except those that are null by design.
type netPeerOut struct {
	Node     string   `json:"node"`
	IP       string   `json:"ip"`
	Subnet   string   `json:"subnet"`
	Key      string   `json:"key"`
	Endpoint string   `json:"endpoint"`
	Site     string   `json:"site"`
	Remote   bool     `json:"remote"`
	NAT      bool     `json:"nat"`
	Relay    bool     `json:"relay"`
	Carried  []string `json:"carried"`
}

type netEndpointOut struct {
	Address string `json:"address"`
	App     string `json:"app"`
}

type netPlanOut struct {
	Mode           string           `json:"mode"`
	CIDR           string           `json:"cidr"`
	Mesh           string           `json:"mesh"`
	Meshed         bool             `json:"meshed"`
	SwitchTo       string           `json:"switchTo"`
	Step           string           `json:"step"`
	Self           netPeerOut       `json:"self"`
	Peers          []netPeerOut     `json:"peers"`
	Relayed        []netPeerOut     `json:"relayed"`
	Unreachable    []string         `json:"unreachable"`
	Relaying       [][2]string      `json:"relaying"`
	Endpoints      []netEndpointOut `json:"endpoints"`
	IsolateDefault bool             `json:"isolateDefault"`
	TCPPorts       []uint16         `json:"tcpPorts"`
}

type netMembersOut struct {
	App       string   `json:"app"`
	Addresses []string `json:"addresses"`
}

type netPolicyOut struct {
	CIDR     string          `json:"cidr"`
	Subnet   string          `json:"subnet"`
	Gateway  string          `json:"gateway"`
	Apps     []string        `json:"apps"`
	Members  []netMembersOut `json:"members"`
	Open     []string        `json:"open"`
	Nodes    []string        `json:"nodes"`
	TCPPorts []uint16        `json:"tcpPorts"`
}

type netRulesOut struct {
	In       [][]string `json:"in"`
	InJump   []string   `json:"inJump"`
	Mesh     [][]string `json:"mesh"`
	MeshJump []string   `json:"meshJump"`
	Forward  [][]string `json:"forward"`
	Spoof    [][]string `json:"spoof"`
	MSS      [][]string `json:"mss"`
	NAT      [][]string `json:"nat"`
}

type netRouteOut struct {
	Node string `json:"node"`
	Dst  string `json:"dst"`
	Via  string `json:"via"`
	Src  string `json:"src"`
}

type netNeighbourOut struct {
	Node   string `json:"node"`
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Tunnel string `json:"tunnel"`
}

type netPeerConfigOut struct {
	PublicKey         string   `json:"publicKey"`
	Remove            bool     `json:"remove"`
	Endpoint          string   `json:"endpoint"`
	ReplaceAllowedIPs bool     `json:"replaceAllowedIps"`
	AllowedIPs        []string `json:"allowedIps"`
	Keepalive         int64    `json:"keepalive"`
}

type netWireGuardOut struct {
	PrivateKey bool               `json:"privateKey"`
	ListenPort *int               `json:"listenPort"`
	Peers      []netPeerConfigOut `json:"peers"`
}

type netTransportOut struct {
	Name       string            `json:"name"`
	Mode       string            `json:"mode"`
	Routes     string            `json:"routes"`
	MTU        int               `json:"mtu"`
	Addresses  []string          `json:"addresses"`
	RouteList  []netRouteOut     `json:"routeList"`
	Neighbours []netNeighbourOut `json:"neighbours"`
	WireGuard  *netWireGuardOut  `json:"wireguard"`
}

type netCheckOut struct {
	Level  int    `json:"level"`
	Detail string `json:"detail"`
}

type netAnswer struct {
	Plan        netPlanOut        `json:"plan"`
	Local       []string          `json:"local"`
	Remote      []string          `json:"remote"`
	Tunnels     []string          `json:"tunnels"`
	WGInterface string            `json:"wgInterface"`
	Policy      netPolicyOut      `json:"policy"`
	Rules       netRulesOut       `json:"rules"`
	Transports  []netTransportOut `json:"transports"`
	Remove      []string          `json:"remove"`
	Relay       *netCheckOut      `json:"relay"`
	Shadowed    []string          `json:"shadowed"`
	Stale       []string          `json:"stale"`
	PublicKey   string            `json:"publicKey"`
}

func texts[T fmt.Stringer](v []T) []string {
	out := []string{}
	for _, x := range v {
		out = append(out, x.String())
	}
	return out
}

func orEmpty[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

func peerOut(pe peer) netPeerOut {
	o := netPeerOut{Node: pe.node, IP: pe.ip.String(), Subnet: pe.subnet.String(), Key: keyText(pe.key),
		Site: pe.site, Remote: pe.remote, NAT: pe.nat, Relay: pe.relay, Carried: texts(pe.carried)}
	if pe.endpoint.IsValid() {
		o.Endpoint = pe.endpoint.String()
	}
	return o
}

func peersOut(peers []peer) []netPeerOut {
	out := []netPeerOut{}
	for _, pe := range peers {
		out = append(out, peerOut(pe))
	}
	return out
}

func peerNames(peers []peer) []string {
	out := []string{}
	for _, pe := range peers {
		out = append(out, pe.node)
	}
	return out
}

// goTransport is one interface tunnel() sets up.
type goTransport struct {
	name, mode string
	p          plan
	set        routeSet
}

// goTransports are the interfaces tunnel() sets up for p, and those it
// removes (Next's handling by finishSwitch reads the kernel and is left
// out).
func goTransports(p plan) ([]goTransport, []string) {
	switch {
	case p.switching() && p.step == SwitchMove:
		return []goTransport{{Next, p.switchTo, p, routesAll}, {Interface, p.mode, p, routesNone}}, []string{}
	case p.switching():
		return []goTransport{{Interface, p.mode, p, routesAll}, {Next, p.switchTo, p, routesProbe}}, []string{}
	case p.mode != ModePlain:
		return []goTransport{{Interface, p.mode, p, routesAll}}, []string{SiteInterface}
	}
	var out []goTransport
	remove := []string{}
	if remote := p.remote(); len(remote) == 0 {
		remove = append(remove, SiteInterface)
	} else {
		out = append(out, goTransport{SiteInterface, ModeWireGuard, p.only(remote), routesAll})
	}
	if p.meshed {
		remove = append(remove, Interface)
	} else {
		out = append(out, goTransport{Interface, p.mode, p.only(p.local()), routesAll})
	}
	return out, remove
}

var routeSetNames = map[routeSet]string{routesAll: "all", routesProbe: "probe", routesNone: "none"}

func routeText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func (c netCase) transportOut(tr goTransport) netTransportOut {
	// transport's MTU: the uplink and remote MTUs stand in for what the
	// kernel reports (uplinkFor, remoteUplinkMTU).
	uplink := c.uplinkMTU
	if encrypted(tr.mode) && len(tr.p.remote()) > 0 && c.remoteMTU > 0 {
		uplink = min(uplink, c.remoteMTU)
	}
	if c.lineMTU > 0 {
		uplink = min(uplink, c.lineMTU)
	}
	o := netTransportOut{Name: tr.name, Mode: tr.mode, Routes: routeSetNames[tr.set], MTU: TunnelMTU(tr.mode, uplink),
		RouteList: []netRouteOut{}, Neighbours: []netNeighbourOut{}}
	// setUp's addresses.
	addrs := []netip.Prefix{netip.PrefixFrom(vtepAddr(tr.p.self.subnet), 32)}
	if tr.p.mode == ModeMesh || tr.p.meshed {
		addrs = append(addrs, netip.PrefixFrom(tr.p.self.ip, 32))
	}
	o.Addresses = texts(addrs)
	for _, r := range wantRoutes(tr.p, !encrypted(tr.mode), tr.set) {
		o.RouteList = append(o.RouteList, netRouteOut{Node: r.node, Dst: r.dst.String(), Via: routeText(r.via), Src: routeText(r.src)})
	}
	if !encrypted(tr.mode) {
		// vxlanPeers' entries.
		for _, pe := range tr.p.peers {
			o.Neighbours = append(o.Neighbours, netNeighbourOut{Node: pe.node, IP: pe.ip.String(), MAC: vtepMAC(pe.subnet).String(), Tunnel: vtepAddr(pe.subnet).String()})
		}
		return o
	}
	// wgPeers.
	d := c.devices[tr.name]
	if d == nil {
		d = &wgtypes.Device{}
	}
	keyed := slices.DeleteFunc(slices.Clone(tr.p.peers), func(pe peer) bool { return pe.key == wgtypes.Key{} })
	cfg := peerChanges(d, c.key, tr.mode, keyed, c.now)
	if cfg == nil {
		return o
	}
	wg := &netWireGuardOut{PrivateKey: cfg.PrivateKey != nil, Peers: []netPeerConfigOut{}}
	if cfg.ListenPort != nil {
		port := *cfg.ListenPort
		wg.ListenPort = &port
	}
	var removed []netPeerConfigOut
	for _, pc := range cfg.Peers {
		po := netPeerConfigOut{PublicKey: pc.PublicKey.String(), Remove: pc.Remove, ReplaceAllowedIPs: pc.ReplaceAllowedIPs, AllowedIPs: []string{}}
		if pc.Endpoint != nil {
			po.Endpoint = pc.Endpoint.String()
		}
		for _, n := range pc.AllowedIPs {
			po.AllowedIPs = append(po.AllowedIPs, n.String())
		}
		if pc.PersistentKeepaliveInterval != nil {
			po.Keepalive = int64(*pc.PersistentKeepaliveInterval / time.Second)
		}
		if pc.Remove {
			removed = append(removed, po)
		} else {
			wg.Peers = append(wg.Peers, po)
		}
	}
	// Go lists removed peers in map order; both sides sort them by key.
	slices.SortFunc(removed, func(a, b netPeerConfigOut) int { return strings.Compare(a.PublicKey, b.PublicKey) })
	wg.Peers = append(wg.Peers, removed...)
	o.WireGuard = wg
	return o
}

// goNetPlan is the reference: what internal/clusternet makes of c.
func goNetPlan(c netCase) []byte {
	n := &Net{cfg: Config{Node: c.node, PrivateIP: c.ip, Key: PrivateKey{k: c.key}}}
	p, err := n.plan(c.cfg)
	if err != nil {
		return canonicalJSON(map[string]string{"error": err.Error()})
	}
	a := netAnswer{
		Plan: netPlanOut{Mode: p.mode, CIDR: p.cidr.String(), Meshed: p.meshed, SwitchTo: p.switchTo, Step: p.step,
			Self: peerOut(p.self), Peers: peersOut(p.peers), Relayed: peersOut(p.relayed), Unreachable: orEmpty(p.unreachable),
			Relaying: [][2]string{}, Endpoints: []netEndpointOut{}, IsolateDefault: p.isolateDefault, TCPPorts: orEmpty(p.tcpPorts)},
		Local: peerNames(p.local()), Remote: peerNames(p.remote()), Tunnels: tunnels(p), WGInterface: wgInterface(p),
		Shadowed: orEmpty(shadowed(p, c.locals)),
	}
	if p.mesh.IsValid() {
		a.Plan.Mesh = p.mesh.String()
	}
	for _, pair := range p.relaying {
		a.Plan.Relaying = append(a.Plan.Relaying, [2]string{pair[0].String(), pair[1].String()})
	}
	for _, ad := range slices.SortedFunc(maps.Keys(p.endpoints), netip.Addr.Compare) {
		a.Plan.Endpoints = append(a.Plan.Endpoints, netEndpointOut{Address: ad.String(), App: p.endpoints[ad]})
	}
	pol := buildPolicy(p, c.local)
	a.Policy = netPolicyOut{CIDR: pol.cidr.String(), Subnet: pol.subnet.String(), Gateway: pol.gateway.String(),
		Apps: orEmpty(pol.apps), Members: []netMembersOut{}, Open: texts(pol.open), Nodes: texts(pol.nodes), TCPPorts: orEmpty(pol.tcpPorts)}
	for _, app := range pol.apps {
		a.Policy.Members = append(a.Policy.Members, netMembersOut{App: app, Addresses: texts(pol.members[app])})
	}
	a.Rules = netRulesOut{In: inputRules(p, c.ip), InJump: inputJump(p), Forward: forwardRules(tunnels(p), p.relaying),
		Spoof: orEmpty(spoofRules(p)), MSS: orEmpty(mssRules(tunnels(p))), NAT: [][]string{}}
	if p.mode == ModeMesh || len(p.remote()) > 0 {
		a.Rules.Mesh, a.Rules.MeshJump = meshRules(p), []string{"-i", wgInterface(p), "-j", chainMesh}
	}
	for _, name := range tunnels(p) {
		a.Rules.NAT = append(a.Rules.NAT, []string{"-o", name, "-j", "RETURN"})
	}
	trs, remove := goTransports(p)
	a.Transports, a.Remove = []netTransportOut{}, remove
	for _, tr := range trs {
		a.Transports = append(a.Transports, c.transportOut(tr))
	}
	if chk, ok := relayCheck(p); ok {
		a.Relay = &netCheckOut{Level: chk.Level, Detail: chk.Detail}
	}
	if c.since != nil {
		a.Stale = orEmpty(stalePeers(c.staleDevs, c.since, c.now))
	}
	if c.key != (wgtypes.Key{}) {
		a.PublicKey = c.key.PublicKey().String()
	}
	return canonicalJSON(a)
}

func canonicalJSON(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimSpace(b.Bytes())
}

func runNode(t *testing.T, bin string, stdin []byte, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return bytes.TrimSpace(out), nil
}

func nodeBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		t.Skip("ARMADA_NODE_BIN is not set (make node)")
	}
	return bin
}

func newKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// namedNetCases are the configurations of this package's tests.
func namedNetCases(t *testing.T) []netCase {
	t.Helper()
	priv := newKey(t)
	at := func(name string, cfg *armadav1.NetworkConfig, node, ip string) netCase {
		return netCase{name: name, cfg: cfg, node: node, ip: netip.MustParseAddr(ip), key: priv, uplinkMTU: 1500}
	}
	var cases []netCase
	a := np("a", "10.0.0.1", "10.120.0.0/24")
	three := config(a, np("b", "10.0.0.2", "10.120.1.0/24"), np("c", "10.0.0.3", "10.120.2.0/24"))
	cases = append(cases, at("parse", three, "a", "10.0.0.1"), at("parse from b", three, "b", "10.0.0.2"),
		at("single", config(a), "a", "10.0.0.1"))
	noKey := at("parse without a key", three, "c", "10.0.0.3")
	noKey.key = wgtypes.Key{}
	cases = append(cases, noKey)
	refused := map[string]*armadav1.NetworkConfig{
		"unknown mode":       {Mode: "ipsec", ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{a}},
		"public CIDR":        {Mode: ModePlain, ClusterCidr: "8.8.0.0/16", Peers: []*armadav1.NetworkPeer{a}},
		"IPv6 CIDR":          {Mode: ModePlain, ClusterCidr: "fd00::/48", Peers: []*armadav1.NetworkPeer{a}},
		"CIDR not canonical": {Mode: ModePlain, ClusterCidr: "10.120.0.1/16", Peers: []*armadav1.NetworkPeer{a}},
		"not in list":        config(np("b", "10.0.0.2", "10.120.1.0/24")),
		"self elsewhere":     config(np("a", "10.0.0.9", "10.120.0.0/24")),
		"bad name":           config(a, np("B;rm", "10.0.0.2", "10.120.1.0/24")),
		"public peer":        config(a, np("b", "1.1.1.1", "10.120.1.0/24")),
		"loopback peer":      config(a, np("b", "127.0.0.1", "10.120.1.0/24")),
		"IPv6 peer":          config(a, np("b", "fd00::2", "10.120.1.0/24")),
		"mapped peer":        config(a, np("b", "::ffff:10.0.0.2", "10.120.1.0/24")),
		"zoned peer":         config(a, np("b", "fe80::1%eth0", "10.120.1.0/24")),
		"peer in CIDR":       config(a, np("b", "10.120.9.9", "10.120.1.0/24")),
		"subnet outside":     config(a, np("b", "10.0.0.2", "10.121.1.0/24")),
		"subnet too large":   config(a, np("b", "10.0.0.2", "10.120.0.0/23")),
		"subnet host bits":   config(a, np("b", "10.0.0.2", "10.120.1.5/24")),
		"default route":      config(a, np("b", "10.0.0.2", "0.0.0.0/0")),
		"duplicate subnet":   config(a, np("b", "10.0.0.2", "10.120.0.0/24")),
		"duplicate address":  config(a, np("b", "10.0.0.1", "10.120.1.0/24")),
		"duplicate name":     config(a, np("a", "10.0.0.2", "10.120.1.0/24")),
	}
	for _, name := range slices.Sorted(maps.Keys(refused)) {
		cases = append(cases, at(name, refused[name], "a", "10.0.0.1"))
	}
	many := config(a)
	for range maxPeers {
		many.Peers = append(many.Peers, a)
	}
	cases = append(cases, at("too many peers", many, "a", "10.0.0.1"))

	// The wireguard mode (TestParseWireGuard).
	ka, kb := key(t), key(t)
	withKey := func(p *armadav1.NetworkPeer, k wgtypes.Key) *armadav1.NetworkPeer {
		p = proto.Clone(p).(*armadav1.NetworkPeer)
		p.PublicKey = k.String()
		return p
	}
	wg := func(peers ...*armadav1.NetworkPeer) *armadav1.NetworkConfig {
		c := config(peers...)
		c.Mode = ModeWireGuard
		return c
	}
	cases = append(cases,
		at("wireguard", wg(withKey(np("a", "10.0.0.1", "10.120.0.0/24"), ka), withKey(np("b", "10.0.0.2", "10.120.1.0/24"), kb), np("c", "10.0.0.3", "10.120.2.0/24")), "a", "10.0.0.1"),
		at("bad key", wg(np("a", "10.0.0.1", "10.120.0.0/24"), &armadav1.NetworkPeer{Node: "b", PrivateIp: "10.0.0.2", Subnet: "10.120.1.0/24", PublicKey: "not-a-key"}), "a", "10.0.0.1"),
		at("zero key", wg(np("a", "10.0.0.1", "10.120.0.0/24"), withKey(np("b", "10.0.0.2", "10.120.1.0/24"), wgtypes.Key{})), "a", "10.0.0.1"),
		at("duplicate key", wg(withKey(np("a", "10.0.0.1", "10.120.0.0/24"), ka), withKey(np("b", "10.0.0.2", "10.120.1.0/24"), ka)), "a", "10.0.0.1"),
	)
	wgNoKey := cases[len(cases)-4]
	wgNoKey.name, wgNoKey.key = "wireguard without a key", wgtypes.Key{}
	cases = append(cases, wgNoKey)

	// The mesh mode (TestParseMesh, TestMeshRules).
	ma := meshPeer(t, "a", "10.121.0.1", "10.120.0.0/24", "")
	mb := meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "203.0.113.2")
	cases = append(cases, at("mesh", meshConfig(ma, mb, meshPeer(t, "c", "10.121.0.3", "10.120.2.0/24", "")), "a", "10.121.0.1"),
		at("mesh rules", meshConfig(meshPeer(t, "a", "10.121.0.1", "10.120.0.0/24", "203.0.113.1"), meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "203.0.113.2")), "a", "10.121.0.1"))
	meshRefused := map[string]*armadav1.NetworkConfig{
		"no mesh CIDR":        {Mode: ModeMesh, ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{ma}},
		"public mesh CIDR":    {Mode: ModeMesh, ClusterCidr: "10.120.0.0/16", MeshCidr: "8.8.0.0/16", Peers: []*armadav1.NetworkPeer{ma}},
		"overlapping CIDRs":   {Mode: ModeMesh, ClusterCidr: "10.120.0.0/16", MeshCidr: "10.0.0.0/8", Peers: []*armadav1.NetworkPeer{ma}},
		"mesh CIDR too small": {Mode: ModeMesh, ClusterCidr: "10.120.0.0/16", MeshCidr: "10.121.0.0/30", Peers: []*armadav1.NetworkPeer{ma}},
		"mesh not canonical":  {Mode: ModeMesh, ClusterCidr: "10.120.0.0/16", MeshCidr: "10.121.0.1/16", Peers: []*armadav1.NetworkPeer{ma}},
		"address outside":     meshConfig(ma, meshPeer(t, "b", "10.0.0.2", "10.120.1.0/24", "203.0.113.2")),
		"endpoint loopback":   meshConfig(ma, meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "127.0.0.1")),
		"endpoint multicast":  meshConfig(ma, meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "224.0.0.1")),
		"endpoint link-local": meshConfig(ma, meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "169.254.169.254")),
		"endpoint IPv6":       meshConfig(ma, meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "2001:db8::1")),
		"endpoint with port":  meshConfig(ma, meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "203.0.113.2:51820")),
		"endpoint in mesh":    meshConfig(ma, meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "10.121.0.9")),
		"endpoint in cluster": meshConfig(ma, meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "10.120.5.5")),
		"endpoint broadcast":  meshConfig(ma, meshPeer(t, "b", "10.121.0.2", "10.120.1.0/24", "255.255.255.255")),
	}
	for _, name := range slices.Sorted(maps.Keys(meshRefused)) {
		cases = append(cases, at(name, meshRefused[name], "a", "10.121.0.1"))
	}

	// Sites (TestParseSites, TestSiteRules, TestParseMeshAddresses,
	// TestMeshAddressRules, TestShadowed).
	sa := sitePeer(t, "a", "10.0.0.1", "10.120.0.0/24", "203.0.113.1", "")
	sb := sitePeer(t, "b", "10.0.0.2", "10.120.1.0/24", "", "")
	sc := sitePeer(t, "c", "10.5.0.3", "10.120.2.0/24", "203.0.113.3", "far")
	sd := sitePeer(t, "d", "10.5.0.4", "10.120.3.0/24", "", "far")
	se := &armadav1.NetworkPeer{Node: "e", PrivateIp: "10.5.0.5", Subnet: "10.120.4.0/24", Endpoint: "203.0.113.5", Site: "far"}
	sm := sitePeer(t, "m", "10.122.0.1", "10.120.5.0/24", "203.0.113.6", "cloud")
	sn := sitePeer(t, "n", "10.122.0.2", "10.120.6.0/24", "203.0.113.7", "cloud")
	for _, mode := range []string{ModePlain, ModeWireGuard} {
		sites := &armadav1.NetworkConfig{Mode: mode, ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{sa, sb, sc, sd, se}}
		meshed := &armadav1.NetworkConfig{Mode: mode, ClusterCidr: "10.120.0.0/16", MeshCidr: "10.122.0.0/16", Peers: []*armadav1.NetworkPeer{sa, sb, sm, sn}}
		cases = append(cases, at(mode+" sites", sites, "a", "10.0.0.1"), at(mode+" sites from c", sites, "c", "10.5.0.3"),
			at(mode+" mesh addresses", meshed, "a", "10.0.0.1"), at(mode+" mesh addresses from m", meshed, "m", "10.122.0.1"))
	}
	shadow := &armadav1.NetworkConfig{Mode: ModePlain, ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{
		sa, sb, sitePeer(t, "c", "192.168.1.7", "10.120.2.0/24", "203.0.113.3", "office"), sitePeer(t, "d", "10.9.0.4", "10.120.3.0/24", "203.0.113.4", "office")}}
	sh := at("shadowed", shadow, "a", "10.0.0.1")
	sh.locals = []localPrefix{{dev: "eth0", prefix: netip.MustParsePrefix("10.0.0.1/24")}, {dev: "wlan0", prefix: netip.MustParsePrefix("192.168.1.20/24")}, {dev: "tun0", prefix: netip.MustParsePrefix("10.9.0.4/32")}}
	sh2 := at("shadowed from the office", shadow, "c", "192.168.1.7")
	sh2.locals = []localPrefix{{dev: "eth0", prefix: netip.MustParsePrefix("10.0.5.9/16")}}
	cases = append(cases, sh, sh2,
		at("invalid site", &armadav1.NetworkConfig{Mode: ModePlain, ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{sa, sitePeer(t, "x", "10.0.0.9", "10.120.9.0/24", "203.0.113.9", "Far Away")}}, "a", "10.0.0.1"),
		at("switch with another site", &armadav1.NetworkConfig{Mode: ModePlain, ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{sa, sc}, SwitchTo: ModeWireGuard, SwitchStep: SwitchPrepare}, "a", "10.0.0.1"))
	for _, bad := range []string{"10.120.0.0/24", "8.8.0.0/16", "nope"} {
		cases = append(cases, at("mesh CIDR "+bad, &armadav1.NetworkConfig{Mode: ModePlain, ClusterCidr: "10.120.0.0/16", MeshCidr: bad, Peers: []*armadav1.NetworkPeer{sa, sb}}, "a", "10.0.0.1"))
	}

	// Nodes behind NAT and relays (nat_test.go).
	nat := natCluster(t)
	for _, from := range []struct{ node, ip string }{{"r1", "10.0.0.1"}, {"n1", "10.0.0.2"}, {"n2", "10.0.0.3"}, {"r2", "10.5.0.1"}, {"m1", "10.5.0.2"}, {"x", "10.5.0.4"}} {
		cases = append(cases, at("nat from "+from.node, nat, from.node, from.ip))
	}
	noR1 := natCluster(t)
	noR1.Peers[0].Relay = false
	noRelays := proto.Clone(noR1).(*armadav1.NetworkConfig)
	noRelays.Peers[3].Relay = false
	third := natCluster(t)
	home := sitePeer(t, "h1", "192.168.1.2", "10.120.7.0/24", "", "home")
	home.BehindNat = true
	office := sitePeer(t, "o1", "192.168.2.2", "10.120.8.0/24", "", "office")
	office.BehindNat = true
	third.Peers = append(third.Peers, home, office)
	natRelay := natCluster(t)
	natRelay.Peers[1].Relay = true
	natEndpoint := natCluster(t)
	natEndpoint.Peers[4].Endpoint = "203.0.113.9"
	cases = append(cases, at("relay fallback", noR1, "n1", "10.0.0.2"), at("no relay", noRelays, "n1", "10.0.0.2"),
		at("third site", third, "h1", "192.168.1.2"), at("third site relay", third, "r1", "10.0.0.1"),
		at("relay behind NAT", natRelay, "r1", "10.0.0.1"), at("endpoint behind NAT", natEndpoint, "r1", "10.0.0.1"))

	// Switches (TestParseSwitch, TestSwitchRules).
	two := []*armadav1.NetworkPeer{np("a", "10.0.0.1", "10.120.0.0/24"), np("b", "10.0.0.2", "10.120.1.0/24")}
	for _, s := range []struct{ mode, to, step string }{
		{ModePlain, ModeWireGuard, SwitchPrepare}, {ModePlain, ModeWireGuard, SwitchMove},
		{ModeWireGuard, ModePlain, SwitchPrepare}, {ModeWireGuard, ModePlain, SwitchMove},
		{ModePlain, ModePlain, SwitchPrepare}, {ModePlain, ModeMesh, SwitchPrepare}, {ModePlain, "ipsec", SwitchPrepare},
		{ModePlain, ModeWireGuard, "cleanup"}, {ModePlain, ModeWireGuard, ""}, {ModePlain, "", SwitchMove},
	} {
		cfg := &armadav1.NetworkConfig{Mode: s.mode, ClusterCidr: "10.120.0.0/16", Peers: two, SwitchTo: s.to, SwitchStep: s.step}
		cases = append(cases, at(fmt.Sprintf("switch %s to %s %s", s.mode, s.to, s.step), cfg, "a", "10.0.0.1"))
	}
	cases = append(cases, at("mesh switch", &armadav1.NetworkConfig{Mode: ModeMesh, ClusterCidr: "10.120.0.0/16", MeshCidr: "10.122.0.0/16", SwitchTo: ModeWireGuard, SwitchStep: SwitchPrepare}, "a", "10.122.0.1"))

	// TCP ports (TestParseTCPPorts).
	for _, ports := range [][]uint32{{6379, 5432, 6379}, {0}, {53}, {80}, {443}, {22}, {65536}, {1 << 31}, make([]uint32, maxTCPPorts+1), nil} {
		cfg := config(a)
		cfg.TcpPorts = ports
		cases = append(cases, at(fmt.Sprintf("tcp ports %v", ports[:min(len(ports), 3)]), cfg, "a", "10.0.0.1"))
	}

	// Container addresses and the policy (TestParseEndpoints,
	// TestBuildPolicy).
	eps := config(np("a", "10.0.0.1", "10.120.0.0/24"), np("b", "10.0.0.2", "10.120.1.0/24"))
	eps.Endpoints = []*armadav1.NetworkEndpoint{ep("10.120.0.5", "web"), ep("10.120.1.7", "api.shop"), ep("10.120.1.9", "web"), ep("10.120.1.9", "api.shop")}
	cases = append(cases, at("endpoints", eps, "a", "10.0.0.1"))
	for _, e := range []*armadav1.NetworkEndpoint{ep("10.121.0.5", "web"), ep("8.8.8.8", "web"), ep("10.120.1.0", "web"), ep("10.120.1.1", "web"),
		ep("10.120.1.255", "web"), ep("fd00::5", "web"), ep("10.120.1.5/32", "web"), ep("10.120.1.5", "Web;drop"), ep("10.120.1.5", "web.default"), ep("10.120.1.5", "canary--web")} {
		cfg := config(np("a", "10.0.0.1", "10.120.0.0/24"))
		cfg.Endpoints = []*armadav1.NetworkEndpoint{e}
		cases = append(cases, at("endpoint "+e.GetAddress()+" "+e.GetApp(), cfg, "a", "10.0.0.1"))
	}
	pol := config(np("a", "10.0.0.1", "10.120.0.0/24"), np("b", "10.0.0.2", "10.120.1.0/24"))
	pol.Endpoints = []*armadav1.NetworkEndpoint{ep("10.120.1.7", "api.shop"), ep("10.120.1.8", "web"), ep("10.120.0.9", "gone")}
	local := map[netip.Addr]string{netip.MustParseAddr("10.120.0.5"): "web", netip.MustParseAddr("10.120.0.6"): "api.shop",
		netip.MustParseAddr("10.120.1.99"): "web", netip.MustParseAddr("10.120.0.1"): "web", netip.MustParseAddr("10.120.0.7"): "Bad"}
	withLocal := at("policy", pol, "a", "10.0.0.1")
	withLocal.local = local
	emptyLocal := at("policy with no local containers", pol, "a", "10.0.0.1")
	emptyLocal.local = map[netip.Addr]string{}
	isolated := proto.Clone(pol).(*armadav1.NetworkConfig)
	isolated.IsolateDefault = true
	isoLocal := at("policy, default isolated", isolated, "a", "10.0.0.1")
	isoLocal.local = local
	cases = append(cases, withLocal, emptyLocal, isoLocal, at("policy without a local list", pol, "a", "10.0.0.1"))

	// MTUs: a line below the uplink, and a smaller uplink towards other
	// sites.
	m := at("mtu", &armadav1.NetworkConfig{Mode: ModePlain, ClusterCidr: "10.120.0.0/16", Peers: []*armadav1.NetworkPeer{sa, sb, sc}}, "a", "10.0.0.1")
	m.uplinkMTU, m.lineMTU, m.remoteMTU = 9000, 1492, 1400
	cases = append(cases, m)
	return cases
}

// randomNetCase builds a configuration of the kind the control plane sends,
// with the mistakes parse must refuse mixed in at random.
func randomNetCase(t *testing.T, r *rand.Rand, i int) netCase {
	t.Helper()
	pick := func(n int) bool { return r.IntN(n) == 0 }
	from := func(s ...string) string { return s[r.IntN(len(s))] }
	// Half the configurations carry mistakes, the other half none.
	noisy := pick(2)
	bad := func(n int) bool { return noisy && pick(n) }
	cfg := &armadav1.NetworkConfig{ClusterCidr: "10.120.0.0/16", IsolateDefault: pick(3)}
	switch n := r.IntN(20); {
	case n < 9:
		cfg.Mode = ModePlain
	case n < 15:
		cfg.Mode = ModeWireGuard
	default:
		cfg.Mode = ModeMesh
	}
	if bad(20) {
		cfg.Mode = from("ipsec", "", "Plain")
	}
	if bad(12) {
		cfg.ClusterCidr = from("10.120.0.1/16", "8.8.0.0/16", "10.120.0.0/25", "172.20.0.0/14", "10.120.0.0/016", "")
	}
	hasMesh := cfg.Mode == ModeMesh || pick(2)
	if hasMesh {
		cfg.MeshCidr = "10.122.0.0/16"
		if bad(12) {
			cfg.MeshCidr = from("10.120.0.0/24", "10.122.0.1/16", "nope", "10.122.0.0/28", "8.8.0.0/16", "")
		}
	}
	// Shapes: a switch between modes (one site, no mesh addresses), many
	// nodes behind NAT with this node a relay or behind NAT itself, or any
	// mix.
	shape := r.IntN(6)
	switching, natty := shape == 0 && cfg.Mode != ModeMesh, shape == 1 || shape == 2
	if switching {
		hasMesh, cfg.MeshCidr = false, ""
		cfg.SwitchTo, cfg.SwitchStep = ModePlain, from(SwitchPrepare, SwitchMove)
		if cfg.Mode == ModePlain {
			cfg.SwitchTo = ModeWireGuard
		}
	}
	if pick(30) || bad(5) {
		cfg.SwitchTo, cfg.SwitchStep = from(ModeMesh, "", ModePlain, ModeWireGuard), from("", "cleanup", SwitchMove, SwitchPrepare)
	}
	sites := []string{"", "", "", "far", "cloud"}
	if switching {
		sites = []string{""}
	}
	nodes := 1 + r.IntN(8)
	keys := map[int]wgtypes.Key{}
	for j := range nodes {
		site := sites[r.IntN(len(sites))]
		if bad(20) {
			site = from("Far", "-x", strings.Repeat("s", 64))
		}
		ip := fmt.Sprintf("10.0.0.%d", j+1)
		switch {
		case cfg.Mode == ModeMesh:
			ip = fmt.Sprintf("10.122.0.%d", j+1)
		case site == "far":
			ip = fmt.Sprintf("10.5.0.%d", j+1)
		case site == "cloud" && hasMesh && pick(2):
			ip = fmt.Sprintf("10.122.0.%d", j+1)
		case site == "cloud":
			ip = fmt.Sprintf("192.168.%d.2", j+1)
		}
		if bad(20) {
			ip = from("1.1.1.1", "::ffff:10.0.0.9", fmt.Sprintf("fd00::%d", j+1), "010.0.0.1", "127.0.0.1", "10.120.9.9", "100.64.0.9", "fe80::1%eth0", "")
		}
		pe := &armadav1.NetworkPeer{Node: fmt.Sprintf("n%d", j), PrivateIp: ip, Subnet: fmt.Sprintf("10.120.%d.0/24", j), Site: site}
		if bad(20) {
			pe.Node = from("N1", "", "a--b", "n0", strings.Repeat("n", 64), "b;rm")
		}
		if bad(20) {
			pe.Subnet = from("10.120.1.5/24", "10.120.0.0/24", "10.121.0.0/24", "10.120.0.0/23", "fd00::/24", "x")
		}
		switch n := r.IntN(100); {
		case n < 85:
			k := newKey(t).PublicKey()
			if bad(15) && len(keys) > 0 {
				k = keys[r.IntN(len(keys))]
			}
			keys[len(keys)] = k
			pe.PublicKey = k.String()
		case n < 88 && noisy:
			pe.PublicKey = from("not-a-key", wgtypes.Key{}.String(), "YQ==")
		}
		if !pick(3) {
			pe.Endpoint = fmt.Sprintf("203.0.113.%d", j+1)
			if bad(15) {
				pe.Endpoint = from("127.0.0.1", "10.120.5.5", "224.0.0.1", "203.0.113.1:51820", "10.122.0.99", "0.0.0.0", "2001:db8::1")
			}
		}
		pe.BehindNat = pick(5) || natty && pick(2)
		if pe.BehindNat && pick(3) {
			pe.Endpoint = ""
		}
		pe.Relay = !pe.BehindNat && pe.Endpoint != "" && pick(3) || bad(30)
		cfg.Peers = append(cfg.Peers, pe)
	}
	self := r.IntN(nodes)
	switch sp := cfg.Peers[self]; {
	case natty:
		// This node relays for its site, or sits behind NAT.
		sp.BehindNat, sp.Relay = shape == 2, shape == 1
		if sp.Relay && sp.Endpoint == "" {
			sp.Endpoint = fmt.Sprintf("203.0.113.%d", self+1)
		}
	case shape == 3 && hasMesh && cfg.Mode != ModeMesh:
		// This node has no private network: a mesh address.
		sp.Site, sp.PrivateIp = "cloud", fmt.Sprintf("10.122.0.%d", self+1)
	}
	for range r.IntN(7) {
		addr := fmt.Sprintf("10.120.%d.%d", r.IntN(nodes+1), 2+r.IntN(5))
		if bad(8) {
			addr = from("10.120.0.1", "10.120.0.255", "10.121.0.5", "fd00::5", "x")
		}
		cfg.Endpoints = append(cfg.Endpoints, &armadav1.NetworkEndpoint{Address: addr, App: from("web", "api.shop", "db.staging", "web", "api.shop")})
		if bad(15) {
			cfg.Endpoints[len(cfg.Endpoints)-1].App = from("Web;x", "web.default", "")
		}
	}
	for range r.IntN(4) {
		port := uint32(from2(r, 5432, 6379, 9000, 3306))
		if bad(10) {
			port = uint32(from2(r, 0, 53, 51820, 65536))
		}
		cfg.TcpPorts = append(cfg.TcpPorts, port)
	}
	c := netCase{name: fmt.Sprintf("random %d", i), cfg: cfg, node: fmt.Sprintf("n%d", self), uplinkMTU: from2(r, 1500, 1450, 9000),
		now: time.Unix(1_800_000_000, 0), key: newKey(t)}
	c.ip, _ = netip.ParseAddr(cfg.Peers[self].GetPrivateIp())
	if bad(10) {
		c.ip = netip.MustParseAddr("10.0.0.99")
	}
	if bad(8) {
		c.key = wgtypes.Key{}
	}
	if pick(4) {
		c.lineMTU = from2(r, 1492, 1400)
	}
	if pick(3) {
		c.remoteMTU = from2(r, 1400, 1300)
	}
	if !pick(3) {
		c.local = map[netip.Addr]string{}
		for range r.IntN(5) {
			a := netip.MustParseAddr(fmt.Sprintf("10.120.%d.%d", self, 1+r.IntN(9)))
			if pick(6) {
				a = netip.MustParseAddr(from("10.120.7.7", "fd00::7", "10.120.0.255"))
			}
			c.local[a] = from("web", "api.shop", "db.staging", "Bad", "web.default")
		}
	}
	for range r.IntN(3) {
		c.locals = append(c.locals, localPrefix{dev: from("eth0", "wlan0", "tun0"),
			prefix: netip.MustParsePrefix(from("10.0.0.1/24", "192.168.1.20/24", "10.5.0.9/16", "10.9.0.4/32", "203.0.113.1/24", "10.122.0.5/16", "10.0.0.0/8"))})
	}
	// WireGuard devices near what the plan wants: matching, roamed,
	// stale, with peers that left.
	n := &Net{cfg: Config{Node: c.node, PrivateIP: c.ip, Key: PrivateKey{k: c.key}}}
	p, err := n.plan(cfg)
	if err != nil {
		return c
	}
	trs, _ := goTransports(p)
	c.devices = map[string]*wgtypes.Device{}
	for _, tr := range trs {
		if !encrypted(tr.mode) || pick(3) {
			continue
		}
		keyed := slices.DeleteFunc(slices.Clone(tr.p.peers), func(pe peer) bool { return pe.key == wgtypes.Key{} })
		want := peerChanges(&wgtypes.Device{}, c.key, tr.mode, keyed, c.now)
		d := &wgtypes.Device{PrivateKey: c.key, ListenPort: WireGuardPort}
		if pick(5) {
			d.PrivateKey = newKey(t)
		}
		if pick(5) {
			d.ListenPort = 0
		}
		for _, pc := range want.Peers {
			if pick(5) {
				continue
			}
			pe := wgtypes.Peer{PublicKey: pc.PublicKey, Endpoint: pc.Endpoint, AllowedIPs: slices.Clone(pc.AllowedIPs),
				PersistentKeepaliveInterval: keepalive, LastHandshakeTime: c.now.Add(-time.Duration(r.IntN(400)) * time.Second)}
			if pick(4) {
				pe.Endpoint = &net.UDPAddr{IP: net.ParseIP("198.51.100.7").To4(), Port: 40000}
			}
			if pick(6) {
				pe.LastHandshakeTime = time.Time{}
			}
			if pick(6) {
				slices.Reverse(pe.AllowedIPs)
			}
			if pick(8) {
				pe.AllowedIPs = pe.AllowedIPs[:1]
			}
			if pick(8) {
				pe.PersistentKeepaliveInterval = 0
			}
			d.Peers = append(d.Peers, pe)
		}
		for range r.IntN(3) {
			d.Peers = append(d.Peers, wgtypes.Peer{PublicKey: newKey(t).PublicKey()})
		}
		c.devices[tr.name] = d
	}
	if pick(2) {
		c.since = map[wgtypes.Key]wgPeerSeen{}
		dev := &wgtypes.Device{}
		for _, pe := range p.peers {
			if pe.key == (wgtypes.Key{}) {
				continue
			}
			if !pick(4) {
				c.since[pe.key] = wgPeerSeen{node: pe.node, since: c.now.Add(-time.Duration(r.IntN(600)) * time.Second)}
			}
			hp := wgtypes.Peer{PublicKey: pe.key, LastHandshakeTime: c.now.Add(-time.Duration(r.IntN(400)) * time.Second)}
			if pick(4) {
				hp.LastHandshakeTime = time.Time{}
			}
			dev.Peers = append(dev.Peers, hp)
		}
		c.staleDevs = []*wgtypes.Device{dev, {Peers: slices.Clone(dev.Peers)}}
	}
	return c
}

func from2(r *rand.Rand, v ...int) int { return v[r.IntN(len(v))] }

// armada-node net plan (node/src/net) must plan what this package plans,
// error texts included. CI sets ARMADA_NODE_BIN (make node).
func TestArmadaNodeNetPlanMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	// What the valid plans exercised, by a mark in their answer.
	marks := []string{`"remote":true`, `"nat":true`, `"relaying":[[`, `"relayed":[{`, `"unreachable":["`, `"meshed":true`,
		`"switchTo":"wireguard"`, `"switchTo":"plain"`, `"mode":"mesh"`, `"wireguard":{`, `"remove":true`, `"stale":[`, `"open":["`}
	seen := map[string]int{}
	check := func(c netCase) bool {
		t.Helper()
		got, err := runNode(t, bin, c.request(t), "net", "plan")
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		want := goNetPlan(c)
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: armada-node and Go differ:\n armada-node: %s\n Go:          %s", c.name, got, want)
		}
		if bytes.HasPrefix(want, []byte(`{"error"`)) {
			return false
		}
		for _, m := range marks {
			if bytes.Contains(want, []byte(m)) {
				seen[m]++
			}
		}
		return true
	}
	named := namedNetCases(t)
	for _, c := range named {
		check(c)
	}
	clear(seen)
	r := rand.New(rand.NewPCG(3, 4))
	const random = 600
	valid := 0
	for i := range random {
		if check(randomNetCase(t, r, i)) {
			valid++
		}
	}
	t.Logf("%d named cases and %d random configurations compared, %d of them valid", len(named), random, valid)
	if valid < random/4 || valid > random*9/10 {
		t.Fatalf("%d of %d random configurations were valid: the generator needs both kinds", valid, random)
	}
	for _, m := range marks {
		t.Logf("valid random plans with %s: %d", m, seen[m])
		if seen[m] < 5 {
			t.Errorf("only %d valid random plans have %s", seen[m], m)
		}
	}
}

// armada-node net key reads and writes network.key as LoadOrCreateKey and
// RotateKey do, and derives the same public key.
func TestArmadaNodeNetKeyMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	dir := t.TempDir()
	goPath := filepath.Join(dir, "go.key")
	k, err := LoadOrCreateKey(goPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := runNode(t, bin, nil, "net", "key", goPath); err != nil || string(got) != k.Public() {
		t.Fatalf("Go's key: armada-node %q, %v; Go %q", got, err, k.Public())
	}
	rustPath := filepath.Join(dir, "rust.key")
	pub, err := runNode(t, bin, nil, "net", "key", rustPath)
	if err != nil {
		t.Fatal(err)
	}
	if k, err := LoadOrCreateKey(rustPath); err != nil || k.Public() != string(pub) {
		t.Fatalf("armada-node's key: Go %v, %v; armada-node %q", k.Public(), err, pub)
	}
	if fi, err := os.Stat(rustPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("armada-node's key: mode %v, %v", fi.Mode(), err)
	}
	rotated, err := runNode(t, bin, nil, "net", "key", "rotate", rustPath)
	if err != nil || string(rotated) == string(pub) {
		t.Fatalf("rotate: %q, %v", rotated, err)
	}
	if k, err := LoadOrCreateKey(rustPath); err != nil || k.Public() != string(rotated) {
		t.Fatalf("rotated key: Go %v, %v; armada-node %q", k.Public(), err, rotated)
	}
	// Keys written by hand, as base64 with or without the newline.
	for i := range 20 {
		priv := newKey(t)
		path := filepath.Join(dir, fmt.Sprintf("hand%d.key", i))
		body := priv.String()
		if i%2 == 0 {
			body += "\n"
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := runNode(t, bin, nil, "net", "key", path); err != nil || string(got) != priv.PublicKey().String() {
			t.Fatalf("key %d: armada-node %q, %v; Go %q", i, got, err, priv.PublicKey())
		}
	}
	// What Go refuses, armada-node refuses alike.
	for i, body := range []string{"nope\n", wgtypes.Key{}.String() + "\n", "YQ==\n"} {
		path := filepath.Join(dir, fmt.Sprintf("bad%d.key", i))
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, goErr := LoadOrCreateKey(path)
		_, err := runNode(t, bin, nil, "net", "key", path)
		if goErr == nil || err == nil || !strings.HasSuffix(err.Error(), goErr.Error()) {
			t.Errorf("%q: armada-node %v, Go %v", body, err, goErr)
		}
	}
	if err := os.Chmod(goPath, 0o644); err != nil {
		t.Fatal(err)
	}
	_, goErr := LoadOrCreateKey(goPath)
	if _, err := runNode(t, bin, nil, "net", "key", goPath); goErr == nil || err == nil || !strings.HasSuffix(err.Error(), goErr.Error()) {
		t.Errorf("readable key: armada-node %v, Go %v", err, goErr)
	}
}

// armada-node net cache keeps mesh.json as saveMeshCache does, and each
// reads what the other wrote.
func TestArmadaNodeNetCacheMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	dir := t.TempDir()
	full := natCluster(t)
	full.MeshCidr = "10.122.0.0/16"
	full.Endpoints = []*armadav1.NetworkEndpoint{{Address: "10.120.0.5", App: "web"}}
	full.TcpPorts = []uint32{5432}
	full.SwitchTo, full.SwitchStep = ModeWireGuard, SwitchPrepare
	full.IsolateDefault = true
	in, err := protojson.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	// Go writes, armada-node reads.
	goPath := filepath.Join(dir, "go.json")
	if err := saveMeshCache(goPath, full); err != nil {
		t.Fatal(err)
	}
	out, err := runNode(t, bin, nil, "net", "cache", "load", goPath)
	if err != nil {
		t.Fatal(err)
	}
	got := &armadav1.NetworkConfig{}
	if err := protojson.Unmarshal(out, got); err != nil || !proto.Equal(got, meshCacheOf(full)) {
		t.Fatalf("armada-node read %s, %v", out, err)
	}
	// armada-node writes, Go reads; neither writes an unchanged list again.
	rustPath := filepath.Join(dir, "rust.json")
	if _, err := runNode(t, bin, in, "net", "cache", "save", rustPath); err != nil {
		t.Fatal(err)
	}
	if got, err := loadMeshCache(rustPath); err != nil || !proto.Equal(got, meshCacheOf(full)) {
		t.Fatalf("Go read %v, %v", got, err)
	}
	if fi, err := os.Stat(rustPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", fi.Mode(), err)
	}
	old := time.Now().Add(-time.Hour)
	for _, path := range []string{goPath, rustPath} {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveMeshCache(rustPath, full); err != nil {
		t.Fatal(err)
	}
	if _, err := runNode(t, bin, in, "net", "cache", "save", goPath); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{goPath, rustPath} {
		if fi, _ := os.Stat(path); !fi.ModTime().Equal(old) {
			t.Errorf("%s: an unchanged list was written again", filepath.Base(path))
		}
	}
	// No file, and one others can read.
	if out, err := runNode(t, bin, nil, "net", "cache", "load", filepath.Join(dir, "none.json")); err != nil || string(out) != "null" {
		t.Errorf("no file: %s, %v", out, err)
	}
	if err := os.Chmod(goPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runNode(t, bin, nil, "net", "cache", "load", goPath); err == nil {
		t.Error("a readable list accepted")
	}
}
