//go:build linux

package clusternet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// Ports a project container may reach on its own node (ADR 0026): the DNS
// server on the bridge gateway, and the proxy's HTTP ports on any of the
// node's addresses (internal ingress on the gateway, public ingress, which
// the internet reaches anyway).
const (
	dnsPort   = 53
	httpPort  = 80
	httpsPort = 443
)

// blockedRanges are what a project container never reaches outside the
// cluster CIDR (ADR 0026): the private, shared, loopback, and link-local
// ranges, so the private network, the machines on it, and the cloud's
// metadata service are out of reach. The cluster CIDR is inside 10/8, but
// traffic within it is decided before these apply.
var blockedRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// isolationTable is the nftables table, in the ip and bridge families,
// that keeps apps and projects apart (ADR 0026). It only ever drops: its
// accepts end its own chains, and every other table still sees the packet.
const isolationTable = "armada"

// isolate replaces the isolation tables with ones built from pol, in one
// transaction, so no packet ever sees half a ruleset.
func isolate(pol policy) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	for _, fam := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyBridge} {
		t := &nftables.Table{Name: isolationTable, Family: fam}
		// Adding first makes the delete succeed when there is no table.
		c.AddTable(t)
		c.DelTable(t)
		c.AddTable(t)
		if err := buildTable(c, t, pol); err != nil {
			return err
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	return nil
}

// removeIsolation deletes the isolation tables.
func removeIsolation() error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	for _, fam := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyBridge} {
		t := &nftables.Table{Name: isolationTable, Family: fam}
		c.AddTable(t)
		c.DelTable(t)
	}
	return c.Flush()
}

// hasIsolation reports whether the isolation tables exist, for doctor.
func hasIsolation() (bool, error) {
	c, err := nftables.New()
	if err != nil {
		return false, err
	}
	for _, fam := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyBridge} {
		if _, err := c.ListTableOfFamily(isolationTable, fam); err != nil {
			if errors.Is(err, unix.ENOENT) {
				return false, nil
			}
			return false, err
		}
	}
	return true, nil
}

// buildTable adds to t:
//
//   - a set of addresses per app (a0, a1, ...) and a chain per app that
//     accepts only sources from its set and drops the rest;
//   - a map from every known container address to its app's chain;
//   - a forward chain: traffic from one container address of the cluster
//     to another goes through the destination's app chain, and is dropped
//     when the destination is unknown. Sources that are a node's own
//     (tunnel end, bridge) pass.
//
// The ip table first passes replies of known connections. It also isolates
// this node's containers from the platform: in the forward chain,
// connections to the private, shared, and link-local ranges and to every
// node are dropped; in the input chain,
// only the DNS server on the gateway and the proxy's HTTP ports are open.
// The bridge table, which sees traffic between containers of this node,
// passes ARP and drops everything but IPv4.
func buildTable(c *nftables.Conn, t *nftables.Table, pol policy) error {
	bridge := t.Family == nftables.TableFamilyBridge
	dst := &nftables.Set{Table: t, Name: "dst", KeyType: nftables.TypeIPAddr, DataType: nftables.TypeVerdict, IsMap: true}
	var targets []nftables.SetElement
	for i, app := range pol.apps {
		name := "a" + strconv.Itoa(i)
		set := &nftables.Set{Table: t, Name: name, KeyType: nftables.TypeIPAddr}
		if err := c.AddSet(set, addrElements(pol.members[app])); err != nil {
			return err
		}
		ch := c.AddChain(&nftables.Chain{Name: "app" + strconv.Itoa(i), Table: t})
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: join(srcIn(bridge, set, false), accept())})
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: drop()})
		for _, a := range pol.members[app] {
			targets = append(targets, nftables.SetElement{Key: a.AsSlice(), VerdictData: &expr.Verdict{Kind: expr.VerdictJump, Chain: ch.Name}})
		}
	}
	if err := c.AddSet(dst, targets); err != nil {
		return err
	}

	accept0 := nftables.ChainPolicyAccept
	prio := nftables.ChainPriorityFilter
	if bridge {
		prio = nftables.ChainPriorityRef(-200) // the bridge family's filter priority
	}
	fwd := c.AddChain(&nftables.Chain{Name: "forward", Table: t, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward, Priority: prio, Policy: &accept0})
	rule := func(ch *nftables.Chain, e ...[]expr.Any) {
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: join(e...)})
	}
	if bridge {
		// Between containers of this node, on the bridge only.
		rule(fwd, ifname(expr.MetaKeyBRIIIFNAME, embedded.BridgeName, true), accept())
		rule(fwd, etherType(unix.ETH_P_ARP, false), accept())
		rule(fwd, etherType(unix.ETH_P_IP, true), drop())
	}
	if !bridge {
		// Replies, such as a container's to a proxy on another node
		// (whose source is that node's tunnel end), belong to connections
		// these rules let open. The bridge table needs no such rule: the
		// rules between containers of one node are symmetric.
		rule(fwd, notNewConn(), accept())
	}
	inCIDR := join(prefix(bridge, 12, pol.cidr), prefix(bridge, 16, pol.cidr))
	for _, node := range []byte{0, 1} {
		rule(fwd, inCIDR, hostByte(bridge, node), accept())
	}
	rule(fwd, inCIDR, payload(bridge, 16), []expr.Any{&expr.Lookup{SourceRegister: 1, SetName: dst.Name, SetID: dst.ID, DestRegister: 0, IsDestRegSet: true}})
	rule(fwd, inCIDR, drop())
	if bridge {
		return nil
	}

	open := &nftables.Set{Table: t, Name: "open", KeyType: nftables.TypeIPAddr}
	if err := c.AddSet(open, addrElements(pol.open)); err != nil {
		return err
	}
	nodes := &nftables.Set{Table: t, Name: "nodes", KeyType: nftables.TypeIPAddr}
	if err := c.AddSet(nodes, addrElements(pol.nodes)); err != nil {
		return err
	}
	// Containers of this node that are isolated: in the node subnet and not
	// open.
	isolated := join(prefix(false, 12, pol.subnet), srcIn(false, open, true))
	for _, r := range blockedRanges {
		rule(fwd, isolated, prefix(false, 16, r), drop())
	}
	rule(fwd, isolated, payload(false, 16), []expr.Any{&expr.Lookup{SourceRegister: 1, SetName: nodes.Name, SetID: nodes.ID}}, drop())

	in := c.AddChain(&nftables.Chain{Name: "input", Table: t, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &accept0})
	rule(in, isolated, notNewConn(), accept())
	gw := join(payload(false, 16), cmp(pol.gateway.AsSlice()))
	rule(in, isolated, gw, l4(unix.IPPROTO_UDP), dport(dnsPort), accept())
	rule(in, isolated, gw, l4(unix.IPPROTO_TCP), dport(dnsPort), accept())
	rule(in, isolated, l4(unix.IPPROTO_TCP), dport(httpPort), accept())
	rule(in, isolated, l4(unix.IPPROTO_TCP), dport(httpsPort), accept())
	rule(in, isolated, drop())
	return nil
}

func join(parts ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func accept() []expr.Any { return []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}} }
func drop() []expr.Any   { return []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}} }

func addrElements(addrs []netip.Addr) []nftables.SetElement {
	out := make([]nftables.SetElement, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, nftables.SetElement{Key: a.AsSlice()})
	}
	return out
}

// payload loads 4 bytes of the IPv4 header at off (12: source, 16:
// destination) into register 1. The bridge family checks first that the
// frame carries IPv4.
func payload(bridge bool, off uint32) []expr.Any {
	var out []expr.Any
	if bridge {
		out = etherType(unix.ETH_P_IP, false)
	}
	return append(out, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: 4})
}

func cmp(data []byte) []expr.Any {
	return []expr.Any{&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data}}
}

// prefix matches the address at off against p.
func prefix(bridge bool, off uint32, p netip.Prefix) []expr.Any {
	mask := make([]byte, 4)
	binary.BigEndian.PutUint32(mask, ^uint32(0)<<(32-p.Bits()))
	return join(payload(bridge, off), []expr.Any{
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: make([]byte, 4)},
	}, cmp(p.Masked().Addr().AsSlice()))
}

// hostByte matches a source address whose last byte is b: in a node
// subnet, 0 is the node's tunnel end and 1 its bridge.
func hostByte(bridge bool, b byte) []expr.Any {
	return join(payload(bridge, 12), []expr.Any{
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: []byte{0, 0, 0, 0xff}, Xor: make([]byte, 4)},
	}, cmp([]byte{0, 0, 0, b}))
}

// srcIn matches a source address in set, or not in it with invert.
func srcIn(bridge bool, set *nftables.Set, invert bool) []expr.Any {
	return join(payload(bridge, 12), []expr.Any{&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID, Invert: invert}})
}

func etherType(proto uint16, invert bool) []expr.Any {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, proto)
	op := expr.CmpOpEq
	if invert {
		op = expr.CmpOpNeq
	}
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyPROTOCOL, Register: 1}, &expr.Cmp{Op: op, Register: 1, Data: data}}
}

// ifname matches the input or output interface name, or with invert every
// other one.
func ifname(key expr.MetaKey, name string, invert bool) []expr.Any {
	data := make([]byte, unix.IFNAMSIZ)
	copy(data, name)
	op := expr.CmpOpEq
	if invert {
		op = expr.CmpOpNeq
	}
	return []expr.Any{&expr.Meta{Key: key, Register: 1}, &expr.Cmp{Op: op, Register: 1, Data: data}}
}

func l4(proto byte) []expr.Any {
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}}}
}

func dport(port uint16) []expr.Any {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, port)
	return []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data}}
}

// ctState matches connections whose state has any of bits, or none with
// invert.
func ctState(bits uint32, invert bool) []expr.Any {
	mask := make([]byte, 4)
	binary.NativeEndian.PutUint32(mask, bits)
	op := expr.CmpOpNeq
	if invert {
		op = expr.CmpOpEq
	}
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: make([]byte, 4)},
		&expr.Cmp{Op: op, Register: 1, Data: make([]byte, 4)},
	}
}

// notNewConn matches replies and related traffic of known connections (one
// opened before a rule changed keeps going until it ends).
func notNewConn() []expr.Any {
	return ctState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED, false)
}
