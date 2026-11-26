package server

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

// Scenarios of the cluster network and the runtime move (ADR 0055, pull
// request 13), run against both servers by runParity: the network in
// every assignment (peers with their keys, endpoints, sites, and relays,
// the container addresses the firewalls keep apart, the default space's
// isolation, the mesh range), switches of the mode step by step as the
// nodes report them, joins over the leader's public address with the peer
// list (mesh clusters and other sites), key rotation and the conditions
// of usage reports, and the move of containerd nodes to the supervisor
// runtime. The ports of internal TCP apps come with the proxy
// configuration (parity_ingress_test.go).

// parityKey is a WireGuard public key made of n.
func parityKey(n int) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(n)}, 32))
}

// netAgent records a ready node and connects its agent with hello.
func (sc *scenario) netAgent(id, ip string, hello *armadav1.Hello) *parityAgent {
	sc.t.Helper()
	sc.node(id, ip, 8000, 16<<30, nil)
	hello.PrivateIp, hello.CpuMillis, hello.MemoryBytes, hello.Containers = ip, 8000, 16<<30, true
	a, err := sc.connectAgent(id, sc.nodeAgent(id), hello)
	if err != nil {
		sc.t.Fatal(err)
	}
	return a
}

// netNote records the network and the runtime move plan of each agent's
// latest assignment.
func (sc *scenario) netNote(label string, agents ...*parityAgent) {
	sc.t.Helper()
	for _, a := range agents {
		as := a.assignment()
		sc.note(label+" "+a.id+" network", as.GetNetwork())
		sc.note(label+" "+a.id+" runtime move", as.GetRuntimeMove())
	}
}

// mark waits until the server read what a's agent sent before: a new
// network key sent after it is recorded once the server read both. It
// works on nodes without replicas.
func (sc *scenario) mark(a *parityAgent) {
	sc.t.Helper()
	sc.mu.Lock()
	sc.marks++
	key := parityKey(100 + sc.marks)
	sc.mu.Unlock()
	a.send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_NetworkKey{NetworkKey: &armadav1.NetworkKeyChanged{PublicKey: key}}})
	sc.eventually("key of "+a.id, func() bool {
		n, err := sc.st.GetNode(sc.ctx, a.id)
		return err == nil && n.NetworkKey == key
	})
}

// sendUsage sends a usage report through a's agent and waits until the
// server has it.
func (sc *scenario) sendUsage(a *parityAgent, u *armadav1.UsageReport) {
	sc.t.Helper()
	a.send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Usage{Usage: u}})
	sc.mark(a)
}

// setIP records a replica running with a container address, as its
// agent reports it.
func (sc *scenario) setIP(r store.Replica, ip string) {
	sc.t.Helper()
	st := store.ReplicaStatus{ID: r.ID, State: store.ReplicaRunning, Ready: true, ContainerID: "c-" + r.ID, Address: ip + ":80", IP: ip}
	if err := sc.st.UpdateReplicaStatus(sc.ctx, r.NodeID, st); err != nil {
		sc.t.Fatal(err)
	}
}

// replicasOf returns the replicas of app by ID.
func (sc *scenario) replicasOf(app string) []store.Replica {
	sc.t.Helper()
	rs, err := sc.st.ListReplicas(sc.ctx, store.ReplicaFilter{App: app})
	if err != nil {
		sc.t.Fatal(err)
	}
	return rs
}

func (sc *scenario) initNetwork(n store.Network) {
	sc.t.Helper()
	if err := sc.st.InitNetwork(sc.ctx, n); err != nil {
		sc.t.Fatal(err)
	}
}

var parityPlain = store.Network{Mode: store.NetworkPlain, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")}

// The network every assignment carries: peers with subnets, keys, and
// endpoints, container addresses (an address two apps claim, one outside
// the node's subnet, and the gateway left out), the default space's
// isolation, and the mesh range.
func TestParityNetworkConfig(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		sc.initNetwork(parityPlain)
		n1 := sc.netAgent("n1", "10.0.0.11", &armadav1.Hello{NetworkKey: parityKey(1), Endpoint: "203.0.113.11"})
		n2 := sc.netAgent("n2", "10.0.0.12", &armadav1.Hello{NetworkKey: parityKey(2)})
		// Never connected: a peer with no key.
		sc.node("n3", "10.0.0.13", 8000, 16<<30, nil)
		sc.deploy("web", fmt.Sprintf(parityWeb, "1", 3))
		sc.deploy("api", "name: api\nimage: nginx:1\ningress:\n  type: external\n  port: 80\nscale:\n  min: 3\n")
		sc.pass("placed")
		web, api := sc.replicasOf("web"), sc.replicasOf("api")
		subnet := map[string]string{}
		for _, id := range []string{"n1", "n2", "n3"} {
			n, err := sc.st.GetNode(sc.ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			subnet[id] = strings.TrimSuffix(n.Subnet, ".0/24")
		}
		for i, r := range web {
			sc.setIP(r, fmt.Sprintf("%s.%d", subnet[r.NodeID], 10+i))
		}
		for _, r := range api {
			switch r.NodeID {
			case web[0].NodeID:
				// Claimed by web too: left out.
				sc.setIP(r, fmt.Sprintf("%s.%d", subnet[r.NodeID], 10))
			case web[1].NodeID:
				sc.setIP(r, subnet[r.NodeID]+".1") // the gateway
			default:
				sc.setIP(r, "192.168.7.7") // outside the node's subnet
			}
		}
		sc.pass("addresses")
		sc.netNote("addresses", n1, n2)

		on := true
		resp, err := sc.admin.UpdateSpace(sc.ctx, &armadav1.UpdateSpaceRequest{Name: "default", NetworkIsolation: &on})
		sc.answer("isolate the default space", resp, err)
		for _, cidr := range []string{"nope", "10.124.0.0/33", "8.0.0.0/16", "10.124.0.0/16"} {
			cc, err := sc.admin.SetClusterConfig(sc.ctx, &armadav1.SetClusterConfigRequest{SetMeshCidr: true, Config: &armadav1.ClusterConfig{MeshCidr: cidr}})
			sc.answer("mesh CIDR "+cidr, cc, err)
		}
		sc.pass("isolated")
		sc.netNote("isolated", n1)
		sc.keyspace("keyspace")
	})
}

// Peers carry their sites, and sites with a node behind NAT get a relay:
// an admin's choice while it can relay (one per site, the one replaced
// named), else the same node every pass; a drained choice gives way. A
// switch of the mode and a site refuse each other.
func TestParitySitesAndRelays(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		sc.initNetwork(parityPlain)
		a1 := sc.netAgent("a1", "10.0.0.1", &armadav1.Hello{NetworkKey: parityKey(1), Endpoint: "203.0.113.1", NetworkSwitch: true})
		for i, id := range []string{"a2", "a3", "nat", "b1"} {
			sc.node(id, fmt.Sprintf("10.0.0.%d", i+2), 8000, 16<<30, nil)
			st := store.NodeStatus{State: store.NodeReady, LastSeen: sc.clock.now(), NetworkKey: parityKey(i + 2), Endpoint: fmt.Sprintf("203.0.113.%d", i+2)}
			if id == "nat" {
				st.Endpoint, st.BehindNAT = "", true
			}
			if err := sc.st.SetNodeStatus(sc.ctx, id, st); err != nil {
				t.Fatal(err)
			}
		}
		resp, err := sc.admin.SetNodeSite(sc.ctx, &armadav1.SetNodeSiteRequest{Node: "b1", Site: "far"})
		sc.answer("b1 to far", resp, err)
		sc.pass("sites")
		sc.netNote("sites", a1)
		sc.pass("again")
		sc.netNote("again", a1)

		relay := func(label string, req *armadav1.SetNodeRelayRequest) {
			resp, err := sc.admin.SetNodeRelay(sc.ctx, req)
			sc.answer(label, resp, err)
			sc.pass(label)
			sc.netNote(label, a1)
		}
		relay("relay behind NAT", &armadav1.SetNodeRelayRequest{Node: "nat"})
		relay("relay a2", &armadav1.SetNodeRelayRequest{Node: "a2"})
		relay("relay a3", &armadav1.SetNodeRelayRequest{Node: "a3"})
		cr, err := sc.admin.CordonNode(sc.ctx, &armadav1.CordonNodeRequest{Node: "a3", Cordoned: true})
		sc.answer("drain a3", cr, err)
		sc.pass("a3 drained")
		sc.netNote("a3 drained", a1)
		cr, err = sc.admin.CordonNode(sc.ctx, &armadav1.CordonNodeRequest{Node: "a3"})
		sc.answer("resume a3", cr, err)
		relay("clear", &armadav1.SetNodeRelayRequest{Node: "a3", Clear: true})
		sc.status("status", "")

		sw := &armadav1.SetClusterConfigRequest{SetNetwork: true, Config: &armadav1.ClusterConfig{Network: store.NetworkWireGuard}}
		cc, err := sc.admin.SetClusterConfig(sc.ctx, sw)
		sc.answer("switch with b1 in another site", cc, err)
		resp, err = sc.admin.SetNodeSite(sc.ctx, &armadav1.SetNodeSiteRequest{Node: "b1"})
		sc.answer("b1 back", resp, err)
		cc, err = sc.admin.SetClusterConfig(sc.ctx, sw)
		sc.answer("switch", cc, err)
		resp, err = sc.admin.SetNodeSite(sc.ctx, &armadav1.SetNodeSiteRequest{Node: "b1", Site: "far"})
		sc.answer("site during a switch", resp, err)
		sc.keyspace("keyspace")
	})
}

// A switch of the network's mode (ADR 0050): refused while a connected
// agent cannot switch and for a mesh, then moved on step by step once
// every connected node reports the step done (a report for another step,
// a node that never connected, and a disconnected one); given up while
// preparing, and too late once moving.
func TestParityNetworkSwitch(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		sc.initNetwork(parityPlain)
		n1 := sc.netAgent("n1", "10.0.0.11", &armadav1.Hello{NetworkSwitch: true})
		n2 := sc.netAgent("n2", "10.0.0.12", &armadav1.Hello{})
		// n3 never connected: nothing waits for it.
		sc.node("n3", "10.0.0.13", 8000, 16<<30, nil)
		set := func(label, to string) {
			cc, err := sc.admin.SetClusterConfig(sc.ctx, &armadav1.SetClusterConfigRequest{SetNetwork: true, Config: &armadav1.ClusterConfig{Network: to}})
			sc.answer(label, cc, err)
		}
		set("with an old agent", store.NetworkWireGuard)
		sc.disconnect(n2)
		n2 = sc.reconnect("n2", "10.0.0.12", &armadav1.Hello{NetworkSwitch: true})
		set("to mesh", store.NetworkMesh)
		set("to nothing", "")
		set("to wireguard", store.NetworkWireGuard)
		set("again", store.NetworkWireGuard)
		report := func(a *parityAgent, step string, ready bool, unreached ...string) {
			sc.sendUsage(a, &armadav1.UsageReport{NetworkSwitch: &armadav1.NetworkSwitchStatus{To: store.NetworkWireGuard, Step: step, Ready: ready, Unreached: unreached}})
		}
		sc.pass("started")
		sc.netNote("started", n1)
		report(n1, store.SwitchPrepare, true)
		report(n2, store.SwitchPrepare, false, "n1", "Bad;Name")
		sc.pass("n2 waits")
		sc.netNote("n2 waits", n1)
		sc.clusterStatus("n2 waits")
		report(n2, store.SwitchMove, true)
		sc.pass("another step")
		sc.netNote("another step", n1)
		report(n2, store.SwitchPrepare, true)
		sc.pass("prepared")
		sc.netNote("prepared", n1, n2)
		sc.clusterStatus("prepared")
		set("give up while moving", store.NetworkPlain)
		report(n1, store.SwitchMove, true)
		sc.disconnect(n2)
		sc.pass("n2 away")
		sc.netNote("n2 away", n1)
		n2 = sc.reconnect("n2", "10.0.0.12", &armadav1.Hello{NetworkSwitch: true})
		report(n2, store.SwitchMove, true)
		sc.pass("switched")
		sc.netNote("switched", n1, n2)
		cc, err := sc.admin.GetClusterConfig(sc.ctx, &armadav1.GetClusterConfigRequest{})
		sc.answer("config", cc, err)

		set("back to plain", store.NetworkPlain)
		cc, err = sc.admin.GetClusterConfig(sc.ctx, &armadav1.GetClusterConfigRequest{})
		sc.answer("config while switching", cc, err)
		set("give up", store.NetworkWireGuard)
		sc.pass("given up")
		sc.netNote("given up", n1)
		sc.keyspace("keyspace")
	})
}

// reconnect connects a node's agent again.
func (sc *scenario) reconnect(id, ip string, hello *armadav1.Hello) *parityAgent {
	sc.t.Helper()
	hello.PrivateIp, hello.CpuMillis, hello.MemoryBytes, hello.Containers = ip, 8000, 16<<30, true
	a, err := sc.connectAgent(id, sc.nodeAgent(id), hello)
	if err != nil {
		sc.t.Fatal(err)
	}
	return a
}

// A node's key is rotated through its agent and reaches its peers; a key
// another node holds and a malformed one are refused. A node that cannot
// rotate, one not connected, and an unknown one are refused. Usage
// reports raise and clear PeerUnreachable and WireGuardUserspace.
func TestParityNetworkKeysAndPeers(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		sc.initNetwork(store.Network{Mode: store.NetworkWireGuard, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16")})
		n1 := sc.netAgent("n1", "10.0.0.11", &armadav1.Hello{NetworkKey: parityKey(1), KeyRotation: true})
		n2 := sc.netAgent("n2", "10.0.0.12", &armadav1.Hello{NetworkKey: parityKey(2)})
		rotate := func(label, node string) {
			resp, err := sc.admin.RotateNodeKey(sc.ctx, &armadav1.RotateNodeKeyRequest{Node: node})
			sc.answer(label, resp, err)
		}
		rotate("rotate n1", "n1")
		rotate("rotate n2", "n2")
		rotate("rotate ghost", "ghost")
		rotate("rotate a bad name", "Bad;Name")
		n1.assignment()
		asked := 0
		for _, m := range n1.othersSeen() {
			if m.GetRotateNetworkKey() != nil {
				asked++
			}
		}
		sc.note("n1 asked", asked)
		n1.send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_NetworkKey{NetworkKey: &armadav1.NetworkKeyChanged{PublicKey: parityKey(9)}}})
		sc.waitEvent("n1", "NetworkKeyRotated", 1)
		sc.pass("rotated")
		sc.netNote("rotated", n2)
		// n1's key, then a malformed one: neither is taken.
		for _, k := range []string{parityKey(9), "short"} {
			n2.send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_NetworkKey{NetworkKey: &armadav1.NetworkKeyChanged{PublicKey: k}}})
		}
		sc.mark(n2)

		for _, u := range []*armadav1.UsageReport{
			{UnreachablePeers: []string{"b"}, WireguardUserspace: true},
			{PeersChecked: true},
			{PeersChecked: true, UnreachablePeers: []string{"b", "Not A Name", "c"}},
			{PeersChecked: true, UnreachablePeers: []string{"b", "c"}},
			{PeersChecked: true, WireguardUserspace: true},
			{PeersChecked: true, UnreachablePeers: []string{"b"}},
		} {
			sc.sendUsage(n1, u)
		}
		sc.disconnect(n2)
		rotate("rotate n2 away", "n2")
		sc.keyspace("keyspace")
	})
}

// publicJoinClient reaches a join listener named after a public address
// at the loopback address it listens on, once it is open.
func (sc *scenario) publicJoinClient(local, caHash string) armadav1.JoinServiceClient {
	sc.t.Helper()
	pin, err := pki.ParseCAHash(caHash)
	if err != nil {
		sc.t.Fatal(err)
	}
	var ca = sc.fx.ca.Cert
	sc.eventually("join listener open", func() bool {
		got, err := pki.FetchPinnedCA(sc.ctx, local, pin)
		if err == nil {
			ca = got
		}
		sc.recordListening(local, err == nil, true)
		return err == nil
	})
	conn, err := grpc.NewClient(local, append(sc.recordJoinDial(local), grpc.WithTransportCredentials(credentials.NewTLS(pki.JoinClientTLS(ca))))...)
	if err != nil {
		sc.t.Fatal(err)
	}
	sc.t.Cleanup(func() { _ = conn.Close() })
	return armadav1.NewJoinServiceClient(conn)
}

// recordListening records whether something listens at addr, which the
// replay asks of its own server's listener: with handshake a TLS
// handshake that completes (FetchPinnedCA's), else a TCP connection
// (a listener that closes connections before TLS still listens).
func (sc *scenario) recordListening(addr string, up, handshake bool) {
	if sc.rec == nil {
		return
	}
	step := sc.rec.add(map[string]any{"op": "listening", "addr": sc.rec.template(addr), "tls": handshake})
	sc.rec.expect(step, "expect", up)
}

// closed waits until nothing listens at addr.
func (sc *scenario) closed(addr string) {
	sc.t.Helper()
	sc.eventually("listener closed", func() bool {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
		}
		sc.recordListening(addr, err == nil, false)
		return err != nil
	})
}

// A mesh cluster's join listener faces the public only while a token is
// open; machines join with their key and endpoint, get a mesh address and
// the peer list (ADR 0049).
func TestParityMeshJoin(t *testing.T) {
	runParity(t, parityConfig{join: true, meshJoin: true, joinBurst: 100}, func(sc *scenario) {
		sc.initNetwork(store.Network{Mode: store.NetworkMesh, ClusterCIDR: netip.MustParsePrefix("10.120.0.0/16"), MeshCIDR: netip.MustParsePrefix("10.121.0.0/16")})
		for _, req := range []*armadav1.CreateJoinTokenRequest{{TtlSeconds: 7200}, {From: "203.0.113.9:22"}} {
			resp, err := sc.admin.CreateJoinToken(sc.ctx, req)
			sc.answer(fmt.Sprintf("token %v", req), resp, err)
		}
		tok, err := sc.admin.CreateJoinToken(sc.ctx, &armadav1.CreateJoinTokenRequest{})
		if err != nil {
			t.Fatal(err)
		}
		id, _, _ := strings.Cut(tok.Token, ".")
		sc.alias(id, "<token>")
		sc.alias(tok.Token, "<token>.<secret>")
		sc.answer("token", tok, nil)
		jc := sc.publicJoinClient(sc.sut.joinLocal(), tok.CaHash)
		for _, c := range []struct {
			name string
			mod  func(*armadav1.JoinRequest)
		}{
			{"no key", func(r *armadav1.JoinRequest) { r.NetworkKey = "" }},
			{"bad endpoint", func(r *armadav1.JoinRequest) { r.Endpoint = "127.0.0.1" }},
			{"behind NAT with an endpoint", func(r *armadav1.JoinRequest) { r.BehindNat = true }},
		} {
			req, _ := joinReq(t, tok.Token, "m1", "")
			req.NetworkKey, req.Endpoint = parityKey(1), "198.51.100.2"
			c.mod(req)
			_, err := jc.Join(sc.ctx, req)
			sc.note("join: "+c.name, err)
		}
		// A private IP the machine found is not its address in a mesh.
		req, _ := joinReq(t, tok.Token, "m1", "10.0.0.5")
		req.NetworkKey, req.Endpoint = parityKey(1), "198.51.100.2"
		resp, err := jc.Join(sc.ctx, req)
		sc.answer("join m1", resp, err)
		sc.closed(sc.sut.joinLocal())
		sc.keyspace("keyspace")
	})
}

// A plain cluster's machines of another site join over the leader's
// endpoint while a token for one is open, with their key and endpoint,
// and get the peer list with their sites; one with no private network
// gets a mesh address, one behind NAT none; a server of another site
// joins the same way (ADR 0050).
func TestParitySiteJoin(t *testing.T) {
	runParity(t, parityConfig{join: true, siteJoin: true, joinBurst: 100, masterKey: true, cluster: true}, func(sc *scenario) {
		sc.initNetwork(parityPlain)
		for _, req := range []*armadav1.CreateJoinTokenRequest{{Site: "office", TtlSeconds: 7200}, {From: "198.51.100.9"}} {
			resp, err := sc.admin.CreateJoinToken(sc.ctx, req)
			sc.answer(fmt.Sprintf("token %v", req), resp, err)
		}
		toks := map[string]*armadav1.CreateJoinTokenResponse{}
		for _, c := range []struct {
			name string
			req  *armadav1.CreateJoinTokenRequest
		}{
			{"first", &armadav1.CreateJoinTokenRequest{}},
			{"office", &armadav1.CreateJoinTokenRequest{Site: "office"}},
			{"cloud", &armadav1.CreateJoinTokenRequest{Site: "cloud"}},
			{"home", &armadav1.CreateJoinTokenRequest{Site: "home"}},
			{"server", &armadav1.CreateJoinTokenRequest{Site: "far", Server: true}},
		} {
			tok, err := sc.admin.CreateJoinToken(sc.ctx, c.req)
			if err != nil {
				t.Fatal(err)
			}
			id, _, _ := strings.Cut(tok.Token, ".")
			sc.alias(id, "<"+c.name+" token>")
			sc.alias(tok.Token, "<"+c.name+" token>.<secret>")
			sc.answer("token "+c.name, tok, nil)
			toks[c.name] = tok
		}
		jc := sc.publicJoinClient(sc.sut.siteJoinLocal(), toks["office"].CaHash)
		join := func(label, tok, name, ip string, mod func(*armadav1.JoinRequest)) {
			req, _ := joinReq(t, tok, name, ip)
			req.NetworkKey, req.Endpoint = parityKey(len(name)+int(name[1])), "198.51.100.2"
			mod(req)
			resp, err := jc.Join(sc.ctx, req)
			sc.answer(label, resp, err)
		}
		none := func(*armadav1.JoinRequest) {}
		join("first-site token over the public address", toks["first"].Token, "w1", "10.0.0.5", none)
		join("no key", toks["office"].Token, "w1", "10.0.0.5", func(r *armadav1.JoinRequest) { r.NetworkKey = "" })
		join("bad endpoint", toks["office"].Token, "w1", "10.0.0.5", func(r *armadav1.JoinRequest) { r.Endpoint = "127.0.0.1" })
		join("w1", toks["office"].Token, "w1", "10.0.0.5", none)
		join("w3 without a private network", toks["cloud"].Token, "w3", "", func(r *armadav1.JoinRequest) { r.Endpoint = "198.51.100.3" })
		cc, err := sc.admin.SetClusterConfig(sc.ctx, &armadav1.SetClusterConfigRequest{SetMeshCidr: true, Config: &armadav1.ClusterConfig{MeshCidr: "10.124.0.0/24"}})
		sc.answer("mesh CIDR with a mesh address held", cc, err)
		join("behind NAT with an endpoint", toks["home"].Token, "w4", "192.168.1.4", func(r *armadav1.JoinRequest) { r.BehindNat = true })
		join("w4 behind NAT", toks["home"].Token, "w4", "192.168.1.4", func(r *armadav1.JoinRequest) { r.BehindNat, r.Endpoint = true, "" })
		sreq := joinServerReq(t, toks["server"].Token, "cp-2", "10.0.0.2")
		sreq.NetworkKey, sreq.Endpoint = parityKey(42), "198.51.100.7"
		sresp, err := jc.JoinServer(sc.ctx, sreq)
		sc.answer("server cp-2", sresp, err)
		sc.closed(sc.sut.siteJoinLocal())
		// The first-site token still works at the private address.
		req, _ := joinReq(t, toks["first"].Token, "w2", "10.0.0.6")
		resp, err := sc.joinClient(toks["first"]).Join(sc.ctx, req)
		sc.answer("w2 at the private address", resp, err)
		sc.keyspace("keyspace")
	})
}

// moveNote records each agent's runtime move plan and whether the server
// asked it to move.
func (sc *scenario) moveNote(label string, agents ...*parityAgent) {
	sc.t.Helper()
	for _, a := range agents {
		as := a.assignment()
		asked := 0
		for _, m := range a.othersSeen() {
			if m.GetMoveRuntime() != nil {
				asked++
			}
		}
		a.clearOthers()
		sc.note(label+" "+a.id, map[string]any{"plan": planText(as.GetRuntimeMove()), "asked": asked, "replicas": len(as.GetReplicas())})
	}
	rec, err := sc.st.GetMeta(sc.ctx, metaRuntimeMove)
	if err != nil {
		rec = err.Error()
	}
	sc.note(label+" record", rec)
}

func planText(p *armadav1.RuntimeMovePlan) string {
	if p == nil {
		return "none"
	}
	return fmt.Sprintf("%s %q operator=%t", p.GetState(), p.GetReason(), p.GetOperator())
}

// runtimes reports how each agent's node runs containers.
func (sc *scenario) runtimes(agent string, agents ...*parityAgent) {
	sc.t.Helper()
	for _, a := range agents {
		sc.sendUsage(a, &armadav1.UsageReport{Runtime: &armadav1.RuntimeStatus{Agent: agent}})
	}
}

// The leader moves containerd nodes one at a time, workers before
// servers: off until turned on (audited), each drained while its
// replicas start elsewhere, asked to move once none is left, done once it
// reports the supervisor; a move that takes too long is given up with
// what the node said and tried again after the backoff; turning the move
// off ends one that drains.
func TestParityRuntimeMove(t *testing.T) {
	runParity(t, parityConfig{cluster: true}, func(sc *scenario) {
		hello := func() *armadav1.Hello { return &armadav1.Hello{RuntimeMove: true} }
		n1 := sc.netAgent("n1", "10.0.0.11", hello())
		n2 := sc.netAgent("n2", "10.0.0.12", hello())
		cp := sc.netAgent("cp-1", "10.0.0.1", hello())
		all := []*parityAgent{n1, n2, cp}
		// What each node reports, again before every pass: reports count
		// for 35 seconds.
		rt := map[*parityAgent]*armadav1.RuntimeStatus{}
		for _, a := range all {
			rt[a] = &armadav1.RuntimeStatus{Agent: AgentContainerdName}
		}
		step := func(label string, d time.Duration) {
			sc.advance(d)
			for _, a := range all {
				sc.sendUsage(a, &armadav1.UsageReport{Runtime: rt[a]})
			}
			sc.pass(label)
			sc.moveNote(label, all...)
		}
		setMove := func(label string, on bool) {
			cc, err := sc.admin.SetClusterConfig(sc.ctx, &armadav1.SetClusterConfigRequest{SetRuntimeMove: true, Config: &armadav1.ClusterConfig{RuntimeMoveOff: !on}})
			sc.answer(label, cc, err)
		}
		setMove("off", false)
		sc.deploy("web", fmt.Sprintf(parityWeb, "1", 2))
		sc.pass("placed")
		sc.serve("web")
		step("off", 5*time.Second)
		setMove("on", true)
		step("on", 0)
		// n1 drains: its replica starts elsewhere, then leaves.
		step("replacement placed", time.Second)
		sc.serve("web")
		step("replacement serves", 4*time.Second)
		step("drained and asked", 11*time.Second)
		step("not asked again within 30s", time.Second)
		step("asked again", 30*time.Second)
		rt[n1] = &armadav1.RuntimeStatus{Agent: "supervisor-rust"}
		step("n1 moved", time.Second)
		step("n2 starts", time.Second)
		step("n2 replacement placed", time.Second)
		sc.serve("web")
		step("n2 replacement serves", 4*time.Second)
		step("n2 drained and asked", 11*time.Second)
		// n2 never reports the supervisor: given up after ten minutes, with
		// what it said.
		rt[n2] = &armadav1.RuntimeStatus{Agent: AgentContainerdName, MoveError: "the disk is full\x1b"}
		step("n2 not yet given up", 9*time.Minute)
		step("n2 given up", time.Minute)
		step("the server drains", time.Second)
		setMove("off while draining", false)
		step("stopped", time.Second)
		setMove("on again", true)
		step("n2 waits for the backoff", time.Second)
		rt[n2] = &armadav1.RuntimeStatus{Agent: "supervisor-go"}
		step("n2 moved by hand", time.Second)
		sc.keyspace("keyspace")
	})
}

// AgentContainerdName is runtime.AgentContainerd.
const AgentContainerdName = "containerd"

// A node that is the only one waits for its operator, and so does one
// that holds local volumes; an agent that cannot move itself waits for an
// upgrade; the others move.
func TestParityRuntimeMoveWaits(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		hello := func() *armadav1.Hello { return &armadav1.Hello{RuntimeMove: true, Volumes: true} }
		n1 := sc.netAgent("n1", "10.0.0.11", hello())
		sc.runtimes(AgentContainerdName, n1)
		sc.pass("alone")
		sc.moveNote("alone", n1)
		n2 := sc.netAgent("n2", "10.0.0.12", hello())
		old := sc.netAgent("n3", "10.0.0.13", &armadav1.Hello{Volumes: true})
		sc.deploy("web", fmt.Sprintf(parityVolume, "1"))
		sc.pass("placed")
		sc.runtimes(AgentContainerdName, n1, n2, old)
		sc.pass("waits")
		sc.moveNote("waits", n1, n2, old)
		sc.keyspace("keyspace")
	})
}
