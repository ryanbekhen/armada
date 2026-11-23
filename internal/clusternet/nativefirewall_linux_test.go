package clusternet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
)

// The firewall in armada-node net firewall (node/src/net/firewall.rs) is
// compared with this package's without root: the nftables batches as the
// netlink messages Go's library would send, and the iptables commands as
// the argument lists Go would run against a model of iptables.
//
// Normalisation: each message's sequence number and port ID are zeroed
// (the socket numbers messages when it sends them), and the set IDs of a
// batch start where Go's process-wide counter stands, which the test reads
// before each batch and hands to armada-node.

// policyJSON writes a policy as armada-node reads it (net plan's form).
func policyJSON(pol policy) map[string]any {
	members := []map[string]any{}
	for _, app := range pol.apps {
		members = append(members, map[string]any{"app": app, "addresses": orEmpty(texts(pol.members[app]))})
	}
	gw := ""
	if pol.gateway.IsValid() {
		gw = pol.gateway.String()
	}
	return map[string]any{"cidr": pol.cidr.String(), "subnet": pol.subnet.String(), "gateway": gw,
		"apps": orEmpty(pol.apps), "members": members, "open": orEmpty(texts(pol.open)),
		"nodes": orEmpty(texts(pol.nodes)), "tcpPorts": orEmpty(pol.tcpPorts)}
}

// nextSetID is the ID Go's nftables library gives the next set it adds.
func nextSetID() uint32 {
	c, _ := nftables.New(nftables.WithTestDial(func([]netlink.Message) ([]netlink.Message, error) { return nil, nil }))
	s := &nftables.Set{Table: &nftables.Table{Name: "probe", Family: nftables.TableFamilyIPv4}, Name: "probe", KeyType: nftables.TypeIPAddr}
	_ = c.AddSet(s, nil)
	return s.ID + 1
}

// captureNft runs f on a connection that keeps what Flush sends, as hex,
// with sequence numbers and port IDs zeroed.
func captureNft(t *testing.T, f func(*nftables.Conn) error) []string {
	t.Helper()
	out := []string{}
	c, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		for _, m := range req {
			b, err := m.MarshalBinary()
			if err != nil {
				return nil, err
			}
			clear(b[8:16])
			out = append(out, hex.EncodeToString(b))
		}
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := f(c); err != nil {
		t.Fatal(err)
	}
	return out
}

type nftAnswer struct {
	Action  string   `json:"action"`
	Isolate []string `json:"isolate"`
	Update  []string `json:"update"`
	Remove  []string `json:"remove"`
}

// compareNft compares one policy, after prev (nil for none), with the
// tables existing or not.
func compareNft(t *testing.T, bin, name string, prev *policy, pol policy, has bool) string {
	t.Helper()
	req := map[string]any{"Policy": policyJSON(pol), "HasTables": has}
	want := nftAnswer{Action: isolationAction(prev, pol, func() bool { return has })}
	req["FirstSetID"] = nextSetID()
	want.Isolate = captureNft(t, func(c *nftables.Conn) error { return isolateOn(c, pol) })
	if prev != nil {
		req["Previous"] = policyJSON(*prev)
		req["UpdateSetID"] = nextSetID()
		want.Update = captureNft(t, func(c *nftables.Conn) error { return updateIsolationOn(c, *prev, pol) })
	}
	want.Remove = captureNft(t, removeIsolationOn)
	in, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := runNode(t, bin, in, "net", "firewall", "nft")
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if w := canonicalJSON(want); !bytes.Equal(got, w) {
		t.Fatalf("%s: armada-node and Go differ:\n%s", name, firstDifference(got, w))
	}
	return want.Action
}

// firstDifference names the first message that differs.
func firstDifference(got, want []byte) string {
	var g, w nftAnswer
	if json.Unmarshal(got, &g) != nil || json.Unmarshal(want, &w) != nil {
		return fmt.Sprintf(" armada-node: %s\n Go:          %s", got, want)
	}
	if g.Action != w.Action {
		return fmt.Sprintf("action %s, Go %s", g.Action, w.Action)
	}
	for _, part := range []struct {
		name string
		g, w []string
	}{{"isolate", g.Isolate, w.Isolate}, {"update", g.Update, w.Update}, {"remove", g.Remove, w.Remove}} {
		for i := range max(len(part.g), len(part.w)) {
			var a, b string
			if i < len(part.g) {
				a = part.g[i]
			}
			if i < len(part.w) {
				b = part.w[i]
			}
			if a != b {
				return fmt.Sprintf("%s, message %d of %d/%d:\n armada-node: %s\n Go:          %s", part.name, i, len(part.g), len(part.w), a, b)
			}
		}
	}
	return "same messages, different JSON"
}

// randomIsolation is a policy of the kind updates go between: apps that
// come and go, addresses that move, open containers, ports, and now and
// then another frame.
func randomIsolation(r *rand.Rand) policy {
	pol := policy{
		cidr:    netip.MustParsePrefix("10.120.0.0/16"),
		subnet:  netip.MustParsePrefix("10.120.0.0/24"),
		gateway: netip.MustParseAddr("10.120.0.1"),
		members: map[string][]netip.Addr{},
		nodes:   []netip.Addr{netip.MustParseAddr("10.52.9.2"), netip.MustParseAddr("10.52.9.3")},
	}
	if r.IntN(10) == 0 {
		pol.nodes = pol.nodes[:1]
	}
	if r.IntN(20) == 0 {
		pol.subnet, pol.gateway = netip.MustParsePrefix("10.120.1.0/24"), netip.MustParseAddr("10.120.1.1")
	}
	used := map[netip.Addr]bool{}
	for i := range 12 {
		if r.IntN(3) == 0 {
			continue
		}
		app := fmt.Sprintf("app%d.p%d", i, i%3)
		if i%4 == 0 {
			app = fmt.Sprintf("app%d", i)
		}
		for range 1 + r.IntN(4) {
			a := netip.AddrFrom4([4]byte{10, 120, byte(r.IntN(2)), byte(2 + r.IntN(30))})
			if !used[a] {
				used[a] = true
				pol.members[app] = append(pol.members[app], a)
				if a.As4()[2] == 0 && r.IntN(2) == 0 {
					pol.open = append(pol.open, a)
				}
			}
		}
		if len(pol.members[app]) == 0 {
			delete(pol.members, app)
			continue
		}
		slices.SortFunc(pol.members[app], netip.Addr.Compare)
		pol.apps = append(pol.apps, app)
	}
	slices.Sort(pol.apps)
	slices.SortFunc(pol.open, netip.Addr.Compare)
	pol.tcpPorts = []uint16{}
	if r.IntN(8) != 0 {
		for range 1 + r.IntN(3) {
			pol.tcpPorts = append(pol.tcpPorts, uint16(5000+r.IntN(6)))
		}
		slices.Sort(pol.tcpPorts)
		pol.tcpPorts = slices.Compact(pol.tcpPorts)
	}
	return pol
}

// armada-node net firewall nft must send the nftables messages this
// package sends: the policies of the plan cases, and random sequences of
// updates. CI sets ARMADA_NODE_BIN (make node).
func TestArmadaNodeNftMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	actions := map[string]int{}
	policies := 0
	cases := namedNetCases(t)
	r := rand.New(rand.NewPCG(5, 6))
	for i := range 300 {
		cases = append(cases, randomNetCase(t, r, i))
	}
	for _, c := range cases {
		n := &Net{cfg: Config{Node: c.node, PrivateIP: c.ip, Key: PrivateKey{k: c.key}}}
		p, err := n.plan(c.cfg)
		if err != nil {
			continue
		}
		pol := buildPolicy(p, c.local)
		actions[compareNft(t, bin, c.name, nil, pol, false)]++
		policies++
	}
	// A rebuild at 300 apps, and the update that adds one more.
	big := policy{cidr: netip.MustParsePrefix("10.120.0.0/16"), subnet: netip.MustParsePrefix("10.120.0.0/24"),
		gateway: netip.MustParseAddr("10.120.0.1"), members: map[string][]netip.Addr{},
		nodes: []netip.Addr{netip.MustParseAddr("10.52.9.2")}, tcpPorts: []uint16{}}
	for i := range 300 {
		app := fmt.Sprintf("app%d.p%d", i, i%20)
		big.apps = append(big.apps, app)
		big.members[app] = []netip.Addr{netip.AddrFrom4([4]byte{10, 120, byte(i / 250), byte(2 + i%250)})}
	}
	slices.Sort(big.apps)
	more := big
	more.members = map[string][]netip.Addr{"new.p0": {netip.MustParseAddr("10.120.9.9")}}
	for app, a := range big.members {
		more.members[app] = a
	}
	more.apps = append(slices.Clone(big.apps), "new.p0")
	slices.Sort(more.apps)
	actions[compareNft(t, bin, "300 apps", &big, more, true)]++

	rs := rand.New(rand.NewPCG(7, 27))
	const rounds = 400
	cur := randomIsolation(rs)
	for round := range rounds {
		next := randomIsolation(rs)
		if rs.IntN(15) == 0 {
			next = cur
		}
		actions[compareNft(t, bin, fmt.Sprintf("round %d", round), &cur, next, rs.IntN(10) != 0)]++
		cur = next
	}
	for _, a := range []string{isolationKeep, isolationUpdate, isolationRebuild} {
		if actions[a] == 0 {
			t.Errorf("no case chose %s: %v", a, actions)
		}
	}
	t.Logf("%d plan policies, 1 large update, and %d random updates compared; actions %v", policies, rounds, actions)
}

// simChain is a chain of the iptables model; its rules are the text -S
// prints after "-A NAME ".
type simChain struct {
	Name    string
	Builtin bool
	Rules   []string
}

// iptablesSim is the model of iptables both sides run against
// (iptables.rs's Sim): chains by table in the order they were made.
type iptablesSim struct {
	tables map[string][]*simChain
	fail   []string
	calls  [][]string
}

func newIptablesSim(tables map[string][]simChain, fail []string) *iptablesSim {
	s := &iptablesSim{tables: map[string][]*simChain{}, fail: fail, calls: [][]string{}}
	for table, chains := range tables {
		for _, c := range chains {
			s.tables[table] = append(s.tables[table], &simChain{Name: c.Name, Builtin: c.Builtin, Rules: slices.Clone(c.Rules)})
		}
	}
	return s
}

// emptyTables are iptables' built-in chains with no rules.
func emptyTables() map[string][]simChain {
	out := map[string][]simChain{}
	for table, chains := range map[string][]string{
		"filter": {"INPUT", "FORWARD", "OUTPUT"},
		"raw":    {"PREROUTING", "OUTPUT"},
		"mangle": {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"},
		"nat":    {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"},
	} {
		for _, c := range chains {
			out[table] = append(out[table], simChain{Name: c, Builtin: true, Rules: []string{}})
		}
	}
	return out
}

func (s *iptablesSim) state() map[string][]simChain {
	out := map[string][]simChain{}
	for table, chains := range s.tables {
		out[table] = []simChain{}
		for _, c := range chains {
			out[table] = append(out[table], simChain{Name: c.Name, Builtin: c.Builtin, Rules: append([]string{}, c.Rules...)})
		}
	}
	return out
}

func (s *iptablesSim) chain(table, name string) *simChain {
	for _, c := range s.tables[table] {
		if c.Name == name {
			return c
		}
	}
	return nil
}

var errSim = errors.New("exit status 1")

func (s *iptablesSim) exec(args []string) ([]byte, error) {
	s.calls = append(s.calls, slices.Clone(args))
	out, ok := s.call(args)
	if !ok {
		return []byte("simulated failure"), errSim
	}
	return []byte(out), nil
}

func (s *iptablesSim) call(a []string) (string, bool) {
	if len(a) >= 2 && a[0] == "-w" {
		a = a[2:]
	}
	if slices.Contains(s.fail, strings.Join(a, " ")) {
		return "", false
	}
	table := "filter"
	if len(a) >= 2 && a[0] == "-t" {
		table, a = a[1], a[2:]
	}
	if len(a) < 2 {
		return "", false
	}
	op, name, rest := a[0], a[1], strings.Join(a[2:], " ")
	switch op {
	case "-N":
		if s.chain(table, name) != nil {
			return "", false
		}
		s.tables[table] = append(s.tables[table], &simChain{Name: name})
		return "", true
	case "-X":
		i := slices.IndexFunc(s.tables[table], func(c *simChain) bool { return c.Name == name })
		if i < 0 {
			return "", false
		}
		s.tables[table] = slices.Delete(s.tables[table], i, i+1)
		return "", true
	}
	c := s.chain(table, name)
	if c == nil {
		return "", false
	}
	switch op {
	case "-L":
		return "", true
	case "-S":
		var b strings.Builder
		if c.Builtin {
			fmt.Fprintf(&b, "-P %s ACCEPT\n", name)
		} else {
			fmt.Fprintf(&b, "-N %s\n", name)
		}
		for _, r := range c.Rules {
			fmt.Fprintf(&b, "-A %s %s\n", name, r)
		}
		return b.String(), true
	case "-F":
		c.Rules = nil
		return "", true
	case "-A":
		c.Rules = append(c.Rules, rest)
		return "", true
	case "-I":
		c.Rules = slices.Insert(c.Rules, 0, strings.Join(a[3:], " "))
		return "", true
	case "-C":
		return "", slices.Contains(c.Rules, rest)
	case "-D":
		i := slices.Index(c.Rules, rest)
		if i < 0 {
			return "", false
		}
		c.Rules = slices.Delete(c.Rules, i, i+1)
		return "", true
	}
	return "", false
}

type cleanJSON struct{ Next, Site bool }

type iptablesAnswer struct {
	PlanError    string     `json:"planError"`
	Calls        [][]string `json:"calls"`
	Error        string     `json:"error"`
	Clean        cleanJSON  `json:"clean"`
	RemoveCalls  [][]string `json:"removeCalls"`
	RemoveErrors []string   `json:"removeErrors"`
}

// goIptables runs Net.firewall and removeFirewall against the model, each
// from tables, and returns what armada-node net firewall iptables answers,
// with the tables the firewall left.
func goIptables(c netCase, clean cleanJSON, tables map[string][]simChain, fail []string) (iptablesAnswer, map[string][]simChain) {
	saved := iptables
	defer func() { iptables = saved }()
	a := iptablesAnswer{Calls: [][]string{}, Clean: clean, RemoveErrors: []string{}}
	after := tables
	n := &Net{cfg: Config{Node: c.node, PrivateIP: c.ip, Key: PrivateKey{k: c.key}}, nextClean: clean.Next, siteClean: clean.Site}
	if p, err := n.plan(c.cfg); err != nil {
		a.PlanError = err.Error()
	} else {
		sim := newIptablesSim(tables, fail)
		iptables = iptablesCmd{fake: sim.exec}
		if err := n.firewall(p); err != nil {
			a.Error = err.Error()
		}
		a.Calls, a.Clean, after = sim.calls, cleanJSON{Next: n.nextClean, Site: n.siteClean}, sim.state()
	}
	sim := newIptablesSim(tables, fail)
	for _, err := range removeFirewall(iptablesCmd{fake: sim.exec}) {
		if err != nil {
			a.RemoveErrors = append(a.RemoveErrors, err.Error())
		}
	}
	a.RemoveCalls = sim.calls
	return a, after
}

// The calls that fail in some cases, as the model sees them.
var simFailures = []string{
	"-t filter -N ARMADA-NET-IN", "-t raw -F ARMADA-NET-PRE", "-t nat -I POSTROUTING 1 -o armada-net -j RETURN",
	"-D INPUT -p udp -m udp --dport 4789 -j ARMADA-NET-IN", "-F ARMADA-NET-FWD", "-X ARMADA-NET-MESH",
	"-t mangle -C FORWARD -j ARMADA-NET-MSS", "-t filter -L ARMADA-NET-MESH -n", "-t filter -F ARMADA-NET-MESH",
}

// perturb changes the tables a firewall left as a node's would drift: a
// rule gone, a chain gone, old jumps and returns left behind.
func perturb(r *rand.Rand, tables map[string][]simChain) {
	add := func(table, chain, rule string) {
		for i := range tables[table] {
			if tables[table][i].Name == chain {
				tables[table][i].Rules = append(tables[table][i].Rules, rule)
			}
		}
	}
	switch r.IntN(8) {
	case 0:
		for table := range tables {
			for i := range tables[table] {
				if rs := tables[table][i].Rules; len(rs) > 0 && r.IntN(3) == 0 {
					j := r.IntN(len(rs))
					tables[table][i].Rules = slices.Delete(slices.Clone(rs), j, j+1)
				}
			}
		}
	case 1:
		add("filter", "INPUT", "-p udp -m udp --dport 9999 -j ARMADA-NET-IN")
		add("filter", "INPUT", "-p udp -m udp --dport 4789 -j ARMADA-NET-IN")
	case 2:
		add("nat", "POSTROUTING", "-o armada-next -j RETURN")
		add("nat", "POSTROUTING", "-o armada-next -j RETURN")
		add("nat", "POSTROUTING", "-o armada-wg -j RETURN")
	case 3:
		add("filter", "INPUT", "-i armada-wg -j ARMADA-NET-MESH")
		add("filter", "INPUT", "-i armada-net -j ARMADA-NET-MESH")
	case 4:
		for table := range tables {
			tables[table] = slices.DeleteFunc(slices.Clone(tables[table]), func(c simChain) bool { return !c.Builtin && r.IntN(2) == 0 })
		}
	}
}

// armada-node net firewall iptables must run the iptables commands this
// package runs, in order, against the same state: the plan cases one after
// another, each from what the one before left, drifted now and then, with
// failures mixed in.
func TestArmadaNodeIptablesMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	cases := namedNetCases(t)
	r := rand.New(rand.NewPCG(8, 9))
	const random = 600
	for i := range random {
		cases = append(cases, randomNetCase(t, r, i))
	}
	tables := emptyTables()
	compared, failed, planned := 0, 0, 0
	for _, c := range cases {
		if r.IntN(10) == 0 {
			tables = emptyTables()
		}
		perturb(r, tables)
		clean := cleanJSON{Next: r.IntN(2) == 0, Site: r.IntN(2) == 0}
		fail := []string{}
		if r.IntN(6) == 0 {
			fail = []string{simFailures[r.IntN(len(simFailures))]}
		}
		var req map[string]any
		if err := json.Unmarshal(c.request(t), &req); err != nil {
			t.Fatal(err)
		}
		req["Clean"], req["Tables"], req["Fail"] = clean, tables, fail
		in, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		got, err := runNode(t, bin, in, "net", "firewall", "iptables")
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		want, after := goIptables(c, clean, tables, fail)
		if w := canonicalJSON(want); !bytes.Equal(got, w) {
			t.Fatalf("%s: armada-node and Go differ:\n armada-node: %s\n Go:          %s", c.name, got, w)
		}
		compared++
		if want.PlanError == "" {
			planned++
		}
		if want.Error != "" || len(want.RemoveErrors) > 0 {
			failed++
		}
		tables = after
	}
	if failed == 0 || planned < 100 {
		t.Errorf("only %d cases with a plan and %d with failures", planned, failed)
	}
	t.Logf("%d cases compared (%d planned, %d with failing calls)", compared, planned, failed)
}
