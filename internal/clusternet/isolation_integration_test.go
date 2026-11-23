//go:build integration && linux

package clusternet

import (
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"os/exec"
	"slices"
	"sort"
	"testing"
	"time"
)

// dumpRules returns the isolation tables in a form that compares by meaning:
// without handles, with rules in order and set elements sorted.
func dumpRules(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("nft", "-j", "list", "ruleset").Output()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Nftables []map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, item := range doc.Nftables {
		if _, meta := item["metainfo"]; meta {
			continue
		}
		strip(item)
		b, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(b))
	}
	sort.Stable(sort.StringSlice(lines))
	return fmt.Sprint(lines)
}

func strip(v any) {
	switch x := v.(type) {
	case map[string]any:
		delete(x, "handle")
		for k, c := range x {
			strip(c)
			if l, ok := c.([]any); ok && k == "elem" {
				sort.Slice(l, func(i, j int) bool {
					a, _ := json.Marshal(l[i])
					b, _ := json.Marshal(l[j])
					return string(a) < string(b)
				})
			}
		}
	case []any:
		for _, c := range x {
			strip(c)
		}
	}
}

func randomPolicy(r *rand.Rand) policy {
	pol := policy{
		cidr:    netip.MustParsePrefix("10.120.0.0/16"),
		subnet:  netip.MustParsePrefix("10.120.0.0/24"),
		gateway: netip.MustParseAddr("10.120.0.1"),
		members: map[string][]netip.Addr{},
		nodes:   []netip.Addr{netip.MustParseAddr("10.52.9.2"), netip.MustParseAddr("10.52.9.3")},
	}
	used := map[netip.Addr]bool{}
	for i := range 12 {
		if r.IntN(3) == 0 {
			continue
		}
		app := fmt.Sprintf("app%d.p%d", i, i%3)
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
	// Internal TCP ports (ADR 0039); always some, which keeps the frame.
	for range 1 + r.IntN(3) {
		pol.tcpPorts = append(pol.tcpPorts, uint16(5000+r.IntN(6)))
	}
	slices.Sort(pol.tcpPorts)
	pol.tcpPorts = slices.Compact(pol.tcpPorts)
	return pol
}

// Whatever the changes, updating in place ends with exactly the rules a rebuild
// makes. Run it as root in its own network namespace, on a machine with nft:
//
//	go test -c -tags integration ./internal/clusternet -o t
//	ip netns add t; ip netns exec t ./t -test.run IsolationUpdate
func TestIsolationUpdateMatchesRebuild(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 27))
	cur := randomPolicy(r)
	if err := isolate(cur); err != nil {
		t.Fatal(err)
	}
	prev := dumpRules(t)
	changes := 0
	for round := range 200 {
		next := randomPolicy(r)
		if err := updateIsolation(cur, next); err != nil {
			t.Fatalf("round %d: %v\nfrom %+v\nto %+v", round, err, cur, next)
		}
		got := dumpRules(t)
		if err := isolate(next); err != nil {
			t.Fatal(err)
		}
		if want := dumpRules(t); got != want {
			t.Fatalf("round %d: the update left other rules than a rebuild:\n%s\n---\n%s", round, got, want)
		}
		// The comparison sees a change at all.
		if got != prev {
			changes++
		}
		prev = got
		cur = next
	}
	if changes < 190 {
		t.Errorf("the rules changed in only %d of 200 rounds: the dump misses what matters", changes)
	}
}

// How long a replica that comes or goes takes at the size of a large cluster.
func TestIsolationUpdateTime(t *testing.T) {
	pol := policy{
		cidr:    netip.MustParsePrefix("10.120.0.0/16"),
		subnet:  netip.MustParsePrefix("10.120.0.0/24"),
		gateway: netip.MustParseAddr("10.120.0.1"),
		members: map[string][]netip.Addr{},
		nodes:   []netip.Addr{netip.MustParseAddr("10.52.9.2")},
	}
	for i := range 1000 {
		app := fmt.Sprintf("app%d.p%d", i, i%20)
		pol.apps = append(pol.apps, app)
		pol.members[app] = []netip.Addr{netip.AddrFrom4([4]byte{10, 120, byte(i / 250), byte(2 + i%250)})}
	}
	slices.Sort(pol.apps)
	start := time.Now()
	if err := isolate(pol); err != nil {
		t.Fatal(err)
	}
	t.Logf("rebuild at 1000 apps: %s", time.Since(start))
	next := pol
	next.members = maps.Clone(pol.members)
	next.apps = append(slices.Clone(pol.apps), "new.p0")
	slices.Sort(next.apps)
	next.members["new.p0"] = []netip.Addr{netip.MustParseAddr("10.120.9.9")}
	start = time.Now()
	if err := updateIsolation(pol, next); err != nil {
		t.Fatal(err)
	}
	t.Logf("update, one new app at 1000: %s", time.Since(start))
	start = time.Now()
	if err := updateIsolation(next, pol); err != nil {
		t.Fatal(err)
	}
	t.Logf("update, one app gone at 1000: %s", time.Since(start))
}

// largePolicy has n container addresses over the cluster CIDR in apps of
// about perApp replicas, and many open containers.
func largePolicy(n, shift, perApp int) policy {
	cidr := netip.MustParsePrefix("10.96.0.0/11")
	pol := policy{cidr: cidr, subnet: netip.MustParsePrefix("10.96.0.0/24"), gateway: netip.MustParseAddr("10.96.0.1"), members: map[string][]netip.Addr{}}
	base := cidr.Addr().As4()
	for i := range n {
		v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
		v += uint32(300 + i + shift)
		addr := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		app := fmt.Sprintf("app%d", i/perApp)
		pol.members[app] = append(pol.members[app], addr)
	}
	pol.apps = slices.Sorted(maps.Keys(pol.members))
	for i := 2; i < 250; i++ {
		pol.open = append(pol.open, netip.AddrFrom4([4]byte{10, 96, 0, byte(i)}))
	}
	for i := range 2000 {
		pol.nodes = append(pol.nodes, netip.AddrFrom4([4]byte{10, 1, byte(i / 250), byte(1 + i%250)}))
	}
	return pol
}

// elements counts the elements of every set and map in the ip table.
func elements(t *testing.T) map[string]int {
	t.Helper()
	out, err := exec.Command("nft", "-j", "list", "table", "ip", isolationTable).Output()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Nftables []map[string]struct {
			Name string `json:"name"`
			Elem []any  `json:"elem"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, item := range doc.Nftables {
		for _, kind := range []string{"set", "map"} {
			if s, ok := item[kind]; ok {
				got[s.Name] = len(s.Elem)
			}
		}
	}
	return got
}

// Sets and maps of any size reach the kernel whole: one netlink message
// carries only so many elements (maxSetElements).
func TestIsolationLargeSets(t *testing.T) {
	t.Cleanup(func() { _ = removeIsolation() })
	check := func(pol policy) {
		t.Helper()
		got := elements(t)
		total := 0
		for _, app := range pol.apps {
			total += len(pol.members[app])
			if set, _ := appNames(app); got[set] != len(pol.members[app]) {
				t.Fatalf("set of %s holds %d of %d addresses", app, got[set], len(pol.members[app]))
			}
		}
		if got["dst"] != total || got["open"] != len(pol.open) || got["nodes"] != len(pol.nodes) {
			t.Fatalf("dst %d of %d, open %d of %d, nodes %d of %d", got["dst"], total, got["open"], len(pol.open), got["nodes"], len(pol.nodes))
		}
	}
	for _, n := range []int{1500, 6000, 20000} {
		pol := largePolicy(n, 0, 400)
		if err := isolate(pol); err != nil {
			t.Fatalf("%d addresses: %v", n, err)
		}
		check(pol)
	}
	// In place: thousands of addresses leave and come.
	old := largePolicy(20000, 0, 400)
	pol := largePolicy(20000, 5000, 400)
	if !sameFrame(old, pol) {
		t.Fatal("not the same frame")
	}
	if err := updateIsolation(old, pol); err != nil {
		t.Fatal(err)
	}
	check(pol)
}
