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
	return pol
}

// Whatever the changes, updating in place ends with exactly the rules a rebuild
// makes. Run it as root in its own network namespace, on a machine with nft:
//
//	go test -c -tags integration ./internal/clusternet -o t
//	ip netns add t; ip netns exec t ./t -test.run IsolationUpdate
func TestIsolationUpdateMatchesRebuild(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 27)) //nolint:gosec // a repeatable test
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
