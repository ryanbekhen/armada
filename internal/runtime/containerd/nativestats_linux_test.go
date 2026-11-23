package containerd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/supervisor"
)

// statsFixture is a supervisor store's containers as files: bundles
// (records and specs), cgroups, /proc/PID/net/dev, and one stand-in shim
// per group answering "state ID".
type statsFixture struct {
	dir, shimDir, cgroups, proc string
}

type fixtureContainer struct {
	id, group string
	labels    map[string]string
	state     string // the shim's answer to "state ID"
	cgroup    map[string]string
	cgroupsAt string // the spec's cgroupsPath; "-" for none
	pid       int
	netDev    string
}

func newStatsFixture(t *testing.T, cs []fixtureContainer) statsFixture {
	t.Helper()
	root := t.TempDir()
	f := statsFixture{dir: filepath.Join(root, "b"), shimDir: filepath.Join(root, "s"), cgroups: filepath.Join(root, "cg"), proc: filepath.Join(root, "p")}
	write := func(p, s string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	answers := map[string]map[string]string{}
	for _, c := range cs {
		rec, _ := json.Marshal(map[string]any{"id": c.id, "image": "x", "labels": c.labels, "group": c.group, "created": "2026-11-23T08:00:00Z"})
		write(filepath.Join(f.dir, c.id, "record.json"), string(rec))
		spec := map[string]any{"ociVersion": "1.2.0"}
		if c.cgroupsAt != "-" {
			at := c.cgroupsAt
			if at == "" {
				at = "/armada/" + c.id
			}
			spec["linux"] = map[string]any{"cgroupsPath": at}
		}
		b, _ := json.Marshal(spec)
		write(filepath.Join(f.dir, c.id, "config.json"), string(b))
		for name, body := range c.cgroup {
			write(filepath.Join(f.cgroups, "armada", c.id, name), body)
		}
		if c.netDev != "" {
			write(filepath.Join(f.proc, fmt.Sprint(c.pid), "net", "dev"), c.netDev)
		}
		if answers[c.group] == nil {
			answers[c.group] = map[string]string{}
		}
		answers[c.group]["state "+c.id] = c.state
	}
	for group, a := range answers {
		sock := (&supervisor.Shims{Dir: f.shimDir}).Get(group).Socket
		if err := os.MkdirAll(f.shimDir, 0o700); err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				line, _ := bufio.NewReader(conn).ReadString('\n')
				answer, ok := a[strings.TrimSpace(line)]
				if !ok {
					answer = "err container not found"
				}
				_, _ = conn.Write([]byte(answer + "\n"))
				_ = conn.Close()
			}
		}()
	}
	return f
}

// driver is a driver on the fixture's store, with armada-node at bin
// (none: Go's code).
func (f statsFixture) driver(t *testing.T, bin string) (*Driver, *supervisor.Native) {
	t.Helper()
	st := &supervisor.Store{Bundles: supervisor.Bundles{Dir: f.dir}, Shims: &supervisor.Shims{Dir: f.shimDir}, CgroupRoot: f.cgroups}
	d := &Driver{ctr: st}
	if bin != "" {
		n, err := supervisor.OpenNative(bin, filepath.Join(t.TempDir(), "images"))
		if err != nil {
			t.Fatal(err)
		}
		st.Native, st.Shims.Native, d.native = n, n, n
	}
	return d, d.native
}

func cgroupFiles(usage, inactive, current, oom string) map[string]string {
	return map[string]string{
		"cpu.stat":       "usage_usec " + usage + "\nuser_usec 1\nsystem_usec 2\n",
		"memory.stat":    "anon 5\nfile 6\ninactive_file " + inactive + "\nactive_file 7\n",
		"memory.events":  "low 0\nhigh 0\nmax 0\noom 1\noom_kill " + oom + "\n",
		"memory.current": current + "\n",
	}
}

const netDevEth0 = "Inter-|   Receive                                                |  Transmit\n" +
	" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
	"    lo:    1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0\n" +
	"  eth0:   52000     300    0    0    0     0          0         0    41000     250    0    0    0     0       0          0\n"

// armada-node's runtime stats samples what the driver's Stats samples, for
// every container of a round in one call: CPU, memory without inactive
// file pages, out-of-memory kills, egress and a lost interface from
// /proc/PID/net/dev, a replica's members added, missing containers and
// tasks as not found; what Go words as an error, Go samples itself.
func TestArmadaNodeStatsMatchesGo(t *testing.T) {
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		t.Skip("ARMADA_NODE_BIN names no armada-node to compare with")
	}
	old := procRoot
	t.Cleanup(func() { procRoot = old })
	app := map[string]string{"armada.runtime/kind": "app"}
	member := func(pod string) map[string]string {
		return map[string]string{"armada.runtime/kind": "member", "armada.runtime/pod": pod}
	}
	cs := []fixtureContainer{
		{id: "web-r1-a", group: "web", labels: app, state: "ok running 100", pid: 100, cgroup: cgroupFiles("2500000", "1024", "40960", "0"), netDev: netDevEth0},
		{id: "web-r1-a-side", group: "web", labels: member("web-r1-a"), state: "ok running 101", pid: 101, cgroup: cgroupFiles("500000", "0", "8192", "2"), netDev: netDevEth0},
		{id: "web-r1-a-init", group: "web", labels: member("web-r1-a"), state: "ok exited 0", cgroup: cgroupFiles("100", "0", "4096", "0")},
		{id: "web-r1-a-gone", group: "web", labels: member("web-r1-a"), state: "err container web-r1-a-gone not found"},
		{id: "web-r1-a-nocg", group: "web", labels: member("web-r1-a"), state: "ok running 103", pid: 103},
		// Odd files: CRLF lines, a signed number, a key twice, inactive
		// pages above the usage, and no eth0 (a lost interface).
		{id: "odd", group: "odd", state: "ok running 200", pid: 200, cgroup: map[string]string{
			"cpu.stat":       "usage_usec 7\r\nusage_usec 9\r\nuser_usec +3\nsystem_usec\n",
			"memory.stat":    "inactive_file 9999\n",
			"memory.events":  "oom_kill 18446744073709551615",
			"memory.current": "  100\t\n",
		}, netDev: "Inter-|\n face |\n    lo: 1 2 3 4 5 6 7 8 9 10\n"},
		{id: "huge", group: "odd", state: "ok created 201", pid: 201, cgroup: cgroupFiles("18446744073709551615", "0", "18446744073709551615", "5"),
			netDev: "eth0: 0 0 0 0 0 0 0 0 99999999999999999999\n"},
		{id: "negative-pid", group: "odd", state: "ok running -4", cgroup: cgroupFiles("1", "0", "1", "0")},
		{id: "exited", group: "odd", state: "ok exited 137", cgroup: cgroupFiles("3", "0", "3", "1")},
		{id: "notask", group: "odd", state: "err container notask not found"},
		{id: "nocgroup", group: "odd", state: "ok running 300", pid: 300},
		{id: "badcurrent", group: "odd", state: "ok running 301", pid: 301, cgroup: map[string]string{"cpu.stat": "", "memory.stat": "", "memory.events": "", "memory.current": "lots"}},
		{id: "longline", group: "odd", state: "ok running 302", pid: 302, cgroup: map[string]string{"cpu.stat": strings.Repeat("x", 70000) + "\n", "memory.stat": "", "memory.events": "", "memory.current": "1"}},
		{id: "nospec", group: "odd", state: "ok running 303", pid: 303, cgroupsAt: "-"},
		{id: "shimerr", group: "odd", state: "err busy"},
		{id: "oddstate", group: "odd2", state: "ok paused 1"},
		{id: "escape", group: "odd", state: "ok running 304", pid: 304, cgroupsAt: "../../armada/web-r1-a"},
	}
	f := newStatsFixture(t, cs)
	procRoot = f.proc
	ids := []string{"missing"}
	for _, c := range cs {
		ids = append(ids, c.id)
	}
	// Go words these as errors, or (oddstate) would abandon the shim:
	// left to Go. Abandoning runs systemctl; the stand-in at the
	// fixture's path is not there, which Go reports as an error too.
	redo := []string{"web-r1-a-nocg", "nocgroup", "badcurrent", "longline", "nospec", "shimerr", "oddstate"}

	goDrv, _ := f.driver(t, "")
	goDrv.ctr.(*supervisor.Store).Shims.Systemctl = filepath.Join(t.TempDir(), "systemctl")
	nodeDrv, n := f.driver(t, bin)
	nodeDrv.ctr.(*supervisor.Store).Shims.Systemctl = goDrv.ctr.(*supervisor.Store).Shims.Systemctl
	ctx := context.Background()
	stats, errs := nodeDrv.StatsBatch(ctx, ids)
	for i, id := range ids {
		want, werr := goDrv.Stats(ctx, id)
		if stats[i] != want || errText(errs[i]) != errText(werr) || errors.Is(errs[i], runtime.ErrNotFound) != errors.Is(werr, runtime.ErrNotFound) {
			t.Errorf("%s:\n go   %+v %v\n rust %+v %v", id, want, werr, stats[i], errs[i])
		}
	}
	if got := n.StoodIn("stats"); got != len(redo) {
		t.Errorf("Go sampled %d containers, want %d (%v)", got, len(redo), redo)
	}
	// A sample that is all there is to check.
	if stats[1].CPU.Microseconds() != 3000100 || stats[1].MemoryBytes != 40960-1024+8192+4096 || stats[1].OOMKills != 2 || stats[1].EgressBytes != 41000 {
		t.Errorf("web-r1-a: %+v", stats[1])
	}
	if stats[7].CPU != math.MaxInt64/1000*1000 {
		t.Errorf("huge CPU %d", stats[7].CPU)
	}

	// Stats alone goes through the same call.
	before := n.StoodIn("stats")
	if st, err := nodeDrv.Stats(ctx, "odd"); err != nil || st != stats[6] || n.StoodIn("stats") != before {
		t.Errorf("Stats(odd) = %+v, %v", st, err)
	}

	// Without armada-node at its path, Go samples every container.
	gone, _ := f.driver(t, filepath.Join(t.TempDir(), "armada-node"))
	gone.ctr.(*supervisor.Store).Shims.Systemctl = goDrv.ctr.(*supervisor.Store).Shims.Systemctl
	if st, err := gone.Stats(ctx, "web-r1-a"); err != nil || st != stats[1] {
		t.Errorf("fallback: %+v, %v", st, err)
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
