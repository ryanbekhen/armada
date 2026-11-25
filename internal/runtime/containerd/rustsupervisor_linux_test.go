//go:build linux

package containerd

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
	"github.com/ryanbekhen/armada/internal/runtime/supervisor"
)

// The Rust agent's supervisor runtime (agent/src/supervisor, ADR 0055
// item 16e) is checked against this driver through what testdata/rust
// keeps: the CNI plugins' calls (each one's environment and input) and
// libcni's cache files for a container attached with a port and one
// attached at a given namespace, then released (cni.json); the container
// files (files.json); and List and Inspect over bundles written by Go's
// Bundles with stand-in shims answering (containers.json). The Rust tests
// (supervisor::parity) replay them. go test -update rewrites the files.

var update = flag.Bool("update", false, "rewrite testdata/rust")

const rsRoot = "ROOT"

// rsPluginResult is what every stand-in plugin answers ADD with (the
// Rust tests' PLUGIN_RESULT).
const rsPluginResult = `{"cniVersion":"1.0.0","interfaces":[{"name":"armada0","mac":"02:41:0a:79:00:01"},{"name":"veth1","mac":"aa:bb:cc:dd:ee:ff"},{"name":"eth0","mac":"0a:58:0a:79:00:05","sandbox":"NETNS"}],"ips":[{"interface":2,"address":"10.121.0.5/24","gateway":"10.121.0.1"}],"routes":[{"dst":"0.0.0.0/0"}],"dns":{}}`

// rsPlugins writes the stand-in plugins: each records "PLUGIN COMMAND ID
// NETNS IFNAME PATH ARGS" and its input as a numbered file in log.
func rsPlugins(t *testing.T, dir, log string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(log, 0o755); err != nil {
		t.Fatal(err)
	}
	result := strings.ReplaceAll(rsPluginResult, "NETNS", "%s")
	body := `#!/bin/sh
d=` + log + `
n=$(ls "$d" | wc -l)
f="$d/$(printf %03d "$n")"
{ echo "$(basename "$0") $CNI_COMMAND $CNI_CONTAINERID $CNI_NETNS $CNI_IFNAME $CNI_PATH $CNI_ARGS"; cat; } > "$f"
if [ "$CNI_COMMAND" = ADD ]; then printf '` + result + `' "$CNI_NETNS"; fi
`
	for _, p := range []string{"bridge", "portmap", "firewall", "loopback"} {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

type rsCall struct {
	Head  string `json:"head"`
	Input string `json:"input"`
}

func rsCalls(t *testing.T, log, root string) []rsCall {
	t.Helper()
	entries, err := os.ReadDir(log)
	if err != nil {
		t.Fatal(err)
	}
	var out []rsCall
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(log, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		head, input, _ := strings.Cut(string(b), "\n")
		out = append(out, rsCall{Head: strings.ReplaceAll(head, root, rsRoot), Input: strings.ReplaceAll(input, root, rsRoot)})
	}
	return out
}

// rsCache is a cache file with root replaced, also in the configuration
// it holds as base64.
func rsCache(cache, conf []byte, root string) string {
	s := strings.ReplaceAll(string(cache), base64.StdEncoding.EncodeToString(conf),
		base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(string(conf), root, rsRoot))))
	return strings.ReplaceAll(s, root, rsRoot)
}

type rsCNI struct {
	Calls    []rsCall `json:"calls"`
	Cache    string   `json:"cache"`
	CacheAt  string   `json:"cacheAt"`
	Address  string   `json:"address"`
	Forgot   []string `json:"forgot"`
	Released bool     `json:"released"`
}

// rsCompare compares got with testdata/rust/name, or writes it with
// -update.
func rsCompare(t *testing.T, name string, got any) {
	t.Helper()
	b, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	path := filepath.Join("testdata", "rust", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (go test -update writes it)", err)
	}
	if string(want) != string(b) {
		t.Fatalf("%s differs from what this driver does now (go test -update rewrites it, and the Rust test checks it):\n%s", path, b)
	}
}

// TestRustSupervisorCNI keeps what libcni does for the driver's network.
func TestRustSupervisorCNI(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	paths := embedded.Paths{DataDir: filepath.Join(root, "data"), RunDir: filepath.Join(root, "run")}
	log := filepath.Join(root, "cni-log")
	rsPlugins(t, filepath.Join(paths.Bin(), embedded.DirCNI), log)
	nw, err := newNetwork(paths, netip.MustParsePrefix("10.121.0.0/24"), 1450)
	if err != nil {
		t.Fatal(err)
	}
	n := nw.(*cniNetwork)
	var out rsCNI
	n.forget = func(a netip.Addr) error {
		out.Forgot = append(out.Forgot, a.String())
		return nil
	}
	// A container with a published port, its namespace gone by the time
	// it is released (the plugins then get no namespace).
	id, ns := "web-r1-0a0b0c0d", filepath.Join(paths.NetNS(), "cni-fake-0")
	pm := &portMapping{HostIP: "10.0.0.5", HostPort: 20001, ContainerPort: 8080}
	if _, err := n.cni.AddNetworkList(ctx, n.conf, n.runtimeConf(id, ns, pm)); err != nil {
		t.Fatal(err)
	}
	cache, err := os.ReadFile(filepath.Join(paths.CNI(), "cache", "results", "armada-"+id+"-eth0"))
	if err != nil {
		t.Fatal(err)
	}
	out.Cache = rsCache(cache, n.conf.Bytes, root)
	if err := n.Teardown(ctx, id, ns, pm); err != nil {
		t.Fatal(err)
	}
	// A namespace the caller made: attached with no port.
	id2, ns2 := "sandbox-q1", filepath.Join(root, "sandboxes", "q1")
	if _, err := n.SetupAt(ctx, id2, ns2); err != nil {
		t.Fatal(err)
	}
	cache, err = os.ReadFile(filepath.Join(paths.CNI(), "cache", "results", "armada-"+id2+"-eth0"))
	if err != nil {
		t.Fatal(err)
	}
	out.CacheAt = rsCache(cache, n.conf.Bytes, root)
	if out.Address, err = n.Address(id2, ns2); err != nil {
		t.Fatal(err)
	}
	if err := n.Teardown(ctx, id2, "", nil); err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(filepath.Join(paths.CNI(), "cache", "results", "armada-"+id2+"-eth0"))
	out.Released = os.IsNotExist(err)
	out.Calls = rsCalls(t, log, root)
	rsCompare(t, "cni.json", out)
}

type rsResolv struct {
	Host   string   `json:"host"`
	DNS    []string `json:"dns"`
	Search []string `json:"search"`
	Want   string   `json:"want"`
}

type rsFiles struct {
	Resolv    []rsResolv        `json:"resolv"`
	Hosts     map[string]string `json:"hosts"`
	Hostnames map[string]string `json:"hostnames"`
}

// TestRustSupervisorFiles keeps the container files the driver writes.
func TestRustSupervisorFiles(t *testing.T) {
	var out rsFiles
	for _, c := range []rsResolv{
		{Host: "nameserver 127.0.0.53\r\nsearch a.example b.example\noptions edns0 trust-ad\nsearch c.example .\n", Search: []string{"internal"}},
		{Host: "nameserver 10.0.0.2\nnameserver ::1\nnameserver fe80::1%eth0\nnameserver ::ffff:127.0.0.1\n"},
		{Host: "", DNS: []string{"10.121.0.1"}, Search: []string{"a", "b", "a", "c", "d", "e", "f", "g"}},
		{Host: "options ndots:2\nsearch x.example\n  search\tTAB.example  \nnameserver 10.9.9.9 extra\n", DNS: []string{"10.121.0.1"}, Search: []string{"space.internal", "internal"}},
		{Host: "# nameserver 10.1.1.1\nnameserver\nnameserver 1.1.1.1\nsearch .\n"},
	} {
		c.Want = string(resolvConf([]byte(c.Host), c.DNS, c.Search))
		out.Resolv = append(out.Resolv, c)
	}
	out.Hosts = map[string]string{}
	out.Hostnames = map[string]string{}
	for _, n := range []string{"web-r1", "_web_r1.", "a.b-", strings.Repeat("x", 70) + ".y", "api.space-r2"} {
		out.Hostnames[n] = hostname(n)
		out.Hosts[n] = string(hostsFile("10.121.0.7", hostname(n)))
	}
	out.Hosts[""] = string(hostsFile("", "web"))
	rsCompare(t, "files.json", out)
}

type rsMember struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	State     string `json:"state"`
	ExitCode  int    `json:"exitCode"`
	StartedAt string `json:"startedAt"`
}

type rsContainer struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Image      string            `json:"image"`
	Labels     map[string]string `json:"labels"`
	State      string            `json:"state"`
	ExitCode   int               `json:"exitCode"`
	HostIP     string            `json:"hostIP"`
	HostPort   int               `json:"hostPort"`
	IP         string            `json:"ip"`
	StartedAt  string            `json:"startedAt"`
	StartError string            `json:"startError"`
	Members    []rsMember        `json:"members"`
}

func rsTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func rsContainerOf(c runtime.Container) rsContainer {
	out := rsContainer{ID: c.ID, Name: c.Name, Image: c.Image, Labels: c.Labels, State: c.State, ExitCode: c.ExitCode,
		HostIP: c.HostIP, HostPort: c.HostPort, IP: c.IP, StartedAt: rsTime(c.StartedAt), StartError: c.StartError, Members: []rsMember{}}
	for _, m := range c.Members {
		out.Members = append(out.Members, rsMember{ID: m.ID, Name: m.Name, Role: m.Role, State: m.State, ExitCode: m.ExitCode, StartedAt: rsTime(m.StartedAt)})
	}
	return out
}

type rsContainers struct {
	// Files are the bundles' files, by path under the bundles' directory.
	Files map[string]string `json:"files"`
	// Shims answer each request line, by group.
	Shims map[string]map[string]string `json:"shims"`
	List  []rsContainer                `json:"list"`
	Web   []rsContainer                `json:"web"`
	// Inspect is every container's Inspect, by ID ("not found" for an
	// error).
	Inspect map[string]rsContainer `json:"inspect"`
}

// rsShim answers requests from a table, as a shim of the group would.
func rsShim(t *testing.T, sock string, answers map[string]string) {
	t.Helper()
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				a, ok := answers[strings.TrimSuffix(line, "\n")]
				if !ok {
					a = "err unknown request"
				}
				_, _ = c.Write([]byte(a + "\n"))
			}()
		}
	}()
}

// TestRustSupervisorContainers keeps what List and Inspect make of
// bundles Go wrote and of what their shims answer.
func TestRustSupervisorContainers(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	bundles := filepath.Join(root, "containers")
	shimDir := filepath.Join(root, "shim")
	if err := os.MkdirAll(shimDir, 0o700); err != nil {
		t.Fatal(err)
	}
	st := &supervisor.Store{
		Bundles: supervisor.Bundles{Dir: bundles},
		Shims:   &supervisor.Shims{Dir: shimDir, Bin: "/nonexistent/armada-shim", Runc: filepath.Join(root, "no-runc")},
	}
	d := &Driver{ctr: st}
	t0 := time.Date(2026, 11, 20, 10, 0, 0, 123456000, time.UTC)
	at := func(s int) string { return t0.Add(time.Duration(s) * time.Second).Format(time.RFC3339Nano) }
	app := func(name, kind string, extra map[string]string) map[string]string {
		l := map[string]string{"armada.managed": "true", labelKind: kind, labelName: name}
		maps.Copy(l, extra)
		return l
	}
	recs := []supervisor.Record{
		{ID: "web-r1-aaaa0001", Image: "docker.io/library/web:1", Group: "web@p", Created: t0, Labels: app("web-r1", "app", map[string]string{
			"armada.app": "web", "armada.replica": "web-r1", labelIP: "10.121.0.5", labelHostIP: "10.0.0.5", labelHostPort: "20001",
			labelPort: "8080", labelNetNS: "/run/armada/netns/cni-x", labelStarted: at(5)})},
		{ID: "armada-migrate-bbbb0002", Image: "docker.io/library/web:1", Group: "web@p", Created: t0, Labels: app("migrate", kindMember, map[string]string{
			"armada.app": "web", runtime.LabelRole: runtime.RoleInit, runtime.LabelContainer: "migrate", labelPod: "web-r1-aaaa0001", labelStarted: at(1)})},
		{ID: "armada-seed-bbbb0003", Image: "docker.io/library/web:1", Group: "web@p", Created: t0, Labels: app("seed", kindMember, map[string]string{
			"armada.app": "web", runtime.LabelRole: runtime.RoleInit, runtime.LabelContainer: "seed", labelPod: "web-r1-aaaa0001", labelStarted: at(2)})},
		{ID: "armada-proxy-cccc0004", Image: "docker.io/library/side:1", Group: "web@p", Created: t0, Labels: app("proxy", kindMember, map[string]string{
			"armada.app": "web", runtime.LabelRole: runtime.RoleSidecar, runtime.LabelContainer: "proxy", labelPod: "web-r1-aaaa0001", labelStarted: at(3)})},
		{ID: "api-r1-dddd0005", Image: "docker.io/library/api:2", Group: "api@p", Created: t0, Labels: app("api-r1", "app", map[string]string{
			"armada.app": "api", labelFailed: "sidecar log: create container: no", labelStarted: "not a time"})},
		{ID: "armada-haproxy-eeee0006", Image: "docker.io/library/haproxy:3", Group: "armada-haproxy-eeee0006", Created: t0, Labels: app("armada-haproxy", "system", map[string]string{
			runtime.LabelSystem: "haproxy", labelHostIP: "8.8.8.8", labelHostPort: "80"})},
		{ID: "armada-x-ffff0007", Image: "docker.io/library/web:1", Group: "armada-x-ffff0007", Created: t0, Labels: app("x", kindMember, map[string]string{
			runtime.LabelRole: runtime.RoleSidecar, runtime.LabelContainer: "x", labelPod: "gone-1111"})},
		{ID: "web-r2-aaaa0008", Image: "docker.io/library/web:1", Group: "web@p", Created: t0, Labels: app("", "app", map[string]string{"armada.app": "web"})},
	}
	spec := &specs.Spec{Version: specs.Version, Process: &specs.Process{Args: []string{"/app"}, Cwd: "/"}}
	for _, r := range recs {
		if _, err := st.Bundles.Create(r, spec, nil); err != nil {
			t.Fatal(err)
		}
	}
	// A record naming another container is left out.
	if err := os.MkdirAll(filepath.Join(bundles, "stray"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundles, "stray", "record.json"), []byte(`{"id":"other","image":"x","group":"g","created":"2026-11-20T10:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	shims := map[string]map[string]string{
		"web@p": {
			"list":                          "ok web-r1-aaaa0001 running:41 armada-migrate-bbbb0002 exited:0 armada-seed-bbbb0003 exited:0 armada-proxy-cccc0004 running:43 web-r2-aaaa0008 created:44",
			"state web-r1-aaaa0001":         "ok running 41",
			"state armada-migrate-bbbb0002": "ok exited 0",
			"state armada-seed-bbbb0003":    "ok exited 0",
			"state armada-proxy-cccc0004":   "ok running 43",
			"state web-r2-aaaa0008":         "ok created 44",
		},
		"armada-haproxy-eeee0006": {
			"list":                          "ok armada-haproxy-eeee0006 running:50",
			"state armada-haproxy-eeee0006": "ok running 50",
		},
		"armada-x-ffff0007": {
			"list":                    "ok",
			"state armada-x-ffff0007": "err container armada-x-ffff0007 not found",
		},
		// api@p has no shim: it is gone, and its container ended.
	}
	for g, a := range shims {
		rsShim(t, st.Shims.Get(g).Socket, a)
	}
	out := rsContainers{Files: map[string]string{}, Shims: shims, Inspect: map[string]rsContainer{}}
	err := filepath.WalkDir(bundles, func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(bundles, p)
		out.Files[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	all, err := d.List(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	for _, c := range all {
		out.List = append(out.List, rsContainerOf(c))
	}
	web, err := d.List(ctx, map[string]string{"armada.app": "web"})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(web, func(i, j int) bool { return web[i].ID < web[j].ID })
	for _, c := range web {
		out.Web = append(out.Web, rsContainerOf(c))
	}
	ids := []string{"nope"}
	for _, r := range recs {
		ids = append(ids, r.ID)
	}
	slices.Sort(ids)
	for _, id := range ids {
		c, err := d.Inspect(ctx, id)
		if err != nil {
			out.Inspect[id] = rsContainer{State: err.Error()}
			continue
		}
		out.Inspect[id] = rsContainerOf(c)
	}
	rsCompare(t, "containers.json", out)
}
