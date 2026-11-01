package containerd

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"

	"github.com/ryanbekhen/armada/internal/runtime"
)

func genSpec(t *testing.T, opts ...oci.SpecOpts) *oci.Spec {
	t.Helper()
	ctx := namespaces.WithNamespace(context.Background(), "test")
	s, err := oci.GenerateSpecWithPlatform(ctx, nil, "linux/amd64", &containers.Container{ID: "armada-web-1"},
		append([]oci.SpecOpts{oci.WithProcessArgs("/app", "serve")}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAppSpecDefaults(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "db")
	s := genSpec(t, appOpts(appSpec{
		spec: runtime.ContainerSpec{
			Name: "armada-web-1", Env: []string{"A=1"},
			MemoryBytes: 256 << 20, NanoCPUs: 500_000_000, PidsLimit: 100,
			Files: []runtime.FileMount{{Source: secret, Target: "/run/secrets/db"}},
		},
		netns: "/run/armada/netns/cni-1",
		files: containerFiles{resolv: "/d/resolv.conf", hosts: "/d/hosts", hostname: "/d/hostname"},
		tini:  "/opt/tini", cgroup: "/armada/armada-web-1",
	})...)

	if got := s.Process.Args; !slices.Equal(got, []string{initPath, "--", "/app", "serve"}) {
		t.Errorf("args %v", got)
	}
	if !s.Process.NoNewPrivileges {
		t.Error("no-new-privileges not set")
	}
	for _, c := range []string{"CAP_NET_RAW", "CAP_MKNOD", "CAP_AUDIT_WRITE", "CAP_SYS_ADMIN"} {
		if slices.Contains(s.Process.Capabilities.Bounding, c) || slices.Contains(s.Process.Capabilities.Effective, c) {
			t.Errorf("capability %s kept", c)
		}
	}
	if !slices.Contains(s.Process.Capabilities.Bounding, "CAP_NET_BIND_SERVICE") {
		t.Error("default capabilities missing")
	}
	r := s.Linux.Resources
	if *r.Memory.Limit != 256<<20 || *r.Memory.Swap != 256<<20 {
		t.Errorf("memory %d swap %d", *r.Memory.Limit, *r.Memory.Swap)
	}
	if *r.CPU.Quota != 50000 || *r.CPU.Period != cpuPeriod {
		t.Errorf("cpu quota %d period %d", *r.CPU.Quota, *r.CPU.Period)
	}
	if r.Pids.Limit == nil || *r.Pids.Limit != 100 {
		t.Errorf("pids %v", r.Pids)
	}
	if s.Linux.CgroupsPath != "/armada/armada-web-1" {
		t.Errorf("cgroup %s", s.Linux.CgroupsPath)
	}
	var netns string
	for _, ns := range s.Linux.Namespaces {
		if ns.Type == "network" {
			netns = ns.Path
		}
	}
	if netns != "/run/armada/netns/cni-1" {
		t.Errorf("network namespace %q", netns)
	}
	mounts := map[string][]string{}
	for _, m := range s.Mounts {
		mounts[m.Destination] = m.Options
	}
	for _, dst := range []string{"/etc/resolv.conf", "/etc/hosts", "/etc/hostname", "/run/secrets/db", initPath} {
		if !slices.Contains(mounts[dst], "ro") {
			t.Errorf("mount %s: options %v", dst, mounts[dst])
		}
	}
	if !slices.Contains(mounts["/run/secrets/db"], "noexec") || slices.Contains(mounts[initPath], "noexec") {
		t.Error("wrong noexec placement")
	}
	if !slices.Contains(s.Process.Env, "A=1") || s.Hostname != "armada-web-1" {
		t.Errorf("env %v hostname %s", s.Process.Env, s.Hostname)
	}
	if s.Root.Readonly {
		t.Error("app rootfs must stay writable")
	}
}

func TestSystemSpec(t *testing.T) {
	s := genSpec(t, systemOpts(runtime.SystemSpec{
		Name: "armada-haproxy", User: "0:0", CapAdd: []string{"NET_BIND_SERVICE"},
		Mounts: []runtime.Mount{{Source: "/etc/armada/haproxy", Target: "/usr/local/etc/haproxy", ReadOnly: true}, {Source: "/run/armada/haproxy", Target: "/var/run/haproxy"}},
	}, "/armada/armada-haproxy", nil)...)
	if !slices.Equal(s.Process.Capabilities.Bounding, []string{"CAP_NET_BIND_SERVICE"}) {
		t.Errorf("capabilities %v", s.Process.Capabilities.Bounding)
	}
	if !s.Root.Readonly || !s.Process.NoNewPrivileges {
		t.Error("system container must have a read-only rootfs and no-new-privileges")
	}
	for _, ns := range s.Linux.Namespaces {
		if ns.Type == "network" {
			t.Error("system container must use the host network")
		}
	}
	if len(s.Process.Rlimits) != 1 || s.Process.Rlimits[0].Hard != nofile {
		t.Errorf("rlimits %v", s.Process.Rlimits)
	}
}

func TestArgsWithoutCommand(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "test")
	if _, err := oci.GenerateSpecWithPlatform(ctx, nil, "linux/amd64", &containers.Container{ID: "x"}, withInit); err == nil {
		t.Error("accepted a container without a command")
	}
}

func TestResolvConf(t *testing.T) {
	host := []byte("nameserver 127.0.0.53\nsearch example.internal\noptions edns0 trust-ad\n")
	got := string(resolvConf(host, nil))
	if !strings.HasPrefix(got, "nameserver 8.8.8.8\nnameserver 8.8.4.4\n") || !strings.Contains(got, "search example.internal\n") || strings.Contains(got, "127.0.0.53") {
		t.Errorf("loopback host conf: %q", got)
	}
	got = string(resolvConf([]byte("nameserver 10.0.0.2\nnameserver ::1\n"), nil))
	if got != "nameserver 10.0.0.2\n" {
		t.Errorf("host servers: %q", got)
	}
	got = string(resolvConf([]byte("nameserver 10.0.0.2\n"), []string{"10.121.0.1"}))
	if got != "nameserver 10.121.0.1\n" {
		t.Errorf("explicit DNS: %q", got)
	}
}

func TestWriteFiles(t *testing.T) {
	dir := t.TempDir()
	f, err := writeFiles(dir, "armada-web-1-0a1b2c3d", "armada-web-1", "10.121.0.5", []string{"10.121.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f.hosts)
	if !strings.Contains(string(b), "10.121.0.5\tarmada-web-1\n") {
		t.Errorf("hosts %q", b)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "armada-web-1-0a1b2c3d")); fi.Mode().Perm() != 0o700 {
		t.Errorf("container dir mode %v", fi.Mode())
	}
}

func TestPickPort(t *testing.T) {
	used := map[int]bool{}
	for p := portMin; p <= portMax; p++ {
		used[p] = true
	}
	delete(used, 25000)
	p, err := pickPort("10.0.0.6", used, func(string, int) bool { return true })
	if err != nil || p != 25000 {
		t.Errorf("got %d %v", p, err)
	}
	if _, err := pickPort("10.0.0.6", nil, func(string, int) bool { return false }); err == nil {
		t.Error("no error when every port is taken")
	}
}

func TestCredentials(t *testing.T) {
	if credentials(nil) != nil {
		t.Error("credentials without auth")
	}
	hub := credentials(&runtime.RegistryAuth{Username: "u", Password: "p", ServerAddress: "https://index.docker.io/v1/"})
	if u, p, _ := hub("registry-1.docker.io"); u != "u" || p != "p" {
		t.Error("Docker Hub alias not matched")
	}
	if u, _, _ := hub("ghcr.io"); u != "" {
		t.Error("credentials sent to another registry")
	}
	gh := credentials(&runtime.RegistryAuth{Username: "u", Password: "p", ServerAddress: "GHCR.io"})
	if u, _, _ := gh("ghcr.io"); u != "u" {
		t.Error("ghcr.io not matched")
	}
	if u, _, _ := gh("ghcr.io.evil.example"); u != "" {
		t.Error("suffix host matched")
	}
}

func TestNormalize(t *testing.T) {
	ref, fam, dig, err := normalize("nginx:1.27")
	if err != nil || ref != "docker.io/library/nginx:1.27" || fam != "nginx" || dig {
		t.Errorf("%s %s %v %v", ref, fam, dig, err)
	}
	d := "sha256:" + strings.Repeat("a", 64)
	ref, fam, dig, err = normalize("ghcr.io/o/app:v1@" + d)
	if err != nil || ref != "ghcr.io/o/app@"+d || fam != "ghcr.io/o/app" || !dig {
		t.Errorf("%s %s %v %v", ref, fam, dig, err)
	}
	for _, bad := range []string{"", "nginx@sha256:short", "a b", "repo/UPPER"} {
		if _, _, _, err := normalize(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestBridgeAndCNIConfig(t *testing.T) {
	b, err := BridgeOf(netip.MustParsePrefix("10.121.0.0/24"))
	if err != nil || b.Gateway.String() != "10.121.0.1" {
		t.Fatalf("%+v %v", b, err)
	}
	for _, bad := range []string{"8.8.8.0/24", "10.0.0.0/30", "fd00::/64"} {
		if _, err := BridgeOf(netip.MustParsePrefix(bad)); err == nil {
			t.Errorf("accepted subnet %s", bad)
		}
	}
	raw, err := cniConfig(b, "/run/armada/cni/ipam")
	if err != nil {
		t.Fatal(err)
	}
	var conf struct {
		Plugins []map[string]any `json:"plugins"`
	}
	if err := json.Unmarshal(raw, &conf); err != nil || len(conf.Plugins) != 3 {
		t.Fatalf("%s %v", raw, err)
	}
	if !strings.Contains(string(raw), `"routes":[{"dst":"0.0.0.0/0"}]`) {
		t.Errorf("no default route: %s", raw)
	}
	pm := portMappings(&portMapping{HostIP: "10.0.0.6", HostPort: 21000, ContainerPort: 8080})
	if pm[0]["hostIP"] != "10.0.0.6" {
		t.Errorf("port mapping %v", pm)
	}
	if portMappings(nil) != nil {
		t.Error("mapping without a port")
	}
}

func TestLabelsRoundTrip(t *testing.T) {
	l := map[string]string{labelHostIP: "10.0.0.6", labelHostPort: "21000", labelPort: "8080"}
	if pm := mappingFromLabels(l); pm == nil || pm.HostPort != 21000 || pm.ContainerPort != 8080 {
		t.Errorf("%+v", pm)
	}
	if mappingFromLabels(map[string]string{}) != nil {
		t.Error("mapping from empty labels")
	}
	if !matches(map[string]string{"a": "1", "b": "2"}, map[string]string{"a": "1"}) || matches(map[string]string{}, map[string]string{"a": "1"}) {
		t.Error("label matching")
	}
}

func TestNewID(t *testing.T) {
	a, err := newID("armada-web-1")
	b, _ := newID("armada-web-1")
	if err != nil || a == b || !strings.HasPrefix(a, "armada-web-1-") {
		t.Errorf("%q %q %v", a, b, err)
	}
	for _, bad := range []string{"", "../x", "a/b"} {
		if _, err := newID(bad); err == nil {
			t.Errorf("accepted name %q", bad)
		}
	}
}
