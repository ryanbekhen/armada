package containerd

import (
	"context"
	"encoding/json"
	"errors"
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
			MemoryBytes: 256 << 20, NanoCPUs: 500_000_000, CPUReserveMillis: 500, PidsLimit: 100,
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
	if r.CPU.Shares == nil || *r.CPU.Shares != 512 {
		t.Errorf("cpu shares %v, want 512 for 500m", r.CPU.Shares)
	}
	if r.Pids.Limit == nil || *r.Pids.Limit != 100 {
		t.Errorf("pids %v", r.Pids)
	}
	if s.Linux.CgroupsPath != "/armada/armada-web-1" {
		t.Errorf("cgroup %s", s.Linux.CgroupsPath)
	}
	var netns string
	var cgroupns bool
	for _, ns := range s.Linux.Namespaces {
		switch ns.Type {
		case "network":
			netns = ns.Path
		case "cgroup":
			cgroupns = ns.Path == ""
		}
	}
	if netns != "/run/armada/netns/cni-1" {
		t.Errorf("network namespace %q", netns)
	}
	if !cgroupns {
		t.Error("app container must get its own cgroup namespace")
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
	if !slices.Contains(mounts["/sys/fs/cgroup"], "ro") {
		t.Errorf("cgroup mount: options %v", mounts["/sys/fs/cgroup"])
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
	}, "/armada/armada-haproxy", nil, selinuxLabels{})...)
	if !slices.Equal(s.Process.Capabilities.Bounding, []string{"CAP_NET_BIND_SERVICE"}) {
		t.Errorf("capabilities %v", s.Process.Capabilities.Bounding)
	}
	if !s.Root.Readonly || !s.Process.NoNewPrivileges {
		t.Error("system container must have a read-only rootfs and no-new-privileges")
	}
	var cgroupns bool
	for _, ns := range s.Linux.Namespaces {
		switch ns.Type {
		case "network":
			t.Error("system container must use the host network")
		case "cgroup":
			cgroupns = ns.Path == ""
		}
	}
	if !cgroupns {
		t.Error("system container must get its own cgroup namespace")
	}
	if len(s.Process.Rlimits) != 1 || s.Process.Rlimits[0].Hard != nofile {
		t.Errorf("rlimits %v", s.Process.Rlimits)
	}
}

// Confined containers get their process and mount label; unconfined ones
// keep the runtime's label.
func TestSELinuxLabels(t *testing.T) {
	l := selinuxLabels{process: "system_u:system_r:container_t:s0:c1,c2", mount: "system_u:object_r:container_file_t:s0:c1,c2"}
	for name, opts := range map[string][]oci.SpecOpts{
		"app":    appOpts(appSpec{spec: runtime.ContainerSpec{Name: "web"}, selinux: l}),
		"system": systemOpts(runtime.SystemSpec{Name: "armada-haproxy"}, "/armada/x", nil, l),
	} {
		s := genSpec(t, opts...)
		if s.Process.SelinuxLabel != l.process || s.Linux.MountLabel != l.mount {
			t.Errorf("%s: labels %q %q", name, s.Process.SelinuxLabel, s.Linux.MountLabel)
		}
		if got := processLabel(s); got != l.process {
			t.Errorf("%s: processLabel = %q", name, got)
		}
	}
	s := genSpec(t, appOpts(appSpec{spec: runtime.ContainerSpec{Name: "web"}})...)
	if s.Process.SelinuxLabel != "" || s.Linux.MountLabel != "" || processLabel(s) != "" {
		t.Errorf("unconfined container labelled: %q %q", s.Process.SelinuxLabel, s.Linux.MountLabel)
	}
	if processLabel(nil) != "" {
		t.Error("processLabel(nil)")
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
	raw, err := cniConfig(b, "/run/armada/cni/ipam", 0)
	if err != nil {
		t.Fatal(err)
	}
	var conf struct {
		Plugins []map[string]any `json:"plugins"`
	}
	if err := json.Unmarshal(raw, &conf); err != nil || len(conf.Plugins) != 4 {
		t.Fatalf("%s %v", raw, err)
	}
	if !strings.Contains(string(raw), `"routes":[{"dst":"0.0.0.0/0"}]`) || strings.Contains(string(raw), `"mtu"`) {
		t.Errorf("no default route, or an MTU nobody asked for: %s", raw)
	}
	if raw, _ := cniConfig(b, "/run/armada/cni/ipam", 1400); !strings.Contains(string(raw), `"mtu":1400`) {
		t.Errorf("MTU not set: %s", raw)
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

func TestCPUShares(t *testing.T) {
	t.Parallel()
	for millis, want := range map[int64]uint64{1: 2, 10: 10, 100: 102, 1000: 1024, 64000: 65536, 1 << 40: 262144} {
		if got := cpuShares(millis); got != want {
			t.Errorf("cpuShares(%d) = %d, want %d", millis, got, want)
		}
	}
}

func TestBridgeMAC(t *testing.T) {
	t.Parallel()
	b, err := BridgeOf(netip.MustParsePrefix("10.121.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	mac := bridgeMAC(b.Gateway)
	if mac.String() != "02:41:0a:79:00:01" {
		t.Errorf("bridgeMAC = %s", mac)
	}
	// Locally administered (bit 1) and unicast (bit 0 clear).
	if mac[0]&0x02 == 0 || mac[0]&0x01 != 0 {
		t.Errorf("%s is not a locally administered unicast address", mac)
	}
	other, _ := BridgeOf(netip.MustParsePrefix("10.122.0.0/24"))
	if bridgeMAC(other.Gateway).String() == mac.String() {
		t.Error("two subnets share a bridge address")
	}
}

// A new network namespace has its loopback down; without the plugin localhost
// reaches nothing inside a container.
func TestCNIConfigBringsUpLoopback(t *testing.T) {
	t.Parallel()
	b, err := cniConfig(runtime.Bridge{Subnet: netip.MustParsePrefix("10.120.0.0/24"), Gateway: netip.MustParseAddr("10.120.0.1")}, "/run/ipam", 0)
	if err != nil {
		t.Fatal(err)
	}
	var conf struct {
		Plugins []struct {
			Type string `json:"type"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(b, &conf); err != nil {
		t.Fatal(err)
	}
	if len(conf.Plugins) == 0 || conf.Plugins[0].Type != "bridge" {
		t.Fatalf("the bridge must come first: its result names the container's address: %+v", conf.Plugins)
	}
	if !slices.ContainsFunc(conf.Plugins, func(p struct {
		Type string `json:"type"`
	}) bool {
		return p.Type == "loopback"
	}) {
		t.Errorf("no loopback plugin: %+v", conf.Plugins)
	}
}

func TestVolumeMountOptions(t *testing.T) {
	t.Parallel()
	s := genSpec(t, appOpts(appSpec{spec: runtime.ContainerSpec{Name: "web", Volumes: []runtime.VolumeMount{
		{Source: "/var/lib/armada/volumes/web/data", Target: "/data"},
		{Source: "/var/lib/armada/nfs/web/up", Target: "/up", Shared: true, ReadOnly: true},
	}}})...)
	want := map[string]string{"/data": "rbind,rw,nosuid,nodev", "/up": "rbind,ro,nosuid,nodev"}
	for _, m := range s.Mounts {
		if w, ok := want[m.Destination]; ok {
			if got := strings.Join(m.Options, ","); got != w {
				t.Errorf("%s: %s, want %s", m.Destination, got, w)
			}
			delete(want, m.Destination)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing mounts %v", want)
	}
}

func TestPullErrorSaysWhatItMeans(t *testing.T) {
	t.Parallel()
	denied := errors.New(`failed to resolve reference "ghcr.io/acme/web:1.4.2": failed to authorize: failed to fetch anonymous token: unexpected status from GET request to https://ghcr.io/token: 403 Forbidden`)
	if got := pullError("ghcr.io/acme/web:1.4.2", false, denied).Error(); !strings.Contains(got, "does not exist, or it is private and the app has no registry credentials") || !strings.Contains(got, "403 Forbidden") {
		t.Errorf("anonymous: %s", got)
	}
	if got := pullError("ghcr.io/acme/web:1.4.2", true, denied).Error(); !strings.Contains(got, "refused the app's credentials") {
		t.Errorf("with credentials: %s", got)
	}
	if got := pullError("nginx:nope", false, errors.New("docker.io/library/nginx:nope: not found")).Error(); !strings.Contains(got, "no such image or tag") {
		t.Errorf("not found: %s", got)
	}
	if got := pullError("nginx:1", false, errors.New("dial tcp: i/o timeout")).Error(); got != "pull nginx:1: dial tcp: i/o timeout" {
		t.Errorf("other: %s", got)
	}
}
