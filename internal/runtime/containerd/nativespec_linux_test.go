package containerd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/contrib/seccomp"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// The parity tests of armada-node runtime (node/src/runtime): the spec of
// every kind of container, the seccomp profile per architecture, and the
// AppArmor profile, each compared with what this package and containerd
// build. Gated on ARMADA_NODE_BIN.

func nodeBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		t.Skip("ARMADA_NODE_BIN names no armada-node to compare with")
	}
	return bin
}

func runNode(t *testing.T, bin string, stdin []byte, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("armada-node %v: %v: %s", args, err, stderr.String())
	}
	return out
}

// testImage is an image whose configuration sits in a content store, as
// the supervisor runtime hands its images to the spec options.
type testImage struct {
	desc ocispec.Descriptor
	cs   content.Store
}

func (i testImage) Config(context.Context) (ocispec.Descriptor, error) { return i.desc, nil }
func (i testImage) ContentStore() content.Store                        { return i.cs }

// bindClient's snapshots mount a fixture directory as the container's
// root filesystem, which the user options read through containerd's own
// view of the mounts.
type bindClient struct{ root string }

func (c bindClient) SnapshotService(string) snapshots.Snapshotter { return bindSnapshots{root: c.root} }

type bindSnapshots struct {
	snapshots.Snapshotter
	root string
}

func (b bindSnapshots) Mounts(context.Context, string) ([]mount.Mount, error) {
	return []mount.Mount{{Type: "bind", Source: b.root, Options: []string{"rbind", "ro"}}}, nil
}

// specCase is one container whose spec both build.
type specCase struct {
	name      string
	spec      runtime.ContainerSpec
	member    *runtime.MemberSpec
	system    *runtime.SystemSpec
	image     string // the config blob
	mediaType string
	rootfs    string
	selinux   selinuxLabels
	noSeccomp bool
	apparmor  bool
}

// What armada-node runtime spec reads, as node/src/runtime/mod.rs
// documents it.
type nativeSpecRequest struct {
	Spec           runtime.ContainerSpec
	Member         *runtime.MemberSpec
	System         *runtime.SystemSpec
	Image          json.RawMessage
	ImageMediaType string
	NetNS          string
	Files          struct{ Resolv, Hosts, Hostname string }
	Tini           string
	Cgroup         string
	SELinux        struct{ Process, Mount string }
	Seccomp        bool
	AppArmor       string
	Rootfs         string
	Arch           string
	Namespace      string
	ID             string
}

const (
	specID    = "web-r1-3f2a"
	specNetNS = "/var/run/netns/" + specID
	specTini  = "/var/lib/armada/runtime/pack-1a2b/bin/tini"
)

var specFiles = containerFiles{
	resolv:   "/var/lib/armada/containers/" + specID + "/resolv.conf",
	hosts:    "/var/lib/armada/containers/" + specID + "/hosts",
	hostname: "/var/lib/armada/containers/" + specID + "/hostname",
}

// goSpec builds the case's spec as the driver does: the options of
// Run (appSpecOpts), startMember (the member's own spec), or RunSystem
// (systemSpecOpts), applied by oci.GenerateSpec as the supervisor's
// NewContainer applies them.
func goSpec(ctx context.Context, cs content.Store, c specCase) ([]byte, error) {
	mt := c.mediaType
	if mt == "" {
		mt = ocispec.MediaTypeImageConfig
	}
	blob := []byte(c.image)
	desc := ocispec.Descriptor{MediaType: mt, Digest: digest.FromBytes(blob), Size: int64(len(blob))}
	if err := content.WriteBlob(ctx, cs, desc.Digest.String(), bytes.NewReader(blob), desc); err != nil {
		return nil, err
	}
	img := testImage{desc: desc, cs: cs}
	cgroup := cgroupParent + "/" + specID
	var opts []oci.SpecOpts
	if c.system != nil {
		var sc oci.SpecOpts
		if !c.noSeccomp {
			sc = seccompOpt()
		}
		opts = systemSpecOpts(img, *c.system, cgroup, sc, c.selinux)
	} else {
		s := c.spec
		if c.member != nil {
			s = memberContainerSpec(c.spec, *c.member)
		}
		a := appSpec{
			spec: s, netns: specNetNS, files: specFiles, tini: specTini, cgroup: cgroup,
			group:   shimGroup(c.spec.Labels[runtime.LabelApp], specTini),
			selinux: c.selinux,
		}
		if !c.noSeccomp {
			a.seccomp = seccompOpt()
		}
		if c.apparmor {
			a.apparmor = withAppArmor(func() error { return nil })
		}
		opts = appSpecOpts(img, a)
	}
	cc := &containers.Container{ID: specID, SnapshotKey: specID, Snapshotter: "overlayfs"}
	sp, err := oci.GenerateSpec(ctx, bindClient{root: c.rootfs}, cc, opts...)
	if err != nil {
		return nil, err
	}
	return json.Marshal(sp)
}

func nativeRequest(c specCase) nativeSpecRequest {
	r := nativeSpecRequest{
		Spec: c.spec, Member: c.member, System: c.system,
		Image: json.RawMessage(c.image), ImageMediaType: c.mediaType,
		NetNS: specNetNS, Tini: specTini, Cgroup: cgroupParent + "/" + specID,
		Seccomp: !c.noSeccomp, Rootfs: c.rootfs, Arch: goruntime.GOARCH,
		Namespace: "armada", ID: specID,
	}
	if r.ImageMediaType == "" {
		r.ImageMediaType = ocispec.MediaTypeImageConfig
	}
	r.Files.Resolv, r.Files.Hosts, r.Files.Hostname = specFiles.resolv, specFiles.hosts, specFiles.hostname
	r.SELinux.Process, r.SELinux.Mount = c.selinux.process, c.selinux.mount
	if c.apparmor {
		r.AppArmor = apparmorProfile
	}
	return r
}

// writeRootfs makes the fixture root filesystems the user options read.
func writeRootfs(t *testing.T) map[string]string {
	t.Helper()
	base := t.TempDir()
	passwd := "root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000::/home/app:/bin/sh\n" +
		"svc:x:1001:1002::/:/bin/false\n  spaced:x:1003:1003\r\nweird:x:abc:5\n" +
		"big:x:4294967297:4294967298\n\n"
	group := "root:x:0:\nwheel:x:10:root,app\napp:x:1000:\ngrp:x:2000:app,svc\n" +
		"svc:x:1002:svc\naudio:x:29:app\n# app:x:9:app\nempty:x::app\n"
	type entry struct{ path, data, link string }
	layouts := map[string][]entry{
		"full":      {{path: "etc/passwd", data: passwd}, {path: "etc/group", data: group}},
		"empty":     nil,
		"nopasswd":  {{path: "etc/group", data: group}},
		"nogroup":   {{path: "etc/passwd", data: passwd}},
		"linked":    {{path: "real/passwd", data: passwd}, {path: "real/group", data: group}, {path: "etc/passwd", link: "/real/passwd"}, {path: "etc/group", link: "../../real/group"}},
		"etclink":   {{path: "real/passwd", data: passwd}, {path: "real/group", data: group}, {path: "etc", link: "/real"}},
		"loop":      {{path: "etc/passwd", link: "passwd"}, {path: "etc/group", data: group}},
		"dirpasswd": {{path: "etc/passwd/x", data: ""}, {path: "etc/group", data: group}},
		"etcfile":   {{path: "etc", data: "x"}},
		"dangling":  {{path: "etc/passwd", link: "/nowhere/passwd"}, {path: "etc/group", data: group}},
		"longline":  {{path: "etc/passwd", data: "app:x:1000:1000\n" + strings.Repeat("x", 70000) + "\n"}, {path: "etc/group", data: group}},
	}
	out := map[string]string{}
	for name, entries := range layouts {
		root := filepath.Join(base, name)
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			p := filepath.Join(root, e.path)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			var err error
			if e.link != "" {
				err = os.Symlink(e.link, p)
			} else {
				err = os.WriteFile(p, []byte(e.data), 0o644)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		out[name] = root
	}
	return out
}

// imageBlob is an image configuration blob with these fields set.
func imageBlob(user string, env, entrypoint, cmd []string, wd string) string {
	cfg := map[string]any{}
	if user != "" {
		cfg["User"] = user
	}
	if env != nil {
		cfg["Env"] = env
	}
	if entrypoint != nil {
		cfg["Entrypoint"] = entrypoint
	}
	if cmd != nil {
		cfg["Cmd"] = cmd
	}
	if wd != "" {
		cfg["WorkingDir"] = wd
	}
	b, _ := json.Marshal(map[string]any{"architecture": goruntime.GOARCH, "os": "linux", "config": cfg, "rootfs": map[string]any{"type": "layers"}})
	return string(b)
}

var userForms = []string{
	"", "0", "1000", "1000:1000", "app", "app:grp", "app:1000", "1000:grp", "svc", "spaced", "nobody",
	"1000:nogroup", "a:b:c", "99999999999999999999", "-1", "0:-1", "2147483648", "2147483647", "4242",
	"+5", ":", "app:", ":grp", "weird", "1003", "big", "4294967297:2",
}

func specCases(roots map[string]string) []specCase {
	pathEnv := []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	base := runtime.ContainerSpec{
		Name: "web-r1", Image: "registry.example/web:1",
		Env:    []string{"PORT=8080", "ARMADA_APP=web"},
		Labels: map[string]string{runtime.LabelApp: "web", "armada.replica": "web-r1"},
	}
	img := imageBlob("", pathEnv, []string{"/entry"}, []string{"serve"}, "/srv")
	var cases []specCase
	for root := range roots {
		for _, u := range userForms {
			cases = append(cases, specCase{
				name: "user " + root + " " + u, spec: base, rootfs: roots[root],
				image: imageBlob(u, pathEnv, nil, []string{"run"}, ""),
			})
		}
		for _, u := range []string{"", "1000", "app:grp", "nobody"} {
			cases = append(cases, specCase{
				name: "system user " + root + " " + u, rootfs: roots[root], image: img,
				system: &runtime.SystemSpec{Name: "haproxy", Cmd: []string{"haproxy", "-f", "/x"}, User: u, CapAdd: []string{"NET_BIND_SERVICE"}},
			})
		}
	}
	full := roots["full"]
	with := func(name string, f func(c *specCase)) {
		c := specCase{name: name, spec: base, rootfs: full, image: img}
		f(&c)
		cases = append(cases, c)
	}
	with("plain", func(*specCase) {})
	with("no seccomp", func(c *specCase) { c.noSeccomp = true })
	with("apparmor", func(c *specCase) { c.apparmor = true })
	with("selinux", func(c *specCase) {
		c.selinux = selinuxLabels{process: "system_u:system_r:container_t:s0:c1,c2", mount: "system_u:object_r:container_file_t:s0:c1,c2"}
	})
	with("entrypoint", func(c *specCase) { c.spec.Entrypoint = []string{"/bin/app", "--x"}; c.spec.Cmd = []string{"a"} })
	with("cmd", func(c *specCase) { c.spec.Cmd = []string{"/bin/sh", "-c", "echo <&>"} })
	with("no command", func(c *specCase) { c.image = imageBlob("", nil, nil, nil, "") })
	with("empty image env", func(c *specCase) { c.image = imageBlob("", []string{}, []string{"/e"}, nil, "") })
	with("bad media type", func(c *specCase) { c.mediaType = "application/json" })
	with("docker media type", func(c *specCase) { c.mediaType = "application/vnd.docker.container.image.v1+json" })
	with("env overrides", func(c *specCase) {
		c.image = imageBlob("", []string{"A=1", "B=2", "A=3", "", "C"}, []string{"/e"}, nil, "")
		c.spec.Env = []string{"A=9", "B", "D=4", "D=5", "=x", "HOSTNAME=mine", "E=<tag>&\u2028"}
	})
	with("limits", func(c *specCase) {
		c.spec.MemoryBytes, c.spec.NanoCPUs, c.spec.CPUReserveMillis, c.spec.PidsLimit = 256<<20, 1_500_000_000, 250, 512
	})
	with("tiny cpu", func(c *specCase) { c.spec.NanoCPUs, c.spec.CPUReserveMillis = 1, 1 })
	with("huge cpu", func(c *specCase) { c.spec.NanoCPUs, c.spec.CPUReserveMillis = 1<<62, 1<<62 })
	with("files and volumes", func(c *specCase) {
		c.spec.Files = []runtime.FileMount{{Source: "/var/lib/armada/secrets/web/a", Target: "/run/secrets/a"}}
		c.spec.Volumes = []runtime.VolumeMount{
			{Source: "/var/lib/armada/volumes/web/data", Target: "/data"},
			{Source: "/var/lib/armada/nfs/web/media", Target: "/media", Shared: true, ReadOnly: true},
		}
	})
	with("no app label", func(c *specCase) { c.spec.Labels = nil })
	with("odd name", func(c *specCase) { c.spec.Name = "_" + strings.Repeat("ab_", 30) + "." })
	with("unicode name", func(c *specCase) { c.spec.Name = strings.Repeat("a", 62) + "é" })
	with("working dir", func(c *specCase) { c.image = imageBlob("app", nil, nil, []string{"x"}, "/home/app") })
	with("case-folded config", func(c *specCase) {
		c.image = `{"CONFIG":{"user":"app","env":["X=1"],"cmd":["a"],"Cmd":["b"],"entrypoint":null,"workingdir":"/w"},"config":{"Env":null}}`
	})
	with("null config", func(c *specCase) { c.image = `{"config":null}` })
	members := []runtime.MemberSpec{
		{Name: "migrate", Image: "registry.example/migrate:1", Cmd: []string{"migrate", "up"}, Env: []string{"ARMADA_CONTAINER=migrate"}, MemoryBytes: 64 << 20, CPUReserveMillis: 10},
		{Name: "log", Image: "registry.example/log:1", Entrypoint: []string{"/log"}, NanoCPUs: 100_000_000, PidsLimit: 64,
			Files: []runtime.FileMount{{Source: "/s/a", Target: "/run/secrets/a"}}, Volumes: []runtime.VolumeMount{{Source: "/v/data", Target: "/data", ReadOnly: true}}},
	}
	for i := range members {
		with("member "+members[i].Name, func(c *specCase) {
			c.spec.Init, c.spec.Sidecars = members[:1], members[1:]
			c.member = &members[i]
			c.apparmor = true
		})
	}
	for _, caps := range [][]string{nil, {}, {"NET_BIND_SERVICE"}, {"SYS_ADMIN", "SYS_PTRACE", "DAC_READ_SEARCH"}, {"CHOWN", "SETUID", "SETGID", "SYS_NICE", "BPF", "PERFMON"}} {
		cases = append(cases, specCase{
			name: fmt.Sprintf("system caps %v", caps), rootfs: full, image: img,
			system: &runtime.SystemSpec{Name: "haproxy", CapAdd: caps, Mounts: []runtime.Mount{{Source: "/etc/armada/haproxy", Target: "/usr/local/etc/haproxy", ReadOnly: true}, {Source: "/run/armada/haproxy", Target: "/var/run/haproxy"}}},
		})
	}
	cases = append(cases, specCase{
		name: "system selinux", rootfs: full, image: imageBlob("", nil, nil, nil, ""),
		system:  &runtime.SystemSpec{Name: "x"},
		selinux: selinuxLabels{process: "system_u:system_r:container_t:s0:c5,c9", mount: "system_u:object_r:container_file_t:s0:c5,c9"},
	})
	return cases
}

func randomSpecCase(r *rand.Rand, roots map[string]string, names []string) specCase {
	pick := func(n int) bool { return r.IntN(n) == 0 }
	some := func(pool []string) []string {
		var out []string
		for range r.IntN(4) {
			out = append(out, pool[r.IntN(len(pool))])
		}
		return out
	}
	envs := []string{"A=1", "B=x y", "A=2", "C", "PATH=/x", "D=<b>&", "", "E="}
	words := []string{"/bin/sh", "-c", "run", "--flag=1", "é", "a b"}
	var entry, cmd []string
	if !pick(3) {
		entry = some(words)
	}
	if !pick(3) {
		cmd = some(words)
	}
	var env []string
	if !pick(4) {
		env = some(envs)
	}
	c := specCase{
		name:   "random",
		rootfs: roots["full"],
		image:  imageBlob(userForms[r.IntN(len(userForms))], env, entry, cmd, []string{"", "/w"}[r.IntN(2)]),
	}
	if pick(4) {
		c.rootfs = roots[names[r.IntN(len(names))]]
	}
	if pick(5) {
		c.system = &runtime.SystemSpec{Name: "sys", Cmd: some(words), User: []string{"", "app", "1000:1000"}[r.IntN(3)], CapAdd: some([]string{"NET_ADMIN", "SYS_ADMIN", "KILL", "SYSLOG"})}
		for range r.IntN(3) {
			c.system.Mounts = append(c.system.Mounts, runtime.Mount{Source: "/m", Target: "/t", ReadOnly: pick(2)})
		}
	} else {
		s := runtime.ContainerSpec{Name: []string{"web-r1", "api-r2.shop", "x"}[r.IntN(3)], Entrypoint: some(words), Env: some(envs)}
		if pick(2) {
			s.Cmd = some(words)
		}
		if pick(2) {
			s.Labels = map[string]string{runtime.LabelApp: []string{"web", "api.shop", ""}[r.IntN(3)]}
		}
		if pick(2) {
			s.MemoryBytes = r.Int64N(1 << 34)
		}
		if pick(2) {
			s.NanoCPUs = r.Int64N(1 << 36)
		}
		if pick(2) {
			s.CPUReserveMillis = r.Int64N(1 << 20)
		}
		if pick(2) {
			s.PidsLimit = r.Int64N(1 << 16)
		}
		for i := range r.IntN(3) {
			s.Files = append(s.Files, runtime.FileMount{Source: fmt.Sprintf("/s/%d", i), Target: fmt.Sprintf("/run/secrets/%d", i)})
		}
		for i := range r.IntN(3) {
			s.Volumes = append(s.Volumes, runtime.VolumeMount{Source: fmt.Sprintf("/v/%d", i), Target: fmt.Sprintf("/data%d", i), Shared: pick(2), ReadOnly: pick(2)})
		}
		c.spec = s
		if pick(4) {
			m := runtime.MemberSpec{Name: "side", Image: "i", Entrypoint: some(words), Cmd: some(words), Env: some(envs), MemoryBytes: r.Int64N(1 << 30), PidsLimit: r.Int64N(100)}
			if len(s.Files) > 0 {
				m.Files = s.Files[:1]
			}
			c.spec.Sidecars = []runtime.MemberSpec{m}
			c.member = &m
		}
		c.apparmor = pick(2)
	}
	c.noSeccomp = pick(6)
	if pick(3) {
		c.selinux = selinuxLabels{process: "system_u:system_r:container_t:s0:c1,c2", mount: "system_u:object_r:container_file_t:s0:c1,c2"}
	}
	return c
}

// TestArmadaNodeSpecMatchesGo checks that armada-node runtime spec writes
// the config.json this package's options and containerd write, or
// GenerateSpec's error, for every kind of container: the cases above
// (user forms against fixture root filesystems, limits, files, volumes,
// members, system containers, SELinux, seccomp, AppArmor) and random ones.
// Both encodings are compared as JSON trees and then byte for byte.
func TestArmadaNodeSpecMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	ctx := namespaces.WithNamespace(context.Background(), "armada")
	cs, err := local.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	roots := writeRootfs(t)
	cases := specCases(roots)
	names := make([]string, 0, len(roots))
	for n := range roots {
		names = append(names, n)
	}
	// Map order would make the random cases differ between runs.
	slices.Sort(names)
	r := rand.New(rand.NewPCG(7, 11))
	for range 400 {
		cases = append(cases, randomSpecCase(r, roots, names))
	}
	errs := map[string]int{}
	for i, c := range cases {
		want, gerr := goSpec(ctx, cs, c)
		if gerr != nil {
			errs[gerr.Error()]++
			want, _ = json.Marshal(map[string]string{"error": gerr.Error()})
		}
		in, err := json.Marshal(nativeRequest(c))
		if err != nil {
			t.Fatal(err)
		}
		got := runNode(t, bin, in, "runtime", "spec")
		var wt, gt any
		if err := json.Unmarshal(want, &wt); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(got, &gt); err != nil {
			t.Fatalf("case %d %s: armada-node wrote no JSON: %v: %s", i, c.name, err, got)
		}
		if !reflect.DeepEqual(wt, gt) {
			t.Errorf("case %d %s differs:\n go:   %s\n rust: %s", i, c.name, want, got)
			continue
		}
		if !bytes.Equal(want, got) {
			t.Errorf("case %d %s: same tree, different bytes:\n go:   %s\n rust: %s", i, c.name, want, got)
		}
	}
	failed := 0
	for _, n := range errs {
		failed += n
	}
	t.Logf("%d cases compared: %d specs built, %d refused with these errors: %v", len(cases), len(cases)-failed, failed, errs)
}

var boundingSets = [][]string{
	nil,
	{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_KILL"},
	{"CAP_SYS_ADMIN"},
	{"CAP_DAC_READ_SEARCH", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_CHROOT", "CAP_SYS_MODULE", "CAP_SYS_PACCT", "CAP_SYS_PTRACE", "CAP_SYS_RAWIO", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_SYS_NICE", "CAP_SYSLOG", "CAP_BPF", "CAP_PERFMON"},
	{"CAP_BPF", "CAP_PERFMON", "CAP_SYS_NICE", "CAP_SYS_PTRACE", "CAP_BPF"},
}

// TestArmadaNodeSeccompMatchesGo compares armada-node's seccomp profile
// (node/src/runtime/seccomp.rs) with containerd's DefaultProfile for
// several bounding sets: on this machine's architecture with the real
// function, and for amd64 and arm64 with containerd's source built with
// runtime.GOARCH replaced by an argument (checked against the real
// function on this architecture first).
func TestArmadaNodeSeccompMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	type req struct {
		Arch     string
		Bounding []string
	}
	for _, b := range boundingSets {
		want, err := json.Marshal(seccomp.DefaultProfile(&specs.Spec{Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{Bounding: b}}}))
		if err != nil {
			t.Fatal(err)
		}
		in, _ := json.Marshal(req{Arch: goruntime.GOARCH, Bounding: b})
		if got := runNode(t, bin, in, "runtime", "seccomp"); !bytes.Equal(want, got) {
			t.Errorf("%s %v:\n go:   %s\n rust: %s", goruntime.GOARCH, b, want, got)
		}
	}
	profiles := seccompForArchs(t, []string{goruntime.GOARCH, "amd64", "arm64"})
	for i, b := range boundingSets {
		own, _ := json.Marshal(seccomp.DefaultProfile(&specs.Spec{Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{Bounding: b}}}))
		if !bytes.Equal(own, profiles[goruntime.GOARCH][i]) {
			t.Fatalf("the rewritten DefaultProfile differs from containerd's on %s", goruntime.GOARCH)
		}
		for _, arch := range []string{"amd64", "arm64"} {
			in, _ := json.Marshal(req{Arch: arch, Bounding: b})
			if got := runNode(t, bin, in, "runtime", "seccomp"); !bytes.Equal(profiles[arch][i], got) {
				t.Errorf("%s %v:\n go:   %s\n rust: %s", arch, b, profiles[arch][i], got)
			}
		}
	}
}

// seccompForArchs builds containerd's seccomp_default.go with GOARCH as a
// variable and returns its profiles for every bounding set per arch.
func seccompForArchs(t *testing.T, archs []string) map[string][][]byte {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command to build containerd's profile for other architectures")
	}
	modDir, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/containerd/containerd/v2").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	src, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(modDir)), "contrib", "seccomp", "seccomp_default.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, r := range [][2]string{{"package seccomp", "package main"}, {"\t\"runtime\"\n", ""}, {"runtime.GOARCH", "goarch"}} {
		if !strings.Contains(text, r[0]) {
			t.Fatalf("containerd's seccomp_default.go has no %q any more", r[0])
		}
		text = strings.ReplaceAll(text, r[0], r[1])
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("testdata", "seccomp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir); _ = os.Remove("testdata") })
	main := `package main

import (
	"encoding/json"
	"os"

	"github.com/opencontainers/runtime-spec/specs-go"
)

var goarch string

func main() {
	var sets [][]string
	if err := json.NewDecoder(os.Stdin).Decode(&sets); err != nil {
		panic(err)
	}
	out := map[string][]*specs.LinuxSeccomp{}
	for _, goarch = range os.Args[1:] {
		for _, b := range sets {
			out[goarch] = append(out[goarch], DefaultProfile(&specs.Spec{Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{Bounding: b}}}))
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		panic(err)
	}
}
`
	for name, data := range map[string]string{"profile.go": text, "main.go": main} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sets, _ := json.Marshal(boundingSets)
	cmd := exec.Command("go", append([]string{"run", "./" + dir}, archs...)...)
	cmd.Stdin = bytes.NewReader(sets)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go run: %v: %s", err, stderr.String())
	}
	var raw map[string][]json.RawMessage
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatal(err)
	}
	res := map[string][][]byte{}
	for arch, ps := range raw {
		for _, p := range ps {
			res[arch] = append(res[arch], []byte(p))
		}
	}
	return res
}

// TestArmadaNodeAppArmorMatchesGo compares armada-node's AppArmor profile
// (node/src/runtime/apparmor.rs) with appArmorProfile's on this machine,
// byte for byte.
func TestArmadaNodeAppArmorMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	for _, name := range []string{apparmorProfile, "x", "armada-test.1"} {
		want, err := appArmorProfile(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := runNode(t, bin, nil, "runtime", "apparmor", name); string(got) != want {
			t.Errorf("%s:\n go:\n%s\n rust:\n%s", name, want, got)
		}
	}
}
