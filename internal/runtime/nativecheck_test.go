package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestArmadaNodeCheckMatchesGo checks that armada-node runtime check
// (node/src/runtime/check.rs) refuses what CheckContainerSpec refuses,
// with the same error text, and accepts the rest.
func TestArmadaNodeCheckMatchesGo(t *testing.T) {
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		t.Skip("ARMADA_NODE_BIN names no armada-node to compare with")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "secret")
	vol := filepath.Join(dir, "vol")
	vol2 := filepath.Join(dir, "vol2")
	link := filepath.Join(dir, "link")
	fifo := filepath.Join(dir, "fifo")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{vol, vol2} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	f := FileMount{Source: file, Target: "/run/secrets/x"}
	v := VolumeMount{Source: vol, Target: "/data"}
	cases := []ContainerSpec{
		{},
		{Files: []FileMount{f}, Volumes: []VolumeMount{v}},
		{Files: []FileMount{{Source: "rel", Target: "/x"}}},
		{Files: []FileMount{{Source: file + "/", Target: "/x"}}},
		{Files: []FileMount{{Source: file, Target: "/"}}},
		{Files: []FileMount{{Source: "/", Target: "/x"}}},
		{Files: []FileMount{{Source: file, Target: "/a/../b"}}},
		{Files: []FileMount{{Source: dir + "/missing", Target: "/x"}}},
		{Files: []FileMount{{Source: dir + "/a\x00b", Target: "/x"}}},
		{Files: []FileMount{{Source: vol, Target: "/x"}}},
		{Files: []FileMount{{Source: link, Target: "/x"}}},
		{Files: []FileMount{{Source: fifo, Target: "/x"}}},
		{Files: []FileMount{{Source: "/x\"y\n", Target: "/x"}}},
		{Volumes: make([]VolumeMount, 9)},
		{Volumes: []VolumeMount{{Source: "data", Target: "/data"}}},
		{Volumes: []VolumeMount{{Source: vol + ":x", Target: "/data"}}},
		{Volumes: []VolumeMount{{Source: vol + ",x", Target: "/data"}}},
		{Volumes: []VolumeMount{{Source: vol, Target: "data"}}},
		{Volumes: []VolumeMount{{Source: vol, Target: ""}}},
		{Volumes: []VolumeMount{{Source: vol, Target: "/" + strings.Repeat("a", 300)}}},
		{Volumes: []VolumeMount{{Source: vol, Target: "/a b"}}},
		{Volumes: []VolumeMount{{Source: vol, Target: "/a//b"}}},
		{Volumes: []VolumeMount{{Source: vol, Target: "/a/./b"}}},
		{Volumes: []VolumeMount{{Source: vol, Target: "/etc/hosts"}}},
		{Volumes: []VolumeMount{{Source: vol, Target: "/proc"}}},
		{Volumes: []VolumeMount{{Source: vol, Target: "/sys/x"}}},
		{Volumes: []VolumeMount{{Source: vol, Target: "/devx"}}},
		{Volumes: []VolumeMount{{Source: file, Target: "/data"}}},
		{Volumes: []VolumeMount{{Source: dir + "/none", Target: "/data"}}},
		{Volumes: []VolumeMount{v, {Source: vol2, Target: "/data"}}},
		{Files: []FileMount{{Source: file, Target: "/data"}}, Volumes: []VolumeMount{v}},
		{DNS: []string{"10.0.0.2", "fd00::1"}},
		{DNS: []string{"8.8.8.8"}},
		{DNS: []string{"010.0.0.1"}},
		{DNS: []string{"::ffff:10.0.0.1"}},
		{DNS: []string{"fe80::1%eth0"}},
		{DNS: []string{"100.64.1.1", "127.0.0.1", "::1"}},
		{DNS: []string{"FD00::1"}},
		{DNSSearch: []string{"internal"}},
		{DNSSearch: []string{"shop.internal"}},
		{DNSSearch: []string{"default.internal"}},
		{DNSSearch: []string{"internal", "shop.internal"}},
		{DNSSearch: []string{"example.com"}},
		{DNSSearch: []string{"Shop.internal"}},
		{DNSSearch: []string{strings.Repeat("a", 31) + ".internal"}},
		{Port: 8080, HostIP: "10.0.0.1"},
		{Port: 8080, HostIP: "1.2.3.4"},
		{Port: 8080},
		{Port: -1, HostIP: "10.0.0.1"},
		{Port: 70000, HostIP: "10.0.0.1"},
		{Init: make([]MemberSpec, 5)},
		{Sidecars: make([]MemberSpec, 5)},
		{Init: []MemberSpec{{Name: "app", Image: "x"}}},
		{Init: []MemberSpec{{Name: "migrate", Image: "x"}}, Sidecars: []MemberSpec{{Name: "migrate", Image: "y"}}},
		{Init: []MemberSpec{{Name: "Migrate", Image: "x"}}},
		{Init: []MemberSpec{{Name: strings.Repeat("a", 31), Image: "x"}}},
		{Init: []MemberSpec{{Name: "m\n", Image: "x"}}},
		{Sidecars: []MemberSpec{{Name: "log"}}},
		{Files: []FileMount{f}, Volumes: []VolumeMount{v}, Sidecars: []MemberSpec{{Name: "log", Image: "x", Files: []FileMount{f}, Volumes: []VolumeMount{v}}}},
		{Sidecars: []MemberSpec{{Name: "log", Image: "x", Files: []FileMount{f}}}},
		{Volumes: []VolumeMount{v}, Sidecars: []MemberSpec{{Name: "log", Image: "x", Volumes: []VolumeMount{{Source: vol, Target: "/data", ReadOnly: true}}}}},
	}
	r := rand.New(rand.NewPCG(5, 4))
	for range 300 {
		cases = append(cases, randomCheckSpec(r, f, v, VolumeMount{Source: vol2, Target: "/cache", Shared: true}))
	}
	failed := 0
	for i, s := range cases {
		want := "{}"
		if err := CheckContainerSpec(s); err != nil {
			b, _ := json.Marshal(map[string]string{"error": err.Error()})
			want = string(b)
		}
		in, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "runtime", "check")
		cmd.Stdin = bytes.NewReader(in)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("case %d: armada-node: %v: %s", i, err, stderr.String())
		}
		if string(out) != want {
			failed++
			t.Errorf("case %d %+v:\n go:   %s\n rust: %s", i, s, want, out)
		}
	}
	t.Logf("%d cases, %d differ", len(cases), failed)
}

func randomCheckSpec(r *rand.Rand, f FileMount, v, shared VolumeMount) ContainerSpec {
	pick := func(n int) bool { return r.IntN(n) == 0 }
	var s ContainerSpec
	if pick(2) {
		s.Files = []FileMount{f}
	}
	if pick(3) {
		s.Files = append(s.Files, FileMount{Source: f.Source, Target: []string{"/a", "/etc/x", "rel", "/a/"}[r.IntN(4)]})
	}
	if pick(2) {
		s.Volumes = []VolumeMount{v}
	}
	if pick(3) {
		s.Volumes = append(s.Volumes, shared)
	}
	if pick(5) {
		s.Volumes = append(s.Volumes, VolumeMount{Source: v.Source, Target: []string{"/data", "/x y", "/ok"}[r.IntN(3)]})
	}
	for range r.IntN(3) {
		s.DNS = append(s.DNS, []string{"10.1.2.3", "fd12::5", "1.1.1.1", "10.1.2", "::1", "172.32.0.1", "172.16.0.1", "192.168.1.1"}[r.IntN(8)])
	}
	for range r.IntN(3) {
		s.DNSSearch = append(s.DNSSearch, []string{"internal", "a.internal", "default.internal", "a.b.internal", "x"}[r.IntN(5)])
	}
	if pick(3) {
		s.Port = []int{80, 0, 65535, 65536}[r.IntN(4)]
		s.HostIP = []string{"10.0.0.1", "", "203.0.113.1", "fd00::1"}[r.IntN(4)]
	}
	members := func(role string) []MemberSpec {
		var out []MemberSpec
		for i := range r.IntN(6) {
			m := MemberSpec{Name: fmt.Sprintf("%s%d", role, i%3), Image: "img"}
			if pick(6) {
				m.Image = ""
			}
			if pick(4) {
				m.Name = []string{"app", "Bad", "ok-1", "x-"}[r.IntN(4)]
			}
			if pick(3) {
				m.Files = []FileMount{f}
			}
			if pick(3) {
				m.Volumes = []VolumeMount{v}
			}
			out = append(out, m)
		}
		return out
	}
	s.Init = members("init")
	s.Sidecars = members("side")
	return s
}
