package driverkit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckName(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"docker", "podman", "apple-container", "a", "x1", strings.Repeat("a", 32)} {
		if err := CheckName(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "embedded", "Docker", "-x", "x-", "a_b", "a.b", "../x", "a/b", "a b", "x\n", strings.Repeat("a", 33)} {
		if err := CheckName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func validSpec(t *testing.T) ContainerSpec {
	t.Helper()
	return ContainerSpec{
		Name: "armada-web-1", Image: "busybox", MemoryBytes: 64 << 20, PidsLimit: 100,
		Security: Security{NoNewPrivileges: true, DropCapabilities: RequiredDroppedCaps},
	}
}

func TestCheckContainerSpec(t *testing.T) {
	t.Parallel()
	if err := CheckContainerSpec(validSpec(t)); err != nil {
		t.Fatalf("valid spec refused: %v", err)
	}
	dir := t.TempDir()
	tests := map[string]func(*ContainerSpec){
		"no name":             func(s *ContainerSpec) { s.Name = "" },
		"no image":            func(s *ContainerSpec) { s.Image = "" },
		"new privileges":      func(s *ContainerSpec) { s.Security.NoNewPrivileges = false },
		"no memory limit":     func(s *ContainerSpec) { s.MemoryBytes = 0 },
		"no PID limit":        func(s *ContainerSpec) { s.PidsLimit = 0 },
		"capability kept":     func(s *ContainerSpec) { s.Security.DropCapabilities = []string{"MKNOD", "AUDIT_WRITE"} },
		"public publish":      func(s *ContainerSpec) { s.Port, s.HostIP = 8080, "8.8.8.8" },
		"wildcard publish":    func(s *ContainerSpec) { s.Port, s.HostIP = 8080, "0.0.0.0" },
		"public nameserver":   func(s *ContainerSpec) { s.DNS = []string{"1.1.1.1"} },
		"directory mount":     func(s *ContainerSpec) { s.Files = []FileMount{{Source: dir, Target: "/run/x"}} },
		"relative mount":      func(s *ContainerSpec) { s.Files = []FileMount{{Source: "x", Target: "/run/x"}} },
		"unclean target":      func(s *ContainerSpec) { s.Files = []FileMount{{Source: "/etc/hosts", Target: "/run/../etc/x"}} },
		"mount without paths": func(s *ContainerSpec) { s.Files = []FileMount{{}} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := validSpec(t)
			mutate(&s)
			if err := CheckContainerSpec(s); err == nil {
				t.Errorf("accepted %+v", s)
			}
		})
	}
}

func TestCheckSystemSpec(t *testing.T) {
	t.Parallel()
	ok := SystemSpec{Name: "armada-haproxy", Image: "haproxy@sha256:x", Labels: map[string]string{"armada.system": "haproxy"},
		Mounts: []Mount{{Source: "/var/lib/armada/haproxy", Target: "/usr/local/etc/haproxy", ReadOnly: true}}}
	if err := CheckSystemSpec(ok); err != nil {
		t.Fatalf("valid spec refused: %v", err)
	}
	for name, s := range map[string]SystemSpec{
		"no label":  {Name: ok.Name, Image: ok.Image},
		"no name":   {Image: ok.Image, Labels: ok.Labels},
		"no image":  {Name: ok.Name, Labels: ok.Labels},
		"bad mount": {Name: ok.Name, Image: ok.Image, Labels: ok.Labels, Mounts: []Mount{{Source: "/a:/b", Target: "/c"}}},
	} {
		if err := CheckSystemSpec(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestListenAt(t *testing.T) {
	t.Parallel()
	// Short path: socket paths are limited to about 100 bytes.
	base, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	dir := filepath.Join(base, "drivers")
	l, err := listenAt(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, "test.sock"): 0o600} {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v, %v", path, fi.Mode().Perm(), err)
		}
	}
	// A stale socket is replaced; a regular file is not.
	if l2, err := listenAt(dir, "test"); err != nil {
		t.Errorf("stale socket: %v", err)
	} else {
		_ = l2.Close()
	}
	_ = l.Close()
	if err := os.WriteFile(filepath.Join(dir, "file.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenAt(dir, "file"); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("regular file replaced: %v", err)
	}
	if _, err := Listen("../escape"); err == nil {
		t.Error("Listen accepted an invalid name")
	}
}

func TestStatusRoundTrip(t *testing.T) {
	t.Parallel()
	if err := FromStatus(toStatus(ErrNotFound)); !errors.Is(err, ErrNotFound) {
		t.Errorf("not found: %v", err)
	}
	var pe *PlatformError
	err := FromStatus(toStatus(&PlatformError{Image: "x", Want: "linux/arm64", Have: []string{"linux/amd64"}}))
	if !errors.As(err, &pe) || pe.Want != "linux/arm64" || len(pe.Have) != 1 {
		t.Errorf("platform error: %v", err)
	}
	if err := FromStatus(toStatus(errors.New("boom"))); err == nil || err.Error() != "boom" {
		t.Errorf("other error: %v", err)
	}
}
