package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckExecCommand(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", MaxExecArgLen)
	for _, ok := range [][]string{{"sh"}, {"sh", "-c", "echo hi"}, {"x", long}, make([]string, MaxExecArgs)} {
		if len(ok) == MaxExecArgs {
			for i := range ok {
				ok[i] = "a"
			}
		}
		if err := CheckExecCommand(ok); err != nil {
			t.Errorf("%.40q: %v", ok, err)
		}
	}
	for _, bad := range [][]string{nil, {}, {""}, {"sh", long + "a"}, {"sh", "secret\x00value"}, make([]string, MaxExecArgs+1)} {
		err := CheckExecCommand(bad)
		if err == nil {
			t.Errorf("%.40q accepted", bad)
		} else if strings.Contains(err.Error(), "secret") {
			t.Errorf("error repeats an argument: %v", err)
		}
	}
}

func TestCheckVolumeMount(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	link := filepath.Join(dir, "l")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckVolumeMount(VolumeMount{Source: dir, Target: "/data"}); err != nil {
		t.Errorf("valid mount: %v", err)
	}
	for _, bad := range []VolumeMount{
		{Source: "relative", Target: "/data"},
		{Source: "/", Target: "/data"},
		{Source: dir + "/../x", Target: "/data"},
		{Source: dir + ",ro", Target: "/data"},
		{Source: dir + ":x", Target: "/data"},
		{Source: dir, Target: "/"},
		{Source: dir, Target: "/proc/self"},
		{Source: dir, Target: "data"},
		{Source: dir, Target: "/data/../etc"},
		{Source: file, Target: "/data"},
		{Source: link, Target: "/data"},
		{Source: filepath.Join(dir, "missing"), Target: "/data"},
	} {
		if err := CheckVolumeMount(bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	two := ContainerSpec{Image: "x", Volumes: []VolumeMount{{Source: dir, Target: "/data"}, {Source: dir, Target: "/data"}}}
	if err := CheckContainerSpec(two); err == nil {
		t.Error("two volumes at one target accepted")
	}
}
