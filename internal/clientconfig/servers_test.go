package clientconfig

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func machineFile(t *testing.T, content string, trusted bool) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "servers")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	origPath, origTrusted := serversPath, serversTrusted
	serversPath = p
	serversTrusted = func(fs.FileInfo) bool { return trusted }
	t.Cleanup(func() { serversPath, serversTrusted = origPath, origTrusted })
}

func TestMachineServers(t *testing.T) {
	machineFile(t, "10.0.0.1:7443\n10.0.0.2:7443\n\n10.0.0.1:7443\n", true)
	if got := MachineServers(); !slices.Equal(got, []string{"10.0.0.1:7443", "10.0.0.2:7443"}) {
		t.Errorf("MachineServers = %v", got)
	}
	// The config's order comes first; the machine adds what it lacks.
	if got := withMachineServers([]string{"10.0.0.9:7443", "10.0.0.2:7443"}); !slices.Equal(got, []string{"10.0.0.9:7443", "10.0.0.2:7443", "10.0.0.1:7443"}) {
		t.Errorf("withMachineServers = %v", got)
	}
}

func TestMachineServersRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		content string
		trusted bool
	}{
		"not root's or writable by others": {"10.0.0.1:7443\n", false},
		"public address":                   {"10.0.0.1:7443\n8.8.8.8:7443\n", true},
		"not an address":                   {"server\n", true},
		"empty":                            {"", true},
	} {
		t.Run(name, func(t *testing.T) {
			machineFile(t, tc.content, tc.trusted)
			if got := MachineServers(); got != nil {
				t.Errorf("MachineServers = %v, want nil", got)
			}
			if got := withMachineServers([]string{"10.0.0.9:7443"}); !slices.Equal(got, []string{"10.0.0.9:7443"}) {
				t.Errorf("withMachineServers = %v", got)
			}
		})
	}
	origPath := serversPath
	serversPath = filepath.Join(t.TempDir(), "missing")
	t.Cleanup(func() { serversPath = origPath })
	if got := MachineServers(); got != nil {
		t.Errorf("missing file: %v", got)
	}
}

func TestWriteMachineServers(t *testing.T) {
	// A directory created under a strict umask (the units' 0077) still
	// lets every user reach the file.
	dir := filepath.Join(t.TempDir(), "etc-armada")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	machineFile(t, "", true)
	serversPath = filepath.Join(dir, "servers")
	if err := WriteMachineServers([]string{"10.0.0.1:7443", "10.0.0.2:7443"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(serversPath)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, %v", fi.Mode(), err)
	}
	if got := MachineServers(); !slices.Equal(got, []string{"10.0.0.1:7443", "10.0.0.2:7443"}) {
		t.Errorf("read back %v", got)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o711 {
		t.Errorf("directory mode = %v, %v; want 0711", fi.Mode().Perm(), err)
	}
	if err := WriteMachineServers([]string{"8.8.8.8:7443"}); err == nil {
		t.Error("public address written")
	}
}

func TestSameServers(t *testing.T) {
	if !SameServers([]string{"a", "b"}, []string{"b", "a", "a"}) || SameServers([]string{"a"}, []string{"a", "b"}) {
		t.Error("SameServers")
	}
	if got := ParseServers(" 10.0.0.1:7443, 10.0.0.2:7443,,10.0.0.1:7443"); !slices.Equal(got, []string{"10.0.0.1:7443", "10.0.0.2:7443"}) {
		t.Errorf("ParseServers = %v", got)
	}
}
