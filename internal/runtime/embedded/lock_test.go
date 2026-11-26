package embedded

import (
	"encoding/json"
	"maps"
	"os"
	"strings"
	"testing"
)

func TestLock(t *testing.T) {
	t.Parallel()
	names := map[string]bool{}
	files := map[string]bool{}
	for _, a := range Lock {
		if names[a.Name] {
			t.Errorf("%s pinned twice", a.Name)
		}
		names[a.Name] = true
		for _, arch := range []string{"amd64", "arm64"} {
			if len(a.SHA256[arch]) != 64 {
				t.Errorf("%s: no SHA-256 for %s", a.Name, arch)
			}
			u := a.URLFor(arch)
			if !strings.HasPrefix(u, "https://") || strings.Contains(u, "{arch}") {
				t.Errorf("%s: URL %s", a.Name, u)
			}
		}
		for _, f := range a.Files {
			if err := checkName(f); err != nil {
				t.Errorf("%s: %v", a.Name, err)
			}
			files[f] = true
		}
		if len(a.Files) == 0 {
			files[a.Name] = true
		}
	}
	for _, f := range []string{BinContainerd, BinShim, BinRunc, BinTini, BinEtcd, BinEtcdutl} {
		if !files[f] {
			t.Errorf("%s is not in the bundle", f)
		}
	}
	if len(files) > maxPackFiles {
		t.Errorf("%d files, the pack allows %d", len(files), maxPackFiles)
	}
}

func TestURLFor(t *testing.T) {
	t.Parallel()
	a := Artifact{URL: "https://example.test/x-{arch}.tgz"}
	if got := a.URLFor("arm64"); got != "https://example.test/x-arm64.tgz" {
		t.Errorf("URLFor: %s", got)
	}
}

func TestFilesFor(t *testing.T) {
	t.Parallel()
	a := Artifact{Files: map[string]string{"x-{arch}/etcd": "etcd"}}
	if got := a.FilesFor("arm64"); len(got) != 1 || got["x-arm64/etcd"] != "etcd" {
		t.Errorf("FilesFor: %v", got)
	}
	if got := (Artifact{}).FilesFor("amd64"); got != nil {
		t.Errorf("FilesFor without files: %v", got)
	}
}

// The pinned etcd is the version armadad embeds (go.mod), so a member's
// files keep their version whether it is embedded or runs from the pack
// (ADR 0055).
func TestEtcdMatchesModule(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	var pinned string
	for _, a := range Lock {
		if a.Name == "etcd" {
			pinned = a.Version
		}
	}
	for _, mod := range []string{"go.etcd.io/etcd/server/v3", "go.etcd.io/etcd/etcdutl/v3"} {
		found := false
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == mod {
				found = true
				if f[1] != "v"+pinned {
					t.Errorf("go.mod requires %s %s, lock.go pins etcd %s", mod, f[1], pinned)
				}
			}
		}
		if !found {
			t.Errorf("go.mod does not require %s", mod)
		}
	}
}

// pack/lock.json holds the pins armada-pack builds the pack from (ADR
// 0055, item 20); lock.go keeps the same pins for Go's code while it is in
// the repository.
func TestLockMatchesFile(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../../pack/lock.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Artifacts []struct {
			Name    string            `json:"name"`
			Version string            `json:"version"`
			URL     string            `json:"url"`
			SHA256  map[string]string `json:"sha256"`
			Files   map[string]string `json:"files"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Artifacts) != len(Lock) {
		t.Fatalf("pack/lock.json pins %d artifacts, lock.go %d", len(file.Artifacts), len(Lock))
	}
	for i, a := range Lock {
		f := file.Artifacts[i]
		if f.Name != a.Name || f.Version != a.Version || f.URL != a.URL ||
			!maps.Equal(f.SHA256, a.SHA256) || !maps.Equal(f.Files, a.Files) {
			t.Errorf("pack/lock.json's %s differs from lock.go's %s", f.Name, a.Name)
		}
	}
}
