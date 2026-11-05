package embedded

import (
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
	for _, f := range []string{BinContainerd, BinShim, BinRunc, BinTini} {
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
