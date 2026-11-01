package embedded

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testPack(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	p, err := Pack("amd64", map[string]string{"runc": "1.0"}, files)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInstall(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runtime")
	files := map[string][]byte{"runc": []byte("runc-binary"), "cni/bridge": []byte("bridge-binary")}
	pack := testPack(t, files)

	bin, m, err := Install(root, pack)
	if err != nil {
		t.Fatal(err)
	}
	if bin != filepath.Join(root, "current", "bin") || m.Arch != "amd64" || m.Versions["runc"] != "1.0" {
		t.Fatalf("bin=%s manifest=%+v", bin, m)
	}
	for n, want := range files {
		got, err := os.ReadFile(filepath.Join(bin, n))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s = %q, %v", n, got, err)
		}
		fi, _ := os.Stat(filepath.Join(bin, n))
		if fi.Mode().Perm() != 0o755 {
			t.Errorf("%s mode %v", n, fi.Mode())
		}
	}
	if fi, _ := os.Stat(root); fi.Mode().Perm() != 0o700 {
		t.Errorf("root mode %v", fi.Mode())
	}

	// A tampered file is replaced on the next install.
	if err := os.WriteFile(filepath.Join(bin, "runc"), []byte("evil"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Install(root, pack); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(bin, "runc")); string(got) != "runc-binary" {
		t.Errorf("tampered runc not restored: %q", got)
	}

	// A file swapped for a symlink is replaced as well.
	target := filepath.Join(t.TempDir(), "elsewhere")
	_ = os.WriteFile(target, []byte("runc-binary"), 0o755)
	_ = os.Remove(filepath.Join(bin, "runc"))
	if err := os.Symlink(target, filepath.Join(bin, "runc")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Install(root, pack); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(filepath.Join(bin, "runc")); !fi.Mode().IsRegular() {
		t.Error("symlink not replaced")
	}

	// A new pack becomes current and the old one is removed.
	pack2 := testPack(t, map[string][]byte{"runc": []byte("runc-2")})
	bin2, _, err := Install(root, pack2)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(bin2, "runc")); string(got) != "runc-2" {
		t.Errorf("runc after upgrade = %q", got)
	}
	entries, _ := os.ReadDir(root)
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	if len(dirs) != 1 {
		t.Errorf("pack directories after upgrade: %v", dirs)
	}
}

func TestPackRejectsBadNames(t *testing.T) {
	for _, n := range []string{"", "../x", "/abs", "a/../b", "a\\b", "MANIFEST.json", "..", "a/"} {
		if _, err := Pack("amd64", nil, map[string][]byte{n: []byte("x")}); err == nil {
			t.Errorf("name %q accepted", n)
		}
	}
}

// rawPack builds a pack by hand, for malformed inputs Pack refuses to make.
func rawPack(t *testing.T, entries []tar.Header, bodies []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for i, h := range entries {
		h.Size = int64(len(bodies[i]))
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			_, _ = tw.Write([]byte(bodies[i]))
		}
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

func TestInstallRejectsMalformedPacks(t *testing.T) {
	sum := "a6a1a4ef6f4c1bf3a4a9a8a0a3c5f5ef0d2b0d3c4e5f60718293a4b5c6d7e8f9"
	manifest := `{"arch":"amd64","files":{"runc":"` + sum + `"}}`
	cases := map[string][]byte{
		"not gzip":     []byte("plain"),
		"no manifest":  rawPack(t, []tar.Header{{Name: "runc"}}, []string{"x"}),
		"bad name":     rawPack(t, []tar.Header{{Name: manifestName}}, []string{`{"files":{"../runc":"` + sum + `"}}`}),
		"bad checksum": rawPack(t, []tar.Header{{Name: manifestName}}, []string{`{"files":{"runc":"zz"}}`}),
		"extra entry": rawPack(t, []tar.Header{{Name: manifestName}, {Name: "runc"}, {Name: "evil"}},
			[]string{manifest, "x", "y"}),
		"symlink entry": rawPack(t, []tar.Header{{Name: manifestName}, {Name: "runc", Typeflag: tar.TypeSymlink, Linkname: "/bin/sh"}},
			[]string{manifest, ""}),
		"wrong content": rawPack(t, []tar.Header{{Name: manifestName}, {Name: "runc"}}, []string{manifest, "not matching"}),
		"missing file":  rawPack(t, []tar.Header{{Name: manifestName}}, []string{manifest}),
	}
	for name, pack := range cases {
		root := filepath.Join(t.TempDir(), "runtime")
		if _, _, err := Install(root, pack); err == nil {
			t.Errorf("%s: installed", name)
		}
		if _, err := os.Lstat(filepath.Join(root, "current")); err == nil {
			t.Errorf("%s: current link created", name)
		}
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), ".") {
				t.Errorf("%s: left %s behind", name, e.Name())
			}
		}
	}
}

func TestContainerdConfig(t *testing.T) {
	c := ContainerdConfig(Paths{DataDir: "/var/lib/armada", RunDir: "/run/armada"})
	for _, want := range []string{
		"version = 4\n",
		"imports = []\n",
		`root = "/var/lib/armada/containerd"`,
		`address = "/run/armada/containerd/containerd.sock"`,
		`"io.containerd.grpc.v1.cri"`,
		`"io.containerd.server.v1.grpc-tcp"`,
		`"io.containerd.monitor.container.v1.restart"`,
	} {
		if !strings.Contains(c, want) {
			t.Errorf("config lacks %s:\n%s", want, c)
		}
	}
}
