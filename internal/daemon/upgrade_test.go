package daemon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type tarFile struct {
	name, body string
	typ        byte
}

// fakeRelease writes a release mirror for tag with files in its archive
// and returns the download base.
func fakeRelease(t *testing.T, tag string, files []tarFile, corrupt bool) string {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, tag)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		typ := f.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(f.body)), Typeflag: typ}
		if typ != tar.TypeReg {
			h.Size, h.Linkname = 0, "/etc/shadow"
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			_, _ = io.WriteString(tw, f.body)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	archive := fmt.Sprintf("armada_%s_linux_amd64.tar.gz", strings.TrimPrefix(tag, "v"))
	sum := sha256.Sum256(buf.Bytes())
	if corrupt {
		buf.WriteString("x")
	}
	if err := os.WriteFile(filepath.Join(dir, archive), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(hex.EncodeToString(sum[:])+"  "+archive+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return "file://" + base
}

var releaseFiles = []tarFile{
	{name: "armadad", body: "new armadad"},
	{name: "armada", body: "new armada"},
	{name: "deploy/systemd/armada-server.service", body: "ExecStart=/usr/local/bin/armadad server\n"},
	{name: "deploy/systemd/armada-agent.service", body: "ExecStart=/usr/local/bin/armadad agent\n"},
	{name: "README.md", body: "skipped"},
	{name: "../../escape", body: "never"},
	{name: "armada-link", typ: tar.TypeSymlink},
}

func testUpgrader(t *testing.T, base string, active string) (*upgrader, *[]string, *bytes.Buffer) {
	t.Helper()
	bin, units := t.TempDir(), t.TempDir()
	for _, b := range []string{"armadad", "armada"} {
		if err := os.WriteFile(filepath.Join(bin, b), []byte("old "+b), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var calls []string
	var out bytes.Buffer
	u := &upgrader{
		base: base, binDir: bin, unitDir: units, restart: true, goarch: "amd64",
		systemctl: func(_ context.Context, args ...string) error {
			calls = append(calls, strings.Join(args, " "))
			return nil
		},
		isActive: func(_ context.Context, unit string) bool { return unit == active },
		out:      &out, warn: io.Discard,
	}
	return u, &calls, &out
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUpgrade(t *testing.T) {
	t.Parallel()
	base := fakeRelease(t, "v0.2.0", releaseFiles, false)
	u, calls, out := testUpgrader(t, base, "armada-agent")
	if err := u.run(context.Background(), "v0.1.0", "v0.2.0"); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"armadad", "armada"} {
		if got := read(t, filepath.Join(u.binDir, b)); got != "new "+b {
			t.Errorf("%s = %q", b, got)
		}
		if fi, _ := os.Stat(filepath.Join(u.binDir, b)); fi.Mode().Perm() != 0o755 {
			t.Errorf("%s mode %v", b, fi.Mode())
		}
	}
	if got := read(t, filepath.Join(u.unitDir, "armada-agent.service")); got != "ExecStart="+filepath.Join(u.binDir, "armadad")+" agent\n" {
		t.Errorf("unit = %q", got)
	}
	if !slices.Equal(*calls, []string{"daemon-reload", "restart armada-agent"}) {
		t.Errorf("systemctl calls %v", *calls)
	}
	if !strings.Contains(out.String(), "Upgraded to v0.2.0 (from v0.1.0); restarted armada-agent.") {
		t.Errorf("output %q", out.String())
	}
	entries, _ := os.ReadDir(u.unitDir)
	if len(entries) != 2 {
		t.Errorf("unit dir holds %d files", len(entries))
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(u.binDir), "escape")); err == nil {
		t.Error("archive entry escaped")
	}
}

func TestUpgradeRefuses(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		base, current, target, want string
		requireSig                  bool
	}{
		"checksum":  {fakeRelease(t, "v0.2.0", releaseFiles, true), "v0.1.0", "v0.2.0", "checksum mismatch", false},
		"downgrade": {fakeRelease(t, "v0.1.0", releaseFiles, false), "v0.2.0", "v0.1.0", "older", false},
		"version":   {fakeRelease(t, "v0.2.0", releaseFiles, false), "v0.1.0", "v0.2.0; x", "invalid version", false},
		"signature": {fakeRelease(t, "v0.2.0", releaseFiles, false), "v0.1.0", "v0.2.0", "cosign is not installed", true},
		"no armada": {fakeRelease(t, "v0.2.0", releaseFiles[:1], false), "v0.1.0", "v0.2.0", "has no armada", false},
		"missing":   {"file:///nonexistent", "v0.1.0", "v0.2.0", "download", false},
		"scheme":    {"http://example.com", "v0.1.0", "v0.2.0", "want https", false},
	} {
		u, calls, _ := testUpgrader(t, tc.base, "armada-server")
		u.requireSig = tc.requireSig
		err := u.run(context.Background(), tc.current, tc.target)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
		if got := read(t, filepath.Join(u.binDir, "armadad")); got != "old armadad" || len(*calls) != 0 {
			t.Errorf("%s: installed anyway (%q, %v)", name, got, *calls)
		}
	}

	// The same version is not an error, and changes nothing.
	u, calls, out := testUpgrader(t, "file:///nonexistent", "armada-server")
	if err := u.run(context.Background(), "v0.2.0", "v0.2.0"); err != nil || !strings.Contains(out.String(), "Already at v0.2.0") || len(*calls) != 0 {
		t.Errorf("same version: %v %q %v", err, out.String(), *calls)
	}
}
