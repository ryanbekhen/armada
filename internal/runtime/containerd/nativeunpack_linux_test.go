package containerd

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/diff/apply"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/storage"
	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"

	"github.com/ryanbekhen/armada/internal/runtime/supervisor"
)

// The parity tests of armada-node's layer unpacking (node/src/runtime/
// image/unpack.rs, layers.rs) and of the supervisor store's conversion
// (supervisor.ConvertImages): crafted layers applied by containerd's own
// applier and by armada-node runtime apply, chains of them as the
// overlay snapshotter stacks them, images pulled by both runtimes, and a
// converted supervisor store against armada-node's own pulls; the trees
// must agree entry by entry. Gated on ARMADA_NODE_BIN.
//
// Cases that need root (owners other than the test's, devices, the
// trusted.overlay.opaque attribute, and the first layer through a real
// bind mount) skip without it; run them as root with
//
//	go test -c -o unpack.test ./internal/runtime/containerd
//	sudo ARMADA_NODE_BIN=$PWD/node/target/x86_64-unknown-linux-musl/release/armada-node \
//	    ./unpack.test -test.run 'TestArmadaNode(Unpack|PullUnpacks|Convert)' -test.v

func isRoot() bool { return os.Geteuid() == 0 }

// blobProvider serves one blob to the applier.
type blobProvider struct{ b []byte }

type blobReaderAt struct{ *bytes.Reader }

func (blobReaderAt) Close() error { return nil }

func (p blobProvider) ReaderAt(context.Context, ocispec.Descriptor) (content.ReaderAt, error) {
	return blobReaderAt{bytes.NewReader(p.b)}, nil
}

// applyLayer applies a layer with containerd's applier as the overlay
// snapshotter's mounts hand it over: an overlay mount over lowers (closest
// first) when there are any, else a bind mount of dir. Without root a
// bind mount cannot be made, so the first layer goes to archive.Apply
// directly, which is what the applier runs on the mounted directory.
func applyLayer(ctx context.Context, prov content.Provider, desc ocispec.Descriptor, dir string, lowers []string) (digest.Digest, error) {
	a := apply.NewFileSystemApplier(prov)
	if len(lowers) > 0 {
		work := dir + ".work"
		if err := os.MkdirAll(work, 0o711); err != nil {
			return "", err
		}
		m := mount.Mount{Type: "overlay", Source: "overlay", Options: []string{"workdir=" + work, "upperdir=" + dir, "lowerdir=" + strings.Join(lowers, ":")}}
		d, err := a.Apply(ctx, desc, []mount.Mount{m})
		return d.Digest, err
	}
	if isRoot() {
		d, err := a.Apply(ctx, desc, []mount.Mount{{Type: "bind", Source: dir, Options: []string{"rw", "rbind"}}})
		return d.Digest, err
	}
	ra, err := prov.ReaderAt(ctx, desc)
	if err != nil {
		return "", err
	}
	defer func() { _ = ra.Close() }()
	r := content.NewReader(ra)
	comp, err := images.DiffCompression(ctx, desc.MediaType)
	if err != nil {
		return "", err
	}
	if comp != "" {
		ds, err := compression.DecompressStream(r)
		if err != nil {
			return "", err
		}
		defer func() { _ = ds.Close() }()
		r = ds
	}
	dg := digest.Canonical.Digester()
	tee := io.TeeReader(r, dg.Hash())
	if _, err := archive.Apply(ctx, dir, tee); err != nil {
		return "", err
	}
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return "", err
	}
	return dg.Digest(), nil
}

// directApplier is the applier for a supervisor store in these tests:
// applyLayer on the snapshot's directories.
type directApplier struct{ cs content.Store }

func (a directApplier) Apply(ctx context.Context, desc ocispec.Descriptor, mounts []mount.Mount, _ ...diff.ApplyOpt) (ocispec.Descriptor, error) {
	if isRoot() {
		return apply.NewFileSystemApplier(a.cs).Apply(ctx, desc, mounts)
	}
	m := mounts[0]
	dir, lowers := m.Source, []string(nil)
	for _, o := range m.Options {
		if v, ok := strings.CutPrefix(o, "upperdir="); ok {
			dir = v
		} else if v, ok := strings.CutPrefix(o, "lowerdir="); ok {
			lowers = strings.Split(v, ":")
		}
	}
	d, err := applyLayer(ctx, a.cs, desc, dir, lowers)
	return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: d}, err
}

func rustApply(t *testing.T, bin, dir string, lowers []string, blob []byte, mt string) (string, string) {
	t.Helper()
	args := []string{"runtime", "apply", dir, "--media-type", mt}
	for _, l := range lowers {
		args = append(args, "--lower", l)
	}
	var out struct {
		DiffID string `json:"diffID"`
		Error  string `json:"error"`
	}
	b := runNode(t, bin, blob, args...)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("armada-node runtime apply: %v: %s", err, b)
	}
	return out.DiffID, out.Error
}

// entry is one tar entry of a crafted layer.
type entry struct {
	tar.Header
	body string
}

var past = time.Unix(1_500_000_000, 0)

func file(name string, mode int64, body string) entry {
	return entry{Header: tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: mode, ModTime: past}, body: body}
}

func dirEntry(name string, mode int64) entry {
	return entry{Header: tar.Header{Typeflag: tar.TypeDir, Name: name, Mode: mode, ModTime: past.Add(time.Hour)}}
}

func symlink(name, target string) entry {
	return entry{Header: tar.Header{Typeflag: tar.TypeSymlink, Name: name, Linkname: target, Mode: 0o777, ModTime: past}}
}

func hardlink(name, target string) entry {
	// A link's header sets the mode, owner, and times of the inode it
	// shares, as image builders write them.
	return entry{Header: tar.Header{Typeflag: tar.TypeLink, Name: name, Linkname: target, Mode: 0o644, ModTime: past}}
}

func makeTar(t *testing.T, es []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range es {
		h := e.Header
		if h.Uid == 0 && h.Gid == 0 && !e.rootOwned() && h.Typeflag != tar.TypeXGlobalHeader {
			h.Uid, h.Gid = os.Getuid(), os.Getgid()
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// rootOwned marks an entry meant for uid 0 (Uname "root").
func (e entry) rootOwned() bool { return e.Uname == "root" }

// compress writes a layer for a media type.
func compress(t *testing.T, b []byte, mt string) []byte {
	switch {
	case strings.HasSuffix(mt, "gzip"):
		return gzipBytes(t, b)
	case strings.HasSuffix(mt, "zstd"):
		return zstdBytes(t, b)
	}
	return b
}

// node is what the comparison reads of one entry of a tree.
// checkKnownTree checks what armada-node left for a case where it does
// what containerd's applier did not.
func checkKnownTree(t *testing.T, name, dir string) {
	t.Helper()
	tree := treeOf(t, dir)
	want := map[string]func(map[string]node) bool{
		// The file keeps its own mode and time; the link is the file.
		"hardlink header": func(n map[string]node) bool {
			f, l := n["f"], n["l"]
			return f.Perm == 0o644 && f.Mtime == past.UnixNano() && l.ino == f.ino && l.Perm == 0o644
		},
		// The file the global header's name named is still there.
		"global header": func(n map[string]node) bool { return n["f"].Size == 1 },
		// The gzip inside was read.
		"gzip under a plain type": func(n map[string]node) bool { return n["d"].Size == 1 },
	}[name]
	if want != nil && !want(tree) {
		t.Errorf("%s: armada-node's layer: %+v", name, tree)
	}
}

type node struct {
	Type   fs.FileMode
	Perm   uint32
	UID    uint32
	GID    uint32
	Size   int64
	Sum    string
	Link   string
	Rdev   uint64
	Xattrs map[string]string
	Mtime  int64
	ino    uint64
}

func xattrsOf(p string) map[string]string {
	out := map[string]string{}
	sz, err := unix.Llistxattr(p, nil)
	if err != nil || sz == 0 {
		return out
	}
	buf := make([]byte, sz)
	n, err := unix.Llistxattr(p, buf)
	if err != nil {
		return out
	}
	for _, k := range strings.Split(string(buf[:n]), "\x00") {
		if k == "" {
			continue
		}
		v := make([]byte, 4096)
		m, err := unix.Lgetxattr(p, k, v)
		if err == nil {
			out[k] = string(v[:m])
		}
	}
	return out
}

// treeOf reads every entry under dir.
func treeOf(t *testing.T, dir string) map[string]node {
	t.Helper()
	out := map[string]node{}
	err := filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st := fi.Sys().(*syscall.Stat_t)
		n := node{
			Type: fi.Mode().Type(), Perm: st.Mode & 0o7777, UID: st.Uid, GID: st.Gid,
			Rdev: st.Rdev, Xattrs: xattrsOf(p), Mtime: st.Mtim.Nano(), ino: st.Ino,
		}
		switch {
		case fi.Mode().IsRegular():
			n.Size = fi.Size()
			b, err := os.ReadFile(p)
			if err != nil {
				n.Sum = "unreadable"
				break
			}
			s := sha256.Sum256(b)
			n.Sum = hex.EncodeToString(s[:])
		case fi.Mode()&fs.ModeSymlink != 0:
			n.Link, err = os.Readlink(p)
			if err != nil {
				return err
			}
		}
		rel, _ := filepath.Rel(dir, p)
		out[rel] = n
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// links groups the paths that share an inode.
func links(tr map[string]node) []string {
	by := map[uint64][]string{}
	for p, n := range tr {
		if n.Type == 0 {
			by[n.ino] = append(by[n.ino], p)
		}
	}
	var out []string
	for _, ps := range by {
		if len(ps) > 1 {
			sort.Strings(ps)
			out = append(out, strings.Join(ps, "="))
		}
	}
	sort.Strings(out)
	return out
}

// compareTrees compares two trees entry by entry; mtimes only where one
// side's is older than since (the rest are when the test made them).
func compareTrees(t *testing.T, label string, g, r map[string]node, since time.Time) {
	t.Helper()
	if gk, rk := keys(g), keys(r); !slices.Equal(gk, rk) {
		t.Errorf("%s: entries\nGo          %v\narmada-node %v", label, gk, rk)
		return
	}
	for p, a := range g {
		b := r[p]
		at, bt := a.Mtime, b.Mtime
		if (at >= since.UnixNano() && bt >= since.UnixNano()) || p == "." {
			at, bt = 0, 0
		}
		a.Mtime, b.Mtime, a.ino, b.ino = at, bt, 0, 0
		if a.Type != b.Type || a.Perm != b.Perm || a.UID != b.UID || a.GID != b.GID || a.Size != b.Size ||
			a.Sum != b.Sum || a.Link != b.Link || a.Rdev != b.Rdev || a.Mtime != b.Mtime || !equalLabels(a.Xattrs, b.Xattrs) {
			t.Errorf("%s: %s\nGo          %+v\narmada-node %+v", label, p, a, b)
		}
	}
	if gl, rl := links(g), links(r); !slices.Equal(gl, rl) {
		t.Errorf("%s: hard links Go %v, armada-node %v", label, gl, rl)
	}
}

// mkLayerDir makes a layer's directory as the snapshotter does (0755).
func mkLayerDir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

type unpackCase struct {
	name   string
	root   bool
	mt     string
	layers [][]entry
	// gzip writes every layer gzip-compressed whatever mt says.
	gzip bool
	// truncate cuts every layer's blob in half.
	truncate bool
	// rust is what armada-node does where containerd's applier was
	// found wrong (Go's result is only logged): "applied", or a text
	// its error holds for the layer at index rustLayer.
	rust      string
	rustLayer int
}

const ociGzip = ocispec.MediaTypeImageLayerGzip

func unpackCases() []unpackCase {
	xattr := func(e entry, k, v string) entry {
		e.Format = tar.FormatPAX
		if e.PAXRecords == nil {
			e.PAXRecords = map[string]string{}
		}
		e.PAXRecords["SCHILY.xattr."+k] = v
		return e
	}
	nanos := file("nanos", 0o644, "x")
	nanos.Format, nanos.ModTime, nanos.AccessTime = tar.FormatPAX, past.Add(123456789), past.Add(time.Minute)
	fifo := entry{Header: tar.Header{Typeflag: tar.TypeFifo, Name: "run/fifo", Mode: 0o600, ModTime: past}}
	owned := func(name string, uid, gid int) entry {
		e := file(name, 0o640, name)
		e.Uid, e.Gid, e.Uname = uid, gid, "root"
		return e
	}
	dev := func(name string, flag byte, major, minor int64) entry {
		return entry{Header: tar.Header{Typeflag: flag, Name: name, Mode: 0o660, Devmajor: major, Devminor: minor, ModTime: past, Uname: "root"}}
	}
	return []unpackCase{
		{name: "files", mt: ociGzip, layers: [][]entry{
			{
				xattr(dirEntry("etc/", 0o755), "user.dir", "etc"),
				file("etc/hosts", 0o644, "127.0.0.1 localhost\n"),
				file("bin/tool", 0o755, "#!/bin/sh\n"),
				file("suid", 0o4755, "s"),
				file("sgid", 0o2755, "g"),
				dirEntry("tmp/", 0o1777),
				symlink("lib", "usr/lib"),
				dirEntry("usr/lib/", 0o755),
				file("lib/liby.so", 0o644, "through the link"),
				hardlink("etc/hosts.bak", "etc/hosts"),
				symlink("abs", "/etc/passwd"),
				fifo,
				xattr(file("noted", 0o600, "n"), "user.note", "hello"),
				xattr(file("admin", 0o600, "a"), "trusted.x", "ignored"),
				xattr(symlink("linkattr", "noted"), "user.x", "refused on links"),
				file("replace", 0o644, "file first"),
				dirEntry("replace/", 0o750),
				dirEntry("dir2/", 0o755),
				file("dir2", 0o644, "then a file"),
				file("gone", 0o644, "removed by the whiteout"),
				file(".wh.gone", 0o644, ""),
				dirEntry("opq/", 0o755),
				file("opq/a", 0o644, "a"),
				file("opq/.wh..wh..opq", 0o644, ""),
				file("opq/b", 0o644, "b"),
				nanos,
				dirEntry("empty/", 0o700),
				file("./dot/./slash//file", 0o644, "cleaned"),
			},
			{
				file("etc/new.conf", 0o644, "new"),
				file("usr/lib/libz.so", 0o644, "z"),
				file("lib/libw.so", 0o644, "w"),
				file("etc/hosts", 0o600, "replaced"),
				file("dot/.wh.file", 0o644, ""),
			},
			{
				file("etc/deep/x", 0o644, "deep"),
				dirEntry("usr/", 0o711),
			},
		}},
		// containerd clamps names that climb out into the layer's root;
		// armada-node refuses the layer.
		{name: "traversal", mt: ociGzip, rust: `entry "../escape" leaves the layer's directory`, layers: [][]entry{
			{
				file("x", 0o644, "x"),
				file("../escape", 0o644, "dotdot"),
				file("/abs", 0o644, "absolute"),
				file("a/../../b", 0o644, "cleaned dotdot"),
				symlink("out", "/outside-of-the-layer"),
				file("out/file", 0o644, "through an absolute link"),
				symlink("up", "../../.."),
				file("up/file2", 0o644, "through a relative link"),
				symlink("sl", "/etc/passwd"),
				hardlink("h", "sl"),
				hardlink("h2", "../../etc/../x"),
				symlink("s", "/etc/hostname"),
				file("s", 0o644, "replaces the link"),
				dirEntry("..", 0o700),
				dirEntry("/", 0o700),
			},
			{
				file("../escape2", 0o644, "over a parent"),
				symlink("up2", "../../../.."),
				file("up2/x", 0o644, "x"),
				file("out/more", 0o644, "more"),
			},
		}},
		{name: "traversal resolved within", mt: ociGzip, layers: [][]entry{
			{
				file("x", 0o644, "x"),
				file("/abs", 0o644, "absolute"),
				symlink("out", "/outside-of-the-layer"),
				file("out/file", 0o644, "through an absolute link"),
				symlink("up", "../../.."),
				file("up/file2", 0o644, "through a relative link"),
				symlink("sl", "/etc/passwd"),
				hardlink("h", "sl"),
				hardlink("h2", "/etc/../x"),
				symlink("s", "/etc/hostname"),
				file("s", 0o644, "replaces the link"),
				dirEntry("/", 0o700),
			},
			{
				symlink("up2", "../../../.."),
				file("up2/x", 0o644, "x"),
				file("out/more", 0o644, "more"),
			},
		}},
		{name: "hardlink outside", mt: ociGzip, rust: `hard link target "../../../etc/hostname" leaves the layer's directory`, layers: [][]entry{{hardlink("h", "../../../etc/hostname")}}},
		{name: "hardlink to a directory", mt: ociGzip, rust: `hard link target "../.." leaves the layer's directory`, layers: [][]entry{{hardlink("h", "../..")}}},
		// A hard link's own header changes nothing of the file it links
		// to; containerd applied the link's mode and time to it.
		{name: "hardlink header", mt: ociGzip, rust: "applied", layers: [][]entry{{file("f", 0o644, "f"), {Header: tar.Header{Typeflag: tar.TypeLink, Name: "l", Linkname: "f", Mode: 0o4777, ModTime: time.Unix(77, 0)}}}}},
		// A global header is not an entry; containerd removed what its
		// name named.
		{name: "global header", mt: ociGzip, rust: "applied", layers: [][]entry{{file("f", 0o644, "f"), {Header: tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "f", PAXRecords: map[string]string{"comment": "x"}}}}}},
		{name: "whiteout of the parent", mt: ociGzip, layers: [][]entry{{file("d/.wh..", 0o644, "")}}},
		{name: "empty whiteout", mt: ociGzip, layers: [][]entry{{file(".wh.", 0o644, "")}}},
		{name: "symlink loop", mt: ociGzip, layers: [][]entry{{symlink("loop", "loop"), file("loop/x", 0o644, "x")}}},
		{name: "parent is a file", mt: ociGzip, layers: [][]entry{{file("f", 0o644, "f"), file("f/x", 0o644, "x")}}},
		{name: "unhandled type", mt: ociGzip, layers: [][]entry{{{Header: tar.Header{Typeflag: tar.TypeCont, Name: "c", ModTime: past}}}}},
		{name: "whiteouts", mt: ociGzip, layers: [][]entry{
			{file("a", 0o644, "a"), file("d/b", 0o644, "b")},
			{file(".wh.a", 0o644, ""), file("d/.wh.b", 0o644, ""), file(".wh.never", 0o644, "")},
		}},
		{name: "zstd", mt: ocispec.MediaTypeImageLayerZstd, layers: [][]entry{{file("z", 0o644, "zstd")}, {file("z2", 0o644, "zstd")}}},
		{name: "plain", mt: ocispec.MediaTypeImageLayer, layers: [][]entry{{file("p", 0o644, "plain")}}},
		{name: "docker gzip", mt: images.MediaTypeDockerSchema2LayerGzip, layers: [][]entry{{file("d", 0o644, "docker")}}},
		{name: "docker plain holding gzip", mt: images.MediaTypeDockerSchema2Layer, gzip: true, layers: [][]entry{{file("d", 0o644, "docker")}}},
		// The bytes decide how a blob is read, as its diff ID is
		// checked; containerd read it as a tar and failed.
		{name: "gzip under a plain type", mt: ocispec.MediaTypeImageLayer, gzip: true, rust: "applied", layers: [][]entry{{file("d", 0o644, "x")}}},
		{name: "truncated", mt: ociGzip, truncate: true, layers: [][]entry{{file("big", 0o644, strings.Repeat("x", 4096))}}},
		{name: "owners", root: true, mt: ociGzip, layers: [][]entry{
			{owned("root", 0, 0), owned("other", 1234, 5678), dirEntry("d/", 0o755)},
			{owned("d/x", 4321, 8765)},
		}},
		{name: "devices", root: true, mt: ociGzip, layers: [][]entry{{dev("null", tar.TypeChar, 1, 3), dev("loop", tar.TypeBlock, 7, 0), dev("big", tar.TypeChar, 4095, 1048575)}}},
		{name: "opaque", root: true, mt: ociGzip, layers: [][]entry{
			{file("d/a", 0o644, "a"), file("d/b", 0o644, "b")},
			{file("d/.wh..wh..opq", 0o644, ""), file("d/c", 0o644, "c")},
		}},
	}
}

// blobs builds each layer's blob for a case.
func (c unpackCase) blobs(t *testing.T) [][]byte {
	var out [][]byte
	for _, es := range c.layers {
		b := compress(t, makeTar(t, es), c.mt)
		if c.gzip {
			b = gzipBytes(t, makeTar(t, es))
		}
		if c.truncate {
			b = b[:len(b)/2]
		}
		out = append(out, b)
	}
	return out
}

// Crafted layers applied by containerd's applier and by armada-node: the
// same trees, diff IDs, and refusals, layer after layer of a chain.
func TestArmadaNodeUnpackMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	since := time.Now()
	for _, c := range unpackCases() {
		t.Run(c.name, func(t *testing.T) {
			if c.root && !isRoot() {
				t.Skip("needs root")
			}
			base := t.TempDir()
			blobs := c.blobs(t)
			for side := range 2 {
				mkLayerDir(t, filepath.Join(base, []string{"go", "rust"}[side]))
			}
			var goLowers, rustLowers []string
			for i, blob := range blobs {
				gdir := filepath.Join(base, "go", "L"+string(rune('0'+i)))
				rdir := filepath.Join(base, "rust", "L"+string(rune('0'+i)))
				mkLayerDir(t, gdir)
				mkLayerDir(t, rdir)
				desc := ocispec.Descriptor{MediaType: c.mt, Digest: digest.FromBytes(blob), Size: int64(len(blob))}
				gd, gerr := applyLayer(context.Background(), blobProvider{blob}, desc, gdir, goLowers)
				rd, rerr := rustApply(t, bin, rdir, rustLowers, blob, c.mt)
				if c.rust != "" && (c.rust == "applied" || i == c.rustLayer) {
					// A known difference: armada-node's outcome checked,
					// containerd's logged.
					t.Logf("layer %d: containerd's applier gives %v (known difference)", i, gerr)
					switch {
					case c.rust == "applied" && rerr != "":
						t.Fatalf("layer %d: armada-node refused: %s", i, rerr)
					case c.rust != "applied" && !strings.Contains(rerr, c.rust):
						t.Fatalf("layer %d: armada-node %q, want an error holding %q", i, rerr, c.rust)
					}
					if rerr != "" {
						break
					}
					checkKnownTree(t, c.name, rdir)
					rustLowers = append([]string{rdir}, rustLowers...)
					continue
				}
				if (gerr != nil) != (rerr != "") {
					t.Fatalf("layer %d: Go %v, armada-node %q", i, gerr, rerr)
				}
				if gerr == nil && gd.String() != rd {
					t.Errorf("layer %d: diff IDs Go %s, armada-node %s", i, gd, rd)
				}
				t.Logf("layer %d: Go %v, armada-node %q", i, gerr, rerr)
				compareTrees(t, filepath.Base(gdir), treeOf(t, gdir), treeOf(t, rdir), since)
				if gerr != nil {
					break
				}
				goLowers = append([]string{gdir}, goLowers...)
				rustLowers = append([]string{rdir}, rustLowers...)
			}
			// Nothing was written beside the layers' directories.
			for side, dir := range []string{"go", "rust"} {
				es, err := os.ReadDir(filepath.Join(base, dir))
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range es {
					if !strings.HasPrefix(e.Name(), "L") {
						t.Errorf("side %d wrote %s outside its layers", side, e.Name())
					}
				}
			}
			for _, p := range []string{"/outside-of-the-layer", filepath.Join(base, "escape"), filepath.Join(filepath.Dir(base), "escape")} {
				if _, err := os.Lstat(p); err == nil {
					t.Errorf("%s exists", p)
				}
			}
		})
	}
}

// image layers of a pull: a base, one that changes and removes, and one
// on top; the second image shares the first two.
func unpackImage(t *testing.T, r *testRegistry, extra string) ocispec.Descriptor {
	t.Helper()
	layers := [][]entry{
		{dirEntry("etc/", 0o755), file("etc/os-release", 0o644, "ID=test\n"), hardlink("etc/os-release.2", "etc/os-release"), symlink("bin", "usr/bin"), file("usr/bin/sh", 0o755, "sh"), file("var/gone", 0o644, "g")},
		{file("etc/app.conf", 0o640, "conf"), file("var/.wh.gone", 0o644, ""), file("bin/tool", 0o755, "through the lower layer's link")},
		{file("app/"+extra, 0o644, extra)},
	}
	var descs []ocispec.Descriptor
	var diffs []digest.Digest
	for i, es := range layers {
		tr := makeTar(t, es)
		mt := []string{ociGzip, ocispec.MediaTypeImageLayerZstd, images.MediaTypeDockerSchema2LayerGzip}[i]
		descs = append(descs, r.put(mt, compress(t, tr, mt)))
		diffs = append(diffs, digest.FromBytes(tr))
	}
	cfg := r.putJSON(t, ocispec.MediaTypeImageConfig, ocispec.Image{Platform: platforms.DefaultSpec(), RootFS: ocispec.RootFS{Type: "layers", DiffIDs: diffs}})
	return r.putJSON(t, ocispec.MediaTypeImageManifest, ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: cfg, Layers: descs})
}

// goPullUnpacked pulls into a supervisor store with the layers applied.
func goPullUnpacked(t *testing.T, dir, image string) pullResult {
	t.Helper()
	imgs, err := supervisor.OpenImages(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = imgs.Close() }()
	imgs.UseApplier(directApplier{cs: (&supervisor.Store{Images: imgs}).ContentStore()})
	d := &Driver{ctr: &supervisor.Store{Images: imgs}}
	img, err := d.Pull(context.Background(), image, nil)
	if err != nil {
		return pullResult{err: err.Error()}
	}
	return pullResult{ref: img.Ref, platforms: img.Platforms}
}

// snapshotDirs maps a supervisor store's committed snapshots to their
// directories.
func snapshotDirs(t *testing.T, dir string) map[string]string {
	t.Helper()
	root := filepath.Join(dir, "snapshots")
	ms, err := storage.NewMetaStore(filepath.Join(root, "metadata.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ms.Close() }()
	out := map[string]string{}
	err = ms.WithTransaction(context.Background(), false, func(ctx context.Context) error {
		var names []string
		if err := storage.WalkInfo(ctx, func(_ context.Context, i snapshots.Info) error {
			if i.Kind == snapshots.KindCommitted {
				names = append(names, i.Name)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, n := range names {
			id, _, _, err := storage.GetInfo(ctx, n)
			if err != nil {
				return err
			}
			out[n] = filepath.Join(root, "snapshots", id, "fs")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func chainsOf(t *testing.T, r *testRegistry, m ocispec.Descriptor) []digest.Digest {
	t.Helper()
	var mf ocispec.Manifest
	if err := json.Unmarshal(r.blob(m.Digest), &mf); err != nil {
		t.Fatal(err)
	}
	var cfg ocispec.Image
	if err := json.Unmarshal(r.blob(mf.Config.Digest), &cfg); err != nil {
		t.Fatal(err)
	}
	return identity.ChainIDs(slices.Clone(cfg.RootFS.DiffIDs))
}

func rustMounts(t *testing.T, bin, dir, image string) ([]string, string) {
	t.Helper()
	var out struct {
		Lower []string `json:"lowerdirs"`
		Error string   `json:"error"`
	}
	if err := json.Unmarshal(runNode(t, bin, nil, "runtime", "mounts", dir, image), &out); err != nil {
		t.Fatal(err)
	}
	return out.Lower, out.Error
}

func dirInode(t *testing.T, p string) uint64 {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// Images pulled by the supervisor runtime and by armada-node: every
// chain's unpacked layer is the same tree; armada-node names them for
// overlay top first, keeps a chain another image shares, and prune
// removes only what no image needs.
func TestArmadaNodePullUnpacksMatchesGo(t *testing.T) {
	e := newPullEnv(t)
	since := time.Now()
	a := unpackImage(t, e.reg, "a")
	b := unpackImage(t, e.reg, "b")
	e.reg.tag("apps/a", "1", a)
	e.reg.tag("apps/b", "1", b)
	ref := e.reg.host + "/apps/a:1"
	if g := goPullUnpacked(t, e.goDir, ref); g.err != "" {
		t.Fatal(g.err)
	}
	if r := rustPull(t, e.bin, e.rustDir, e.pki.caFile, ref, nil); r.err != "" {
		t.Fatal(r.err)
	}
	e.checkStores()
	snaps := snapshotDirs(t, e.goDir)
	chains := chainsOf(t, e.reg, a)
	var want []string
	for _, c := range chains {
		g, ok := snaps[c.String()]
		if !ok {
			t.Fatalf("Go has no snapshot of %s", c)
		}
		rdir := filepath.Join(e.rustDir, "layers", c.Encoded())
		compareTrees(t, c.Encoded()[:12], treeOf(t, g), treeOf(t, rdir), since)
		want = append([]string{rdir}, want...)
	}
	if got, msg := rustMounts(t, e.bin, e.rustDir, ref); msg != "" || !slices.Equal(got, want) {
		t.Errorf("mounts %v %q, want %v", got, msg, want)
	}
	if _, msg := rustMounts(t, e.bin, e.rustDir, e.reg.host+"/apps/none:1"); msg == "" {
		t.Error("mounts of an image not pulled")
	}

	shared := dirInode(t, filepath.Join(e.rustDir, "layers", chains[1].Encoded()))
	refB := e.reg.host + "/apps/b:1"
	if r := rustPull(t, e.bin, e.rustDir, e.pki.caFile, refB, nil); r.err != "" {
		t.Fatal(r.err)
	}
	if dirInode(t, filepath.Join(e.rustDir, "layers", chains[1].Encoded())) != shared {
		t.Error("a shared chain was unpacked again")
	}
	chainsB := chainsOf(t, e.reg, b)
	var out struct {
		Removed []string `json:"removed"`
	}
	if err := json.Unmarshal(runNode(t, e.bin, []byte(`{"keep":["`+ref+`"],"graceSeconds":0}`), "runtime", "prune", e.rustDir), &out); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(out.Removed, []string{refB}) {
		t.Fatalf("prune removed %v", out.Removed)
	}
	es, err := os.ReadDir(filepath.Join(e.rustDir, "layers"))
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, x := range es {
		left = append(left, x.Name())
	}
	var kept []string
	for _, c := range chains {
		kept = append(kept, c.Encoded())
	}
	sort.Strings(kept)
	if !slices.Equal(left, kept) || slices.Contains(left, chainsB[2].Encoded()) {
		t.Errorf("layers left %v, want %v", left, kept)
	}
}

// nodeRecord is armada-node's whole record of an image.
type nodeRecord struct {
	Name      string               `json:"name"`
	Target    ocispec.Descriptor   `json:"target"`
	Manifest  ocispec.Descriptor   `json:"manifest"`
	Config    ocispec.Descriptor   `json:"config"`
	Layers    []ocispec.Descriptor `json:"layers"`
	DiffIDs   []digest.Digest      `json:"diffIDs"`
	ChainID   string               `json:"chainID"`
	Platforms []string             `json:"platforms"`
	Labels    map[string]string    `json:"labels"`
}

func nodeRecords(t *testing.T, bin, dir string) map[string]nodeRecord {
	t.Helper()
	var recs []nodeRecord
	if err := json.Unmarshal(runNode(t, bin, nil, "runtime", "images", dir), &recs); err != nil {
		t.Fatal(err)
	}
	out := map[string]nodeRecord{}
	for _, r := range recs {
		out[r.Name] = r
	}
	return out
}

// A supervisor store converted for armada-node reads as armada-node's own
// pulls of the same images: the same records, the same layer trees, the
// blobs linked; armada-node uses it at once, and an image whose layer
// blob is gone is left out.
func TestArmadaNodeConvertMatchesPull(t *testing.T) {
	e := newPullEnv(t)
	since := time.Now()
	node := platforms.DefaultSpec()
	idx := e.reg.indexImage(t, "multi", ocispec.Platform{OS: "linux", Architecture: "s390x"}, ocispec.Platform{OS: "linux", Architecture: node.Architecture, Variant: node.Variant})
	e.reg.tag("apps/multi", "1", idx)
	a := unpackImage(t, e.reg, "a")
	e.reg.tag("apps/a", "1", a)
	lost := unpackImage(t, e.reg, "lost")
	e.reg.tag("apps/lost", "1", lost)
	refs := []string{e.reg.host + "/apps/multi:1", e.reg.host + "/apps/a:1", e.reg.host + "/apps/lost:1"}
	src := filepath.Join(t.TempDir(), "supervisor", "images")
	for _, ref := range refs {
		if g := goPullUnpacked(t, src, ref); g.err != "" {
			t.Fatal(g.err)
		}
		if r := rustPull(t, e.bin, e.rustDir, e.pki.caFile, ref, nil); r.err != "" {
			t.Fatal(r.err)
		}
	}
	var mf ocispec.Manifest
	if err := json.Unmarshal(e.reg.blob(lost.Digest), &mf); err != nil {
		t.Fatal(err)
	}
	gone := mf.Layers[2].Digest
	if err := os.Remove(filepath.Join(src, "content", "blobs", "sha256", gone.Encoded())); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(filepath.Dir(filepath.Dir(src)), "node", "images")
	sum, err := supervisor.ConvertImages(context.Background(), src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Converted) != 2 || sum.Skipped[refs[2]] == "" {
		t.Fatalf("summary %+v", sum)
	}
	got, want := nodeRecords(t, e.bin, dst), nodeRecords(t, e.bin, e.rustDir)
	delete(want, refs[2])
	if !slices.Equal(keys(got), keys(want)) {
		t.Fatalf("records %v, want %v", keys(got), keys(want))
	}
	for name, g := range got {
		w := want[name]
		gj, _ := json.Marshal(g)
		wj, _ := json.Marshal(w)
		if !bytes.Equal(gj, wj) {
			t.Errorf("%s:\nconverted   %s\narmada-node %s", name, gj, wj)
		}
		for _, c := range identity.ChainIDs(slices.Clone(g.DiffIDs)) {
			compareTrees(t, c.Encoded()[:12], treeOf(t, filepath.Join(dst, "layers", c.Encoded())), treeOf(t, filepath.Join(e.rustDir, "layers", c.Encoded())), since)
		}
		for _, d := range append([]ocispec.Descriptor{g.Target, g.Manifest, g.Config}, g.Layers...) {
			from := filepath.Join(src, "content", "blobs", "sha256", d.Digest.Encoded())
			if dirInode(t, from) != dirInode(t, filepath.Join(dst, "content", "blobs", "sha256", d.Digest.Encoded())) {
				t.Errorf("%s: blob %s not linked", name, d.Digest)
			}
		}
		if _, msg := rustMounts(t, e.bin, dst, name); msg != "" {
			t.Errorf("mounts of %s: %s", name, msg)
		}
	}
	// armada-node uses the converted images as its own: a digest-pinned
	// pull finds the image there, a pull of the lost image fetches it.
	pinned := e.reg.host + "/apps/a@" + a.Digest.String()
	if r := rustPull(t, e.bin, dst, e.pki.caFile, pinned, nil); r.err != "" {
		t.Error(r.err)
	}
	if r := rustPull(t, e.bin, dst, e.pki.caFile, refs[2], nil); r.err != "" {
		t.Error(r.err)
	}
	if recs := nodeRecords(t, e.bin, dst); len(recs) != 4 {
		t.Errorf("records after pulls: %v", keys(recs))
	}
}
