package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/volbackup"
)

// The parity tests compare armada-node volume archive|restore|size (ADR
// 0054 step 5) with Go's writeArchive, restoreArchive, and volumeSize:
//
//	ARMADA_NODE_BIN=$PWD/node/target/x86_64-unknown-linux-musl/release/armada-node \
//	  go test -run 'TestArmadaNodeVolume' ./internal/agent/
//
// The gzip streams differ (Go's compress/gzip and flate2 compress
// differently), so archives are compared as the tar bytes inside them.

func nodeBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		t.Skip("ARMADA_NODE_BIN is not set")
	}
	return bin
}

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	return out
}

// firstDiff names where two byte strings part, for failures.
func firstDiff(a, b []byte) string {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			lo := i &^ 511
			return fmt.Sprintf("byte %d (block at %d):\n go   %q\n rust %q", i, lo, a[lo:min(lo+512, len(a))], b[lo:min(lo+512, len(b))])
		}
	}
	return fmt.Sprintf("lengths %d and %d", len(a), len(b))
}

func mustDo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// parityTree makes a volume with every kind of entry and header the
// archive writes: modes with setuid, setgid, and sticky bits, times that
// round up and down, before 1970 and past USTAR's range, names that split
// into USTAR's prefix and names that need PAX, names that are not UTF-8 or
// hold control characters, long and non-ASCII link targets, a hard link,
// and a pipe and a socket left out.
func parityTree(t *testing.T) string {
	t.Helper()
	vol := filepath.Join(t.TempDir(), "v")
	mk := func(p string, mode os.FileMode) {
		mustDo(t, os.MkdirAll(filepath.Join(vol, p), 0o700))
		mustDo(t, os.Chmod(filepath.Join(vol, p), mode))
	}
	file := func(p string, b []byte, mode os.FileMode, mtime time.Time) {
		full := filepath.Join(vol, p)
		mustDo(t, os.WriteFile(full, b, 0o600))
		mustDo(t, os.Chmod(full, mode))
		mustDo(t, os.Chtimes(full, mtime, mtime))
	}
	at := func(sec, nsec int64) time.Time { return time.Unix(sec, nsec) }
	mk(".", 0o751)
	mk("a/b", 0o700)
	mk("sticky", 0o1777)
	big := make([]byte, 200<<10+7)
	_, _ = rand.Read(big)
	file("a/b/f.txt", []byte("hello"), 0o640, at(1_700_000_000, 499_999_999))
	file("big", big, 0o600, at(1_700_000_001, 500_000_000))
	file("empty", nil, 0o644, at(1_600_000_000, 0))
	file("setuid", []byte("u"), 0o4755, at(1_600_000_000, 0))
	file("setgid", []byte("g"), 0o2750, at(1_600_000_000, 0))
	file("old", []byte("o"), 0o600, at(-10, 250_000_000))
	file("future", []byte("f"), 0o600, time.Date(2300, 1, 2, 3, 4, 5, 0, time.UTC))
	split := strings.Repeat("d", 60) + "/" + strings.Repeat("y", 60)
	mk(strings.Repeat("d", 60), 0o755)
	file(split, []byte("split"), 0o644, at(1_600_000_000, 0))
	file(strings.Repeat("n", 150), []byte("long"), 0o644, at(1_600_000_000, 0))
	deep := strings.Repeat("e", 120) + "/" + strings.Repeat("e", 120)
	mk(deep, 0o755)
	file(deep+"/"+strings.Repeat("z", 100), []byte("deep"), 0o644, at(1_600_000_000, 0))
	file("héllo", []byte("h"), 0o644, at(1_600_000_000, 0))
	file("bad\xff\xfe", []byte("b"), 0o644, at(1_600_000_000, 0))
	file("esc\x1b]0;t\x07", []byte("e"), 0o644, at(1_600_000_000, 0))
	mustDo(t, os.Symlink("a/b/f.txt", filepath.Join(vol, "link")))
	mustDo(t, os.Symlink(strings.Repeat("l", 150), filepath.Join(vol, "longlink")))
	mustDo(t, os.Symlink("ünï", filepath.Join(vol, "unilink")))
	mustDo(t, os.Symlink("/nowhere", filepath.Join(vol, "dangling")))
	mustDo(t, os.Link(filepath.Join(vol, "big"), filepath.Join(vol, "hard")))
	mustDo(t, syscall.Mkfifo(filepath.Join(vol, "pipe"), 0o600))
	if l, err := net.Listen("unix", filepath.Join(vol, "sock")); err == nil {
		t.Cleanup(func() { _ = l.Close() })
	}
	// Directory times last: their entries changed them.
	for _, d := range []string{deep, strings.Repeat("d", 60), "a/b", "a", "sticky", "."} {
		mustDo(t, os.Chtimes(filepath.Join(vol, d), at(1_650_000_000, 750_000_000), at(1_650_000_000, 750_000_000)))
	}
	return vol
}

func TestArmadaNodeVolumeArchiveMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	vol := parityTree(t)
	var goBuf, rsBuf bytes.Buffer
	mustDo(t, writeArchive(context.Background(), vol, &goBuf))
	wrote, err := nativeArchive(context.Background(), bin, vol, &rsBuf)
	if err != nil || !wrote {
		t.Fatalf("armada-node: wrote=%v err=%v", wrote, err)
	}
	g, r := gunzip(t, goBuf.Bytes()), gunzip(t, rsBuf.Bytes())
	if !bytes.Equal(g, r) {
		t.Fatalf("the tar differs at %s", firstDiff(g, r))
	}
	// The archive holds every kind of header.
	tr := tar.NewReader(bytes.NewReader(g))
	formats := map[tar.Format]int{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		mustDo(t, err)
		formats[h.Format]++
	}
	if formats[tar.FormatUSTAR] == 0 || formats[tar.FormatPAX] == 0 {
		t.Errorf("formats %v: the tree should need both USTAR and PAX", formats)
	}

	// A volume that does not exist.
	missing := filepath.Join(t.TempDir(), "gone")
	gerr := writeArchive(context.Background(), missing, io.Discard)
	_, rerr := nativeArchive(context.Background(), bin, missing, io.Discard)
	if gerr == nil || rerr == nil || gerr.Error() != rerr.Error() {
		t.Errorf("missing volume:\n go   %v\n rust %v", gerr, rerr)
	}
}

// An entry that changes between its lookup and its open fails both the
// same way. Not parallel: archiveHook is the package's.
func TestArmadaNodeVolumeArchiveRefusesAsGo(t *testing.T) {
	bin := nodeBin(t)
	for _, tc := range []struct{ name, action string }{
		{"f\x1b]0;title\x07", "fifo"},
		{"plain", "fifo"},
		{"shrinks", "truncate"},
	} {
		run := func(native bool) error {
			vol := t.TempDir()
			p := filepath.Join(vol, tc.name)
			mustDo(t, os.WriteFile(p, []byte("some content"), 0o600))
			mustDo(t, os.WriteFile(filepath.Join(vol, "a"), []byte("first"), 0o600))
			if native {
				t.Setenv("ARMADA_NODE_TEST_VOLUME_HOOK", tc.name+":"+tc.action)
				_, err := nativeArchive(context.Background(), bin, vol, io.Discard)
				return err
			}
			archiveHook = func(e string) {
				if e != tc.name {
					return
				}
				if tc.action == "fifo" {
					_ = os.Remove(p)
					_ = syscall.Mkfifo(p, 0o600)
				} else {
					_ = os.Truncate(p, 0)
				}
			}
			defer func() { archiveHook = nil }()
			return writeArchive(context.Background(), vol, io.Discard)
		}
		gerr, rerr := run(false), run(true)
		if gerr == nil || rerr == nil || gerr.Error() != rerr.Error() {
			t.Errorf("%q %s:\n go   %v\n rust %v", tc.name, tc.action, gerr, rerr)
			continue
		}
		if errors.Is(gerr, volbackup.ErrChanged) != errors.Is(rerr, volbackup.ErrChanged) {
			t.Errorf("%q: ErrChanged go %v rust %v", tc.name, errors.Is(gerr, volbackup.ErrChanged), errors.Is(rerr, volbackup.ErrChanged))
		}
	}
}

func TestArmadaNodeVolumeSizeMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	dirs := []string{parityTree(t), t.TempDir(), filepath.Join(t.TempDir(), "gone")}
	got, err := nativeSizes(context.Background(), bin, dirs)
	mustDo(t, err)
	for i, d := range dirs {
		if want := volumeSize(context.Background(), d); got[i] != want {
			t.Errorf("%s: armada-node %d, Go %d", d, got[i], want)
		}
	}
}

// failAfter gives n bytes of b, then err (the session failing).
type failAfter struct {
	b   []byte
	n   int
	err error
}

func (f *failAfter) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, f.err
	}
	k := copy(p, f.b[:min(len(f.b), f.n)])
	f.b, f.n = f.b[k:], f.n-k
	return k, nil
}

func gz(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return buf.Bytes()
}

// rawTar writes headers with their content as given (no defaults).
func rawTar(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := e.h
		if h.ModTime.IsZero() && h.Typeflag != tar.TypeXGlobalHeader {
			h.ModTime = time.Unix(1_600_000_000, 0)
		}
		if h.Typeflag == tar.TypeReg && h.Size == 0 {
			h.Size = int64(len(e.body))
		}
		mustDo(t, tw.WriteHeader(&h))
		_, _ = tw.Write([]byte(e.body))
	}
	mustDo(t, tw.Close())
	return buf.Bytes()
}

type tarEntry struct {
	h    tar.Header
	body string
}

// treeOf lists a restored volume: names, types, modes, times, contents,
// and link targets.
func treeOf(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Fprintf(&b, "%s error\n", p)
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		fi, err := os.Lstat(p)
		if err != nil {
			return nil
		}
		st := fi.Sys().(*syscall.Stat_t)
		fmt.Fprintf(&b, "%q %v %d:%d", rel, fi.Mode(), st.Uid, st.Gid)
		if fi.Mode()&fs.ModeSymlink != 0 {
			// A link's own time is when it was made.
			l, _ := os.Readlink(p)
			fmt.Fprintf(&b, " -> %q\n", l)
			return nil
		}
		fmt.Fprintf(&b, " %d %d.%09d", fi.Size(), st.Mtim.Sec, st.Mtim.Nsec)
		switch {
		case fi.Mode().IsRegular():
			c, _ := os.ReadFile(p)
			fmt.Fprintf(&b, " %x", sha256.Sum256(c))
		}
		b.WriteString("\n")
		return nil
	})
	return b.String()
}

var restoreSuffix = regexp.MustCompile(`\.(restore|old)-[0-9a-f]{12}`)

// TestArmadaNodeVolumeRestoreMatchesGo restores the same archives with
// both and compares the errors (paths and random suffixes aside) and the
// volumes left. Not parallel: restoreSpace is the package's.
func TestArmadaNodeVolumeRestoreMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	uid, gid := os.Getuid(), os.Getgid()
	reg := func(name, body string) tarEntry {
		return tarEntry{tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o640, Uid: uid, Gid: gid}, body}
	}
	dir := func(name string, mode int64) tarEntry {
		return tarEntry{tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: mode, Uid: uid, Gid: gid}, ""}
	}
	link := func(name, to string) tarEntry {
		return tarEntry{tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: to, Uid: uid, Gid: gid}, ""}
	}
	bigBody := make([]byte, 1<<20)
	_, _ = rand.Read(bigBody)
	full := rawTar(t,
		dir("./", 0o751), dir("a/", 0o750), dir("a/b/", 0o700), dir("sticky/", 0o1777),
		reg("a/b/f.txt", "hello"),
		tarEntry{tar.Header{Name: "nanos", Typeflag: tar.TypeReg, Mode: 0o4755, Uid: uid, Gid: gid, Format: tar.FormatPAX,
			ModTime: time.Unix(1_700_000_000, 123_456_789), Size: 1}, "n"},
		tarEntry{tar.Header{Name: "before1970", Typeflag: tar.TypeReg, Mode: 0o600, Uid: uid, Gid: gid, Format: tar.FormatPAX,
			ModTime: time.Unix(-5, 250_000_000), Size: 1}, "b"},
		tarEntry{tar.Header{Name: strings.Repeat("g", 150), Typeflag: tar.TypeReg, Mode: 0o600, Uid: uid, Gid: gid, Format: tar.FormatGNU, Size: 1}, "g"},
		reg("big", string(bigBody)),
		reg("empty", ""),
		link("link", "a/b/f.txt"), link("dangling", "/nowhere"),
		reg("héllo\xff", "h"),
	)
	gzFull := gz(t, full)
	badCRC := append([]byte(nil), gzFull...)
	badCRC[len(badCRC)-8] ^= 0xff
	trailing := append(append([]byte(nil), gzFull...), "garbage after the archive"...)
	noEnd := full[:len(full)-1024]

	cases := []struct {
		name  string
		in    []byte
		space *fsFree
		fail  int // the session fails after this many bytes (0: never)
	}{
		{name: "full", in: gzFull},
		{name: "bad crc", in: badCRC},
		{name: "trailing data", in: trailing},
		{name: "no end blocks", in: gz(t, noEnd)},
		{name: "cut in a file", in: gz(t, full)[:len(gzFull)/2]},
		{name: "not gzip", in: []byte("nope, this is not a gzip stream")},
		{name: "short", in: []byte("\x1f\x8b")},
		{name: "empty", in: nil},
		{name: "not tar", in: gz(t, bytes.Repeat([]byte("x"), 2048))},
		{name: "parent", in: gz(t, rawTar(t, reg("../escape", "x")))},
		{name: "absolute", in: gz(t, rawTar(t, reg("/etc/escape", "x")))},
		{name: "through link", in: gz(t, rawTar(t, link("l", "/tmp"), reg("l/escape", "x")))},
		{name: "missing parent", in: gz(t, rawTar(t, reg("a/b", "x")))},
		{name: "device", in: gz(t, rawTar(t, tarEntry{tar.Header{Name: "dev\x1b", Typeflag: tar.TypeChar, Mode: 0o600, Uid: uid, Gid: gid}, ""}))},
		{name: "fifo", in: gz(t, rawTar(t, tarEntry{tar.Header{Name: "p", Typeflag: tar.TypeFifo, Mode: 0o600}, ""}))},
		{name: "hard link", in: gz(t, rawTar(t, reg("a", "x"), tarEntry{tar.Header{Name: "b", Typeflag: tar.TypeLink, Linkname: "a"}, ""}))},
		{name: "file twice", in: gz(t, rawTar(t, reg("a", "x"), reg("a", "y")))},
		{name: "dir over file", in: gz(t, rawTar(t, reg("a", "x"), dir("a/", 0o755)))},
		{name: "link over file", in: gz(t, rawTar(t, reg("a", "x"), link("a", "b")))},
		{name: "empty name", in: gz(t, rawTar(t, tarEntry{tar.Header{Name: "", Typeflag: tar.TypeReg, Mode: 0o600, Size: 1, Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": "x"}}, "x"}))},
		{name: "global header", in: gz(t, rawTar(t, tarEntry{tar.Header{Name: "g", Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": "x"}}, ""}))},
		{name: "negative size", in: gz(t, rawTar(t, tarEntry{tar.Header{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o755, Size: -1}, ""}))},
		{name: "owner", in: gz(t, rawTar(t, tarEntry{tar.Header{Name: "root", Typeflag: tar.TypeReg, Mode: 0o600, Uid: 0, Gid: 0, Size: 1}, "r"}))},
		{name: "read-only dir", in: gz(t, rawTar(t, dir("ro/", 0o555), reg("ro/f", "x")))},
		{name: "space", in: gzFull, space: &fsFree{Bytes: 1<<30 + 100, TotalBytes: 10 << 30, Inodes: 1000, TotalInodes: 10000}},
		{name: "inodes", in: gzFull, space: &fsFree{Bytes: 100 << 30, TotalBytes: 200 << 30, Inodes: 500, TotalInodes: 10000}},
		{name: "space fits", in: gzFull, space: &fsFree{Bytes: 100 << 30, TotalBytes: 200 << 30, Inodes: 9000, TotalInodes: 10000}},
		{name: "session fails in the header", in: gzFull, fail: 5},
		{name: "session fails in a file", in: gzFull, fail: len(gzFull) / 2},
		{name: "session fails at the end", in: gzFull, fail: len(gzFull)},
	}
	norm := func(s, dst string) string {
		return restoreSuffix.ReplaceAllString(strings.ReplaceAll(s, dst, "VOL"), ".$1-X")
	}
	for _, tc := range cases {
		run := func(native bool) (string, string, string) {
			dst := filepath.Join(t.TempDir(), "app", "data")
			mustDo(t, os.MkdirAll(dst, 0o700))
			mustDo(t, os.WriteFile(filepath.Join(dst, "kept"), []byte("1"), 0o600))
			for _, p := range []string{filepath.Join(dst, "kept"), dst} {
				mustDo(t, os.Chtimes(p, time.Unix(1_500_000_000, 0), time.Unix(1_500_000_000, 0)))
			}
			var r io.Reader = bytes.NewReader(tc.in)
			if tc.fail > 0 {
				r = &failAfter{b: tc.in, n: tc.fail, err: errors.New("receive archive: the session ended")}
			}
			var err error
			if native {
				env := "unknown"
				if tc.space != nil {
					env = fmt.Sprintf("%d,%d,%d,%d", tc.space.Bytes, tc.space.TotalBytes, tc.space.Inodes, tc.space.TotalInodes)
				}
				t.Setenv("ARMADA_NODE_TEST_VOLUME_SPACE", env)
				_, err = nativeRestore(bin, dst, r)
			} else {
				restoreSpace = func(string) (fsFree, bool) {
					if tc.space == nil {
						return fsFree{}, false
					}
					return *tc.space, true
				}
				err = restoreArchive(dst, r)
				restoreSpace = fsSpace
			}
			msg := "ok"
			if err != nil {
				msg = norm(err.Error(), dst)
			}
			left, _ := os.ReadDir(filepath.Dir(dst))
			names := make([]string, 0, len(left))
			for _, e := range left {
				names = append(names, e.Name())
			}
			tree := treeOf(t, dst)
			// Leave the trees removable.
			_ = filepath.WalkDir(dst, func(p string, d fs.DirEntry, err error) error {
				if err == nil && d.IsDir() {
					_ = os.Chmod(p, 0o700)
				}
				return nil
			})
			return msg, tree, strings.Join(names, ",")
		}
		gmsg, gtree, gleft := run(false)
		rmsg, rtree, rleft := run(true)
		t.Logf("%s: %s", tc.name, gmsg)
		if gmsg != rmsg {
			t.Errorf("%s: errors differ:\n go   %s\n rust %s", tc.name, gmsg, rmsg)
		}
		if gtree != rtree {
			t.Errorf("%s: volumes differ:\n go:\n%s rust:\n%s", tc.name, gtree, rtree)
		}
		if gleft != rleft {
			t.Errorf("%s: next to the volume: go %s, rust %s", tc.name, gleft, rleft)
		}
	}
}

// Go archives, restores, and measures when armada-node fails before the
// stream is touched, and returns the failure once bytes went through.
func TestNativeVolumeFallsBackToGo(t *testing.T) {
	t.Parallel()
	stand := func(t *testing.T, script string) string {
		p := filepath.Join(t.TempDir(), "armada-node")
		mustDo(t, os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o700))
		return p
	}
	agentWith := func(t *testing.T, bin string) *Agent {
		a, _ := volumeAgent(t)
		a.cfg.VolumeProgram = func() string { return bin }
		return a
	}
	vol := t.TempDir()
	mustDo(t, os.WriteFile(filepath.Join(vol, "f"), []byte("hello"), 0o600))
	var arch bytes.Buffer
	mustDo(t, writeArchive(context.Background(), vol, &arch))

	for name, bin := range map[string]string{
		"missing": filepath.Join(t.TempDir(), "none"),
		"fails":   stand(t, "exit 3"),
	} {
		a := agentWith(t, bin)
		var out bytes.Buffer
		if err := a.archiveVolume(context.Background(), vol, &out); err != nil || len(gunzip(t, out.Bytes())) == 0 {
			t.Errorf("%s: archive: %v", name, err)
		}
		dst := filepath.Join(t.TempDir(), "app", "data")
		if err := a.restoreVolume(dst, bytes.NewReader(arch.Bytes())); err != nil {
			t.Errorf("%s: restore: %v", name, err)
		}
		if b, err := os.ReadFile(filepath.Join(dst, "f")); err != nil || string(b) != "hello" {
			t.Errorf("%s: restored %q %v", name, b, err)
		}
		if got := a.volumeSizes(context.Background(), []string{vol}); len(got) != 1 || got[0] != 5 {
			t.Errorf("%s: sizes %v", name, got)
		}
		for _, op := range []string{"archive", "restore", "size"} {
			if a.volNative.StoodIn(op) != 1 {
				t.Errorf("%s: %s stood in %d times", name, op, a.volNative.StoodIn(op))
			}
		}
	}

	// Output went out, or input came in: the failure is the call's.
	a := agentWith(t, stand(t, `case "$2" in archive) printf abc ;; restore) echo ready >&3; head -c 1 >/dev/null ;; esac; exit 3`))
	var out bytes.Buffer
	err := a.archiveVolume(context.Background(), vol, &out)
	if err == nil || !strings.Contains(err.Error(), "archive volume: armada-node: no answer") || out.String() != "abc" {
		t.Errorf("archive after output: %v %q", err, out.String())
	}
	dst := filepath.Join(t.TempDir(), "app", "data")
	err = a.restoreVolume(dst, bytes.NewReader(arch.Bytes()))
	if err == nil || !strings.Contains(err.Error(), "armada-node: no answer") {
		t.Errorf("restore after input: %v", err)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Error("Go restored after armada-node took the stream")
	}
}
