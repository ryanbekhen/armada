package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/fake"
	"github.com/ryanbekhen/armada/internal/store"
)

func volumeAgent(t *testing.T) (*Agent, *fake.Driver) {
	t.Helper()
	d := fake.New()
	ok := func(context.Context, string, string) error { return nil }
	return New(Config{NodeID: "n1", PrivateIP: "10.0.0.2", Driver: d, CPUMillis: 1000, MemoryBytes: 1 << 30, Check: ok,
		VolumesDir: filepath.Join(t.TempDir(), "volumes")}), d
}

func TestPrepareVolumes(t *testing.T) {
	t.Parallel()
	a, d := volumeAgent(t)
	s := replica("web-r1-a", "nginx", 80)
	s.Volumes = []*armadav1.VolumeSpec{{Name: "data", Path: "/data"}}
	a.setDesired([]*armadav1.ReplicaSpec{s}, nil)
	if _, err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(a.cfg.VolumesDir, "web", "data")
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("volume directory: %v %v", fi, err)
	}
	cs, _ := d.List(context.Background(), map[string]string{runtime.LabelReplica: "web-r1-a"})
	if len(cs) != 1 {
		t.Fatalf("containers %v", cs)
	}
	cspec, _ := d.Spec(cs[0].ID)
	if got := cspec.Volumes; len(got) != 1 || got[0] != (runtime.VolumeMount{Source: dir, Target: "/data"}) {
		t.Errorf("mounts %+v", got)
	}
	// Data written survives the container being recreated.
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureVolume(dir, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "x")); err != nil {
		t.Error("data lost")
	}

	// A link where the volume should be is refused, as are bad names.
	link := filepath.Join(a.cfg.VolumesDir, "web", "evil")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatal(err)
	}
	if err := ensureVolume(link, ""); err == nil {
		t.Error("a link was accepted as a volume")
	}
	for _, v := range [][2]string{{"web", "../x"}, {"../web", "data"}, {"web", "a/b"}, {"web", ""}} {
		if _, err := a.volumeDir(v[0], v[1]); err == nil {
			t.Errorf("volumeDir(%q, %q) accepted", v[0], v[1])
		}
	}

	// A node whose runtime cannot mount volumes refuses the replica.
	b, d2 := volumeAgent(t)
	d2.NoVolumes = true
	b.setDesired([]*armadav1.ReplicaSpec{s}, nil)
	rep, _ := b.Reconcile(context.Background())
	if len(rep.GetReplicas()) != 1 || rep.Replicas[0].State != store.ReplicaFailed || !strings.Contains(rep.Replicas[0].Message, "cannot mount volumes") {
		t.Errorf("report %v", rep)
	}
}

func TestPauseKeepsAppStopped(t *testing.T) {
	t.Parallel()
	a, d := volumeAgent(t)
	ctx := context.Background()
	s := replica("web-r1-a", "nginx", 80)
	a.setDesired([]*armadav1.ReplicaSpec{s}, nil)
	if _, err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.pause(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		rep, err := a.Reconcile(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Replicas) != 1 || rep.Replicas[0].State != store.ReplicaExited || rep.Replicas[0].Message != pausedMessage {
			t.Fatalf("paused report %v", rep)
		}
	}
	cs, _ := d.List(ctx, map[string]string{runtime.LabelApp: "web"})
	for _, c := range cs {
		if c.State == runtime.StateRunning {
			t.Error("container runs while paused")
		}
	}
	a.resume("web")
	rep, _ := a.Reconcile(ctx)
	if len(rep.Replicas) != 1 || rep.Replicas[0].State != store.ReplicaRunning {
		t.Errorf("after resume %v", rep)
	}
	if len(a.crashes) != 0 {
		t.Errorf("the stop counted as a crash: %v", a.crashes)
	}
}

func TestArchiveRoundTrip(t *testing.T) {
	t.Parallel()
	src := filepath.Join(t.TempDir(), "src")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(src, "a", "b"), 0o750))
	must(os.WriteFile(filepath.Join(src, "a", "b", "f.txt"), []byte("hello"), 0o640))
	must(os.WriteFile(filepath.Join(src, "top"), bytes.Repeat([]byte("x"), 3*VolumeChunk+5), 0o600))
	must(os.Symlink("a/b/f.txt", filepath.Join(src, "link")))
	must(os.Chmod(src, 0o751))

	var buf bytes.Buffer
	must(writeArchive(context.Background(), src, &buf))

	dst := filepath.Join(t.TempDir(), "app", "data")
	must(os.MkdirAll(dst, 0o700))
	must(os.WriteFile(filepath.Join(dst, "old"), []byte("gone"), 0o600))
	must(restoreArchive(dst, &buf))

	if b, err := os.ReadFile(filepath.Join(dst, "a", "b", "f.txt")); err != nil || string(b) != "hello" {
		t.Errorf("file: %q %v", b, err)
	}
	if fi, _ := os.Stat(filepath.Join(dst, "a", "b", "f.txt")); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", fi.Mode())
	}
	if fi, _ := os.Stat(filepath.Join(dst, "top")); fi.Size() != 3*VolumeChunk+5 {
		t.Errorf("size %d", fi.Size())
	}
	if l, err := os.Readlink(filepath.Join(dst, "link")); err != nil || l != "a/b/f.txt" {
		t.Errorf("link %q %v", l, err)
	}
	if fi, _ := os.Stat(dst); fi.Mode().Perm() != 0o751 {
		t.Errorf("root mode %v", fi.Mode())
	}
	if _, err := os.Stat(filepath.Join(dst, "old")); err == nil {
		t.Error("restore kept a file the archive does not have")
	}
	entries, _ := os.ReadDir(filepath.Dir(dst))
	if len(entries) != 1 {
		t.Errorf("leftovers next to the volume: %v", entries)
	}
}

func archive(t *testing.T, entries ...*tar.Header) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, h := range entries {
		if h.Typeflag == tar.TypeReg {
			h.Size = 1
		}
		if h.ModTime.IsZero() {
			h.ModTime = time.Now()
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write([]byte("x"))
		}
	}
	_ = tw.Close()
	_ = zw.Close()
	return &buf
}

func TestRestoreRefusesBadArchives(t *testing.T) {
	t.Parallel()
	uid, gid := os.Getuid(), os.Getgid()
	reg := func(name string) *tar.Header {
		return &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Uid: uid, Gid: gid}
	}
	for name, entries := range map[string][]*tar.Header{
		"parent":       {reg("../escape")},
		"absolute":     {reg("/etc/escape")},
		"through link": {{Name: "l", Typeflag: tar.TypeSymlink, Linkname: "/tmp", Uid: uid, Gid: gid}, reg("l/escape")},
		"device":       {{Name: "dev", Typeflag: tar.TypeChar, Mode: 0o600, Uid: uid, Gid: gid}},
		"hard link":    {reg("a"), {Name: "b", Typeflag: tar.TypeLink, Linkname: "a", Uid: uid, Gid: gid}},
		"file twice":   {reg("a"), reg("a")},
	} {
		dst := filepath.Join(t.TempDir(), "app", "data")
		if err := os.MkdirAll(dst, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, "kept"), []byte("1"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := restoreArchive(dst, archive(t, entries...)); err == nil {
			t.Errorf("%s: archive accepted", name)
		}
		if _, err := os.Stat(filepath.Join(dst, "kept")); err != nil {
			t.Errorf("%s: a failed restore changed the volume", name)
		}
		if entries, _ := os.ReadDir(filepath.Dir(dst)); len(entries) != 1 {
			t.Errorf("%s: leftovers %v", name, entries)
		}
	}
	if _, err := os.Stat("/tmp/escape"); err == nil {
		t.Error("an archive wrote through a link")
	}
	// Not an archive at all.
	if err := restoreArchive(filepath.Join(t.TempDir(), "d"), strings.NewReader("nope")); err == nil {
		t.Error("garbage accepted")
	}
}

func TestMeasureVolumes(t *testing.T) {
	t.Parallel()
	a, _ := volumeAgent(t)
	dir := filepath.Join(a.cfg.VolumesDir, "web", "data")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "a"), make([]byte, 100), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "sub", "b"), make([]byte, 50), 0o600)
	_ = os.MkdirAll(filepath.Join(a.cfg.VolumesDir, "web", "data.restore-abc"), 0o700) // not a volume
	got := a.measureVolumes(context.Background())
	if len(got) != 1 || got[0].App != "web" || got[0].Volume != "data" || got[0].Bytes != 150 {
		t.Errorf("measured %v", got)
	}
}

func TestChownVolumeOnlyAsRoot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// A user's agent skips the owner instead of failing the replica.
	if err := chownVolumeAs(dir, "70:70", 501); err != nil {
		t.Errorf("as a user: %v", err)
	}
	// As root a bad owner is still an error (it never passes the spec).
	if err := chownVolumeAs(dir, "x", 0); err == nil {
		t.Error("bad owner accepted as root")
	}
}
