package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// goStore builds Go's image store under <data>/supervisor/images with
// images a and b pulled by the real store (layers applied by markApplier,
// so no privileges are needed), and an active snapshot container-1 on a
// (a container's root filesystem once a bundle names it: addBundle).
func goStore(t *testing.T) (data, src, dst string, a, b Image) {
	t.Helper()
	ctx := context.Background()
	data = t.TempDir()
	src = filepath.Join(data, "supervisor", "images")
	dst = filepath.Join(data, "node", "images")
	s, err := OpenImages(src)
	if err != nil {
		t.Fatal(err)
	}
	s.UseApplier(markApplier{s.content})
	one, two := []byte("layer one"), []byte("layer two")
	if a, err = s.Pull(ctx, "registry.example/a:1", oneLayer(t, one, digest.FromBytes(one)), nil); err != nil {
		t.Fatal(err)
	}
	if b, err = s.Pull(ctx, "registry.example/b:1", oneLayer(t, two, digest.FromBytes(two)), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prepare(ctx, "container-1", a); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return data, src, dst, a, b
}

// bundlesDir is where the agent keeps containers' bundles under data.
func bundlesDir(data string) string { return filepath.Join(data, "supervisor", "containers") }

// addBundle writes a container's bundle record, as Bundles.Create does
// last (the root filesystem is not mounted: no privileges).
func addBundle(t *testing.T, data, id, image string) {
	t.Helper()
	b := Bundles{Dir: bundlesDir(data)}
	if err := os.MkdirAll(filepath.Join(b.Path(id), bundleRootfs), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(b.Path(id), bundleRecord), Record{ID: id, Image: image, Group: id, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

// upper is the writable directory of Go's active snapshot key.
func upper(t *testing.T, src, key string) string {
	t.Helper()
	snaps, err := readSnapshots(context.Background(), filepath.Join(src, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	sn, ok := snaps[key]
	if !ok {
		t.Fatalf("no snapshot %s", key)
	}
	return filepath.Join(sn.dir, "fs")
}

func readIndex(t *testing.T, dst string) nodeIndex {
	t.Helper()
	var idx nodeIndex
	raw, err := os.ReadFile(filepath.Join(dst, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	return idx
}

func gone(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s is still there (%v)", p, err)
	}
}

// MoveImages converts once, and with no container on Go's store removes
// it and records that; a second start reads the record and does nothing.
// A node with no Go store gets a record at once.
func TestMoveImages(t *testing.T) {
	ctx := context.Background()
	data, src, dst, a, b := goStore(t)
	state := filepath.Join(data, "node", MovedFile)
	st, sum, err := MoveImages(ctx, src, dst, bundlesDir(data), state)
	if err != nil {
		t.Fatal(err)
	}
	if sum == nil || len(sum.Converted) != 2 || st.Converted != 2 || st.Layers != 2 || len(st.Skipped) != 0 || !st.Collected || st.Containers != 0 {
		t.Fatalf("state %+v, summary %+v", st, sum)
	}
	gone(t, src)
	got, ok, err := ReadMoveState(state)
	if err != nil || !ok || got.Converted != 2 || got.At.IsZero() || !got.Collected {
		t.Fatalf("record %+v %v %v", got, ok, err)
	}
	if fi, err := os.Stat(state); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("record file %v %v", fi, err)
	}
	idx := readIndex(t, dst)
	for _, img := range []Image{a, b} {
		if _, ok := idx.Images[img.Name]; !ok {
			t.Errorf("index %v lacks %s", idx.Images, img.Name)
		}
	}
	if st2, sum, err := MoveImages(ctx, src, dst, bundlesDir(data), state); err != nil || sum != nil || st2.Converted != 2 {
		t.Errorf("second move %+v %+v %v", st2, sum, err)
	}

	fresh := t.TempDir()
	st, sum, err = MoveImages(ctx, filepath.Join(fresh, "supervisor", "images"), filepath.Join(fresh, "node", "images"),
		bundlesDir(fresh), filepath.Join(fresh, "node", MovedFile))
	if err != nil || sum != nil || !st.Collected || st.Converted != 0 {
		t.Fatalf("fresh node %+v %+v %v", st, sum, err)
	}
}

// The root filesystem of a container on Go's store (running or not)
// moves into armada-node's layout as its prepare makes it: the upper and
// work directories with what the container wrote, and snapshot.json
// naming the image and its layers. Go's store then has no user and goes,
// and armada-node's release (here Go's stand-in for it) removes the root
// filesystem like its own. A bundle armada-node made is left alone.
func TestMoveActive(t *testing.T) {
	ctx := context.Background()
	data, src, dst, a, _ := goStore(t)
	addBundle(t, data, "container-1", a.Name)
	addBundle(t, data, "rust-made", a.Name)
	if err := os.WriteFile(filepath.Join(upper(t, src, "container-1"), "written"), []byte("by the container"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(data, "node", MovedFile)
	st, _, err := MoveImages(ctx, src, dst, bundlesDir(data), state)
	if err != nil {
		t.Fatal(err)
	}
	if st.Containers != 1 || len(st.ContainersLeft) != 0 || !st.Collected {
		t.Fatalf("state %+v", st)
	}
	gone(t, src)
	dir := filepath.Join(dst, "active", "container-1")
	if b, err := os.ReadFile(filepath.Join(dir, "fs", "written")); err != nil || string(b) != "by the container" {
		t.Errorf("upper directory: %q %v", b, err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "work")); err != nil || !fi.IsDir() {
		t.Errorf("work directory %v", err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("snapshot directory %v %v", fi, err)
	}
	var rec nodeSnapshot
	raw, err := os.ReadFile(filepath.Join(dir, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &rec); err != nil || rec.Image != a.Name || !slices.Equal(rec.Parents, []string{a.ChainID.Encoded()}) {
		t.Errorf("snapshot.json %s (%v)", raw, err)
	}
	if _, err := os.Stat(filepath.Join(dst, "layers", a.ChainID.Encoded(), "layer")); err != nil {
		t.Errorf("its layer: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "active", "rust-made")); err == nil {
		t.Error("a bundle with no snapshot in Go's store got one")
	}
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		bin = filepath.Join(data, "no-armada-node")
	}
	n, err := OpenNative(bin, dst)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ARMADA_NODE_BIN") != "" {
		// armada-node reads the moved root filesystem as one it prepared:
		// the same key gives its mounts.
		m, err := n.Prepare(ctx, "container-1", a.Name)
		if err != nil || len(m) != 1 || m[0].Type != "overlay" ||
			!slices.Contains(m[0].Options, "upperdir="+filepath.Join(dir, "fs")) ||
			!slices.Contains(m[0].Options, "workdir="+filepath.Join(dir, "work")) ||
			!slices.Contains(m[0].Options, "lowerdir="+filepath.Join(dst, "layers", a.ChainID.Encoded())) {
			t.Errorf("armada-node's mounts of the moved root filesystem %+v, %v", m, err)
		}
	}
	s := &Store{Native: n, NodeImages: dst, Bundles: Bundles{Dir: bundlesDir(data)}}
	if err := s.release(ctx, "container-1"); err != nil {
		t.Fatal(err)
	}
	if n.StoodIn("release") > 0 && os.Getenv("ARMADA_NODE_BIN") != "" {
		t.Error("Go released it instead of armada-node")
	}
	gone(t, dir)
	if m := s.MoveStatus(); m.GoImages {
		t.Errorf("status %+v", m)
	}
}

// A move cut short anywhere runs again to the same end: a layer already
// moved, a root filesystem already moved, snapshot.json written but the
// directory not renamed, and a record written while Go's store was being
// removed.
func TestMoveImagesAfterCrash(t *testing.T) {
	ctx := context.Background()
	data, src, dst, a, b := goStore(t)
	state := filepath.Join(data, "node", MovedFile)
	// The conversion got as far as a's layer.
	if err := os.MkdirAll(filepath.Join(dst, "layers"), 0o700); err != nil {
		t.Fatal(err)
	}
	snaps, err := committedSnapshots(ctx, filepath.Join(src, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(snaps[a.ChainID.String()], filepath.Join(dst, "layers", a.ChainID.Encoded())); err != nil {
		t.Fatal(err)
	}
	// Two containers: the first moved by a run that crashed after it, the
	// second with its snapshot.json written but not renamed.
	if err := reopen(t, src, func(s *Images) error { _, err := s.Prepare(ctx, "container-2", b); return err }); err != nil {
		t.Fatal(err)
	}
	addBundle(t, data, "container-1", a.Name)
	if _, err := ConvertImages(ctx, src, dst); err != nil {
		t.Fatal(err)
	}
	if moved, _, left, err := moveActive(ctx, src, dst, bundlesDir(data)); err != nil || moved != 1 || len(left) != 0 {
		t.Fatalf("first run moved %d, left %v, %v", moved, left, err)
	}
	addBundle(t, data, "container-2", b.Name)
	if err := os.WriteFile(filepath.Join(filepath.Dir(upper(t, src, "container-2")), "snapshot.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, sum, err := MoveImages(ctx, src, dst, bundlesDir(data), state)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Skipped) != 0 || len(sum.Kept) != 2 || st.Converted != 2 || st.Containers != 2 || !st.Collected {
		t.Fatalf("state %+v, summary %+v", st, sum)
	}
	var rec nodeSnapshot
	raw, _ := os.ReadFile(filepath.Join(dst, "active", "container-2", "snapshot.json"))
	if err := json.Unmarshal(raw, &rec); err != nil || rec.Image != b.Name {
		t.Errorf("container-2's snapshot.json %s (%v)", raw, err)
	}
	gone(t, src)

	// The record written, Go's store half removed: the next start removes
	// the rest.
	data, src, dst, _, _ = goStore(t)
	state = filepath.Join(data, "node", MovedFile)
	if _, err := ConvertImages(ctx, src, dst); err != nil {
		t.Fatal(err)
	}
	if err := writeMoveState(state, MoveState{Converted: 2}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(src, "snapshots", "metadata.db")); err != nil {
		t.Fatal(err)
	}
	st, sum, err = MoveImages(ctx, src, dst, bundlesDir(data), state)
	if err != nil || sum != nil || !st.Collected || st.Converted != 2 {
		t.Fatalf("after a cut removal %+v %+v %v", st, sum, err)
	}
	gone(t, src)
}

// reopen opens Go's store under src, runs f, and closes it.
func reopen(t *testing.T, src string, f func(*Images) error) error {
	t.Helper()
	s, err := OpenImages(src)
	if err != nil {
		return err
	}
	s.UseApplier(markApplier{s.content})
	ferr := f(s)
	if err := s.Close(); err != nil {
		return err
	}
	return ferr
}

// blocked adds a container whose layer is gone from Go's store (so its
// root filesystem cannot move) and returns its image.
func blocked(t *testing.T, data, src string) Image {
	t.Helper()
	ctx := context.Background()
	three := []byte("layer three")
	var c Image
	if err := reopen(t, src, func(s *Images) error {
		var err error
		if c, err = s.Pull(ctx, "registry.example/c:1", oneLayer(t, three, digest.FromBytes(three)), nil); err != nil {
			return err
		}
		_, err = s.Prepare(ctx, "blocked", c)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	snaps, err := committedSnapshots(ctx, filepath.Join(src, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(snaps[c.ChainID.String()]); err != nil {
		t.Fatal(err)
	}
	addBundle(t, data, "blocked", c.Name)
	return c
}

// A container whose root filesystem cannot move keeps Go's store, named
// with why; the store goes with that container, the moved ones not
// holding it, and the record then says so. Images left out are counted
// until then.
func TestMoveActiveLeft(t *testing.T) {
	ctx := context.Background()
	data, src, dst, a, _ := goStore(t)
	addBundle(t, data, "container-1", a.Name)
	c := blocked(t, data, src)
	state := filepath.Join(data, "node", MovedFile)
	st, _, err := MoveImages(ctx, src, dst, bundlesDir(data), state)
	if err != nil {
		t.Fatal(err)
	}
	if st.Containers != 1 || st.ContainersLeft["blocked"] == "" || st.Collected || st.Skipped[c.Name] == "" {
		t.Fatalf("state %+v", st)
	}
	imgs, err := OpenImages(src)
	if err != nil {
		t.Fatal(err)
	}
	n, err := OpenNative(filepath.Join(data, "no-armada-node"), dst)
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{Images: imgs, Native: n, Moved: state, Bundles: Bundles{Dir: bundlesDir(data)}, NodeImages: dst}
	if m := s.MoveStatus(); !m.GoImages || !m.Converted || m.ToPull != 1 {
		t.Fatalf("status %+v", m)
	}
	s.CollectGo(ctx)
	if m := s.MoveStatus(); !m.GoImages {
		t.Fatal("Go's store went with a container on it")
	}
	if err := os.RemoveAll(s.Bundles.Path("blocked")); err != nil { // Bundles.Remove less the unmount
		t.Fatal(err)
	}
	if err := s.release(ctx, "blocked"); err != nil {
		t.Fatal(err)
	}
	if m := s.MoveStatus(); m.GoImages || m.ToPull != 0 {
		t.Fatalf("status once collected %+v", m)
	}
	gone(t, src)
	if st, ok, err := ReadMoveState(state); err != nil || !ok || !st.Collected {
		t.Errorf("record %+v %v %v", st, ok, err)
	}
	if _, err := os.Stat(filepath.Join(dst, "active", "container-1", "fs")); err != nil {
		t.Errorf("the moved root filesystem went with Go's store: %v", err)
	}
	// armada-node pulled c again: nothing is left to pull.
	if err := writeMoveState(state, st); err != nil {
		t.Fatal(err)
	}
	idx := readIndex(t, dst)
	idx.Images[c.Name] = nodeImage{Name: c.Name}
	raw, _ := json.Marshal(idx)
	if err := os.WriteFile(filepath.Join(dst, "index.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if m := s.MoveStatus(); m.ToPull != 0 {
		t.Errorf("status after the pull %+v", m)
	}

	// Without a record (not converted), nothing goes.
	data, src, dst, _, _ = goStore(t)
	imgs, err = OpenImages(src)
	if err != nil {
		t.Fatal(err)
	}
	if n, err = OpenNative(filepath.Join(data, "no-armada-node"), dst); err != nil {
		t.Fatal(err)
	}
	s = &Store{Images: imgs, Native: n, Moved: filepath.Join(data, "node", MovedFile), Bundles: Bundles{Dir: filepath.Join(data, "x")}}
	s.CollectGo(ctx)
	if m := s.MoveStatus(); !m.GoImages || m.Converted {
		t.Errorf("an unconverted store collected: %+v", m)
	}
	_ = s.Close()
}

// Back to Go's code while Go's store is still there: its layers and the
// root filesystems that moved go back, so Go works again without pulling
// (a pull finds every layer unpacked, a container's snapshot is where
// its metadata says), armada-node forgets those images, and the record
// goes, so a later move converts them again.
func TestRevertImages(t *testing.T) {
	ctx := context.Background()
	data, src, dst, a, b := goStore(t)
	addBundle(t, data, "container-1", a.Name)
	state := filepath.Join(data, "node", MovedFile)
	if _, err := ConvertImages(ctx, src, dst); err != nil {
		t.Fatal(err)
	}
	if moved, _, _, err := moveActive(ctx, src, dst, bundlesDir(data)); err != nil || moved != 1 {
		t.Fatalf("moved %d, %v", moved, err)
	}
	if err := writeMoveState(state, MoveState{Converted: 2}); err != nil {
		t.Fatal(err)
	}
	back, err := RevertImages(ctx, src, dst, state)
	if err != nil || back != 3 {
		t.Fatalf("back %d, %v", back, err)
	}
	if _, ok, _ := ReadMoveState(state); ok {
		t.Error("the record stayed")
	}
	if idx := readIndex(t, dst); len(idx.Images) != 0 || !idx.Uncollected {
		t.Errorf("armada-node's index %+v", idx)
	}
	gone(t, filepath.Join(dst, "active", "container-1"))
	gone(t, filepath.Join(filepath.Dir(upper(t, src, "container-1")), "snapshot.json"))
	s, err := OpenImages(src)
	if err != nil {
		t.Fatal(err)
	}
	s.UseApplier(failApplier{})
	if _, ok := s.Get(a.Name); !ok {
		t.Error("Go's record of a went")
	}
	one := []byte("layer one")
	if _, err := s.Pull(ctx, "registry.example/a:1", oneLayer(t, one, digest.FromBytes(one)), nil); err != nil {
		t.Errorf("pull after the layers came back unpacked again: %v", err)
	}
	if m, err := s.Prepare(ctx, "container-1", a); err != nil || len(m) == 0 {
		t.Errorf("container-1's root filesystem: %v %v", m, err)
	}
	if _, err := s.Prepare(ctx, "container-2", b); err != nil {
		t.Error(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	st, sum, err := MoveImages(ctx, src, dst, bundlesDir(data), state)
	if err != nil || len(sum.Converted) != 2 || st.Converted != 2 || st.Containers != 1 || !st.Collected {
		t.Fatalf("second move %+v %+v %v", st, sum, err)
	}

	// Go's store gone: nothing comes back, the record goes.
	if back, err := RevertImages(ctx, src, dst, state); err != nil || back != 0 {
		t.Errorf("after collection: back %d, %v", back, err)
	}
	if _, ok, _ := ReadMoveState(state); ok {
		t.Error("the record stayed")
	}
	if _, err := os.Stat(filepath.Join(dst, "active", "container-1")); err != nil {
		t.Errorf("container-1 lost its root filesystem: %v", err)
	}
}

// A layer gone from both stores is forgotten in Go's, with the images on
// it, so Go pulls and unpacks it again.
func TestRevertImagesLayerGone(t *testing.T) {
	ctx := context.Background()
	data, src, dst, a, b := goStore(t)
	state := filepath.Join(data, "node", MovedFile)
	if _, err := ConvertImages(ctx, src, dst); err != nil {
		t.Fatal(err)
	}
	if err := writeMoveState(state, MoveState{Converted: 2}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dst, "layers", b.ChainID.Encoded())); err != nil {
		t.Fatal(err)
	}
	back, err := RevertImages(ctx, src, dst, state)
	if err != nil || back != 1 {
		t.Fatalf("back %d, %v", back, err)
	}
	s, err := OpenImages(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(b.Name); ok {
		t.Error("Go kept the record of an image whose layer is gone")
	}
	if _, ok := s.Get(a.Name); !ok {
		t.Error("Go lost a")
	}
	s.UseApplier(markApplier{s.content})
	two := []byte("layer two")
	if _, err := s.Pull(ctx, "registry.example/b:1", oneLayer(t, two, digest.FromBytes(two)), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	snaps, err := committedSnapshots(ctx, filepath.Join(src, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(snaps[b.ChainID.String()], "layer")); err != nil || string(got) != string(two) {
		t.Errorf("b's layer was not unpacked again: %q %v", got, err)
	}
}

// failApplier fails every layer: a pull that needs one unpacked fails.
type failApplier struct{}

func (failApplier) Apply(context.Context, ocispec.Descriptor, []mount.Mount, ...diff.ApplyOpt) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, errors.New("no layer should be applied")
}
