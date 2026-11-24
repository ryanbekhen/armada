package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// committedFS is the directory of Go's committed snapshot of chain under
// src.
func committedFS(t *testing.T, src string, img Image) string {
	t.Helper()
	snaps, err := committedSnapshots(context.Background(), filepath.Join(src, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	p, ok := snaps[img.ChainID.String()]
	if !ok {
		t.Fatalf("no committed snapshot %s", img.ChainID)
	}
	return p
}

// keptStore is goStore whose images armada-node's store already holds
// (converted from another Go store with the same images): the move keeps
// armada-node's records and moves no layer.
func keptStore(t *testing.T) (data, src, dst string, a, b Image) {
	t.Helper()
	_, other, _, _, _ := goStore(t)
	data, src, dst, a, b = goStore(t)
	sum, err := ConvertImages(context.Background(), other, dst)
	if err != nil || len(sum.Converted) != 2 {
		t.Fatalf("armada-node's store before the move: %+v %v", sum, err)
	}
	return data, src, dst, a, b
}

// When armada-node's store already has a moved container's layer, Go's
// directory of that layer stays the lower directory of the container's
// overlay: the move holds it in armada-node's store (the same directory,
// renamed) instead of removing it with Go's store, and armada-node's
// collection removes it only once the container's root filesystem went.
// A layer no container stands on goes with Go's store.
func TestMoveImagesHoldsKeptLayers(t *testing.T) {
	ctx := context.Background()
	data, src, dst, a, b := keptStore(t)
	addBundle(t, data, "container-1", a.Name)
	lower := committedFS(t, src, a)
	ino := inode(t, lower)
	if err := os.WriteFile(filepath.Join(upper(t, src, "container-1"), "written"), []byte("by the container"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(data, "node", MovedFile)
	st, sum, err := MoveImages(ctx, src, dst, bundlesDir(data), state)
	if err != nil {
		t.Fatal(err)
	}
	if sum == nil || len(sum.Kept) != 2 || len(sum.Converted) != 0 || st.Layers != 0 || st.Containers != 1 || !st.Collected {
		t.Fatalf("state %+v, summary %+v", st, sum)
	}
	gone(t, src)
	held := heldFor(dst, a.ChainID.Encoded())
	if len(held) != 1 {
		t.Fatalf("held layers of a: %v", held)
	}
	if got := inode(t, held[0]); got != ino {
		t.Errorf("held directory is not Go's directory of the layer (inode %d, want %d)", got, ino)
	}
	if got, err := os.ReadFile(filepath.Join(held[0], "layer")); err != nil || string(got) != "layer one" {
		t.Errorf("held layer: %q %v", got, err)
	}
	if h := heldFor(dst, b.ChainID.Encoded()); len(h) != 0 {
		t.Errorf("a layer no container stands on was held: %v", h)
	}
	if got, err := os.ReadFile(filepath.Join(dst, "active", "container-1", "fs", "written")); err != nil || string(got) != "by the container" {
		t.Errorf("moved upper directory: %q %v", got, err)
	}
	if idx := readIndex(t, dst); !idx.Uncollected || len(idx.Images) != 2 {
		t.Errorf("armada-node's index %+v", idx)
	}

	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		return
	}
	n, err := OpenNative(bin, dst)
	if err != nil {
		t.Fatal(err)
	}
	keep := []string{a.Name, b.Name}
	// Collected while the container is there: the held layer stays.
	if _, err := n.Prune(ctx, keep, nil, time.Hour); err != nil {
		t.Fatal(err)
	}
	if h := heldFor(dst, a.ChainID.Encoded()); len(h) != 1 {
		t.Fatalf("a held layer went while its container is there: %v", h)
	}
	if err := n.Release(ctx, "container-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Prune(ctx, keep, nil, time.Hour); err != nil {
		t.Fatal(err)
	}
	if h := heldFor(dst, a.ChainID.Encoded()); len(h) != 0 {
		t.Errorf("held layer left after its container went: %v", h)
	}
	if idx := readIndex(t, dst); idx.Uncollected {
		t.Error("the store stayed marked for a collection")
	}
	if _, err := os.Stat(filepath.Join(dst, "layers", a.ChainID.Encoded(), "layer")); err != nil {
		t.Errorf("armada-node's own layer of a: %v", err)
	}
}

// The same through CollectGo: a container left in Go's store keeps it;
// once it goes, the moved container's kept layer is held, not removed.
func TestCollectGoHoldsKeptLayers(t *testing.T) {
	ctx := context.Background()
	data, src, dst, a, _ := keptStore(t)
	addBundle(t, data, "container-1", a.Name)
	blocked(t, data, src)
	lower := committedFS(t, src, a)
	ino := inode(t, lower)
	state := filepath.Join(data, "node", MovedFile)
	st, _, err := MoveImages(ctx, src, dst, bundlesDir(data), state)
	if err != nil || st.Collected || st.Containers != 1 {
		t.Fatalf("state %+v %v", st, err)
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
	if err := os.RemoveAll(s.Bundles.Path("blocked")); err != nil {
		t.Fatal(err)
	}
	if err := s.release(ctx, "blocked"); err != nil {
		t.Fatal(err)
	}
	gone(t, src)
	held := heldFor(dst, a.ChainID.Encoded())
	if len(held) != 1 || inode(t, held[0]) != ino {
		t.Fatalf("held layers of a: %v", held)
	}
	if st, ok, err := ReadMoveState(state); err != nil || !ok || !st.Collected {
		t.Errorf("record %+v %v %v", st, ok, err)
	}
}

// A directory of Go's store a mounted overlay still names refuses the
// store's removal; one renamed away since does not.
func TestMoveRefusesMountedGoStore(t *testing.T) {
	ctx := context.Background()
	data, src, dst, _, _ := goStore(t)
	// Go's snapshot of container-1 (no bundle: it stays in Go's store).
	lower := upper(t, src, "container-1")
	info := filepath.Join(data, "mountinfo")
	old := mountInfoPath
	mountInfoPath = info
	t.Cleanup(func() { mountInfoPath = old })
	line := func(lowers ...string) string {
		return "1234 29 0:77 / " + filepath.Join(data, "rootfs") + " rw,relatime shared:1 - overlay overlay rw,lowerdir=" +
			strings.Join(lowers, ":") + ",upperdir=" + filepath.Join(data, "gone", "fs") + ",workdir=" + filepath.Join(data, "gone", "work") + "\n"
	}
	if err := os.WriteFile(info, []byte("25 1 8:1 / / rw - ext4 /dev/sda1 rw\n"+line(filepath.Join(data, "elsewhere"), lower)), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(data, "node", MovedFile)
	st, _, err := MoveImages(ctx, src, dst, bundlesDir(data), state)
	if err == nil || !strings.Contains(err.Error(), lower) || st.Collected {
		t.Fatalf("removal with a mounted lower directory: %+v %v", st, err)
	}
	if _, err := os.Stat(lower); err != nil {
		t.Fatalf("the mounted lower directory went: %v", err)
	}
	// Renamed away (as a moved or held layer is): nothing under Go's
	// store is mounted any more.
	if err := os.WriteFile(info, []byte(line(filepath.Join(src, "snapshots", "snapshots", "999", "fs"))), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, _, err := MoveImages(ctx, src, dst, bundlesDir(data), state); err != nil || !st.Collected {
		t.Fatalf("second start %+v %v", st, err)
	}
	gone(t, src)
}

func TestMoveMountInfoUnescape(t *testing.T) {
	if got := splitUnescaped(`/a\:b:/c`); len(got) != 2 || got[0] != "/a:b" || got[1] != "/c" {
		t.Errorf("split %q", got)
	}
	if got := unescapeMountInfo(`/a\040b\134c\0`); got != `/a b\c\0` {
		t.Errorf("unescape %q", got)
	}
}

// Back to Go's code with Go's store still there: Go's own directory of a
// layer, held for a moved container, comes back rather than armada-node's
// copy, and a layer only armada-node's own containers stand on stays with
// them (Go would remove it with its images while their overlays mount
// it), so Go forgets that image and pulls it again.
func TestRevertImagesHeldAndNodeLayers(t *testing.T) {
	ctx := context.Background()
	data, src, dst, a, b := goStore(t)
	state := filepath.Join(data, "node", MovedFile)
	if _, err := ConvertImages(ctx, src, dst); err != nil {
		t.Fatal(err)
	}
	// a's layer from Go's store is held; armada-node has its own.
	ah := a.ChainID.Encoded()
	if err := os.MkdirAll(filepath.Join(dst, heldDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dst, "layers", ah), filepath.Join(dst, heldDir, ah+".0")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dst, "layers", ah), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "layers", ah, "own"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// A container armada-node made on b.
	if err := os.MkdirAll(filepath.Join(dst, "active", "rust-made", "fs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dst, "active", "rust-made", "snapshot.json"), nodeSnapshot{Image: b.Name, Parents: []string{b.ChainID.Encoded()}}); err != nil {
		t.Fatal(err)
	}
	if err := writeMoveState(state, MoveState{Converted: 2}); err != nil {
		t.Fatal(err)
	}
	back, err := RevertImages(ctx, src, dst, state)
	if err != nil || back != 1 {
		t.Fatalf("back %d, %v", back, err)
	}
	if got, err := os.ReadFile(filepath.Join(committedFS(t, src, a), "layer")); err != nil || string(got) != "layer one" {
		t.Errorf("Go's layer of a: %q %v", got, err)
	}
	if h := heldFor(dst, ah); len(h) != 0 {
		t.Errorf("held layer left: %v", h)
	}
	if _, err := os.Stat(filepath.Join(dst, "layers", ah, "own")); err != nil {
		t.Errorf("armada-node's own layer of a: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "layers", b.ChainID.Encoded(), "layer")); err != nil {
		t.Errorf("the layer armada-node's container stands on left it: %v", err)
	}
	s, err := OpenImages(src)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, ok := s.Get(b.Name); ok {
		t.Error("Go kept b with its layer left in armada-node's store")
	}
	if _, ok := s.Get(a.Name); !ok {
		t.Error("Go lost a")
	}
}
