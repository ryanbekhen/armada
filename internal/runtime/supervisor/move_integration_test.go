//go:build integration

package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// TestIntegrationMoveMountedRootfs moves the root filesystem of a
// container whose overlay is mounted, as on a node upgraded with its
// containers running: the mount keeps reading and writing through the
// rename (its upper directory now in armada-node's store), Go's store
// goes, and armada-node's bundle remove and release unmount and remove it
// like one it prepared itself. With armada-node's store holding the image
// already (kept), Go's directory of the layer stays the overlay's lower
// directory: it is held in armada-node's store, through the move and
// through CollectGo, until the container's root filesystem went and a
// collection removes it.
//
//	make node && go test -c -tags integration ./internal/runtime/supervisor -o mt
//	sudo ARMADA_NODE_BIN=$PWD/node/target/x86_64-unknown-linux-musl/release/armada-node ./mt -test.run IntegrationMoveMountedRootfs -test.v
func TestIntegrationMoveMountedRootfs(t *testing.T) {
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" || os.Geteuid() != 0 {
		t.Skip("needs root and ARMADA_NODE_BIN")
	}
	for _, c := range []struct {
		name string
		// kept: armada-node's store has the image before the move.
		kept bool
		// collectLater: another container keeps Go's store until it
		// goes, so CollectGo removes it.
		collectLater bool
	}{
		{name: "converted"},
		{name: "kept", kept: true},
		{name: "kept-collected-later", kept: true, collectLater: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			moveMounted(t, bin, c.kept, c.collectLater)
		})
	}
}

func moveMounted(t *testing.T, bin string, kept, collectLater bool) {
	ctx := context.Background()
	data := t.TempDir()
	src := filepath.Join(data, "supervisor", "images")
	dst := filepath.Join(data, "node", "images")
	state := filepath.Join(data, "node", MovedFile)
	bundles := Bundles{Dir: bundlesDir(data)}
	one := []byte("layer one")
	pull := func(root string) (*Images, Image) {
		imgs, err := OpenImages(root)
		if err != nil {
			t.Fatal(err)
		}
		imgs.UseApplier(markApplier{imgs.content})
		img, err := imgs.Pull(ctx, "registry.example/a:1", oneLayer(t, one, digest.FromBytes(one)), nil)
		if err != nil {
			t.Fatal(err)
		}
		return imgs, img
	}
	if kept {
		// armada-node's store holds the image already (as after its own
		// pull), from another Go store's conversion.
		other := filepath.Join(data, "other")
		o, _ := pull(other)
		if err := o.Close(); err != nil {
			t.Fatal(err)
		}
		if sum, err := ConvertImages(ctx, other, dst); err != nil || len(sum.Converted) != 1 {
			t.Fatalf("armada-node's store before the move: %+v %v", sum, err)
		}
	}
	imgs, img := pull(src)
	mounts, err := imgs.Prepare(ctx, "c1", img)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundles.Create(Record{ID: "c1", Image: img.Name, Group: "c1"}, &specs.Spec{}, mounts); err != nil {
		t.Fatal(err)
	}
	rootfs := filepath.Join(bundles.Path("c1"), bundleRootfs)
	t.Cleanup(func() { _ = bundles.Remove("c1") })
	if err := imgs.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "before"), []byte("written before"), 0o600); err != nil {
		t.Fatal(err)
	}
	if collectLater {
		blocked(t, data, src)
	}
	reads := func(when string, files map[string]string) {
		t.Helper()
		for name, want := range files {
			if b, err := os.ReadFile(filepath.Join(rootfs, name)); err != nil || string(b) != want {
				t.Errorf("%s through the mount %s: %q %v", name, when, b, err)
			}
		}
	}

	st, _, err := MoveImages(ctx, src, dst, bundles.Dir, state)
	if err != nil {
		t.Fatal(err)
	}
	if st.Containers != 1 || st.Collected == collectLater {
		t.Fatalf("state %+v", st)
	}
	reads("after the move", map[string]string{"layer": string(one), "before": "written before"})
	if err := os.WriteFile(filepath.Join(rootfs, "after"), []byte("written after"), 0o600); err != nil {
		t.Fatalf("write through the mount after the move: %v", err)
	}
	upper := filepath.Join(dst, "active", "c1", "fs")
	if b, err := os.ReadFile(filepath.Join(upper, "after")); err != nil || string(b) != "written after" {
		t.Errorf("the write is not in the moved upper directory: %q %v", b, err)
	}

	n, err := OpenNative(bin, dst)
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{Native: n, NodeImages: dst, Bundles: bundles, Moved: state}
	if collectLater {
		if s.Images, err = OpenImages(src); err != nil {
			t.Fatal(err)
		}
		if err := s.removeBundle(ctx, "blocked"); err != nil {
			t.Fatal(err)
		}
		if err := s.release(ctx, "blocked"); err != nil { // and CollectGo
			t.Fatal(err)
		}
		if st, ok, err := ReadMoveState(state); err != nil || !ok || !st.Collected {
			t.Fatalf("record after CollectGo %+v %v %v", st, ok, err)
		}
	}
	gone(t, src)
	held := heldFor(dst, img.ChainID.Encoded())
	if kept != (len(held) == 1) {
		t.Errorf("held layers %v", held)
	}
	reads("once Go's store went", map[string]string{"layer": string(one), "before": "written before", "after": "written after"})
	if err := os.WriteFile(filepath.Join(rootfs, "later"), []byte("written later"), 0o600); err != nil {
		t.Fatalf("write through the mount once Go's store went: %v", err)
	}
	reads("once Go's store went", map[string]string{"later": "written later"})

	// A collection while the container is there keeps the held layer.
	keep := []string{img.Name}
	if _, err := n.Prune(ctx, keep, keep, time.Hour); err != nil {
		t.Fatal(err)
	}
	if h := heldFor(dst, img.ChainID.Encoded()); len(h) != len(held) {
		t.Fatalf("held layers after a collection with the container there: %v", h)
	}
	reads("after a collection", map[string]string{"layer": string(one), "after": "written after"})

	if err := s.removeBundle(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if err := s.release(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"bundle remove", "release"} {
		if k := n.StoodIn(op); k > 0 {
			t.Errorf("Go did %q instead of armada-node", op)
		}
	}
	gone(t, bundles.Path("c1"))
	gone(t, filepath.Join(dst, "active", "c1"))
	info, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(info), rootfs) {
		t.Errorf("the root filesystem is still mounted at %s", rootfs)
	}
	// The next collection removes what was held.
	if _, err := n.Prune(ctx, keep, nil, time.Hour); err != nil {
		t.Fatal(err)
	}
	if h := heldFor(dst, img.ChainID.Encoded()); len(h) != 0 {
		t.Errorf("held layers left after the container went: %v", h)
	}
	if kept {
		if idx := readIndex(t, dst); idx.Uncollected {
			t.Error("armada-node's store stayed marked for a collection")
		}
	}
	if _, err := os.Stat(filepath.Join(dst, "layers", img.ChainID.Encoded(), "layer")); err != nil {
		t.Errorf("armada-node's layer of the image: %v", err)
	}
}
