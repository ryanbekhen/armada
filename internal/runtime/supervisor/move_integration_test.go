//go:build integration

package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// TestIntegrationMoveMountedRootfs moves the root filesystem of a
// container whose overlay is mounted, as on a node upgraded with its
// containers running: the mount keeps reading and writing through the
// rename (its upper directory now in armada-node's store), Go's store
// goes, and armada-node's bundle remove and release unmount and remove it
// like one it prepared itself.
//
//	make node && go test -c -tags integration ./internal/runtime/supervisor -o mt
//	sudo ARMADA_NODE_BIN=$PWD/node/target/x86_64-unknown-linux-musl/release/armada-node ./mt -test.run IntegrationMoveMountedRootfs -test.v
func TestIntegrationMoveMountedRootfs(t *testing.T) {
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" || os.Geteuid() != 0 {
		t.Skip("needs root and ARMADA_NODE_BIN")
	}
	ctx := context.Background()
	data := t.TempDir()
	src := filepath.Join(data, "supervisor", "images")
	dst := filepath.Join(data, "node", "images")
	bundles := Bundles{Dir: bundlesDir(data)}
	imgs, err := OpenImages(src)
	if err != nil {
		t.Fatal(err)
	}
	imgs.UseApplier(markApplier{imgs.content})
	one := []byte("layer one")
	img, err := imgs.Pull(ctx, "registry.example/a:1", oneLayer(t, one, digest.FromBytes(one)), nil)
	if err != nil {
		t.Fatal(err)
	}
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

	st, _, err := MoveImages(ctx, src, dst, bundles.Dir, filepath.Join(data, "node", MovedFile))
	if err != nil {
		t.Fatal(err)
	}
	if st.Containers != 1 || !st.Collected {
		t.Fatalf("state %+v", st)
	}
	gone(t, src)
	for name, want := range map[string]string{"layer": string(one), "before": "written before"} {
		if b, err := os.ReadFile(filepath.Join(rootfs, name)); err != nil || string(b) != want {
			t.Errorf("%s through the mount after the move: %q %v", name, b, err)
		}
	}
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
	s := &Store{Native: n, NodeImages: dst, Bundles: bundles}
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
}
