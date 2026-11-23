package containerd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// A supervisor node hands its store to armada-node only when NodeBin names
// a program; without one it stays on Go's store. Go's own image store is
// opened beside armada-node's only when it exists, to release the root
// filesystems of containers Go made.
func TestSupervisorBackendChoosesArmadaNode(t *testing.T) {
	open := func(nodeBin string, goStore bool) (native, goImages bool) {
		t.Helper()
		paths := embedded.Paths{DataDir: t.TempDir(), RunDir: t.TempDir()}
		if goStore {
			if err := os.MkdirAll(filepath.Join(paths.DataDir, "supervisor", "images"), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		st, err := newSupervisorBackend(Config{Paths: paths, Supervisor: true, NodeBin: nodeBin}, "/pack/armada-log")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		if st.NodeImages != filepath.Join(paths.DataDir, "node", "images") {
			t.Errorf("armada-node's store %s", st.NodeImages)
		}
		if (st.Native != nil) != (st.Shims.Native != nil) {
			t.Error("the shims and the store disagree on armada-node")
		}
		return st.Native != nil, st.Images != nil
	}
	if n, g := open("", false); n || !g {
		t.Errorf("no armada-node: native %v, Go's images %v", n, g)
	}
	if n, g := open(filepath.Join(t.TempDir(), "missing"), true); n || !g {
		t.Errorf("armada-node missing: native %v, Go's images %v", n, g)
	}
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		t.Skip("ARMADA_NODE_BIN names no armada-node")
	}
	if n, g := open(bin, false); !n || g {
		t.Errorf("armada-node on a new node: native %v, Go's images %v", n, g)
	}
	if n, g := open(bin, true); !n || !g {
		t.Errorf("armada-node on a node Go ran: native %v, Go's images %v", n, g)
	}
}

// With armada-node, the driver reads images from armada-node's store and
// the store refuses to change it itself (pulls and prunes are
// armada-node's).
func TestSupervisorBackendReadsArmadaNodeImages(t *testing.T) {
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		t.Skip("ARMADA_NODE_BIN names no armada-node")
	}
	paths := embedded.Paths{DataDir: t.TempDir(), RunDir: t.TempDir()}
	st, err := newSupervisorBackend(Config{Paths: paths, Supervisor: true, NodeBin: bin}, "/pack/armada-log")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := st.GetImage(ctx, "docker.io/library/alpine:3"); err == nil {
		t.Error("an image found in an empty store")
	}
	if imgs, err := st.ListImages(ctx); err != nil || len(imgs) != 0 {
		t.Errorf("images %v, %v", imgs, err)
	}
	if err := st.DeleteImage(ctx, "x", true); err == nil {
		t.Error("Go removed an image from armada-node's store")
	}
	if err := st.Ping(ctx); err == nil {
		t.Error("ping without armada-shim")
	}
}
