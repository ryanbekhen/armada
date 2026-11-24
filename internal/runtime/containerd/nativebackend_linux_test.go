package containerd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
	"github.com/ryanbekhen/armada/internal/runtime/supervisor"
)

// The agent's start moves images between the stores (ADR 0054, "The
// runtime's move"); doctor's opening of the runtime never does. With
// armada-node, Go's store is converted and, with no container on it,
// removed; the record says so. Back on Go's code, the record goes.
func TestSupervisorBackendMovesImages(t *testing.T) {
	paths := embedded.Paths{DataDir: t.TempDir(), RunDir: t.TempDir()}
	bin := filepath.Join(t.TempDir(), "armada-node")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	goImages := filepath.Join(paths.DataDir, "supervisor", "images")
	moved := filepath.Join(paths.DataDir, NodeDir, supervisor.MovedFile)
	imgs, err := supervisor.OpenImages(goImages)
	if err != nil {
		t.Fatal(err)
	}
	if err := imgs.Close(); err != nil {
		t.Fatal(err)
	}

	// Doctor: nothing moves.
	st, err := newSupervisorBackend(Config{Paths: paths, Supervisor: true, NodeBin: bin}, "/pack/armada-log")
	if err != nil {
		t.Fatal(err)
	}
	d := &Driver{ctr: st, native: st.Native}
	if got := d.RuntimeAgent(); got.Agent != runtime.AgentSupervisorRust || !got.GoImages || got.Converted || !got.Converting() {
		t.Errorf("doctor's view before the move %+v", got)
	}
	_ = st.Close()
	if _, err := os.Stat(moved); !os.IsNotExist(err) {
		t.Fatalf("doctor converted: %v", err)
	}

	// The agent: converted, and Go's store goes.
	st, err = newSupervisorBackend(Config{Paths: paths, Supervisor: true, NodeBin: bin, Agent: true}, "/pack/armada-log")
	if err != nil {
		t.Fatal(err)
	}
	d = &Driver{ctr: st, native: st.Native}
	if got := d.RuntimeAgent(); got.Agent != runtime.AgentSupervisorRust || got.GoImages || !got.Converted || got.Converting() {
		t.Errorf("after the move %+v", got)
	}
	_ = st.Close()
	if _, err := os.Stat(goImages); !os.IsNotExist(err) {
		t.Errorf("Go's store stayed: %v", err)
	}
	if rec, ok, err := supervisor.ReadMoveState(moved); err != nil || !ok || !rec.Collected {
		t.Errorf("record %+v %v %v", rec, ok, err)
	}

	// Back to Go's code: the record goes, so a later move converts again.
	st, err = newSupervisorBackend(Config{Paths: paths, Supervisor: true, Agent: true}, "/pack/armada-log")
	if err != nil {
		t.Fatal(err)
	}
	d = &Driver{ctr: st, native: st.Native}
	if got := d.RuntimeAgent(); got.Agent != runtime.AgentSupervisorGo || got.Converting() {
		t.Errorf("on Go's code %+v", got)
	}
	_ = st.Close()
	if _, err := os.Stat(moved); !os.IsNotExist(err) {
		t.Errorf("the record stayed: %v", err)
	}
	if got := (&Driver{}).RuntimeAgent(); got.Agent != runtime.AgentContainerd {
		t.Errorf("containerd %+v", got)
	}
}

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
