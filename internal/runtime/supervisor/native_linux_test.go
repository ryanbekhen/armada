package supervisor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	rspecs "github.com/opencontainers/runtime-spec/specs-go"
)

// The parity tests of armada-node's container commands (node/src/
// runtime/container, image/snapshot.rs): bundles, root filesystems, and
// shim requests, each compared with what this package does. Gated on
// ARMADA_NODE_BIN; none needs root (a root filesystem is not mounted).

func nodeBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		t.Skip("ARMADA_NODE_BIN names no armada-node to compare with")
	}
	return bin
}

func openNative(t *testing.T) *Native {
	t.Helper()
	n, err := OpenNative(nodeBin(t), filepath.Join(t.TempDir(), "node", "images"))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// errText is an error's text, "" for none.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type specsSpec = rspecs.Spec

// bundleSpecs are specs as the driver builds them (containerd's default
// spec with options), and odd ones.
func bundleSpecs(t *testing.T) map[string]func() *specsSpec {
	t.Helper()
	ctx := namespaces.WithNamespace(context.Background(), "armada")
	gen := func(opts ...oci.SpecOpts) func() *specsSpec {
		return func() *specsSpec {
			s, err := oci.GenerateSpec(ctx, nil, &containers.Container{ID: "web-r1-3f2a"}, opts...)
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
	}
	return map[string]func() *specsSpec{
		"default": gen(),
		"group": gen(oci.WithAnnotations(map[string]string{GroupAnnotation: "web@pack-1a2b", "x": "<&>\u2028"}),
			oci.WithEnv([]string{"A=<b>&c", "B=\u00e9"}), oci.WithProcessArgs("/bin/sh", "-c", "echo 'x' > /y")),
		"readonly": gen(oci.WithRootFSReadonly(), oci.WithHostname("h")),
		"no root": func() *specsSpec {
			s := gen()()
			s.Root = nil
			return s
		},
		"no process": func() *specsSpec {
			s := gen()()
			s.Root, s.Process = nil, nil
			return s
		},
	}
}

// tree lists every file under dir with its mode and, for files, content.
func tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		v := fi.Mode().String()
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			v += " " + string(b)
		}
		out[rel] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Bundles written, listed, relabelled, and removed by armada-node are the
// bytes and modes Go's Bundles writes.
func TestArmadaNodeBundleMatchesGo(t *testing.T) {
	n := openNative(t)
	ctx := context.Background()
	goDir, rustDir := filepath.Join(t.TempDir(), "containers"), filepath.Join(t.TempDir(), "containers")
	gb, rb := Bundles{Dir: goDir}, Bundles{Dir: rustDir}
	labelSets := []map[string]string{nil, {}, {"armada.app": "web", "armada.replica": "web-r1", "z": "<&>"}}
	i := 0
	all := bundleSpecs(t)
	names := slices.Sorted(maps.Keys(all))
	for _, name := range names {
		mk := all[name]
		for _, labels := range labelSets {
			i++
			id := fmt.Sprintf("c%d-%s", i, strings.ReplaceAll(name, " ", "-"))
			rec, err := n.CreateBundle(ctx, rustDir, id, "docker.io/library/alpine:3", labels, mk(), nil)
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			spec := mk()
			group := spec.Annotations[GroupAnnotation]
			if group == "" {
				group = id
			}
			want := Record{ID: id, Image: "docker.io/library/alpine:3", Labels: labels, Group: group, Created: rec.Created}
			if _, err := gb.Create(want, spec, nil); err != nil {
				t.Fatal(err)
			}
			if time.Since(rec.Created) > time.Minute || rec.Created.Location() != time.UTC {
				t.Errorf("%s: created %v", id, rec.Created)
			}
		}
	}
	// Go writes created as time.Time marshals; armada-node's own clock
	// gave the value both wrote.
	if g, r := tree(t, goDir), tree(t, rustDir); !reflect.DeepEqual(g, r) {
		for k := range g {
			if g[k] != r[k] {
				t.Errorf("%s:\n go   %q\n rust %q", k, g[k], r[k])
			}
		}
		if len(g) != len(r) {
			t.Errorf("go has %d entries, armada-node %d", len(g), len(r))
		}
	}

	// A bundle that exists is refused, as NewContainer refuses it.
	_, err := n.CreateBundle(ctx, rustDir, "c1-default", "x", nil, bundleSpecs(t)["default"](), nil)
	if want := "container c1-default: already exists"; errText(err) != want {
		t.Errorf("existing bundle: %v, want %s", err, want)
	}

	// Records, with the bundles Records leaves out or fails on.
	for _, d := range []string{goDir, rustDir} {
		mustWrite(t, filepath.Join(d, "unfinished", bundleConfig), "{}")
		mustWrite(t, filepath.Join(d, "broken", bundleRecord), "{")
		mustWrite(t, filepath.Join(d, "other", bundleRecord), `{"id":"c1-default","image":"x","group":"g","created":"2026-11-23T08:00:00Z"}`)
		mustWrite(t, filepath.Join(d, "badtime", bundleRecord), `{"id":"badtime","image":"x","group":"g","created":"yesterday"}`)
		mustWrite(t, filepath.Join(d, "nulls", bundleRecord), `{"id":"nulls","image":"x","labels":null,"group":"g","created":"2026-11-23T08:00:00.5+07:00"}`)
	}
	goRecs, err := gb.Records()
	if err != nil {
		t.Fatal(err)
	}
	rustRecs, err := n.Records(ctx, rustDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(goRecs) != len(rustRecs) {
		ids := func(rs []Record) (out []string) {
			for _, r := range rs {
				out = append(out, r.ID)
			}
			return out
		}
		t.Fatalf("records: go %v, armada-node %v", ids(goRecs), ids(rustRecs))
	}
	for i := range goRecs {
		g, r := goRecs[i], rustRecs[i]
		if g.ID != r.ID || g.Image != r.Image || g.Group != r.Group || !g.Created.Equal(r.Created) || !maps2Equal(g.Labels, r.Labels) {
			t.Errorf("record %d: go %+v, armada-node %+v", i, g, r)
		}
	}
	if recs, err := n.Records(ctx, filepath.Join(rustDir, "missing")); err != nil || len(recs) != 0 {
		t.Errorf("records of a missing directory: %v, %v", recs, err)
	}
	// A record that cannot be read fails both.
	for _, d := range []string{goDir, rustDir} {
		if err := os.MkdirAll(filepath.Join(d, "zdir", bundleRecord), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	_, gerr := gb.Records()
	_, rerr := n.Records(ctx, rustDir)
	if strings.ReplaceAll(errText(gerr), goDir, "D") != strings.ReplaceAll(errText(rerr), rustDir, "D") || gerr == nil {
		t.Errorf("unreadable record: go %v, armada-node %v", gerr, rerr)
	}
	for _, d := range []string{goDir, rustDir} {
		_ = os.RemoveAll(filepath.Join(d, "zdir"))
	}

	// SetLabels.
	goStore, rustStore := &Store{Bundles: gb}, &Store{Bundles: rb, Native: n}
	for _, id := range []string{"c1-default", "c3-default"} {
		for _, st := range []*Store{goStore, rustStore} {
			c, err := st.LoadContainer(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.SetLabels(ctx, map[string]string{"armada.started": "2026-11-23T08:00:00Z", "armada.app": "api"}); err != nil {
				t.Fatal(err)
			}
		}
		g, _ := os.ReadFile(filepath.Join(goDir, id, bundleRecord))
		r, _ := os.ReadFile(filepath.Join(rustDir, id, bundleRecord))
		if !bytes.Equal(g, r) {
			t.Errorf("%s relabelled:\n go   %s\n rust %s", id, g, r)
		}
	}

	// Remove: with its rootfs directory, the unmount (refused without
	// root, nothing to unmount with it) decides; without, it goes.
	gerr = gb.Remove("c1-default")
	rerr = n.RemoveBundle(ctx, rustDir, "c1-default")
	if errText(gerr) != errText(rerr) {
		t.Errorf("remove: go %v, armada-node %v", gerr, rerr)
	}
	for _, d := range []string{goDir, rustDir} {
		if err := os.Remove(filepath.Join(d, "c2-default", bundleRootfs)); err != nil {
			t.Fatal(err)
		}
	}
	gerr = gb.Remove("c2-default")
	rerr = n.RemoveBundle(ctx, rustDir, "c2-default")
	if gerr != nil || rerr != nil {
		t.Errorf("remove without rootfs: go %v, armada-node %v", gerr, rerr)
	}
	if err := n.RemoveBundle(ctx, rustDir, "never-made"); err != nil {
		t.Errorf("remove a missing bundle: %v", err)
	}
	if g, r := tree(t, goDir), tree(t, rustDir); !reflect.DeepEqual(g, r) {
		t.Errorf("after removals:\n go   %v\n rust %v", g, r)
	}
}

func maps2Equal(a, b map[string]string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func mustWrite(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// layered returns an image of layers whose config names their digests as
// diff IDs (readApplier "applies" them).
func layered(t *testing.T, layers ...[]byte) memRegistry {
	t.Helper()
	desc := func(mt string, b []byte) ocispec.Descriptor {
		return ocispec.Descriptor{MediaType: mt, Digest: digest.FromBytes(b), Size: int64(len(b))}
	}
	blobs := map[digest.Digest][]byte{}
	var lds []ocispec.Descriptor
	var diffs []digest.Digest
	for _, l := range layers {
		ld := desc(ocispec.MediaTypeImageLayer, l)
		lds, diffs = append(lds, ld), append(diffs, ld.Digest)
		blobs[ld.Digest] = l
	}
	cfg, err := json.Marshal(ocispec.Image{Platform: platforms.DefaultSpec(), RootFS: ocispec.RootFS{Type: "layers", DiffIDs: diffs}})
	if err != nil {
		t.Fatal(err)
	}
	cd := desc(ocispec.MediaTypeImageConfig, cfg)
	if lds == nil {
		lds = []ocispec.Descriptor{}
	}
	man, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: cd, Layers: lds})
	if err != nil {
		t.Fatal(err)
	}
	md := desc(ocispec.MediaTypeImageManifest, man)
	blobs[cd.Digest], blobs[md.Digest] = cfg, man
	return memRegistry{root: md, blobs: blobs}
}

// nodeStoreWith writes armada-node's store with one record per image (its
// layers unpacked as empty directories owned like the test).
func nodeStoreWith(t *testing.T, root string, imgs map[string][]digest.Digest) {
	t.Helper()
	idx := nodeIndex{Version: nodeIndexVersion, Images: map[string]nodeImage{}, Verified: map[string]digest.Digest{}}
	old := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339Nano)
	for name, diffs := range imgs {
		d := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString(name), Size: 1}
		chain := ""
		for _, c := range identity.ChainIDs(slices.Clone(diffs)) {
			if err := os.MkdirAll(filepath.Join(root, "layers", c.Encoded()), 0o755); err != nil {
				t.Fatal(err)
			}
			chain = c.String()
		}
		idx.Images[name] = nodeImage{Name: name, Target: d, Manifest: d, Config: d, Layers: []ocispec.Descriptor{}, DiffIDs: diffs, ChainID: chain, Created: old, Updated: old}
	}
	b, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "index.json"), string(b))
}

// shape is a mount with the snapshot's own paths named: W and U for its
// work and upper directories, L0.. for the image's layers (top first).
func shape(m []mount.Mount, own string, layers []string) []mount.Mount {
	out := make([]mount.Mount, len(m))
	for i, x := range m {
		x.Source = strings.ReplaceAll(x.Source, own, "S")
		var opts []string
		for _, o := range x.Options {
			o = strings.ReplaceAll(o, own, "S")
			for j, l := range layers {
				o = strings.ReplaceAll(o, l, fmt.Sprintf("L%d", j))
			}
			opts = append(opts, o)
		}
		x.Options = opts
		out[i] = x
	}
	return out
}

// modes lists the snapshot directory's own modes and fs's owner.
func modes(t *testing.T, dir string) string {
	t.Helper()
	var s []string
	for _, p := range []string{".", "fs", "work"} {
		fi, err := os.Stat(filepath.Join(dir, p))
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		s = append(s, fmt.Sprintf("%s %s %d:%d", p, fi.Mode(), st.Uid, st.Gid))
	}
	return strings.Join(s, ", ")
}

// Root filesystems armada-node prepares are what the overlay snapshotter
// prepares on the same layers: the same mounts (paths aside), directory
// modes, and owner; preparing again gives the same mounts, and a
// collection keeps the layers a root filesystem stands on.
func TestArmadaNodeSnapshotMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	ctx := context.Background()
	goRoot := filepath.Join(t.TempDir(), "supervisor", "images")
	g, err := OpenImages(goRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	g.UseApplier(readApplier{g.content})
	cases := map[string][][]byte{
		"registry.example/none:1":  nil,
		"registry.example/one:1":   {[]byte("one")},
		"registry.example/three:1": {[]byte("a"), []byte("b"), []byte("c")},
	}
	diffs := map[string][]digest.Digest{"registry.example/other:1": {digest.FromString("other")}}
	for name, ls := range cases {
		diffs[name] = []digest.Digest{}
		for _, l := range ls {
			diffs[name] = append(diffs[name], digest.FromBytes(l))
		}
	}
	nodeRoot := filepath.Join(t.TempDir(), "node", "images")
	nodeStoreWith(t, nodeRoot, diffs)
	n, err := OpenNative(bin, nodeRoot)
	if err != nil {
		t.Fatal(err)
	}
	for name, ls := range cases {
		key := "c-" + strings.TrimSuffix(strings.TrimPrefix(name, "registry.example/"), ":1")
		var img Image
		if len(ls) > 0 {
			if img, err = g.Pull(ctx, name, layered(t, ls...), nil); err != nil {
				t.Fatal(err)
			}
		}
		gm, err := g.Prepare(ctx, key, img)
		if err != nil {
			t.Fatal(err)
		}
		rm, err := n.Prepare(ctx, key, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// Go's snapshot directory and layers, from its own mounts.
		var goOwn string
		var goLayers []string
		for _, o := range gm[0].Options {
			if v, ok := strings.CutPrefix(o, "upperdir="); ok {
				goOwn = filepath.Dir(v)
			}
			if v, ok := strings.CutPrefix(o, "lowerdir="); ok {
				goLayers = strings.Split(v, ":")
			}
		}
		if gm[0].Type == "bind" {
			goOwn = filepath.Dir(gm[0].Source)
		}
		var rustLayers []string
		chains := identity.ChainIDs(slices.Clone(diffs[name]))
		for i := len(chains) - 1; i >= 0; i-- {
			rustLayers = append(rustLayers, filepath.Join(nodeRoot, "layers", chains[i].Encoded()))
		}
		rustOwn := filepath.Join(nodeRoot, "active", key)
		if a, b := shape(gm, goOwn, goLayers), shape(rm, rustOwn, rustLayers); !reflect.DeepEqual(a, b) {
			t.Errorf("%s mounts:\n go   %+v\n rust %+v", name, a, b)
		}
		if len(goLayers) != len(rustLayers) {
			t.Errorf("%s: %d layers in Go's mount, %d in armada-node's", name, len(goLayers), len(rustLayers))
		}
		if a, b := modes(t, goOwn), modes(t, rustOwn); a != b {
			t.Errorf("%s directories:\n go   %s\n rust %s", name, a, b)
		}
		again, err := n.Prepare(ctx, key, name)
		if err != nil || !reflect.DeepEqual(again, rm) {
			t.Errorf("%s prepared again: %+v, %v", name, again, err)
		}
		gAgain, err := g.Prepare(ctx, key, img)
		if err != nil || !reflect.DeepEqual(gAgain, gm) {
			t.Errorf("%s prepared again by Go: %+v, %v", name, gAgain, err)
		}
	}

	// What it refuses.
	if _, err := n.Prepare(ctx, "c-x", "registry.example/missing:1"); errText(err) != "image registry.example/missing:1: not found" {
		t.Errorf("missing image: %v", err)
	}
	if _, err := n.Prepare(ctx, "../x", "registry.example/one:1"); errText(err) != `invalid snapshot key "../x"` {
		t.Errorf("key with a separator: %v", err)
	}

	// A collection removes the other image's layer and keeps those of
	// root filesystems, even once their images are gone.
	var removed []string
	if removed, err = n.Prune(ctx, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	if len(removed) != len(diffs) {
		t.Errorf("pruned %v", removed)
	}
	for name, ds := range diffs {
		for _, c := range identity.ChainIDs(slices.Clone(ds)) {
			_, err := os.Stat(filepath.Join(nodeRoot, "layers", c.Encoded()))
			if kept := name != "registry.example/other:1"; kept != (err == nil) {
				t.Errorf("%s layer %s: kept %v, want %v", name, c, err == nil, kept)
			}
		}
	}
	var keys struct{ Keys []string }
	if err := n.run(ctx, nil, &keys, "runtime", "snapshots", nodeRoot); err != nil || len(keys.Keys) != len(cases) {
		t.Errorf("snapshots: %v, %v", keys.Keys, err)
	}

	// Released, a root filesystem goes; releasing one that is gone is not
	// an error, as Go's Release is not.
	for name := range cases {
		key := "c-" + strings.TrimSuffix(strings.TrimPrefix(name, "registry.example/"), ":1")
		for range 2 {
			if err := n.Release(ctx, key); err != nil {
				t.Errorf("release %s: %v", key, err)
			}
			if err := g.Release(ctx, key); err != nil {
				t.Errorf("go release %s: %v", key, err)
			}
		}
		if _, err := os.Stat(filepath.Join(nodeRoot, "active", key)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s still there: %v", key, err)
		}
	}
}

// stand-ins writes programs that log their arguments (one per line, then
// "--end") to log and answer as the shim's tests need: runc lists
// containers c1 and c2, systemctl prints the content of state.
func standIns(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	logArgs := `{ echo "$(basename "$0")"; for a in "$@"; do echo "$a"; done; echo --end; } >> "` + dir + `/log"` + "\n"
	write("runc", logArgs+`case "$*" in *" list -q") echo "c1 c2";; *" delete --force c2") echo "c2 is busy" >&2; if [ -e "`+dir+`/fail-delete" ]; then exit 1; fi;; esac`+"\n")
	write("systemctl", logArgs+`cat "`+dir+`/state" 2>/dev/null`+"\n")
	write("systemd-run", logArgs+`touch "`+dir+`/launched"`+"\n")
	return dir
}

// shimRun is one scenario of For or Abandon on a group's shim.
type shimRun struct {
	log      string
	err      string
	gone     bool
	launched bool
}

// runShims runs fn with shims whose programs are the stand-ins and whose
// directory is dir (made afresh), serving a shim on the socket once
// systemd-run was asked to start one. setup prepares the directory.
func runShims(t *testing.T, progs, dir string, native *Native, setup func(sock, root string), fn func(*Shims) (bool, error)) shimRun {
	t.Helper()
	_ = os.RemoveAll(dir)
	_ = os.Remove(filepath.Join(progs, "log"))
	_ = os.Remove(filepath.Join(progs, "launched"))
	s := &Shims{Dir: dir, Bin: "/pack/armada-shim", Runc: filepath.Join(progs, "runc"), Logger: "/pack/armada-log",
		SystemdRun: filepath.Join(progs, "systemd-run"), Systemctl: filepath.Join(progs, "systemctl"), Native: native}
	sh := s.Get("web@pack-1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	setup(sh.Socket, sh.Root)
	stop := make(chan struct{})
	served := make(chan net.Listener, 1)
	go func() {
		for {
			select {
			case <-stop:
				served <- nil
				return
			case <-time.After(2 * time.Millisecond):
			}
			if _, err := os.Stat(filepath.Join(progs, "launched")); err == nil {
				_ = os.Remove(sh.Socket)
				l, err := net.Listen("unix", sh.Socket)
				if err != nil {
					served <- nil
					return
				}
				go serveOK(l)
				served <- l
				return
			}
		}
	}()
	gone, err := fn(s)
	close(stop)
	if l := <-served; l != nil {
		_ = l.Close()
	}
	b, _ := os.ReadFile(filepath.Join(progs, "log"))
	_, lerr := os.Stat(filepath.Join(progs, "launched"))
	return shimRun{log: string(b), err: errText(err), gone: gone, launched: lerr == nil}
}

func serveOK(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		_, _ = bufio.NewReader(c).ReadString('\n')
		_, _ = c.Write([]byte("ok\n"))
		_ = c.Close()
	}
}

// Starting and abandoning a group's shim through armada-node runs the
// programs Go runs, with the same arguments, in the same cases: a shim
// that answers is kept, one that is gone has its containers ended and
// another started, one that runs but does not answer is an error.
func TestArmadaNodeShimStartMatchesGo(t *testing.T) {
	n := openNative(t)
	progs := standIns(t)
	dir := filepath.Join(t.TempDir(), "shim")
	noSetup := func(string, string) {}
	withRoot := func(_, root string) {
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stale := func(sock, root string) {
		withRoot(sock, root)
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		l.(*net.UnixListener).SetUnlinkOnClose(false)
		_ = l.Close()
	}
	answering := func(sock, _ string) {
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go serveOK(l)
	}
	// silent shims accept a request and close without answering (hang:
	// hold the connection until the caller gives up); the unit's state is
	// what systemctl says.
	silent := func(state string, hang bool) func(string, string) {
		return func(sock, root string) {
			withRoot(sock, root)
			mustWrite(t, filepath.Join(progs, "state"), state+"\n")
			l, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var held []net.Conn
			t.Cleanup(func() {
				_ = l.Close()
				mu.Lock()
				defer mu.Unlock()
				for _, c := range held {
					_ = c.Close()
				}
			})
			go func() {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					if hang {
						mu.Lock()
						held = append(held, c)
						mu.Unlock()
						continue
					}
					_, _ = bufio.NewReader(c).ReadString('\n')
					_ = c.Close()
				}
			}()
		}
	}
	failDelete := func(sock, root string) {
		withRoot(sock, root)
		mustWrite(t, filepath.Join(progs, "fail-delete"), "")
	}
	forShim := func(timeout time.Duration) func(*Shims) (bool, error) {
		return func(s *Shims) (bool, error) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			_, err := s.For(ctx, "web@pack-1")
			return false, err
		}
	}
	abandon := func(timeout time.Duration) func(*Shims) (bool, error) {
		return func(s *Shims) (bool, error) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			return s.Abandon(ctx, s.Get("web@pack-1"))
		}
	}
	cases := []struct {
		name  string
		setup func(string, string)
		fn    func(*Shims) (bool, error)
		// prefix: compare only the error's start (a timeout's own words
		// depend on which of two deadlines fired first).
		prefix bool
	}{
		{"start fresh", noSetup, forShim(10 * time.Second), false},
		{"start after a shim's containers", withRoot, forShim(10 * time.Second), false},
		{"start over a stale socket", stale, forShim(10 * time.Second), false},
		{"keep an answering shim", answering, forShim(10 * time.Second), false},
		{"hangs and active", silent("active", true), forShim(300 * time.Millisecond), true},
		{"closes and active", silent("active", false), forShim(10 * time.Second), false},
		{"closes and inactive", silent("inactive", false), forShim(10 * time.Second), false},
		{"closes and unknown", silent("", false), forShim(10 * time.Second), false},
		{"runc delete fails", failDelete, forShim(10 * time.Second), false},
		{"abandon a gone shim", withRoot, abandon(10 * time.Second), false},
		{"abandon an answering shim", answering, abandon(10 * time.Second), false},
		{"abandon a closing active shim", silent("activating", false), abandon(10 * time.Second), false},
		{"abandon a closing failed shim", silent("failed", false), abandon(10 * time.Second), false},
		{"abandon a hanging shim", silent("failed", true), abandon(300 * time.Millisecond), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, f := range []string{"state", "fail-delete"} {
				_ = os.Remove(filepath.Join(progs, f))
			}
			g := runShims(t, progs, dir, nil, c.setup, c.fn)
			for _, f := range []string{"state", "fail-delete"} {
				_ = os.Remove(filepath.Join(progs, f))
			}
			r := runShims(t, progs, dir, n, c.setup, c.fn)
			if c.prefix {
				// Go's connection ends at its deadline by a close or a
				// timeout, whichever comes first.
				g.err = strings.ReplaceAll(g.err, "use of closed network connection", "i/o timeout")
				// A program the deadline kills reads as killed or as the
				// deadline, depending on which os/exec saw first.
				g.err = strings.ReplaceAll(g.err, "signal: killed", "context deadline exceeded")
				r.err = strings.ReplaceAll(r.err, "signal: killed", "context deadline exceeded")
			}
			if g != r {
				t.Errorf("go:\n%+v\narmada-node:\n%+v", g, r)
			}
		})
	}
	if t.Failed() {
		return
	}
	// The arguments are the ones the shim's units have always had.
	g := runShims(t, progs, dir, n, noSetup, forShim(10*time.Second))
	name := shimName("web@pack-1")
	want := strings.Join([]string{"systemd-run", "--unit=armada-shim-" + name, "--collect", "--quiet",
		"--property=OOMScoreAdjust=-999", "--property=LimitNOFILE=infinity", "--property=LimitNPROC=infinity",
		"--property=LimitCORE=infinity", "--property=TasksMax=infinity", "--",
		"/pack/armada-shim", "serve", filepath.Join(dir, name+".sock"), filepath.Join(dir, name),
		filepath.Join(progs, "runc"), "/pack/armada-log", "--end", ""}, "\n")
	if g.log != want {
		t.Errorf("systemd-run:\n%s\nwant\n%s", g.log, want)
	}
}

// A shim's requests through armada-node are the lines Go sends, and its
// answers and failures come back as Go's: the words, the shim's own
// errors (NotFound), and errors whose errno says the shim is gone.
func TestArmadaNodeShimCallsMatchGo(t *testing.T) {
	n := openNative(t)
	dir := t.TempDir()
	type call struct {
		name string
		do   func(ctx context.Context, sh *Shim) (any, error)
	}
	calls := []call{
		{"create", func(ctx context.Context, sh *Shim) (any, error) { return sh.Create(ctx, "c1", "/b/c1", "/logs") }},
		{"start", func(ctx context.Context, sh *Shim) (any, error) { return nil, sh.Start(ctx, "c1") }},
		{"state", func(ctx context.Context, sh *Shim) (any, error) { return sh.State(ctx, "c1") }},
		{"state exited", func(ctx context.Context, sh *Shim) (any, error) { return sh.State(ctx, "c2") }},
		{"state missing", func(ctx context.Context, sh *Shim) (any, error) { return sh.State(ctx, "nope") }},
		{"wait", func(ctx context.Context, sh *Shim) (any, error) { return sh.Wait(ctx, "c1") }},
		{"kill", func(ctx context.Context, sh *Shim) (any, error) { return nil, sh.Kill(ctx, "c1", 15) }},
		{"kill all", func(ctx context.Context, sh *Shim) (any, error) { return nil, sh.KillAll(ctx, "c1", 9) }},
		{"kill stopped", func(ctx context.Context, sh *Shim) (any, error) { return nil, sh.Kill(ctx, "c2", 15) }},
		{"delete", func(ctx context.Context, sh *Shim) (any, error) { return nil, sh.Delete(ctx, "c1") }},
		{"list", func(ctx context.Context, sh *Shim) (any, error) { return sh.List(ctx) }},
		{"odd answer", func(ctx context.Context, sh *Shim) (any, error) { return sh.call(ctx, "odd") }},
		{"no newline", func(ctx context.Context, sh *Shim) (any, error) { return sh.call(ctx, "eof") }},
		{"bad word", func(ctx context.Context, sh *Shim) (any, error) { return sh.call(ctx, "kill", "c1 x") }},
		{"empty word", func(ctx context.Context, sh *Shim) (any, error) { return sh.call(ctx, "state", "") }},
	}
	answers := map[string]string{
		"create c1 /b/c1 /logs": "ok 42",
		"state c1":              "ok running 42",
		"state c2":              "ok exited 137",
		"state nope":            "err container nope not found",
		"wait c1":               "ok 3",
		"kill c2 15":            "err container c2 is not running",
		"list":                  "ok c1 running:42 c2 exited:0",
		"odd":                   "what",
	}
	type result struct {
		lines    []string
		out, err string
		notFound bool
	}
	run := func(native *Native, sock string, c call) result {
		var lines []string
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				line, _ := bufio.NewReader(conn).ReadString('\n')
				line = strings.TrimSuffix(line, "\n")
				lines = append(lines, line)
				if line == "eof" {
					_, _ = conn.Write([]byte("ok 1"))
				} else if a, ok := answers[line]; ok {
					_, _ = conn.Write([]byte(a + "\n"))
				} else {
					_, _ = conn.Write([]byte("ok\n"))
				}
				_ = conn.Close()
			}
		}()
		sh := (&Shims{Dir: filepath.Dir(sock), Native: native}).Get("g")
		out, cerr := c.do(context.Background(), sh)
		_ = l.Close()
		<-done
		return result{lines: lines, out: fmt.Sprint(out), err: errText(cerr), notFound: NotFound(cerr)}
	}
	sock := (&Shims{Dir: dir}).Get("g").Socket
	for _, c := range calls {
		g := run(nil, sock, c)
		r := run(n, sock, c)
		if !reflect.DeepEqual(g, r) {
			t.Errorf("%s:\n go   %+v\n rust %+v", c.name, g, r)
		}
	}

	// A shim that is gone: nothing at the socket, or nothing listening.
	gone := func(native *Native) (string, bool, bool) {
		sh := (&Shims{Dir: dir, Native: native}).Get("g")
		_, err := sh.List(context.Background())
		return errText(err), errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.ECONNREFUSED)
	}
	ge, gn, gr := gone(nil)
	re, rn, rr := gone(n)
	if ge != re || gn != rn || gr != rr || !gn {
		t.Errorf("no socket: go %q %v %v, armada-node %q %v %v", ge, gn, gr, re, rn, rr)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = l.Close()
	ge, gn, gr = gone(nil)
	re, rn, rr = gone(n)
	if ge != re || gn != rn || gr != rr || !gr {
		t.Errorf("stale socket: go %q %v %v, armada-node %q %v %v", ge, gn, gr, re, rn, rr)
	}
}

// Without armada-node (a pack without it, or one that does not run), Go
// does every bundle and shim call on the same files.
func TestNativeFallsBackToGo(t *testing.T) {
	ctx := context.Background()
	n, err := OpenNative(filepath.Join(t.TempDir(), "armada-node"), filepath.Join(t.TempDir(), "images"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s := &Store{Bundles: Bundles{Dir: dir}, Native: n, Shims: &Shims{Dir: t.TempDir(), Native: n}}
	mustWrite(t, filepath.Join(dir, "c1", bundleRecord), `{"id":"c1","image":"x","group":"g","created":"2026-11-23T08:00:00Z"}`)
	cs, err := s.Containers(ctx)
	if err != nil || len(cs) != 1 || cs[0].ID() != "c1" {
		t.Fatalf("containers: %v, %v", cs, err)
	}
	if _, err := cs[0].SetLabels(ctx, map[string]string{"a": "b"}); err != nil {
		t.Fatal(err)
	}
	sh := s.Shims.Get("g")
	fakeShim(t, sh.Socket, func(req string) string { return "ok c1 running:7" })
	if st, err := sh.List(ctx); err != nil || st["c1"].Pid != 7 {
		t.Fatalf("list: %v, %v", st, err)
	}
	if err := s.removeBundle(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "c1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bundle still there: %v", err)
	}
	if err := n.Release(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Prepare(ctx, "c1", "x"); err == nil {
		t.Fatal("prepared a root filesystem without armada-node")
	}
}
