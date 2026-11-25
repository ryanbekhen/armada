package supervisor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/opencontainers/go-digest"
)

// The Rust agent converts Go's image store at its start as the Go agent
// does (ADR 0055 item 16e; node/src/runtime/image/gostore). TestRustMove
// builds Go's stores with the real store (layers applied by markApplier,
// no privileges), runs Go's MoveImages or CollectGo on each, and keeps the
// data directory before and after, the summary, the record, and what
// readSnapshots reads of metadata.db in testdata/rust/move.json; the Rust
// tests (gostore::tests) write each "before" tree, do the same, and
// compare. go test -run TestRustMove -update rewrites the file; without
// it the file is checked against a fresh run, times and the trees before
// left out (metadata.db and images.json hold the times of the run).

var update = flag.Bool("update", false, "rewrite testdata/rust")

const rmData = "DATA"

// rmEntry is a file, directory, or symbolic link of a tree: a file's
// bytes as its size and the base64 of each non-zero 4 KiB chunk with its
// trailing zeros cut (metadata.db is mostly zeros), or, in trees after,
// a .json file's value; for files after, how many of the tree's files
// are the same file (hard links among them), and before, the first of
// those (by path) when it is another.
type rmEntry struct {
	Type   string            `json:"type"`
	Mode   uint32            `json:"mode"`
	Size   int64             `json:"size,omitempty"`
	Chunks map[string]string `json:"chunks,omitempty"`
	JSON   json.RawMessage   `json:"json,omitempty"`
	Nlink  uint64            `json:"nlink,omitempty"`
	Target string            `json:"target,omitempty"`
	Same   string            `json:"same,omitempty"`
}

type rmCase struct {
	Name string `json:"name"`
	// Op is "move" (MoveImages) or "collect" (CollectGo).
	Op        string                `json:"op"`
	Before    map[string]rmEntry    `json:"before"`
	Snapshots map[string]rmSnapshot `json:"snapshots"`
	After     map[string]rmEntry    `json:"after"`
	Summary   json.RawMessage       `json:"summary,omitempty"`
	Error     string                `json:"error,omitempty"`
}

type rmSnapshot struct {
	Dir    string `json:"dir"`
	Kind   int    `json:"kind"`
	Parent string `json:"parent,omitempty"`
}

// rmTree reads the tree under data; after, .json files are kept as values
// with data's path replaced.
func rmTree(t *testing.T, data string, after bool) map[string]rmEntry {
	t.Helper()
	out := map[string]rmEntry{}
	inodes := map[string]uint64{}
	err := filepath.WalkDir(data, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == data {
			return err
		}
		rel, _ := filepath.Rel(data, p)
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		e := rmEntry{Mode: uint32(fi.Mode().Perm())}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			e.Type = "link"
			e.Target, err = os.Readlink(p)
			if err != nil {
				return err
			}
		case fi.IsDir():
			e.Type = "dir"
		default:
			e.Type = "file"
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			inodes[rel] = fi.Sys().(*syscall.Stat_t).Ino
			if after && strings.HasSuffix(p, ".json") {
				e.JSON = json.RawMessage(strings.ReplaceAll(string(b), data, rmData))
				break
			}
			if strings.HasSuffix(p, ".json") {
				// Records of an earlier run name its directory.
				b = bytes.ReplaceAll(b, []byte(data), []byte(rmData))
			}
			e.Size = int64(len(b))
			for off := 0; off < len(b); off += 4096 {
				c := bytes.TrimRight(b[off:min(off+4096, len(b))], "\x00")
				if len(c) > 0 {
					if e.Chunks == nil {
						e.Chunks = map[string]string{}
					}
					e.Chunks[strconv.Itoa(off)] = base64.StdEncoding.EncodeToString(c)
				}
			}
		}
		out[rel] = e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	links := map[uint64]uint64{}
	first := map[uint64]string{}
	for rel, ino := range inodes {
		links[ino]++
		if f, ok := first[ino]; !ok || rel < f {
			first[ino] = rel
		}
	}
	for rel, ino := range inodes {
		e := out[rel]
		if after {
			e.Nlink = links[ino]
		} else if first[ino] != rel {
			e.Same = first[ino]
		}
		out[rel] = e
	}
	return out
}

func rmSnapshots(t *testing.T, data, src string) map[string]rmSnapshot {
	t.Helper()
	snaps, err := readSnapshots(context.Background(), filepath.Join(src, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]rmSnapshot{}
	for name, s := range snaps {
		rel, _ := filepath.Rel(data, s.dir)
		out[name] = rmSnapshot{Dir: rel, Kind: int(s.kind), Parent: s.parent}
	}
	return out
}

func rmSummary(t *testing.T, sum *ConvertSummary, data string) json.RawMessage {
	t.Helper()
	if sum == nil {
		return nil
	}
	v := map[string]any{
		"converted": nonNil(sum.Converted), "kept": nonNil(sum.Kept),
		"skipped": sum.Skipped, "layers": sum.Layers,
	}
	if v["skipped"] == nil || len(sum.Skipped) == 0 {
		v["skipped"] = map[string]string{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return json.RawMessage(strings.ReplaceAll(string(b), data, rmData))
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func TestRustMove(t *testing.T) {
	ctx := context.Background()
	var cases []rmCase
	run := func(name, op, data, src, dst string, prepare func()) {
		c := rmCase{Name: name, Op: op, Before: rmTree(t, data, false), Snapshots: rmSnapshots(t, data, src)}
		if prepare != nil {
			prepare()
		}
		state := filepath.Join(data, "node", MovedFile)
		switch op {
		case "move":
			_, sum, err := MoveImages(ctx, src, dst, bundlesDir(data), state)
			if err != nil {
				c.Error = strings.ReplaceAll(err.Error(), data, rmData)
			}
			c.Summary = rmSummary(t, sum, data)
		case "collect":
			imgs, err := OpenImages(src)
			if err != nil {
				t.Fatal(err)
			}
			n, err := OpenNative(filepath.Join(data, "no-armada-node"), dst)
			if err != nil {
				t.Fatal(err)
			}
			s := &Store{Images: imgs, Native: n, Moved: state, Bundles: Bundles{Dir: bundlesDir(data)}, NodeImages: dst}
			s.CollectGo(ctx)
			if s.Images != nil {
				_ = s.Images.Close()
			}
		}
		c.After = rmTree(t, data, true)
		cases = append(cases, c)
	}

	// Every image converted, the container's root filesystem moved, and
	// Go's store removed.
	data, src, dst, a, _ := goStore(t)
	addBundle(t, data, "container-1", a.Name)
	run("moved", "move", data, src, dst, nil)

	// An image whose layer blob is gone is left out; a container whose
	// layer is gone stays in Go's store, which stays with it. Then the
	// container goes and CollectGo removes the store.
	data, src, dst, a, b := goStore(t)
	addBundle(t, data, "container-1", a.Name)
	blocked(t, data, src)
	if err := os.Remove(blobPath(src, digest.FromString("layer two"))); err != nil {
		t.Fatal(err)
	}
	run("left", "move", data, src, dst, nil)
	if err := os.RemoveAll(Bundles{Dir: bundlesDir(data)}.Path("blocked")); err != nil {
		t.Fatal(err)
	}
	run("collected", "collect", data, src, dst, nil)

	// armada-node's store already holds the images: records kept, and Go's
	// directory of the layer the moved container's overlay mounts held.
	data, src, dst, a, _ = keptStore(t)
	addBundle(t, data, "container-1", a.Name)
	if err := os.WriteFile(filepath.Join(upper(t, src, "container-1"), "written"), []byte("by the container"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("held", "move", data, src, dst, nil)

	// A second start with the record not collected: the conversion does
	// not run again, the moved container is counted, and the blocked one
	// is left again.
	data, src, dst, a, _ = goStore(t)
	addBundle(t, data, "container-1", a.Name)
	blocked(t, data, src)
	state := filepath.Join(data, "node", MovedFile)
	if _, _, err := MoveImages(ctx, src, dst, bundlesDir(data), state); err != nil {
		t.Fatal(err)
	}
	run("again", "move", data, src, dst, nil)

	// No Go store: a record at once.
	data = t.TempDir()
	if err := os.MkdirAll(filepath.Join(data, "node"), 0o700); err != nil {
		t.Fatal(err)
	}
	run("none", "move", data, filepath.Join(data, "supervisor", "images"), filepath.Join(data, "node", "images"), nil)

	// A blob whose digest does not match (in a store that was copied,
	// say) is not verified: its image is left out and the blob removed.
	data, src, dst, _, b = goStore(t)
	p := blobPath(src, b.Config.Digest)
	cfg, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(cfg, '\n'), 0o400); err != nil {
		t.Fatal(err)
	}
	run("damaged", "move", data, src, dst, nil)

	out, err := json.MarshalIndent(map[string]any{"cases": cases}, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	path := filepath.Join("testdata", "rust", "move.json")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%v (go test -run TestRustMove -update writes it)", err)
	} else if err != nil {
		t.Fatal(err)
	}
	if a, b := rmStable(t, want), rmStable(t, out); !reflect.DeepEqual(a, b) {
		ka, _ := json.Marshal(a)
		kb, _ := json.Marshal(b)
		t.Errorf("testdata/rust/move.json is stale (go test -run TestRustMove -update):\nhave %s\nwant %s", ka, kb)
	}
}

// rmStable is a fixture without what changes from run to run: the trees
// before, metadata.db's and images.json's bytes, and times.
func rmStable(t *testing.T, b []byte) any {
	t.Helper()
	var v struct{ Cases []map[string]any }
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	var walk func(any) any
	walk = func(x any) any {
		switch x := x.(type) {
		case map[string]any:
			for k, v := range x {
				switch k {
				case "created", "updated", "at":
					x[k] = "TIME"
				default:
					x[k] = walk(v)
				}
			}
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
		}
		return x
	}
	for _, c := range v.Cases {
		delete(c, "before")
		if after, ok := c["after"].(map[string]any); ok {
			for p := range after {
				if strings.HasSuffix(p, "metadata.db") || strings.HasSuffix(p, recordsFile) {
					delete(after, p)
				}
			}
		}
		walk(c)
	}
	sort.Slice(v.Cases, func(i, j int) bool { return v.Cases[i]["name"].(string) < v.Cases[j]["name"].(string) })
	return v.Cases
}
