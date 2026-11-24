package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
)

// A node's move from Go's image store (<data dir>/supervisor/images) to
// armada-node's (<data dir>/node/images), ADR 0054 "The runtime's move":
// before the runtime starts, the agent converts the store's images, moves
// the root filesystems of the containers that exist into armada-node's
// layout, and removes Go's store (MoveImages); a container whose root
// filesystem could not move keeps the store until it goes
// (Store.CollectGo); and a node that returns to Go's code takes back what
// is still Go's to take (RevertImages).

// MovedFile is the record, in armada-node's directory (<data dir>/node),
// that Go's image store was converted into armada-node's. Present, it
// says the conversion ran to its end and Go's code has not run the node
// since.
const MovedFile = "converted.json"

// moveStateVersion is the version of MovedFile written.
const moveStateVersion = 1

// MoveState is MovedFile.
type MoveState struct {
	Version int       `json:"version"`
	At      time.Time `json:"at"`
	// Converted counts the images in armada-node's store after the
	// conversion: converted, or recorded there before.
	Converted int `json:"converted"`
	// Skipped names each image the conversion left out, and why; each is
	// pulled again when a replica needs it.
	Skipped map[string]string `json:"skipped,omitempty"`
	// Layers counts the unpacked layers moved.
	Layers int `json:"layers"`
	// Containers counts the containers' root filesystems moved into
	// armada-node's store; ContainersLeft names each container whose root
	// filesystem stayed in Go's store, and why.
	Containers     int               `json:"containers,omitempty"`
	ContainersLeft map[string]string `json:"containersLeft,omitempty"`
	// Collected is set once Go's image store is gone: there was none, or
	// no container used it any more.
	Collected bool `json:"collected,omitempty"`
}

// ReadMoveState reads the record at path; ok is false when there is none.
func ReadMoveState(path string) (st MoveState, ok bool, err error) {
	b, err := os.ReadFile(path) //nolint:gosec // under the agent's data directory
	switch {
	case errors.Is(err, os.ErrNotExist):
		return st, false, nil
	case err != nil:
		return st, false, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, false, fmt.Errorf("%s: %w", path, err)
	}
	if st.Version > moveStateVersion {
		return st, false, fmt.Errorf("%s: version %d is newer than %d", path, st.Version, moveStateVersion)
	}
	return st, true, nil
}

func writeMoveState(path string, st MoveState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	st.Version = moveStateVersion
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := writeSynced(tmp, b); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// MoveImages moves a node from Go's image store under src to
// armada-node's under dst before the runtime starts, with neither store in
// use:
//
//  1. Unless the record at statePath exists, ConvertImages converts the
//     images (sum is its summary; nil when it did not run).
//  2. The root filesystem of every container whose bundle (under bundles)
//     stands on an active snapshot of Go's store moves into armada-node's
//     layout (moveActive), running or not: no container restarts.
//  3. The record is written; once no container's root filesystem is left
//     in Go's store, the store is removed and the record says so.
//
// Every step can run again after a crash and finds what it did: the
// record is written only after step 1 ran to its end, a moved root
// filesystem is found in its new place, and a record without collected
// repeats steps 2 and 3 at the next start. A node with no Go store gets a
// record at once.
func MoveImages(ctx context.Context, src, dst, bundles, statePath string) (st MoveState, sum *ConvertSummary, err error) {
	st, ok, err := ReadMoveState(statePath)
	switch {
	case err != nil:
		return st, nil, err
	case ok && st.Collected:
		return st, nil, nil
	}
	if !ok {
		st = MoveState{At: time.Now().UTC()}
		switch _, err := os.Stat(src); {
		case errors.Is(err, os.ErrNotExist):
			st.Collected = true
			return st, nil, writeMoveState(statePath, st)
		case err != nil:
			return st, nil, err
		}
		s, err := ConvertImages(ctx, src, dst)
		if err != nil {
			return st, &s, err
		}
		sum = &s
		st.Converted, st.Layers = len(s.Converted)+len(s.Kept), s.Layers
		if len(s.Skipped) > 0 {
			st.Skipped = s.Skipped
		}
	}
	moved, layers, left, err := moveActive(ctx, src, dst, bundles)
	st.Layers += layers
	if err != nil {
		return st, sum, err
	}
	st.Containers, st.ContainersLeft = moved, nil
	if len(left) > 0 {
		st.ContainersLeft = left
	}
	// The record first: a crash while removing Go's store repeats the
	// removal at the next start.
	if err := writeMoveState(statePath, st); err != nil || len(left) > 0 {
		return st, sum, err
	}
	if err := os.RemoveAll(src); err != nil {
		return st, sum, fmt.Errorf("remove Go's image store: %w", err)
	}
	st.Collected = true
	return st, sum, writeMoveState(statePath, st)
}

// nodeSnapshot is armada-node's record of a container's root filesystem
// (active/<key>/snapshot.json; node/src/runtime/image/snapshot.rs).
type nodeSnapshot struct {
	Image   string   `json:"image"`
	Parents []string `json:"parents"`
}

// validKey is armada-node's rule for a snapshot key (a container ID): one
// path name, not hidden, at most 255 bytes.
func validKey(key string) bool {
	return key != "" && len(key) <= 255 && key[0] != '.' && !strings.ContainsAny(key, "/\x00")
}

// moveActive moves the root filesystem of every container whose bundle
// under bundles stands on an active snapshot of Go's store under src
// into armada-node's store under dst, as armada-node's prepare would have
// made it for that container ID (active/<ID>/ with fs/, work/, and
// snapshot.json naming the image and its layers, the top first), so its
// release removes it like its own. The snapshot's layers not in dst yet
// move to layers/<chain ID hex> first. Each root filesystem moves with one
// rename of its snapshot's directory on the same file system: a running
// container's overlay mount keeps the directories the kernel holds, and
// the bundle's mount point, by which it is unmounted, does not move. It
// returns the root filesystems in dst's layout (moved now or before), the
// layers moved, and the containers left in Go's store with why.
func moveActive(ctx context.Context, src, dst, bundles string) (moved, layers int, left map[string]string, err error) {
	snaps, err := readSnapshots(ctx, filepath.Join(src, "snapshots"))
	if err != nil {
		return 0, 0, nil, err
	}
	recs, err := Bundles{Dir: bundles}.Records()
	if err != nil {
		return 0, 0, nil, err
	}
	left = map[string]string{}
	for _, rec := range recs {
		sn, ok := snaps[rec.ID]
		if !ok || sn.kind != snapshots.KindActive {
			continue // armada-node's own, or none
		}
		target := filepath.Join(dst, "active", rec.ID)
		if _, err := os.Lstat(sn.dir); errors.Is(err, os.ErrNotExist) {
			if _, err := os.Lstat(filepath.Join(target, "snapshot.json")); err == nil {
				moved++ // by an earlier run
			}
			continue
		}
		if !validKey(rec.ID) {
			left[rec.ID] = "not a snapshot key armada-node takes"
			continue
		}
		if _, err := os.Lstat(target); err == nil {
			left[rec.ID] = "armada-node's store already has a root filesystem for it"
			continue
		}
		var parents []string
		why := ""
		for p := sn.parent; p != "" && why == ""; {
			ps, ok := snaps[p]
			d, err := digest.Parse(p)
			if !ok || err != nil || ps.kind != snapshots.KindCommitted {
				why = fmt.Sprintf("layer %s is not a layer of Go's store", p)
				break
			}
			layer := filepath.Join(dst, "layers", d.Encoded())
			if _, err := os.Lstat(layer); err != nil {
				if err := os.MkdirAll(filepath.Dir(layer), 0o700); err != nil {
					return moved, layers, left, err
				}
				if err := os.Rename(filepath.Join(ps.dir, "fs"), layer); err != nil {
					why = fmt.Sprintf("layer %s: %v", p, err)
					break
				}
				layers++
			}
			parents = append(parents, d.Encoded())
			p = ps.parent
		}
		if why != "" {
			left[rec.ID] = why
			continue
		}
		if parents == nil {
			parents = []string{}
		}
		b, err := json.Marshal(nodeSnapshot{Image: rec.Image, Parents: parents})
		if err != nil {
			return moved, layers, left, err
		}
		if err := writeSynced(filepath.Join(sn.dir, "snapshot.json"), b); err != nil {
			return moved, layers, left, err
		}
		if err := os.MkdirAll(filepath.Join(dst, "active"), 0o700); err != nil {
			return moved, layers, left, err
		}
		if err := os.Rename(sn.dir, target); err != nil {
			left[rec.ID] = err.Error()
			continue
		}
		moved++
	}
	return moved, layers, left, nil
}

// RevertImages readies Go's image store under src for Go's code again on
// a node that ran armada-node (agent.json "runtimeAgent": "go"), with
// neither store in use. Where Go's store is still there (a container's
// root filesystem could not move, or the move was cut short), every
// unpacked layer and container root filesystem the move took from it to
// armada-node's store under dst goes back where Go's snapshotter keeps it,
// armada-node's records of those images are dropped (a later move
// converts them again), and layers found in neither store are forgotten
// with the images on them (Go pulls those again). Where it is gone (the
// usual case), nothing comes back: Go pulls the images it needs into a
// new store, and the containers made before keep running from
// armada-node's store, whose root filesystems Go removes with them
// (Store.NodeImages). The record at statePath is removed either way. It
// returns how many layers and root filesystems went back.
func RevertImages(ctx context.Context, src, dst, statePath string) (int, error) {
	all, err := readSnapshots(ctx, filepath.Join(src, "snapshots"))
	if err != nil {
		return 0, err
	}
	back := 0
	snaps := map[string]string{}
	for name, sn := range all {
		switch sn.kind {
		case snapshots.KindCommitted:
			snaps[name] = filepath.Join(sn.dir, "fs")
		case snapshots.KindActive:
			from := filepath.Join(dst, "active", name)
			if _, err := os.Lstat(sn.dir); err == nil || !validKey(name) {
				continue
			}
			if _, err := os.Lstat(from); err != nil {
				continue
			}
			if err := os.Remove(filepath.Join(from, "snapshot.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
				return back, err
			}
			if err := os.Rename(from, sn.dir); err != nil {
				return back, fmt.Errorf("root filesystem %s: %w", name, err)
			}
			back++
		}
	}
	var missing []string
	for _, name := range slices.Sorted(maps.Keys(snaps)) {
		fs := snaps[name]
		if _, err := os.Lstat(fs); err == nil {
			continue
		}
		if d, err := digest.Parse(name); err == nil {
			from := filepath.Join(dst, "layers", d.Encoded())
			if _, err := os.Lstat(from); err == nil {
				if err := os.Rename(from, fs); err != nil {
					return back, fmt.Errorf("layer %s: %w", name, err)
				}
				back++
				continue
			}
		}
		missing = append(missing, name)
	}
	if len(missing) > 0 {
		if err := forgetLayers(ctx, src, missing); err != nil {
			return back, err
		}
	}
	if back > 0 {
		if err := dropUnpacked(dst); err != nil {
			return back, err
		}
	}
	if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return back, err
	}
	return back, nil
}

// forgetLayers removes the committed snapshots of Go's store under src
// that missing names, with every committed snapshot on them, and the
// records of images on them, so Go unpacks them again on its next pull.
// A snapshot a container's root filesystem is on stays (its container
// still runs from the directories the kernel holds).
func forgetLayers(ctx context.Context, src string, missing []string) error {
	s, err := OpenImages(src)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	parent := map[string]string{}
	committed := map[string]bool{}
	if err := s.snap.Walk(ctx, func(_ context.Context, info snapshots.Info) error {
		parent[info.Name] = info.Parent
		committed[info.Name] = info.Kind == snapshots.KindCommitted
		return nil
	}); err != nil {
		return err
	}
	broken := map[string]bool{}
	for _, m := range missing {
		broken[m] = true
	}
	// A snapshot on a broken one is broken.
	for changed := true; changed; {
		changed = false
		for name, p := range parent {
			if !broken[name] && broken[p] {
				broken[name], changed = true, true
			}
		}
	}
	// Leaves first: a parent goes once its children went.
	for progress := true; progress; {
		progress = false
		for name := range broken {
			if !committed[name] {
				continue
			}
			if err := s.snap.Remove(ctx, name); err == nil || errdefs.IsNotFound(err) {
				committed[name], progress = false, true
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, r := range s.recs {
		if broken[r.ChainID.String()] {
			delete(s.recs, name)
		}
	}
	return s.saveLocked()
}

// dropUnpacked removes from armada-node's index under dst every record
// one of whose layers is not unpacked there, marking the store for a
// collection.
func dropUnpacked(dst string) error {
	for _, name := range []string{"pull.lock", "index.lock"} {
		unlock, err := lockFile(filepath.Join(dst, name))
		if err != nil {
			return err
		}
		defer unlock()
	}
	path := filepath.Join(dst, "index.json")
	b, err := os.ReadFile(path) //nolint:gosec // under the agent's data directory
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return err
	}
	var idx nodeIndex
	if err := json.Unmarshal(b, &idx); err != nil {
		return fmt.Errorf("index.json: %w", err)
	}
	if idx.Version > nodeIndexVersion {
		return fmt.Errorf("index.json: version %d is newer than %d", idx.Version, nodeIndexVersion)
	}
	changed := false
	for name, rec := range idx.Images {
		for _, ch := range identity.ChainIDs(slices.Clone(rec.DiffIDs)) {
			if _, err := os.Lstat(filepath.Join(dst, "layers", ch.Encoded())); err != nil {
				delete(idx.Images, name)
				changed, idx.Uncollected = true, true
				break
			}
		}
	}
	if !changed {
		return nil
	}
	out, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dst, "index.json.tmp")
	if err := writeSynced(tmp, out); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// hasSnapshot reports whether key names a snapshot in the store; an
// error other than not found counts as one.
func (s *Images) hasSnapshot(ctx context.Context, key string) bool {
	_, err := s.snap.Stat(ctx, key)
	return err == nil || !errdefs.IsNotFound(err)
}

// CollectGo removes Go's image store (Images) once the record at Moved
// says it was converted and no container's root filesystem is on it
// (ADR 0054, "The runtime's move", step 3); the record then says so.
// Only the agent calls it, with armada-node running the store.
func (s *Store) CollectGo(ctx context.Context) {
	s.goMu.Lock()
	defer s.goMu.Unlock()
	s.collectGoLocked(ctx)
}

// movedOut reports whether container id's root filesystem is in
// armada-node's store, where the move put Go's.
func (s *Store) movedOut(id string) bool {
	if s.NodeImages == "" || !validKey(id) {
		return false
	}
	_, err := os.Lstat(filepath.Join(s.NodeImages, "active", id))
	return err == nil
}

func (s *Store) collectGoLocked(ctx context.Context) {
	if s.Images == nil || s.Native == nil || s.Moved == "" {
		return
	}
	st, ok, err := ReadMoveState(s.Moved)
	if err != nil || !ok {
		return
	}
	recs, err := s.records(ctx)
	if err != nil {
		return
	}
	for _, r := range recs {
		if s.Images.hasSnapshot(ctx, r.ID) && !s.movedOut(r.ID) {
			return
		}
	}
	root := s.Images.root
	if err := s.Images.Close(); err != nil {
		slog.Warn("Go's image store: close", "err", err)
	}
	s.Images = nil
	if err := os.RemoveAll(root); err != nil {
		slog.Warn("Go's image store could not be removed", "dir", root, "err", err)
		return
	}
	st.Collected = true
	if err := writeMoveState(s.Moved, st); err != nil {
		slog.Warn("record of the image store's move", "err", err)
		return
	}
	slog.Info("Go's image store removed: no container uses it any more", "dir", root)
}

// MoveStatus is how the node's move to armada-node's image store goes.
type MoveStatus struct {
	// GoImages: Go's image store is still open beside armada-node's.
	GoImages bool
	// Converted: Moved records the conversion, or there was no Go store.
	Converted bool
	// ToPull counts the images the conversion left out that are not in
	// armada-node's store yet, while Go's store is still there.
	ToPull int
	// Err is MoveErr's text.
	Err string
}

// MoveStatus reads how the move goes, from Moved and armada-node's index.
func (s *Store) MoveStatus() MoveStatus {
	s.goMu.Lock()
	out := MoveStatus{GoImages: s.Images != nil}
	s.goMu.Unlock()
	if s.MoveErr != nil {
		out.Err = s.MoveErr.Error()
	}
	if s.Native == nil || s.Moved == "" {
		return out
	}
	st, ok, err := ReadMoveState(s.Moved)
	out.Converted = (ok && err == nil) || (!out.GoImages && err == nil)
	// Once Go's store is gone, every container made from it was replaced,
	// pulling what it needed: an image still left out is needed by none.
	if ok && !st.Collected && len(st.Skipped) > 0 {
		if idx, err := s.Native.index(); err == nil {
			for name := range st.Skipped {
				if _, ok := idx.Images[name]; !ok {
					out.ToPull++
				}
			}
		}
	}
	return out
}
