package supervisor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/opencontainers/go-digest"
)

// A container whose root filesystem moved from Go's image store into
// armada-node's keeps its overlay mount, and with it every lower
// directory the mount was made with: Go's committed snapshots. Where
// armada-node's store already had a layer (an image it pulled itself, or
// one recorded there before the move), the move leaves Go's directory of
// that layer in Go's store and names armada-node's own in snapshot.json,
// so removing Go's store would remove the lower directories of a running
// container's mount. Before Go's store goes, holdLayers moves every such
// directory into armada-node's store as held/<chain ID hex>.<n>, which
// armada-node's collection removes once no active snapshot names that
// chain any more (the containers on it were released, so unmounted).

// heldDir is where held layers live in armada-node's store.
const heldDir = "held"

// mountInfoPath is read for mounts still naming a directory of Go's store
// (a variable for tests).
var mountInfoPath = "/proc/self/mountinfo"

// activeParents reads the chain ID hexes armada-node's active snapshots
// under dst stand on; all is true when a record cannot be read, so every
// layer counts as named.
func activeParents(dst string) (named map[string]bool, all bool, err error) {
	named = map[string]bool{}
	ents, err := os.ReadDir(filepath.Join(dst, "active"))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return named, false, nil
	case err != nil:
		return nil, false, err
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") {
			continue // a staging directory: armada-node's prepare in progress
		}
		b, err := os.ReadFile(filepath.Join(dst, "active", e.Name(), "snapshot.json")) //nolint:gosec // under the agent's data directory
		var rec nodeSnapshot
		if err == nil {
			err = json.Unmarshal(b, &rec)
		}
		if err != nil {
			all = true
			continue
		}
		for _, p := range rec.Parents {
			named[p] = true
		}
	}
	return named, all, nil
}

// holdLayers moves each committed snapshot directory of Go's store under
// src whose chain an active snapshot of armada-node's store under dst
// names (every one when a record cannot be read) to
// <dst>/held/<chain ID hex>.<n>, and marks armada-node's index for a
// collection. Renames keep a mounted overlay's lower directories; it
// returns how many moved. Neither store may be in use by Go.
func holdLayers(ctx context.Context, src, dst string) (int, error) {
	snaps, err := readSnapshots(ctx, filepath.Join(src, "snapshots"))
	if err != nil {
		return 0, err
	}
	named, all, err := activeParents(dst)
	if err != nil {
		return 0, err
	}
	held := 0
	for name, sn := range snaps {
		if sn.kind != snapshots.KindCommitted {
			continue
		}
		d, err := digest.Parse(name)
		if err != nil || (!all && !named[d.Encoded()]) {
			continue
		}
		from := filepath.Join(sn.dir, "fs")
		if _, err := os.Lstat(from); err != nil {
			continue // moved to layers/ by the conversion, or held before
		}
		if err := os.MkdirAll(filepath.Join(dst, heldDir), 0o700); err != nil {
			return held, err
		}
		to, err := freeHeldName(dst, d.Encoded())
		if err != nil {
			return held, err
		}
		if err := os.Rename(from, to); err != nil {
			return held, fmt.Errorf("hold layer %s: %w", name, err)
		}
		held++
	}
	if held > 0 {
		if err := updateNodeIndex(dst, func(idx *nodeIndex) bool {
			idx.Uncollected = true
			return true
		}); err != nil {
			return held, err
		}
	}
	return held, nil
}

// freeHeldName is the first <dst>/held/<hex>.<n> not taken.
func freeHeldName(dst, hex string) (string, error) {
	for n := 0; n < 1<<16; n++ {
		p := filepath.Join(dst, heldDir, hex+"."+strconv.Itoa(n))
		if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
			return p, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("no free name to hold layer %s", hex)
}

// heldFor lists the held directories of chain hex under dst.
func heldFor(dst, hex string) []string {
	m, _ := filepath.Glob(filepath.Join(dst, heldDir, hex+".*"))
	return m
}

// mountedUnder returns a directory under root that a mounted overlay
// still names (lowerdir, upperdir, workdir) and that is still there, or
// "" when none is. Overlay options keep the paths the mount was made
// with, so a directory renamed away since (a layer moved into
// armada-node's store, a held layer, a moved root filesystem) no longer
// shows: what is left under root is in use and must not be removed.
// Relative lower directories (a mount made from its directory because
// its options were too long) are not seen.
func mountedUnder(root string) (string, error) {
	f, err := os.Open(mountInfoPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	prefix := filepath.Clean(root) + string(filepath.Separator)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		_, after, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		fields := strings.Fields(after)
		if len(fields) < 3 || fields[0] != "overlay" {
			continue
		}
		for _, opt := range strings.Split(fields[2], ",") {
			key, val, ok := strings.Cut(opt, "=")
			if !ok {
				continue
			}
			switch key {
			case "lowerdir", "upperdir", "workdir", "lowerdir+", "datadir+":
			default:
				continue
			}
			for _, p := range splitUnescaped(val) {
				p = unescapeMountInfo(p)
				if !strings.HasPrefix(p, prefix) {
					continue
				}
				if _, err := os.Lstat(p); err == nil {
					return p, nil
				}
			}
		}
	}
	return "", sc.Err()
}

// splitUnescaped splits an overlay directory list on colons not escaped
// with a backslash.
func splitUnescaped(s string) []string {
	var out []string
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s) && s[i+1] == ':':
			b.WriteByte(':')
			i++
		case s[i] == ':':
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteByte(s[i])
		}
	}
	return append(out, b.String())
}

// unescapeMountInfo undoes mountinfo's octal escapes (\040 for a space,
// \011, \012, \134).
func unescapeMountInfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// removeGoStore removes Go's image store under src once no mount needs
// it: the layers armada-node's active snapshots under dst name are held
// first (holdLayers), and a directory a mounted overlay still names
// refuses the removal.
func removeGoStore(ctx context.Context, src, dst string) error {
	if _, err := os.Lstat(src); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if _, err := holdLayers(ctx, src, dst); err != nil {
		return fmt.Errorf("hold the layers of moved containers: %w", err)
	}
	switch p, err := mountedUnder(src); {
	case err != nil:
		return fmt.Errorf("read the mounts: %w", err)
	case p != "":
		return fmt.Errorf("a mounted overlay still uses %s", p)
	}
	if err := os.RemoveAll(src); err != nil {
		return fmt.Errorf("remove Go's image store: %w", err)
	}
	return nil
}
