package embedded

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// Sending logs elsewhere (ADR 0044): the node remembers, per container, how
// far its output was sent, in <logs>/history/export.json.

const (
	exportStateName = "export.json"
	// minTailShare is the least a container may read per tail when many
	// share the budget.
	minTailShare = 64 << 10
)

// tailCursor is where a container's sent output ends: an offset in the
// file with inode Ino, and the time of the last entry sent.
type tailCursor struct {
	Ino  uint64    `json:"ino,omitempty"`
	Off  int64     `json:"off,omitempty"`
	Time time.Time `json:"time,omitzero"`
}

type exportState struct {
	// Target names the destination; another one starts over.
	Target string `json:"target"`
	// Since is when this destination was first used: containers created
	// before it start at the end of their output.
	Since time.Time             `json:"since"`
	Files map[string]tailCursor `json:"files"`
}

func exportStatePath(dir string) string { return filepath.Join(historyDir(dir), exportStateName) }

func loadExportState(dir string) exportState {
	var st exportState
	b, err := os.ReadFile(exportStatePath(dir))
	if err != nil || json.Unmarshal(b, &st) != nil {
		return exportState{}
	}
	return st
}

func saveExportState(dir string, st exportState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(historyDir(dir), 0o700); err != nil {
		return err
	}
	tmp := exportStatePath(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, exportStatePath(dir))
}

// tailFile is one of a container's log files.
type tailFile struct {
	path string
	ino  uint64
	size int64
}

func statTail(path string) (tailFile, bool) {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return tailFile{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return tailFile{}, false
	}
	return tailFile{path: path, ino: st.Ino, size: fi.Size()}, true
}

// containerFiles lists a container's log files, oldest first: history,
// then the rotated live files, then the current one.
func containerFiles(dir, id string, history []historyFile) []tailFile {
	var out []tailFile
	for _, h := range history {
		if f, ok := statTail(h.path); ok {
			out = append(out, f)
		}
	}
	path := filepath.Join(dir, id+".log")
	for i := runtime.LogMaxFiles - 1; i >= 0; i-- {
		p := path
		if i > 0 {
			p += "." + strconv.Itoa(i)
		}
		if f, ok := statTail(p); ok {
			out = append(out, f)
		}
	}
	return out
}

// TailLogs reads the output of app containers written since the last
// committed tail for target, at most about maxBytes (ADR 0044). Containers
// created before target was first used start at the end of their output.
// When a container's file is gone (pruned while the destination was
// unreachable), it goes on from the time of the last entry sent.
func TailLogs(ctx context.Context, dir, target string, maxBytes int64, now time.Time) (runtime.LogTail, error) {
	prev := loadExportState(dir)
	if prev.Target != target || prev.Files == nil {
		prev = exportState{Target: target, Since: now.UTC(), Files: map[string]tailCursor{}}
	}
	files, metas, err := readHistory(dir)
	if err != nil {
		return runtime.LogTail{}, err
	}
	history := map[string][]historyFile{}
	for _, f := range files {
		history[f.id] = append(history[f.id], f)
	}
	ids := make([]string, 0, len(metas))
	for id := range metas {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	next := exportState{Target: target, Since: prev.Since, Files: make(map[string]tailCursor, len(ids))}
	share := max(maxBytes/int64(max(len(ids), 1)), minTailShare)
	budget := maxBytes
	var recs []runtime.LogRecord
	for _, id := range ids {
		m := metas[id]
		c, known := prev.Files[id]
		tf := containerFiles(dir, id, history[id])
		if !known && m.Created.Before(prev.Since) {
			// Output from before this destination is not sent.
			c = tailCursor{Time: now.UTC()}
			if len(tf) > 0 {
				last := tf[len(tf)-1]
				c.Ino, c.Off = last.ino, last.size
			}
			next.Files[id] = c
			continue
		}
		if budget <= 0 || ctx.Err() != nil {
			next.Files[id] = c
			continue
		}
		start, off, byTime := 0, c.Off, false
		if c.Ino != 0 {
			start = slices.IndexFunc(tf, func(f tailFile) bool { return f.ino == c.Ino })
			if start < 0 {
				start, off, byTime = 0, 0, true
			}
		} else {
			off, byTime = 0, !c.Time.IsZero()
		}
		take := min(share, budget)
		for j := max(start, 0); j < len(tf) && take > 0; j++ {
			o := int64(0)
			if j == start {
				o = off
			}
			if o > tf[j].size {
				o = 0 // the file was replaced
			}
			limit := take
			n, err := tailRead(tf[j].path, o, limit, func(e logEntry) {
				if byTime && !e.Time.After(c.Time) {
					return
				}
				st := runtime.Stdout
				if e.Stream == "stderr" {
					st = runtime.Stderr
				}
				recs = append(recs, runtime.LogRecord{Time: e.Time, Stream: st, Data: []byte(e.Log),
					App: m.App, Revision: m.Revision, Replica: m.Replica, Container: m.Container})
				c.Time = e.Time
			})
			if err != nil {
				break // gone in between; the next tail finds where it went
			}
			c.Ino, c.Off = tf[j].ino, o+n
			take -= n
			budget -= n
			if tf[j].size-o > limit {
				break // the budget ended within this file
			}
			// Otherwise the file is done; an older file's trailing partial
			// line, left by a crash, is skipped.
		}
		next.Files[id] = c
	}
	return runtime.LogTail{Records: recs, Commit: func() error {
		if sameState(prev, next) && fileExists(exportStatePath(dir)) {
			return nil // nothing moved: no write every round
		}
		return saveExportState(dir, next)
	}}, nil
}

func sameState(a, b exportState) bool {
	return a.Target == b.Target && a.Since.Equal(b.Since) && maps.EqualFunc(a.Files, b.Files, func(x, y tailCursor) bool {
		return x.Ino == y.Ino && x.Off == y.Off && x.Time.Equal(y.Time)
	})
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// tailRead reads complete entries of path from off, at most limit bytes,
// and returns how many bytes they took.
func tailRead(path string, off, limit int64, fn func(logEntry)) (int64, error) {
	f, err := os.Open(path) //nolint:gosec // paths come from validated container IDs
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	n, err := scanEntries(io.LimitReader(f, limit), fn)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, err
	}
	return n, nil
}
