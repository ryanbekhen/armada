package embedded

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// Log history (ADR 0043): rotated-out and removed containers' log files are
// kept in <logs>/history as <id>.<unix nanoseconds>.log next to <id>.meta,
// which says whose they are.

const (
	historyDirName = "history"
	metaSuffix     = ".meta"
	// DefaultLogRetention is how long history is kept unless the cluster
	// says otherwise.
	DefaultLogRetention = 7 * 24 * time.Hour
	// maxDefaultHistory caps the default history size.
	maxDefaultHistory = 5 << 30
	// minDefaultHistory is the default on a file system too small for 10%
	// to be useful.
	minDefaultHistory = 64 << 20
)

// LogMeta says which container a log history belongs to.
type LogMeta struct {
	App       string    `json:"app"`
	Replica   string    `json:"replica"`
	Revision  string    `json:"revision,omitempty"`
	Container string    `json:"container,omitempty"`
	Created   time.Time `json:"created"`
}

func historyDir(dir string) string { return filepath.Join(dir, historyDirName) }

// WriteLogMeta records whose container id is, so its output is kept in
// history when it rotates out or the container is removed.
func WriteLogMeta(dir, id string, m LogMeta) error {
	if !validID.MatchString(id) {
		return fmt.Errorf("invalid container id %q", id)
	}
	h := historyDir(dir)
	if err := os.MkdirAll(h, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(h, id+metaSuffix), b, 0o600)
}

func hasMeta(dir, id string) bool {
	_, err := os.Stat(filepath.Join(historyDir(dir), id+metaSuffix))
	return err == nil
}

// keep moves a log file of container id into history, or removes it when
// the container has no meta file. seq orders files moved at once.
func keep(dir, id, path string, seq int) error {
	if !hasMeta(dir, id) {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	name := fmt.Sprintf("%s.%d.log", id, time.Now().UnixNano()+int64(seq))
	if err := os.Rename(path, filepath.Join(historyDir(dir), name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// historyFile is a log file in history.
type historyFile struct {
	id   string
	seq  int64
	path string
	size int64
	mod  time.Time
}

// parseHistoryName splits <id>.<seq>.log.
func parseHistoryName(name string) (string, int64, bool) {
	base, ok := strings.CutSuffix(name, ".log")
	if !ok {
		return "", 0, false
	}
	i := strings.LastIndexByte(base, '.')
	if i <= 0 {
		return "", 0, false
	}
	seq, err := strconv.ParseInt(base[i+1:], 10, 64)
	if err != nil || !validID.MatchString(base[:i]) {
		return "", 0, false
	}
	return base[:i], seq, true
}

// readHistory lists history's log files, oldest first, and its meta files.
func readHistory(dir string) ([]historyFile, map[string]LogMeta, error) {
	h := historyDir(dir)
	ents, err := os.ReadDir(h)
	if errors.Is(err, os.ErrNotExist) {
		return nil, map[string]LogMeta{}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var files []historyFile
	metas := map[string]LogMeta{}
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		name := e.Name()
		if id, ok := strings.CutSuffix(name, metaSuffix); ok && validID.MatchString(id) {
			b, err := os.ReadFile(filepath.Join(h, name)) //nolint:gosec // name is a validated container ID
			if err != nil {
				continue
			}
			var m LogMeta
			if json.Unmarshal(b, &m) == nil {
				metas[id] = m
			}
			continue
		}
		id, seq, ok := parseHistoryName(name)
		if !ok {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, historyFile{id: id, seq: seq, path: filepath.Join(h, name), size: fi.Size(), mod: fi.ModTime()})
	}
	slices.SortFunc(files, func(a, b historyFile) int { return int(min(max(a.seq-b.seq, -1), 1)) })
	return files, metas, nil
}

// DefaultHistoryBytes is the history size when the cluster sets none: 10%
// of the file system holding dir, between 64 MiB and 5 GiB.
func DefaultHistoryBytes(dir string) int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return minDefaultHistory
	}
	total := int64(st.Blocks) * st.Bsize //nolint:gosec // block counts fit
	return min(max(total/10, minDefaultHistory), maxDefaultHistory)
}

// PruneLogs removes history older than retention, then the oldest files
// until it holds at most maxBytes, and meta files of removed containers
// with no history left.
func PruneLogs(dir string, retention time.Duration, maxBytes int64, now time.Time) error {
	if retention <= 0 {
		retention = DefaultLogRetention
	}
	if maxBytes <= 0 {
		maxBytes = DefaultHistoryBytes(dir)
	}
	files, metas, err := readHistory(dir)
	if err != nil {
		return err
	}
	var errs []error
	var total int64
	for _, f := range files {
		total += f.size
	}
	left := map[string]bool{}
	for _, f := range files {
		if f.mod.Before(now.Add(-retention)) || total > maxBytes {
			if err := os.Remove(f.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
				left[f.id] = true
				continue
			}
			total -= f.size
			continue
		}
		left[f.id] = true
	}
	for id := range metas {
		if left[id] {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, id+".log")); err == nil {
			continue // the container still runs
		}
		if err := os.Remove(filepath.Join(historyDir(dir), id+metaSuffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// searchState collects the newest matching entries within a byte budget.
type searchState struct {
	q      runtime.LogQuery
	grep   []byte
	read   int64
	out    []runtime.LogRecord
	notice string
}

func (s *searchState) match(e logEntry, m LogMeta) {
	if e.Time.Before(s.q.Since) || (!s.q.Until.IsZero() && e.Time.After(s.q.Until)) {
		return
	}
	if !runtime.ContainsFold([]byte(e.Log), s.grep) {
		return
	}
	st := runtime.Stdout
	if e.Stream == "stderr" {
		st = runtime.Stderr
	}
	s.out = append(s.out, runtime.LogRecord{Time: e.Time, Stream: st, Data: []byte(e.Log), Replica: m.Replica, Container: m.Container})
	// Keep at most twice the limit before trimming to the newest.
	if len(s.out) > 2*s.q.Limit {
		s.trim()
	}
}

func (s *searchState) trim() {
	slices.SortStableFunc(s.out, func(a, b runtime.LogRecord) int { return a.Time.Compare(b.Time) })
	if len(s.out) > s.q.Limit {
		s.out = slices.Delete(s.out, 0, len(s.out)-s.q.Limit)
	}
}

// scanFile reads one log file's entries into s; false means the budget or
// the context ran out.
func (s *searchState) scanFile(ctx context.Context, path string, m LogMeta) bool {
	if ctx.Err() != nil {
		s.notice = "the search took too long; narrow it with --since, --until, or --replica"
		return false
	}
	fi, err := os.Stat(path)
	if err != nil {
		return true
	}
	// A file last written before the window holds nothing in it.
	if fi.ModTime().Before(s.q.Since) {
		return true
	}
	if s.read+fi.Size() > s.q.MaxBytes {
		s.notice = fmt.Sprintf("searched the newest %d MiB of output on this node; narrow it with --since, --until, or --replica", s.q.MaxBytes>>20)
		return false
	}
	f, err := os.Open(path) //nolint:gosec // paths come from validated container IDs
	if err != nil {
		return true
	}
	defer func() { _ = f.Close() }()
	n, _ := scanEntries(f, func(e logEntry) { s.match(e, m) })
	s.read += n
	return true
}

// SearchLogs searches the history and live logs of q.App's containers (ADR
// 0043): the newest q.Limit entries in the window, oldest first. Files are
// read newest first, so a search cut short by its budget keeps the latest
// output.
func SearchLogs(ctx context.Context, dir string, q runtime.LogQuery) ([]runtime.LogRecord, string, error) {
	if q.Limit <= 0 {
		return nil, "", nil
	}
	files, metas, err := readHistory(dir)
	if err != nil {
		return nil, "", err
	}
	s := &searchState{q: q, grep: bytes.ToLower([]byte(q.Grep))}
	want := func(id string) (LogMeta, bool) {
		m, ok := metas[id]
		if !ok || m.App != q.App || (q.Replica != "" && m.Replica != q.Replica) {
			return m, false
		}
		return m, q.Container == "" && (m.Container == "" || m.Container == "app") || m.Container == q.Container
	}
	// Every file of the app's containers, newest first: live files (current,
	// then rotated), then history by when it was moved.
	type source struct {
		path string
		meta LogMeta
	}
	var srcs []source
	ids := make([]string, 0, len(metas))
	for id := range metas {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		m, ok := want(id)
		if !ok {
			continue
		}
		path := filepath.Join(dir, id+".log")
		srcs = append(srcs, source{path, m})
		for i := 1; i < runtime.LogMaxFiles; i++ {
			srcs = append(srcs, source{path + "." + strconv.Itoa(i), m})
		}
	}
	for i := len(files) - 1; i >= 0; i-- {
		if m, ok := want(files[i].id); ok {
			srcs = append(srcs, source{files[i].path, m})
		}
	}
	for _, src := range srcs {
		if !s.scanFile(ctx, src.path, src.meta) {
			break
		}
	}
	s.trim()
	return s.out, s.notice, nil
}
