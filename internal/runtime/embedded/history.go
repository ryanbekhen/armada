package embedded

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

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
		s.notice = noticeTimeout()
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
		s.notice = noticeBudget(s.q.MaxBytes)
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
	return SearchLogsWith(ctx, "", dir, q)
}

// SearchLogsWith is SearchLogs reading the files with `armada-log search`
// at bin (logger/src/search.rs), which reads them many times faster; with
// no bin, a grep that is not ASCII, or a program that fails (an older
// armada-log), it reads them itself.
func SearchLogsWith(ctx context.Context, bin, dir string, q runtime.LogQuery) ([]runtime.LogRecord, string, error) {
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
	if bin != "" && isASCII(q.Grep) {
		paths := make([]string, len(srcs))
		metas := make([]LogMeta, len(srcs))
		for i, src := range srcs {
			paths[i], metas[i] = src.path, src.meta
		}
		out, notice, err := searchWith(ctx, bin, paths, metas, q)
		if err == nil {
			return out, notice, nil
		}
		searchFellBack(err)
	}
	for _, src := range srcs {
		if !s.scanFile(ctx, src.path, src.meta) {
			break
		}
	}
	s.trim()
	return s.out, s.notice, nil
}

// searchFellBack hears why armada-log search was not used; tests make it
// fail.
var searchFellBack = func(error) {}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// Notices of a search cut short, the same from both readers.
func noticeTimeout() string {
	return "the search took too long; narrow it with --since, --until, or --replica"
}

func noticeBudget(maxBytes int64) string {
	return fmt.Sprintf("searched the newest %d MiB of output on this node; narrow it with --since, --until, or --replica", maxBytes>>20)
}

// maxSearchOutput bounds what armada-log search may print: the kept
// entries are at most twice runtime's 5000-entry limit of 16 KiB lines.
const maxSearchOutput = 256 << 20

// searchWith runs `armada-log search` over paths (newest first) and turns
// the entries it kept into records.
func searchWith(ctx context.Context, bin string, paths []string, metas []LogMeta, q runtime.LogQuery) ([]runtime.LogRecord, string, error) {
	args := []string{"search", "--limit", strconv.Itoa(q.Limit), "--max-bytes", strconv.FormatInt(q.MaxBytes, 10)}
	if !q.Since.IsZero() {
		args = append(args, "--since", strconv.FormatInt(q.Since.UnixNano(), 10))
	}
	if !q.Until.IsZero() {
		args = append(args, "--until", strconv.FormatInt(q.Until.UnixNano(), 10))
	}
	if q.Grep != "" {
		args = append(args, "--grep", q.Grep)
	}
	if d, ok := ctx.Deadline(); ok {
		args = append(args, "--deadline-ms", strconv.FormatInt(max(time.Until(d).Milliseconds(), 0), 10))
	}
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // the runtime pack's armada-log with arguments built here
	cmd.Stdin = strings.NewReader(strings.Join(paths, "\n") + "\n")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, "", err
	}
	if err := cmd.Start(); err != nil {
		return nil, "", err
	}
	b, readErr := io.ReadAll(io.LimitReader(stdout, maxSearchOutput))
	if err := cmd.Wait(); err != nil {
		return nil, "", fmt.Errorf("armada-log search: %w", err)
	}
	if readErr != nil {
		return nil, "", readErr
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	end := strings.Fields(lines[len(lines)-1])
	if len(end) != 3 || end[0] != "end" {
		return nil, "", errors.New("armada-log search: no end line")
	}
	var out []runtime.LogRecord
	for _, line := range lines[:len(lines)-1] {
		idx, raw, ok := strings.Cut(line, " ")
		i, err := strconv.Atoi(idx)
		if !ok || err != nil || i < 0 || i >= len(metas) {
			return nil, "", fmt.Errorf("armada-log search: bad line %.40q", line)
		}
		var e logEntry
		if json.Unmarshal([]byte(raw), &e) != nil {
			continue
		}
		st := runtime.Stdout
		if e.Stream == "stderr" {
			st = runtime.Stderr
		}
		out = append(out, runtime.LogRecord{Time: e.Time, Stream: st, Data: []byte(e.Log), Replica: metas[i].Replica, Container: metas[i].Container})
	}
	switch end[1] {
	case "budget":
		return out, noticeBudget(q.MaxBytes), nil
	case "timeout":
		return out, noticeTimeout(), nil
	}
	return out, "", nil
}
