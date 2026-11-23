package embedded

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
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
	return TailLogsWith(ctx, "", dir, target, maxBytes, now, nil)
}

// TailLogsWith is TailLogs, rendering the output as enc's requests with
// the armada-log program bin when both are given: the tail has Bodies
// then. Without them, or when bin fails, Go reads the files and the tail
// has Records.
func TailLogsWith(ctx context.Context, bin, dir, target string, maxBytes int64, now time.Time, enc *runtime.LogEncoding) (runtime.LogTail, error) {
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
	var jobs []tailJob
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
		next.Files[id] = c
		j := tailJob{id: id, meta: m, cursor: c, files: tf, off: c.Off}
		if c.Ino != 0 {
			j.start = slices.IndexFunc(tf, func(f tailFile) bool { return f.ino == c.Ino })
			if j.start < 0 {
				j.start, j.off, j.byTime = 0, 0, true
			}
		} else {
			j.off, j.byTime = 0, !c.Time.IsZero()
		}
		jobs = append(jobs, j)
	}
	share := max(maxBytes/int64(max(len(ids), 1)), minTailShare)
	tail := runtime.LogTail{Commit: func() error {
		if sameState(prev, next) && fileExists(exportStatePath(dir)) {
			return nil // nothing moved: no write every round
		}
		return saveExportState(dir, next)
	}}
	if bin != "" && enc != nil {
		bodies, size, err := exportWith(ctx, bin, jobs, share, maxBytes, now, *enc, next.Files)
		if err == nil {
			tail.Bodies, tail.Size = bodies, size
			return tail, nil
		}
		exportFellBack(err)
	}
	tail.Records = readTails(ctx, jobs, share, maxBytes, next.Files)
	return tail, nil
}

// tailJob is a container whose output a tail reads: its files from start,
// at off in the first, and, when byTime, only entries after its cursor's
// time.
type tailJob struct {
	id     string
	meta   LogMeta
	cursor tailCursor
	files  []tailFile
	start  int
	off    int64
	byTime bool
}

// readTails reads jobs in order within budget, each at most share, and
// records where each ended in cursors.
func readTails(ctx context.Context, jobs []tailJob, share, budget int64, cursors map[string]tailCursor) []runtime.LogRecord {
	var recs []runtime.LogRecord
	for _, job := range jobs {
		if budget <= 0 || ctx.Err() != nil {
			break
		}
		c, m, tf := job.cursor, job.meta, job.files
		take := min(share, budget)
		for j := job.start; j < len(tf) && take > 0; j++ {
			o := int64(0)
			if j == job.start {
				o = job.off
			}
			if o > tf[j].size {
				o = 0 // the file was replaced
			}
			limit := take
			n, err := tailRead(tf[j].path, o, limit, func(e logEntry) {
				if job.byTime && !e.Time.After(c.Time) {
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
		cursors[job.id] = c
	}
	return recs
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

// exportFellBack is called when armada-log export failed and Go reads the
// output instead (tests replace it).
var exportFellBack = func(error) {}

const (
	// maxExportBody bounds one request armada-log export writes: a batch's
	// output escaped as JSON with its labels.
	maxExportBody = 64 << 20
	// maxExportOutput bounds all of it.
	maxExportOutput = 512 << 20
)

// exportWith runs `armada-log export` over jobs and returns the requests
// it rendered and the bytes of output they carry; only then are cursors
// moved to where it ended.
func exportWith(ctx context.Context, bin string, jobs []tailJob, share, budget int64, now time.Time, enc runtime.LogEncoding, cursors map[string]tailCursor) ([][]byte, int64, error) {
	var in strings.Builder
	for _, j := range jobs {
		space, name, send := "", "", "0"
		if enc.Split != nil {
			if sp, n, ok := enc.Split(j.meta.App); ok {
				space, name, send = sp, n, "1"
			}
		}
		container := j.meta.Container
		if container == "" {
			container = "app"
		}
		after := "-"
		if j.byTime {
			after = strconv.FormatInt(j.cursor.Time.Unix(), 10) + "." + strconv.Itoa(j.cursor.Time.Nanosecond())
		}
		if !planLine(&in, "c", send, space, name, j.meta.Replica, j.meta.Revision, container, after) {
			return nil, 0, errors.New("armada-log export: a name holds a tab or line break")
		}
		for k, f := range j.files[j.start:] {
			off := int64(0)
			if k == 0 {
				off = j.off
			}
			if !planLine(&in, "f", strconv.FormatInt(off, 10), strconv.FormatInt(f.size, 10), f.path) {
				return nil, 0, errors.New("armada-log export: a path holds a tab or line break")
			}
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "export", "--format", enc.Format, "--node", enc.Node, //nolint:gosec // the runtime pack's armada-log with arguments built here
		"--now", strconv.FormatInt(now.UnixNano(), 10),
		"--batch-records", strconv.Itoa(enc.BatchRecords), "--batch-bytes", strconv.Itoa(enc.BatchBytes),
		"--budget", strconv.FormatInt(budget, 10), "--share", strconv.FormatInt(share, 10))
	cmd.Stdin = strings.NewReader(in.String())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, err
	}
	if err := cmd.Start(); err != nil {
		return nil, 0, err
	}
	bodies, size, moved, readErr := readExport(bufio.NewReaderSize(stdout, 64<<10), jobs)
	if readErr != nil {
		cancel()
	}
	if err := cmd.Wait(); err != nil {
		// Its exit says more than the output it cut short.
		return nil, 0, fmt.Errorf("armada-log export: %w", err)
	}
	if readErr != nil {
		return nil, 0, readErr
	}
	maps.Copy(cursors, moved)
	return bodies, size, nil
}

// planLine writes fields as one tab-separated line, unless one holds a tab
// or a line break.
func planLine(b *strings.Builder, fields ...string) bool {
	for _, f := range fields {
		if strings.ContainsAny(f, "\t\n") {
			return false
		}
	}
	b.WriteString(strings.Join(fields, "\t"))
	b.WriteByte('\n')
	return true
}

// readExport reads armada-log export's output: requests, then cursors,
// then the end line.
func readExport(r *bufio.Reader, jobs []tailJob) ([][]byte, int64, map[string]tailCursor, error) {
	var (
		bodies [][]byte
		total  int
		moved  = map[string]tailCursor{}
	)
	for {
		line, err := r.ReadSlice('\n')
		if err != nil {
			return nil, 0, nil, fmt.Errorf("armada-log export: %w", err)
		}
		f := strings.Fields(string(line))
		bad := func() error { return fmt.Errorf("armada-log export: bad line %.40q", line) }
		switch {
		case len(f) == 2 && f[0] == "body":
			n, err := strconv.Atoi(f[1])
			if err != nil || n <= 0 || n > maxExportBody || total+n > maxExportOutput {
				return nil, 0, nil, bad()
			}
			b := make([]byte, n)
			if _, err := io.ReadFull(r, b); err != nil {
				return nil, 0, nil, fmt.Errorf("armada-log export: %w", err)
			}
			bodies = append(bodies, b)
			total += n
		case len(f) == 5 && f[0] == "cursor":
			i, err := strconv.Atoi(f[1])
			if err != nil || i < 0 || i >= len(jobs) {
				return nil, 0, nil, bad()
			}
			j := jobs[i]
			c, ok := moved[j.id]
			if !ok {
				c = j.cursor
			}
			if f[2] != "-" {
				k, err1 := strconv.Atoi(f[2])
				off, err2 := strconv.ParseInt(f[3], 10, 64)
				if err1 != nil || err2 != nil || k < 0 || j.start+k >= len(j.files) || off < 0 {
					return nil, 0, nil, bad()
				}
				c.Ino, c.Off = j.files[j.start+k].ino, off
			}
			if f[4] != "-" {
				sec, nsec, ok := strings.Cut(f[4], ".")
				s, err1 := strconv.ParseInt(sec, 10, 64)
				ns, err2 := strconv.ParseInt(nsec, 10, 64)
				if !ok || err1 != nil || err2 != nil || ns < 0 || ns >= 1e9 {
					return nil, 0, nil, bad()
				}
				c.Time = time.Unix(s, ns).UTC()
			}
			moved[j.id] = c
		case len(f) == 2 && f[0] == "end":
			size, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil || size < 0 {
				return nil, 0, nil, bad()
			}
			return bodies, size, moved, nil
		default:
			return nil, 0, nil, bad()
		}
	}
}
