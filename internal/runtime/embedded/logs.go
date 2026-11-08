package embedded

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// Container output is stored as JSON lines, the common json-file log
// json-file driver, one file per container, rotated by size.

// validID matches container IDs the driver creates; IDs end up in paths.
var validID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// maxLogChunk splits very long lines.
const maxLogChunk = 16 << 10

type logEntry struct {
	Log    string    `json:"log"`
	Stream string    `json:"stream"`
	Time   time.Time `json:"time"`
}

// LogPath returns the current log file of container id.
func LogPath(dir, id string) (string, error) {
	if !validID.MatchString(id) {
		return "", fmt.Errorf("invalid container id %q", id)
	}
	return filepath.Join(dir, id+".log"), nil
}

// logFile is a size-rotated log file shared by a container's streams.
type logFile struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	size     int64
	maxSize  int64
	maxFiles int
	now      func() time.Time

	// Write rate limit (token bucket over the output bytes); rate 0 means
	// unlimited. Output over it is dropped, never blocked, so a container
	// that logs synchronously keeps running; one marker line records how
	// much was dropped once output fits again or the streams end.
	rate, burst float64
	tokens      float64
	last        time.Time
	dropped     int64
}

func openLogFile(path string, maxSize int64) (*logFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // path is built from a validated container ID
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &logFile{path: path, f: f, size: fi.Size(), maxSize: maxSize, maxFiles: runtime.LogMaxFiles, now: time.Now}, nil
}

func (l *logFile) write(stream string, data []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if !l.allow(now, len(data)) {
		l.dropped += int64(len(data))
		return nil
	}
	if err := l.flushDropped(now); err != nil {
		return err
	}
	return l.append(logEntry{Log: string(data), Stream: stream, Time: now.UTC()})
}

// allow takes n bytes from the bucket, refilled at rate since the last call.
func (l *logFile) allow(now time.Time, n int) bool {
	if l.rate <= 0 {
		return true
	}
	if l.last.IsZero() {
		l.tokens = l.burst
	} else if d := now.Sub(l.last).Seconds(); d > 0 {
		l.tokens = min(l.burst, l.tokens+d*l.rate)
	}
	l.last = now
	if float64(n) > l.tokens {
		return false
	}
	l.tokens -= float64(n)
	return true
}

// flushDropped records dropped output as one line on stderr.
func (l *logFile) flushDropped(now time.Time) error {
	if l.dropped == 0 {
		return nil
	}
	msg := fmt.Sprintf("[armada: dropped %d bytes of output over the log rate limit of %d bytes per second]\n", l.dropped, int64(l.rate))
	l.dropped = 0
	return l.append(logEntry{Log: msg, Stream: "stderr", Time: now.UTC()})
}

// append writes one entry, rotating first when it would not fit.
func (l *logFile) append(e logEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if l.size > 0 && l.size+int64(len(b)) > l.maxSize {
		if err := l.rotate(); err != nil {
			return err
		}
	}
	n, err := l.f.Write(b)
	l.size += int64(n)
	return err
}

// rotate shifts path -> path.1 -> ... and drops the oldest file.
func (l *logFile) rotate() error {
	if err := l.f.Close(); err != nil {
		return err
	}
	for i := l.maxFiles - 1; i >= 1; i-- {
		src := l.path
		if i > 1 {
			src = l.path + "." + strconv.Itoa(i-1)
		}
		if err := os.Rename(src, l.path+"."+strconv.Itoa(i)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	l.f, l.size = f, 0
	return nil
}

func (l *logFile) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return errors.Join(l.flushDropped(l.now()), l.f.Close())
}

// copyStream writes r to l line by line until EOF.
func (l *logFile) copyStream(stream string, r io.Reader) error {
	br := bufio.NewReaderSize(r, maxLogChunk)
	for {
		line, err := br.ReadSlice('\n')
		if len(line) > 0 {
			if werr := l.write(stream, line); werr != nil {
				return werr
			}
		}
		switch {
		case err == nil, errors.Is(err, bufio.ErrBufferFull):
		case errors.Is(err, io.EOF):
			return nil
		default:
			return err
		}
	}
}

// WriteLogs stores a container's output until both streams end, at most
// runtime.LogRate bytes per second (runtime.LogBurst at once); the rest is
// dropped. It is what `armadad runtime-log` runs inside the shim's logging
// process.
func WriteLogs(dir, id string, stdout, stderr io.Reader) error {
	path, err := LogPath(dir, id)
	if err != nil {
		return err
	}
	l, err := openLogFile(path, runtime.LogMaxSize)
	if err != nil {
		return err
	}
	l.rate, l.burst = runtime.LogRate, runtime.LogBurst
	defer l.Close()
	errs := make(chan error, 2)
	go func() { errs <- l.copyStream("stdout", stdout) }()
	go func() { errs <- l.copyStream("stderr", stderr) }()
	return errors.Join(<-errs, <-errs)
}

// RemoveLogs deletes a container's log files.
func RemoveLogs(dir, id string) error {
	path, err := LogPath(dir, id)
	if err != nil {
		return err
	}
	var errs []error
	for i := 0; i < runtime.LogMaxFiles; i++ {
		p := path
		if i > 0 {
			p += "." + strconv.Itoa(i)
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// logStream implements runtime.LogStream over a channel fed by a reader
// goroutine.
type logStream struct {
	frames chan runtime.LogFrame
	errc   chan error
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *logStream) Next() (runtime.LogFrame, error) {
	f, ok := <-s.frames
	if !ok {
		if err := <-s.errc; err != nil {
			return runtime.LogFrame{}, err
		}
		return runtime.LogFrame{}, io.EOF
	}
	return f, nil
}

func (s *logStream) Close() error {
	s.cancel()
	<-s.done
	return nil
}

// followInterval is how often a followed log file is checked for growth.
var followInterval = 200 * time.Millisecond

// ReadLogs returns a container's stored output, oldest first; Tail keeps
// only the last lines, Follow keeps reading new output until the stream is
// closed or ctx ends.
func ReadLogs(ctx context.Context, dir, id string, opts runtime.LogOptions) (runtime.LogStream, error) {
	path, err := LogPath(dir, id)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		return nil, runtime.ErrNotFound
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &logStream{frames: make(chan runtime.LogFrame, 64), errc: make(chan error, 1), cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		err := readLogs(ctx, path, opts, s.frames)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		s.errc <- err
		close(s.frames)
	}()
	return s, nil
}

func readLogs(ctx context.Context, path string, opts runtime.LogOptions, out chan<- runtime.LogFrame) error {
	send := func(e logEntry) error {
		st := runtime.Stdout
		if e.Stream == "stderr" {
			st = runtime.Stderr
		}
		select {
		case out <- runtime.LogFrame{Stream: st, Data: []byte(e.Log)}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	// Rotated files first, oldest first.
	var entries []logEntry
	keep := func(e logEntry) {
		entries = append(entries, e)
		if opts.Tail > 0 && len(entries) > opts.Tail {
			entries = entries[1:]
		}
	}
	for i := runtime.LogMaxFiles - 1; i >= 1; i-- {
		f, err := os.Open(path + "." + strconv.Itoa(i)) //nolint:gosec // path is built from a validated container ID
		if err != nil {
			continue
		}
		_, err = scanEntries(f, keep)
		_ = f.Close()
		if err != nil {
			return err
		}
	}
	f, err := os.Open(path) //nolint:gosec // path is built from a validated container ID
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	off, err := scanEntries(f, keep)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := send(e); err != nil {
			return err
		}
	}
	if !opts.Follow {
		return nil
	}
	t := time.NewTicker(followInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		// A rotation replaces the file: start over on the new one.
		if cur, err := os.Stat(path); err == nil {
			if old, err := f.Stat(); err == nil && !os.SameFile(old, cur) {
				_ = f.Close()
				if f, err = os.Open(path); err != nil { //nolint:gosec // path is built from a validated container ID
					return err
				}
				off = 0
			}
		}
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return err
		}
		n, err := scanEntries(f, func(e logEntry) {
			if err := send(e); err != nil {
				return
			}
		})
		if err != nil {
			return err
		}
		off += n
	}
}

// scanEntries decodes complete lines from r and returns how many bytes they
// took; a trailing partial line is left for the next read.
func scanEntries(r io.Reader, fn func(logEntry)) (int64, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var n int64
	for {
		line, err := br.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		n += int64(len(line))
		var e logEntry
		if json.Unmarshal(line, &e) == nil {
			fn(e)
		}
	}
}
