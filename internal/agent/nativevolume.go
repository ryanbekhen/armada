package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/ryanbekhen/armada/internal/volbackup"
)

// Volume archives through armada-node (ADR 0054 step 5, second part):
// armada-node volume archive|restore|size does what writeArchive,
// restoreArchive, and volumeSize do, with the archive on its standard
// streams; the agent keeps the session, the pause, and the 64 KiB
// messages. Go does a call itself when armada-node fails before the
// session's stream is touched: an archive armada-node failed before
// writing a byte, a restore it failed before Go handed it a byte of the
// stream (it says "ready" before reading), or a size. Once bytes went
// out, or came in from the session, they cannot be had again, so a later
// failure is the call's error.

// volumeAnswerLimit bounds what the agent reads of an answer: an error
// quoting a long entry name, at most.
const volumeAnswerLimit = 4 << 20

// volumeProgramError is armada-node failing to do a call: it did not
// run, or gave no answer that could be read. Errors it answered with are
// plain.
type volumeProgramError struct{ err error }

func (e volumeProgramError) Error() string { return "armada-node: " + e.err.Error() }
func (e volumeProgramError) Unwrap() error { return e.err }

// answeredError is an error armada-node answered with: Go's text, and
// whether it is volbackup.ErrChanged.
type answeredError struct {
	text    string
	changed bool
}

func (e *answeredError) Error() string { return e.text }

func (e *answeredError) Is(target error) bool {
	return e.changed && target == volbackup.ErrChanged
}

// volumeNative logs each distinct failure of armada-node once per call
// kind and counts the calls Go did instead and those armada-node did.
type volumeNative struct {
	mu    sync.Mutex
	errs  map[string]string
	stood map[string]int
	ran   map[string]int
	// extraCA and env reach tests' buckets (armada-node's --extra-ca and
	// ARMADA_NODE_TEST_BUCKET_ADDR); nodes never set them.
	extraCA string
	env     []string
}

// program is armada-node's path, or "" for Go's code.
func (a *Agent) volumeProgram() string {
	if a.cfg.VolumeProgram == nil {
		return ""
	}
	return a.cfg.VolumeProgram()
}

// fallback reports whether err is armada-node failing (op names the
// call), logging each distinct failure once and a recovery once; redo
// says whether Go does a failed call itself.
func (n *volumeNative) fallback(log *slog.Logger, op string, err error, redo bool) bool {
	var perr volumeProgramError
	failed := errors.As(err, &perr)
	msg := ""
	if failed {
		msg = err.Error()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.errs == nil {
		n.errs, n.stood, n.ran = map[string]string{}, map[string]int{}, map[string]int{}
	}
	prev, seen := n.errs[op]
	n.errs[op] = msg
	switch {
	case failed && redo:
		n.stood[op]++
	case !failed:
		n.ran[op]++
	}
	switch {
	case !failed && seen && prev != "":
		log.Info("armada-node works again", "op", "volume "+op)
	case failed && (!seen || prev != msg) && redo:
		log.Warn("armada-node failed; Go did it instead", "op", "volume "+op, "err", err)
	case failed && (!seen || prev != msg):
		log.Warn("armada-node failed", "op", "volume "+op, "err", err)
	}
	return failed && redo
}

// StoodIn is how many calls of op ("archive", "restore", "size",
// "snapshot", "prune", "snapshots", "restore-snapshot") Go did
// after armada-node failed them; Ran, how many armada-node did.
func (n *volumeNative) StoodIn(op string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.stood[op]
}

func (n *volumeNative) Ran(op string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.ran[op]
}

// archiveVolume writes dir's archive to w (writeArchive).
func (a *Agent) archiveVolume(ctx context.Context, dir string, w io.Writer) error {
	if bin := a.volumeProgram(); bin != "" {
		wrote, err := nativeArchive(ctx, bin, dir, w)
		if !a.volNative.fallback(a.log, "archive", err, !wrote) {
			if errors.As(err, new(volumeProgramError)) {
				err = fmt.Errorf("archive volume: %w", err)
			}
			return err
		}
	}
	return writeArchive(ctx, dir, w)
}

// restoreVolume replaces dir's contents with the gzipped tar r
// (restoreArchive).
func (a *Agent) restoreVolume(dir string, r io.Reader) error {
	if bin := a.volumeProgram(); bin != "" {
		fed, err := nativeRestore(bin, dir, r)
		if !a.volNative.fallback(a.log, "restore", err, !fed) {
			return err
		}
	}
	return restoreArchive(dir, r)
}

// volumeSizes measures every dir (volumeSize).
func (a *Agent) volumeSizes(ctx context.Context, dirs []string) []int64 {
	if bin := a.volumeProgram(); bin != "" && len(dirs) > 0 {
		sizes, err := nativeSizes(ctx, bin, dirs)
		a.volNative.fallback(a.log, "size", err, true)
		if err == nil {
			return sizes
		}
	}
	out := make([]int64, len(dirs))
	for i, d := range dirs {
		out[i] = volumeSize(ctx, d)
	}
	return out
}

// countWriter counts what reached w.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// readAnswer reads what armada-node answers on a pipe, bounded, then
// drains it so the program never blocks on it.
func readAnswer(r io.Reader) []byte {
	b, _ := io.ReadAll(io.LimitReader(r, volumeAnswerLimit))
	_, _ = io.Copy(io.Discard, r)
	return b
}

// programFailed words a call armada-node failed: its exit, its last
// stderr line, and what was missing.
func programFailed(what string, werr error, stderr *bytes.Buffer) error {
	msg := what
	if werr != nil {
		msg += ": " + werr.Error()
	}
	if s := strings.TrimSpace(stderr.String()); s != "" {
		msg += ": " + s
	}
	return volumeProgramError{errors.New(msg)}
}

// nativeArchive runs armada-node volume archive DIR, copying its stdout
// to w; wrote says whether any byte reached w.
func nativeArchive(ctx context.Context, bin, dir string, w io.Writer) (wrote bool, err error) {
	ar, aw, err := os.Pipe()
	if err != nil {
		return false, volumeProgramError{err}
	}
	defer ar.Close()
	cmd := exec.CommandContext(ctx, bin, "volume", "archive", dir) //nolint:gosec // the runtime pack's armada-node
	cmd.ExtraFiles = []*os.File{aw}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		_ = aw.Close()
		return false, volumeProgramError{err}
	}
	if err := cmd.Start(); err != nil {
		_ = aw.Close()
		return false, volumeProgramError{err}
	}
	_ = aw.Close()
	answer := make(chan []byte, 1)
	go func() { answer <- readAnswer(ar) }()

	cw := &countWriter{w: w}
	var writeErr error
	buf := make([]byte, VolumeChunk)
	for {
		n, rerr := out.Read(buf)
		if n > 0 && writeErr == nil {
			if _, err := cw.Write(buf[:n]); err != nil {
				writeErr = err
				_ = cmd.Process.Kill()
			}
		}
		if rerr != nil {
			break
		}
	}
	werr := cmd.Wait()
	b := <-answer
	wrote = cw.n > 0
	switch {
	case writeErr != nil:
		return wrote, fmt.Errorf("archive volume: %w", writeErr)
	case ctx.Err() != nil:
		return wrote, fmt.Errorf("archive volume: %w", ctx.Err())
	}
	var ans struct {
		Error   *string `json:"error"`
		Changed bool    `json:"changed"`
	}
	if len(b) == 0 || json.Unmarshal(b, &ans) != nil {
		return wrote, programFailed("no answer", werr, &stderr)
	}
	if ans.Error != nil {
		return wrote, &answeredError{text: *ans.Error, changed: ans.Changed}
	}
	return wrote, nil
}

// nativeRestore runs armada-node volume restore DIR, handing it r once it
// is ready; fed says whether any byte of r was read.
func nativeRestore(bin, dir string, r io.Reader) (fed bool, err error) {
	ar, aw, err := os.Pipe()
	if err != nil {
		return false, volumeProgramError{err}
	}
	defer ar.Close()
	br, bw, err := os.Pipe()
	if err != nil {
		_ = aw.Close()
		return false, volumeProgramError{err}
	}
	// Not killed with the caller's context: the restore ends when its
	// input does, removing what it wrote, and the session's end is such
	// an error (written on descriptor 4).
	cmd := exec.Command(bin, "volume", "restore", dir) //nolint:gosec,noctx // the runtime pack's armada-node
	cmd.ExtraFiles = []*os.File{aw, br}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err == nil {
		err = cmd.Start()
	}
	_ = aw.Close()
	_ = br.Close()
	if err != nil {
		_ = bw.Close()
		return false, volumeProgramError{err}
	}
	ans := bufio.NewReader(ar)
	if line, _ := ans.ReadString('\n'); line != "ready\n" {
		_ = cmd.Process.Kill()
		_ = bw.Close()
		_ = stdin.Close()
		werr := cmd.Wait()
		return false, programFailed("not ready", werr, &stderr)
	}
	answer := make(chan []byte, 1)
	go func() { answer <- readAnswer(ans) }()

	var readErr error
	buf := make([]byte, VolumeChunk)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			fed = true
			if _, werr := stdin.Write(buf[:n]); werr != nil {
				break // it stopped reading: its answer says why
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			readErr = err
			break
		}
	}
	if readErr != nil {
		msg, _ := json.Marshal(readErr.Error())
		_, _ = bw.Write(msg)
	}
	// Descriptor 4 first: armada-node reads it once stdin ends.
	_ = bw.Close()
	_ = stdin.Close()
	werr := cmd.Wait()
	b := <-answer
	var res struct {
		Error *string `json:"error"`
	}
	if len(b) == 0 || json.Unmarshal(b, &res) != nil {
		return fed, programFailed("no answer", werr, &stderr)
	}
	if res.Error != nil {
		return fed, errors.New(*res.Error)
	}
	return fed, nil
}

// nativeSizes runs armada-node volume size DIR....
func nativeSizes(ctx context.Context, bin string, dirs []string) ([]int64, error) {
	cmd := exec.CommandContext(ctx, bin, append([]string{"volume", "size"}, dirs...)...) //nolint:gosec // the runtime pack's armada-node
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, programFailed("size", err, &stderr)
	}
	var ans struct {
		Sizes []int64 `json:"sizes"`
	}
	if json.Unmarshal(out, &ans) != nil || len(ans.Sizes) != len(dirs) {
		return nil, programFailed("unreadable answer", nil, &stderr)
	}
	return ans.Sizes, nil
}
