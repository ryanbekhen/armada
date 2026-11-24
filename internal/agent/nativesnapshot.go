package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"strings"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/volbackup"
)

// Volume backups through armada-node (ADR 0054 step 5, last part):
// armada-node volume snapshot|prune|snapshots|restore-snapshot does what
// volbackup's Backup, Prune, Snapshots, and Restore do, in the same
// repository format, with the request (the bucket's URL and the key
// among it) on its stdin. The agent keeps the per-volume lock, the pause
// and resume of the app, and the session. armada-node prints "touched"
// before it first writes to the bucket or the volume; Go does a call
// itself when armada-node failed (no readable answer) before that, and
// never after.

// snapshotRequest is what armada-node reads on stdin.
type snapshotRequest struct {
	URL      string        `json:"url"`
	Key      []byte        `json:"key"`
	App      string        `json:"app"`
	Volume   string        `json:"volume"`
	Dir      string        `json:"dir,omitempty"`
	Node     string        `json:"node,omitempty"`
	Now      int64         `json:"now,omitempty"`
	Keep     *snapshotKeep `json:"keep,omitempty"`
	Zone     [][2]int64    `json:"zone,omitempty"`
	Snapshot string        `json:"snapshot,omitempty"`
}

type snapshotKeep struct {
	Last    int `json:"last"`
	Hourly  int `json:"hourly"`
	Daily   int `json:"daily"`
	Weekly  int `json:"weekly"`
	Monthly int `json:"monthly"`
}

// nativeSnapshot is a snapshot as armada-node answers it.
type nativeSnapshot struct {
	ID    string `json:"id"`
	Time  string `json:"time"`
	Files int    `json:"files"`
	Bytes int64  `json:"bytes"`
	Node  string `json:"node"`
}

func (s nativeSnapshot) snapshot() (volbackup.Snapshot, error) {
	t, err := time.Parse(time.RFC3339Nano, s.Time)
	if err != nil {
		return volbackup.Snapshot{}, volumeProgramError{errors.New("unreadable time in the answer")}
	}
	return volbackup.Snapshot{ID: s.ID, Time: t, Files: s.Files, Bytes: s.Bytes, Node: s.Node}, nil
}

// zoneTable is loc as armada-node counts days in it: each offset from UTC
// (seconds) and when it starts (Unix seconds), the first one also before.
// It covers 1900 to 2300, past which a snapshot's time is the nearest
// end's offset.
func zoneTable(loc *time.Location) [][2]int64 {
	t := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	_, off := t.In(loc).Zone()
	out := [][2]int64{{math.MinInt64, int64(off)}}
	for len(out) < 4096 {
		_, end := t.In(loc).ZoneBounds()
		if end.IsZero() || end.Year() > 2300 || !end.After(t) {
			break
		}
		t = end
		_, off := t.In(loc).Zone()
		if int64(off) != out[len(out)-1][1] {
			out = append(out, [2]int64{t.Unix(), int64(off)})
		}
	}
	return out
}

func (a *Agent) snapshotRequest(req *armadav1.VolumeRequest) snapshotRequest {
	b := req.GetBackup()
	return snapshotRequest{URL: b.GetUrl(), Key: b.GetKey(), App: req.GetApp(), Volume: req.GetVolume()}
}

// nativeCall is one armada-node volume backup call.
type nativeCall struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	out     *bufio.Reader
	stderr  bytes.Buffer
	touched bool
	done    bool
}

// startSnapshotCall runs armada-node volume OP with req on its stdin.
// Killed with ctx, except a restore, whose stdin is closed instead: it
// stops between entries and removes what it wrote.
func (a *Agent) startSnapshotCall(ctx context.Context, bin, op string, req snapshotRequest) (*nativeCall, error) {
	args := []string{"volume", op}
	if a.volNative.extraCA != "" {
		args = append(args, "--extra-ca", a.volNative.extraCA)
	}
	c := &nativeCall{}
	c.cmd = exec.CommandContext(ctx, bin, args...) //nolint:gosec // the runtime pack's armada-node
	if len(a.volNative.env) > 0 {
		c.cmd.Env = append(os.Environ(), a.volNative.env...)
	}
	c.cmd.Stderr = &c.stderr
	stdin, err := c.cmd.StdinPipe()
	if err != nil {
		return nil, volumeProgramError{err}
	}
	c.stdin = stdin
	if op == "restore-snapshot" {
		c.cmd.Cancel = stdin.Close
		c.cmd.WaitDelay = time.Minute
	}
	out, err := c.cmd.StdoutPipe()
	if err != nil {
		return nil, volumeProgramError{err}
	}
	c.out = bufio.NewReaderSize(out, 64<<10)
	if err := c.cmd.Start(); err != nil {
		return nil, volumeProgramError{err}
	}
	line, err := json.Marshal(req)
	if err == nil {
		_, err = c.stdin.Write(append(line, '\n'))
	}
	if err != nil {
		_ = c.finish()
		return nil, volumeProgramError{err}
	}
	return c, nil
}

// next reads armada-node's lines up to an answer (JSON) or, in a restore,
// "ready ID"; "touched" lines are noted on the way. A call that ends
// without either fails.
func (c *nativeCall) next() (ready string, answer []byte, err error) {
	for {
		line, rerr := c.out.ReadString('\n')
		line = strings.TrimSuffix(line, "\n")
		switch {
		case line == "touched":
			c.touched = true
			continue
		case strings.HasPrefix(line, "ready ") && rerr == nil:
			return strings.TrimPrefix(line, "ready "), nil, nil
		case strings.HasPrefix(line, "{") && rerr == nil:
			return "", []byte(line), nil
		}
		werr := c.finish()
		return "", nil, programFailed("no answer", werr, &c.stderr)
	}
}

// finish ends the call.
func (c *nativeCall) finish() error {
	if c.done {
		return nil
	}
	c.done = true
	_ = c.stdin.Close()
	_, _ = io.Copy(io.Discard, c.out)
	return c.cmd.Wait()
}

// call runs a call with no handshake and decodes its answer into v; an
// answered error is returned as Go's.
func (a *Agent) snapshotCall(ctx context.Context, bin, op string, req snapshotRequest, v any) (touched bool, err error) {
	c, err := a.startSnapshotCall(ctx, bin, op, req)
	if err != nil {
		return false, err
	}
	_, ans, err := c.next()
	if err != nil {
		return c.touched, ctxErr(ctx, err)
	}
	werr := c.finish()
	if ans == nil {
		return c.touched, programFailed("no answer", werr, &c.stderr)
	}
	return c.touched, decodeAnswer(ans, v)
}

// ctxErr is the caller's context error when it ended the call.
func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// decodeAnswer reads an answer into v, or its error.
func decodeAnswer(ans []byte, v any) error {
	var e struct {
		Error   *string `json:"error"`
		Changed bool    `json:"changed"`
	}
	if json.Unmarshal(ans, &e) != nil {
		return volumeProgramError{errors.New("unreadable answer")}
	}
	if e.Error != nil {
		return &answeredError{text: *e.Error, changed: e.Changed}
	}
	if v != nil && json.Unmarshal(ans, v) != nil {
		return volumeProgramError{errors.New("unreadable answer")}
	}
	return nil
}

// backupSnapshot is Backup: armada-node's, or Go's when it failed before
// writing.
func (a *Agent) backupSnapshot(ctx context.Context, req *armadav1.VolumeRequest, dir string, now time.Time) (volbackup.Snapshot, volbackup.Stats, error) {
	if bin := a.volumeProgram(); bin != "" {
		r := a.snapshotRequest(req)
		r.Dir, r.Node, r.Now = dir, a.cfg.NodeID, now.UnixNano()
		var ans struct {
			Snapshot nativeSnapshot `json:"snapshot"`
			NewBytes int64          `json:"newBytes"`
			Uploaded int64          `json:"uploaded"`
		}
		touched, err := a.snapshotCall(ctx, bin, "snapshot", r, &ans)
		var snap volbackup.Snapshot
		if err == nil {
			snap, err = ans.Snapshot.snapshot()
		}
		if !a.volNative.fallback(a.log, "snapshot", err, !touched) {
			if err != nil {
				return volbackup.Snapshot{}, volbackup.Stats{}, err
			}
			return snap, volbackup.Stats{NewBytes: ans.NewBytes, Uploaded: ans.Uploaded}, nil
		}
	}
	return a.goBackup(ctx, req, dir, now)
}

// pruneSnapshots is Prune.
func (a *Agent) pruneSnapshots(ctx context.Context, req *armadav1.VolumeRequest, now time.Time) (volbackup.Usage, error) {
	if bin := a.volumeProgram(); bin != "" {
		keep, loc := backupKeep(req)
		r := a.snapshotRequest(req)
		r.Now = now.UnixNano()
		r.Keep = &snapshotKeep{Last: keep.Last, Hourly: keep.Hourly, Daily: keep.Daily, Weekly: keep.Weekly, Monthly: keep.Monthly}
		r.Zone = zoneTable(loc)
		var ans struct {
			Snapshots        int     `json:"snapshots"`
			Stored           int64   `json:"stored"`
			DeletedSnapshots int     `json:"deletedSnapshots"`
			DeletedChunks    int     `json:"deletedChunks"`
			Error            *string `json:"error"`
		}
		c, err := a.startSnapshotCall(ctx, bin, "prune", r)
		touched := false
		if err == nil {
			var b []byte
			_, b, err = c.next()
			touched = c.touched
			if err == nil {
				_ = c.finish()
				if json.Unmarshal(b, &ans) != nil {
					err = volumeProgramError{errors.New("unreadable answer")}
				}
			} else {
				err = ctxErr(ctx, err)
			}
		}
		if !a.volNative.fallback(a.log, "prune", err, !touched) {
			u := volbackup.Usage{Snapshots: ans.Snapshots, Stored: ans.Stored, DeletedSnapshots: ans.DeletedSnapshots, DeletedChunks: ans.DeletedChunks}
			if err == nil && ans.Error != nil {
				err = &answeredError{text: *ans.Error}
			}
			return u, err
		}
	}
	return a.goPrune(ctx, req, now)
}

// listSnapshots is Snapshots.
func (a *Agent) listSnapshots(ctx context.Context, req *armadav1.VolumeRequest) ([]volbackup.Snapshot, error) {
	if bin := a.volumeProgram(); bin != "" {
		var ans struct {
			Snapshots []nativeSnapshot `json:"snapshots"`
		}
		touched, err := a.snapshotCall(ctx, bin, "snapshots", a.snapshotRequest(req), &ans)
		var out []volbackup.Snapshot
		for _, s := range ans.Snapshots {
			if err != nil {
				break
			}
			var snap volbackup.Snapshot
			if snap, err = s.snapshot(); err == nil {
				out = append(out, snap)
			}
		}
		if !a.volNative.fallback(a.log, "snapshots", err, !touched) {
			if err != nil {
				return nil, err
			}
			return out, nil
		}
	}
	return a.goSnapshots(ctx, req)
}

// restoreSnapshot resolves latest, pauses the app, and restores: through
// armada-node, which says which snapshot it restores before the agent
// pauses the app, or through Go when armada-node failed before then.
func (a *Agent) restoreSnapshot(ctx context.Context, req *armadav1.VolumeRequest, dir string) (volbackup.Snapshot, error) {
	bin := a.volumeProgram()
	if bin == "" {
		return a.goRestore(ctx, req, dir)
	}
	r := a.snapshotRequest(req)
	r.Dir, r.Snapshot = dir, req.GetSnapshot()
	c, err := a.startSnapshotCall(ctx, bin, "restore-snapshot", r)
	var id string
	var ans []byte
	if err == nil {
		id, ans, err = c.next()
	}
	if err == nil && ans != nil {
		// An error before the snapshot was found: Go's, answered.
		_ = c.finish()
		err = decodeAnswer(ans, nil)
		if err == nil {
			err = volumeProgramError{errors.New("an answer before ready")}
		}
	}
	touched := c != nil && c.touched
	if err != nil {
		if a.volNative.fallback(a.log, "restore-snapshot", err, !touched) {
			return a.goRestore(ctx, req, dir)
		}
		return volbackup.Snapshot{}, err
	}
	if err := a.pause(ctx, req.GetApp()); err != nil {
		_ = c.finish()
		return volbackup.Snapshot{}, err
	}
	defer a.resume(req.GetApp())
	if _, err := io.WriteString(c.stdin, "go\n"); err != nil {
		err = programFailed("go", err, &c.stderr)
		_ = c.finish()
		return a.restoreAfterReady(ctx, req, dir, id, c.touched, err)
	}
	var res struct {
		Snapshot nativeSnapshot `json:"snapshot"`
	}
	_, ans, err = c.next()
	if err == nil {
		_ = c.finish()
		err = decodeAnswer(ans, &res)
	} else {
		err = ctxErr(ctx, err)
	}
	var snap volbackup.Snapshot
	if err == nil {
		snap, err = res.Snapshot.snapshot()
	}
	if err != nil {
		return a.restoreAfterReady(ctx, req, dir, id, c.touched, err)
	}
	a.volNative.fallback(a.log, "restore-snapshot", nil, false)
	return snap, nil
}

// restoreAfterReady is a restore armada-node failed once the app was
// paused: Go restores snapshot id when nothing was touched yet.
func (a *Agent) restoreAfterReady(ctx context.Context, req *armadav1.VolumeRequest, dir, id string, touched bool, err error) (volbackup.Snapshot, error) {
	if !a.volNative.fallback(a.log, "restore-snapshot", err, !touched) {
		return volbackup.Snapshot{}, err
	}
	repo, err := a.openRepo(ctx, req)
	if err != nil {
		return volbackup.Snapshot{}, err
	}
	return goRestoreInto(ctx, repo, dir, id)
}
