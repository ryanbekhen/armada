package agent

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/spec"
)

// Volumes (ADR 0025).
const (
	// VolumeChunk is the most archive data one VolumeData message carries.
	VolumeChunk = 64 << 10
	// maxVolumeSessions bounds the backups, restores, and removals an agent
	// runs at once.
	maxVolumeSessions = 2
	// volumeStopGrace is how long an app's container gets to stop before a
	// backup or restore.
	volumeStopGrace = 30 * time.Second
	// volumeMeasureEvery is how often the agent measures its volumes.
	volumeMeasureEvery = time.Minute
	// pausedMessage is what a replica stopped for a volume operation reports.
	pausedMessage = "stopped while its volume is backed up or restored"
)

// mountsVolumes reports whether this node can hold volumes.
func (a *Agent) mountsVolumes() bool {
	return a.cfg.VolumesDir != "" && runtime.CanMountVolumes(a.cfg.Driver)
}

// volumeDir is where volume name of app lives on this node. Both names are
// checked here, so a path from the server can never leave VolumesDir.
func (a *Agent) volumeDir(app, name string) (string, error) {
	if a.cfg.VolumesDir == "" {
		return "", errors.New("this node has no volume directory")
	}
	if !spec.ValidName(app) || !spec.ValidName(name) {
		return "", fmt.Errorf("invalid volume name %q of app %q", name, app)
	}
	return filepath.Join(a.cfg.VolumesDir, app, name), nil
}

// prepareVolumes creates a replica's volume directories on first use and
// returns their mounts.
func (a *Agent) prepareVolumes(s *armadav1.ReplicaSpec) ([]runtime.VolumeMount, error) {
	if len(s.GetVolumes()) == 0 {
		return nil, nil
	}
	if !a.mountsVolumes() {
		return nil, errors.New("this node cannot mount volumes")
	}
	out := make([]runtime.VolumeMount, 0, len(s.GetVolumes()))
	for _, v := range s.GetVolumes() {
		dir, err := a.volumeDir(s.GetApp(), v.GetName())
		if err != nil {
			return nil, err
		}
		if err := spec.ValidateVolumePath(v.GetPath()); err != nil {
			return nil, fmt.Errorf("volume %s: path: %w", v.GetName(), err)
		}
		if err := ensureVolume(dir, v.GetOwner()); err != nil {
			return nil, fmt.Errorf("volume %s: %w", v.GetName(), err)
		}
		out = append(out, runtime.VolumeMount{Source: dir, Target: v.GetPath()})
	}
	return out, nil
}

// ensureVolume creates dir (mode 0700) unless it exists, and gives it to
// owner if one is set, so an owner added to the spec later applies too. An
// existing dir must be a directory, not a link. Its contents are left
// alone.
func ensureVolume(dir, owner string) error {
	if err := fsutil.MkdirPrivate(filepath.Dir(dir)); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	switch {
	case err == nil && fi.IsDir():
		return chownVolume(dir, owner)
	case err == nil:
		return fmt.Errorf("%s is not a directory", dir)
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	return chownVolume(dir, owner)
}

func chownVolume(dir, owner string) error {
	return chownVolumeAs(dir, owner, os.Geteuid())
}

// chownVolumeAs gives dir to owner when the agent runs as root (euid 0).
// An agent run by a user (macOS nodes, ADR 0016) cannot give files away;
// there the driver's file sharing decides who owns them in the container.
func chownVolumeAs(dir, owner string, euid int) error {
	if owner == "" || euid != 0 {
		return nil
	}
	uid, gid, err := spec.ParseOwner(owner)
	if err != nil {
		return err
	}
	return os.Lchown(dir, uid, gid)
}

// pause stops app's containers on this node and keeps Reconcile from
// starting them again until resume.
func (a *Agent) pause(ctx context.Context, app string) error {
	a.reconcileMu.Lock()
	defer a.reconcileMu.Unlock()
	a.mu.Lock()
	a.paused[app]++
	a.mu.Unlock()
	cs, err := a.cfg.Driver.List(ctx, map[string]string{runtime.LabelManaged: "true", runtime.LabelApp: app})
	if err != nil {
		a.resume(app)
		return err
	}
	for _, c := range cs {
		if stopped(c.State) {
			continue
		}
		if err := a.cfg.Driver.Stop(ctx, c.ID, volumeStopGrace); err != nil {
			a.resume(app)
			return fmt.Errorf("stop %s: %w", c.Name, err)
		}
	}
	return nil
}

// resume lets Reconcile start app's containers again. Those stopped for
// the operation are recreated at once, not as crashes with backoff.
func (a *Agent) resume(app string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, _ := a.cfg.Driver.List(ctx, map[string]string{runtime.LabelManaged: "true", runtime.LabelApp: app})
	a.mu.Lock()
	if a.paused[app]--; a.paused[app] <= 0 {
		delete(a.paused, app)
		for _, c := range cs {
			if stopped(c.State) {
				a.restarts[c.ID] = "stopped for a volume backup or restore"
			}
		}
	}
	a.mu.Unlock()
	a.Trigger()
}

func (a *Agent) isPaused(app string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.paused[app] > 0
}

// serveVolume runs one volume request: it opens the session stream, then
// backs the volume up, restores it, or removes it. Errors go back to the
// server on the stream.
func (a *Agent) serveVolume(ctx context.Context, req *armadav1.VolumeRequest) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := a.cfg.Client.VolumeSession(ctx)
	if err != nil {
		a.log.Warn("open volume stream failed", "err", err)
		return
	}
	first := true
	send := func(m *armadav1.VolumeData) error {
		if first {
			m.RequestId, first = req.GetRequestId(), false
		}
		return stream.Send(m)
	}
	finish := func(err error) {
		m := &armadav1.VolumeData{Done: err == nil}
		if err != nil {
			m.Error = err.Error()
		}
		_ = send(m)
		_ = stream.CloseSend()
		// Wait for the server to end the session, so the last message is
		// delivered before the stream is cancelled.
		for {
			if _, err := stream.Recv(); err != nil {
				return
			}
		}
	}

	if n := a.volumeOps.Add(1); n > maxVolumeSessions {
		a.volumeOps.Add(-1)
		finish(errors.New("this node is already busy with other volume backups or restores"))
		return
	}
	defer a.volumeOps.Add(-1)
	dir, err := a.volumeDir(req.GetApp(), req.GetVolume())
	if err != nil {
		finish(err)
		return
	}
	a.log.Info("volume operation", "op", req.GetOp().String(), "app", req.GetApp(), "volume", req.GetVolume())
	switch req.GetOp() {
	case armadav1.VolumeRequest_OP_BACKUP:
		if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
			finish(fmt.Errorf("volume %s of %s does not exist on this node", req.GetVolume(), req.GetApp()))
			return
		}
		if req.GetStop() {
			if err := a.pause(ctx, req.GetApp()); err != nil {
				finish(err)
				return
			}
			defer a.resume(req.GetApp())
		}
		if err := send(&armadav1.VolumeData{}); err != nil { // attaches the session
			return
		}
		finish(writeArchive(ctx, dir, &chunkWriter{send: send}))
	case armadav1.VolumeRequest_OP_RESTORE:
		if err := a.pause(ctx, req.GetApp()); err != nil {
			finish(err)
			return
		}
		defer a.resume(req.GetApp())
		if err := send(&armadav1.VolumeData{}); err != nil {
			return
		}
		finish(restoreArchive(dir, &chunkReader{recv: stream.Recv}))
	case armadav1.VolumeRequest_OP_REMOVE:
		if a.volumeUsed(req.GetApp(), req.GetVolume()) {
			finish(fmt.Errorf("a replica on this node still uses volume %s of %s", req.GetVolume(), req.GetApp()))
			return
		}
		finish(os.RemoveAll(dir))
	default:
		finish(errors.New("unknown volume operation"))
	}
}

// volumeUsed reports whether a replica assigned to this node mounts the
// volume.
func (a *Agent) volumeUsed(app, name string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.desired {
		if s.GetApp() != app {
			continue
		}
		for _, v := range s.GetVolumes() {
			if v.GetName() == name {
				return true
			}
		}
	}
	return false
}

// chunkWriter sends what is written as VolumeData messages of at most
// VolumeChunk bytes.
type chunkWriter struct {
	send func(*armadav1.VolumeData) error
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		c := p[:min(len(p), VolumeChunk)]
		if err := w.send(&armadav1.VolumeData{Data: append([]byte(nil), c...)}); err != nil {
			return n, err
		}
		n += len(c)
		p = p[len(c):]
	}
	return n, nil
}

// chunkReader reads VolumeData messages until one marks the end.
type chunkReader struct {
	recv func() (*armadav1.VolumeData, error)
	buf  []byte
	end  bool
}

func (r *chunkReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.end {
			return 0, io.EOF
		}
		m, err := r.recv()
		if err != nil {
			return 0, fmt.Errorf("receive archive: %w", err)
		}
		if m.GetError() != "" {
			return 0, errors.New(m.GetError())
		}
		if len(m.GetData()) > VolumeChunk {
			return 0, errors.New("archive chunk too large")
		}
		r.buf, r.end = m.GetData(), m.GetDone()
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// writeArchive writes dir as a gzipped tar: "." for the directory itself,
// then its contents with relative names. Links are stored, never followed;
// sockets, devices, and pipes are left out.
func writeArchive(ctx context.Context, dir string, w io.Writer) error {
	zw := gzip.NewWriter(w)
	tw := tar.NewWriter(zw)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		mode := fi.Mode()
		if !mode.IsDir() && !mode.IsRegular() && mode&fs.ModeSymlink == 0 {
			return nil
		}
		link := ""
		if mode&fs.ModeSymlink != 0 {
			if link, err = os.Readlink(p); err != nil {
				return err
			}
		}
		hdr, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if mode.IsDir() && rel != "." {
			hdr.Name += "/"
		}
		hdr.Uname, hdr.Gname = "", ""
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !mode.IsRegular() {
			return nil
		}
		f, err := os.Open(p) //nolint:gosec // walking the volume's own directory
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.CopyN(tw, f, hdr.Size)
		return err
	})
	if err != nil {
		return fmt.Errorf("archive volume: %w", err)
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return zw.Close()
}

// restoreArchive replaces dir's contents with a gzipped tar from r. The
// archive goes into a new directory next to dir first, so a failure leaves
// the volume as it was. Entries may only be directories, regular files, and
// links, with relative names that stay inside the volume; no entry is
// written through a link.
func restoreArchive(dir string, r io.Reader) error {
	if err := fsutil.MkdirPrivate(filepath.Dir(dir)); err != nil {
		return err
	}
	tmp := dir + ".restore-" + randomSuffix()
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	zr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("read archive: %w", err)
	}
	tr := tar.NewReader(zr)
	type dirTime struct {
		path string
		t    time.Time
	}
	var dirs []dirTime
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read archive: %w", err)
		}
		target, err := archivePath(tmp, hdr.Name)
		if err != nil {
			return err
		}
		mode := hdr.FileInfo().Mode() & (fs.ModePerm | fs.ModeSticky)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if target != tmp {
				if err := os.Mkdir(target, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
					return err
				}
			}
			if fi, err := os.Lstat(target); err != nil || !fi.IsDir() {
				return fmt.Errorf("archive entry %q is not a directory", hdr.Name)
			}
			dirs = append(dirs, dirTime{target, hdr.ModTime})
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY|noFollow, 0o600) //nolint:gosec // checked by archivePath
			if err != nil {
				return fmt.Errorf("archive entry %q: %w", hdr.Name, err)
			}
			_, err = io.CopyN(f, tr, hdr.Size)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return fmt.Errorf("archive entry %q: %w", hdr.Name, err)
			}
			if err := os.Chtimes(target, hdr.ModTime, hdr.ModTime); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return fmt.Errorf("archive entry %q: %w", hdr.Name, err)
			}
		default:
			return fmt.Errorf("archive entry %q: only directories, regular files, and links can be restored", hdr.Name)
		}
		if err := os.Lchown(target, hdr.Uid, hdr.Gid); err != nil {
			return fmt.Errorf("archive entry %q: %w", hdr.Name, err)
		}
		if hdr.Typeflag != tar.TypeSymlink {
			// After the owner: chown clears setuid and setgid, which are
			// left out anyway.
			if err := os.Chmod(target, mode); err != nil {
				return err
			}
		}
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		_ = os.Chtimes(dirs[i].path, dirs[i].t, dirs[i].t)
	}
	old := dir + ".old-" + randomSuffix()
	if err := os.Rename(dir, old); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmp, dir); err != nil {
		_ = os.Rename(old, dir)
		return err
	}
	ok = true
	return os.RemoveAll(old)
}

// archivePath resolves an archive entry name inside root: relative, clean,
// staying inside root, and with every parent an existing directory rather
// than a link.
func archivePath(root, name string) (string, error) {
	clean := path.Clean(strings.TrimSuffix(name, "/"))
	if clean == "." {
		return root, nil
	}
	if name == "" || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("archive entry %q is outside the volume", name)
	}
	parts := strings.Split(clean, "/")
	cur := root
	for _, p := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, p)
		fi, err := os.Lstat(cur)
		if err != nil || !fi.IsDir() {
			return "", fmt.Errorf("archive entry %q: %s is not a directory", name, p)
		}
	}
	return filepath.Join(cur, parts[len(parts)-1]), nil
}

func randomSuffix() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// measureVolumes adds up the size of every volume on this node. Links are
// not followed.
func (a *Agent) measureVolumes(ctx context.Context) []*armadav1.VolumeUsage {
	root := a.cfg.VolumesDir
	apps, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []*armadav1.VolumeUsage
	for _, app := range apps {
		if !app.IsDir() || !spec.ValidName(app.Name()) {
			continue
		}
		vols, err := os.ReadDir(filepath.Join(root, app.Name()))
		if err != nil {
			continue
		}
		for _, v := range vols {
			if !v.IsDir() || !spec.ValidName(v.Name()) {
				continue // leftovers of a restore, among others
			}
			var size int64
			_ = filepath.WalkDir(filepath.Join(root, app.Name(), v.Name()), func(_ string, d fs.DirEntry, err error) error {
				if err != nil || ctx.Err() != nil {
					return ctx.Err()
				}
				if fi, err := d.Info(); err == nil && fi.Mode().IsRegular() {
					size += fi.Size()
				}
				return nil
			})
			out = append(out, &armadav1.VolumeUsage{App: app.Name(), Volume: v.Name(), Bytes: size})
		}
	}
	return out
}
