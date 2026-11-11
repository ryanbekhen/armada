package volbackup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/ryanbekhen/armada/internal/spec"
)

// Repository layout under its root (<prefix><app ID>/<volume>/).
const (
	configKey    = "config"
	chunksDir    = "chunks/"
	snapshotsDir = "snapshots/"
	repoVersion  = 1
	// maxConfig, maxManifest, and maxSealedChunk bound what is read back.
	maxConfig      = 4 << 10
	maxManifest    = 512 << 20
	maxSealedChunk = maxChunk + maxChunk/8 + 1024
	// chunkGrace keeps unreferenced chunks this young: a backup running
	// elsewhere may be about to name them.
	chunkGrace = time.Hour
	// snapshotTime starts a snapshot's ID, so IDs sort by time.
	snapshotTime = "20060102T150405.000Z"
	// uploads is how many chunks are written at once.
	uploads = 4
)

var (
	chunkRe    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	snapshotRe = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{3}Z-[0-9a-f]{8}$`)
)

// Repo is one volume's backup repository.
type Repo struct {
	obj  Objects
	root string
	k    *keys
}

type repoConfig struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Check   string `json:"check"`
}

// Root is where a volume's repository lives in the bucket.
func Root(t Target, app, volume string) string {
	return t.Prefix + app + "/" + volume + "/"
}

// Open opens the repository at root, creating it when the bucket has none
// there. A wrong key is an error that says so.
func Open(ctx context.Context, obj Objects, root string, secret []byte) (*Repo, error) {
	var cfg repoConfig
	b, err := obj.Get(ctx, root+configKey, maxConfig)
	switch {
	case errors.Is(err, ErrNotExist):
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			return nil, err
		}
		cfg = repoConfig{Version: repoVersion, ID: hex.EncodeToString(id)}
		k, err := deriveKeys(secret, id)
		if err != nil {
			return nil, err
		}
		cfg.Check = k.check
		data, err := json.Marshal(cfg)
		if err != nil {
			return nil, err
		}
		if err := obj.Put(ctx, root+configKey, data); err != nil {
			return nil, err
		}
		return &Repo{obj: obj, root: root, k: k}, nil
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, errors.New("the backup repository's config is damaged")
	}
	if cfg.Version != repoVersion {
		return nil, fmt.Errorf("the backup repository has version %d; this Armada reads version %d", cfg.Version, repoVersion)
	}
	id, err := hex.DecodeString(cfg.ID)
	if err != nil || len(id) != 16 {
		return nil, errors.New("the backup repository's config is damaged")
	}
	k, err := deriveKeys(secret, id)
	if err != nil {
		return nil, err
	}
	if k.check != cfg.Check {
		return nil, errors.New("the backup key does not match the one this volume's backups were made with")
	}
	return &Repo{obj: obj, root: root, k: k}, nil
}

// Entry is one file, directory, or link of a snapshot.
type Entry struct {
	// Path is relative to the volume, "/"-separated; "." is the volume.
	Path string `json:"p"`
	// Type is 'd', 'f', or 'l'.
	Type    string   `json:"t"`
	Mode    uint32   `json:"m"`
	UID     int      `json:"u"`
	GID     int      `json:"g"`
	ModTime int64    `json:"mt"` // Unix nanoseconds
	Size    int64    `json:"s,omitempty"`
	Target  string   `json:"l,omitempty"`
	Chunks  []string `json:"c,omitempty"`
}

type manifest struct {
	Version int       `json:"version"`
	Time    time.Time `json:"time"`
	Node    string    `json:"node"`
	Files   int       `json:"files"`
	Bytes   int64     `json:"bytes"`
	Entries []Entry   `json:"entries"`
}

// Snapshot is one backup.
type Snapshot struct {
	ID   string
	Time time.Time
	// Files and Bytes are known after a backup or when the snapshot was
	// read.
	Files int
	Bytes int64
}

// Stats says what a backup did.
type Stats struct {
	// NewBytes is the content no earlier backup had; Uploaded what that
	// took in the bucket.
	NewBytes int64
	Uploaded int64
}

// Backup writes a snapshot of dir. Chunks the repository has are not
// written again; the snapshot is written last, so a failed backup leaves
// only chunks the next one reuses.
func (r *Repo) Backup(ctx context.Context, dir, node string, now time.Time) (Snapshot, Stats, error) {
	have := map[string]bool{}
	err := r.obj.List(ctx, r.root+chunksDir, func(o Object) error {
		if id := path.Base(o.Key); chunkRe.MatchString(id) {
			have[id] = true
		}
		return nil
	})
	if err != nil {
		return Snapshot{}, Stats{}, err
	}
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1))
	if err != nil {
		return Snapshot{}, Stats{}, err
	}
	defer enc.Close()

	up := newUploader(ctx, r)
	var st Stats
	m := manifest{Version: repoVersion, Time: now.UTC(), Node: node}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Snapshot{}, Stats{}, err
	}
	defer root.Close()
	walkErr := fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := up.failed(); err != nil {
			return err
		}
		fi, err := root.Lstat(p)
		if err != nil {
			return err
		}
		mode := fi.Mode()
		e := Entry{Path: p, Mode: uint32(mode.Perm() | mode&fs.ModeSticky), ModTime: fi.ModTime().UnixNano()}
		e.UID, e.GID = owner(fi)
		switch {
		case mode.IsDir():
			e.Type = "d"
		case mode&fs.ModeSymlink != 0:
			e.Type = "l"
			if e.Target, err = root.Readlink(p); err != nil {
				return err
			}
		case mode.IsRegular():
			e.Type = "f"
			f, err := root.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			c := newChunker(f, &r.k.gear)
			for {
				chunk, err := c.next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return fmt.Errorf("read %s: %w", p, err)
				}
				id := r.k.chunkID(chunk)
				e.Chunks = append(e.Chunks, id)
				e.Size += int64(len(chunk))
				if have[id] {
					continue
				}
				have[id] = true
				sealed := r.k.seal(r.chunkKey(id), enc.EncodeAll(chunk, nil))
				st.NewBytes += int64(len(chunk))
				st.Uploaded += int64(len(sealed))
				if err := up.put(r.chunkKey(id), sealed); err != nil {
					return err
				}
			}
			m.Files++
			m.Bytes += e.Size
		default:
			return nil // sockets, devices, and pipes
		}
		m.Entries = append(m.Entries, e)
		return nil
	})
	if err := up.wait(); walkErr == nil {
		walkErr = err
	}
	if walkErr != nil {
		return Snapshot{}, st, fmt.Errorf("back up the volume: %w", walkErr)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return Snapshot{}, st, err
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return Snapshot{}, st, err
	}
	id := m.Time.Format(snapshotTime) + "-" + hex.EncodeToString(suffix)
	key := r.root + snapshotsDir + id
	sealed := r.k.seal(key, enc.EncodeAll(raw, nil))
	if err := r.obj.Put(ctx, key, sealed); err != nil {
		return Snapshot{}, st, err
	}
	st.Uploaded += int64(len(sealed))
	return Snapshot{ID: id, Time: m.Time, Files: m.Files, Bytes: m.Bytes}, st, nil
}

func (r *Repo) chunkKey(id string) string { return r.root + chunksDir + id[:2] + "/" + id }

// uploader writes chunks a few at a time and keeps the first error.
type uploader struct {
	ctx  context.Context
	r    *Repo
	sem  chan struct{}
	wg   sync.WaitGroup
	mu   sync.Mutex
	err  error
	stop context.CancelFunc
}

func newUploader(ctx context.Context, r *Repo) *uploader {
	ctx, cancel := context.WithCancel(ctx)
	return &uploader{ctx: ctx, r: r, sem: make(chan struct{}, uploads), stop: cancel}
}

func (u *uploader) failed() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.err
}

func (u *uploader) put(key string, data []byte) error {
	select {
	case u.sem <- struct{}{}:
	case <-u.ctx.Done():
		if err := u.failed(); err != nil {
			return err
		}
		return u.ctx.Err()
	}
	u.wg.Go(func() {
		defer func() { <-u.sem }()
		if err := u.r.obj.Put(u.ctx, key, data); err != nil {
			u.mu.Lock()
			if u.err == nil {
				u.err = err
			}
			u.mu.Unlock()
			u.stop()
		}
	})
	return nil
}

func (u *uploader) wait() error {
	u.wg.Wait()
	u.stop()
	return u.failed()
}

// Snapshots lists the repository's snapshots, oldest first. Only IDs and
// times are known without reading them.
func (r *Repo) Snapshots(ctx context.Context) ([]Snapshot, error) {
	var out []Snapshot
	err := r.obj.List(ctx, r.root+snapshotsDir, func(o Object) error {
		id := path.Base(o.Key)
		if o.Key != r.root+snapshotsDir+id || !snapshotRe.MatchString(id) {
			return nil
		}
		t, err := time.Parse(snapshotTime, id[:len(snapshotTime)])
		if err != nil {
			return nil
		}
		out = append(out, Snapshot{ID: id, Time: t})
		return nil
	})
	slices.SortFunc(out, func(a, b Snapshot) int {
		if c := a.Time.Compare(b.Time); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out, err
}

// Latest is the newest snapshot's ID, or ErrNotExist.
func (r *Repo) Latest(ctx context.Context) (string, error) {
	s, err := r.Snapshots(ctx)
	if err != nil {
		return "", err
	}
	if len(s) == 0 {
		return "", fmt.Errorf("the volume has no backups: %w", ErrNotExist)
	}
	return s[len(s)-1].ID, nil
}

func (r *Repo) manifest(ctx context.Context, id string) (*manifest, error) {
	if !snapshotRe.MatchString(id) {
		return nil, fmt.Errorf("invalid backup ID %q", id)
	}
	key := r.root + snapshotsDir + id
	sealed, err := r.obj.Get(ctx, key, maxManifest)
	if errors.Is(err, ErrNotExist) {
		return nil, fmt.Errorf("backup %s: %w", id, ErrNotExist)
	}
	if err != nil {
		return nil, err
	}
	z, err := r.k.open(key, sealed)
	if err != nil {
		return nil, err
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(maxManifest), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	raw, err := dec.DecodeAll(z, nil)
	if err != nil {
		return nil, errSealed
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, errSealed
	}
	return &m, nil
}

// Restore reads snapshot id and hands each entry, parents first, with its
// content for files, to write. Every chunk is checked against its name.
func (r *Repo) Restore(ctx context.Context, id string, write func(e Entry, content io.Reader) error) (Snapshot, error) {
	m, err := r.manifest(ctx, id)
	if err != nil {
		return Snapshot{}, err
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(maxChunk), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return Snapshot{}, err
	}
	defer dec.Close()
	for _, e := range m.Entries {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		var content io.Reader
		if e.Type == "f" {
			content = &chunkStream{ctx: ctx, r: r, dec: dec, ids: e.Chunks}
		}
		if err := write(e, content); err != nil {
			return Snapshot{}, err
		}
	}
	return Snapshot{ID: id, Time: m.Time, Files: m.Files, Bytes: m.Bytes}, nil
}

// chunkStream reads a file's chunks in order.
type chunkStream struct {
	ctx context.Context
	r   *Repo
	dec *zstd.Decoder
	ids []string
	buf []byte
}

func (c *chunkStream) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		if len(c.ids) == 0 {
			return 0, io.EOF
		}
		id := c.ids[0]
		c.ids = c.ids[1:]
		if !chunkRe.MatchString(id) {
			return 0, errSealed
		}
		key := c.r.chunkKey(id)
		sealed, err := c.r.obj.Get(c.ctx, key, maxSealedChunk)
		if errors.Is(err, ErrNotExist) {
			return 0, fmt.Errorf("a chunk of the backup is missing from the bucket")
		}
		if err != nil {
			return 0, err
		}
		z, err := c.r.k.open(key, sealed)
		if err != nil {
			return 0, err
		}
		plain, err := c.dec.DecodeAll(z, nil)
		if err != nil || len(plain) > maxChunk || c.r.k.chunkID(plain) != id {
			return 0, errSealed
		}
		c.buf = plain
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

// Usage is what a repository holds.
type Usage struct {
	Snapshots int
	// Stored is every object's size in the bucket.
	Stored int64
	// Deleted counts the snapshots and chunks Prune removed.
	DeletedSnapshots, DeletedChunks int
}

// Prune deletes the snapshots keep does not hold, then the chunks no kept
// snapshot names that are older than an hour, and says what is left.
func (r *Repo) Prune(ctx context.Context, keep spec.BackupKeep, loc *time.Location, now time.Time) (Usage, error) {
	snaps, err := r.Snapshots(ctx)
	if err != nil {
		return Usage{}, err
	}
	times := make([]time.Time, len(snaps))
	for i, s := range snaps {
		times[i] = s.Time
	}
	kept := selectKept(times, keep, loc)
	var u Usage
	used := map[string]bool{}
	keptIDs := map[string]bool{}
	for i, s := range snaps {
		if !kept[i] {
			if err := r.obj.Delete(ctx, r.root+snapshotsDir+s.ID); err != nil {
				return u, err
			}
			u.DeletedSnapshots++
			continue
		}
		m, err := r.manifest(ctx, s.ID)
		if err != nil {
			// Never delete chunks on a partial view.
			return u, fmt.Errorf("read backup %s: %w", s.ID, err)
		}
		for _, e := range m.Entries {
			for _, c := range e.Chunks {
				used[c] = true
			}
		}
		keptIDs[s.ID] = true
		u.Snapshots++
	}
	err = r.obj.List(ctx, r.root, func(o Object) error {
		rel := strings.TrimPrefix(o.Key, r.root)
		switch {
		case strings.HasPrefix(rel, chunksDir):
			if id := path.Base(rel); chunkRe.MatchString(id) && !used[id] && now.Sub(o.Modified) > chunkGrace {
				if err := r.obj.Delete(ctx, o.Key); err != nil {
					return err
				}
				u.DeletedChunks++
				return nil
			}
		case strings.HasPrefix(rel, snapshotsDir):
			if !keptIDs[path.Base(rel)] {
				return nil // deleted above, or not a snapshot
			}
		}
		u.Stored += o.Size
		return nil
	})
	return u, err
}

// owner is a file's uid and gid where the system has them.
var owner = func(fs.FileInfo) (int, int) { return 0, 0 }

// CleanPath checks an entry's path from a snapshot: relative, clean, and
// inside the volume.
func CleanPath(p string) (string, error) {
	if p == "." {
		return p, nil
	}
	if p == "" || len(p) > 4096 || strings.ContainsRune(p, 0) || path.IsAbs(p) || path.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../") {
		return "", fmt.Errorf("backup entry %q is outside the volume", p)
	}
	return filepath.FromSlash(p), nil
}
