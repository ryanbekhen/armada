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
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sync/semaphore"

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
	// uploads is how many objects are written at once, holding at most
	// uploadBytes: a bucket answers each after a round trip, and small
	// files make many small objects.
	uploads     = 32
	uploadBytes = 64 << 20
	// maxPackers bounds the chunks compressed and sealed at once.
	maxPackers = 4
	// fetches is how many chunks a restore reads at once, holding at most
	// fetchBytes ahead; decoders bounds those decompressed at once.
	fetches    = 32
	fetchBytes = 64 << 20
	decoders   = 4
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

// ControlPlaneRoot is where the control plane's backups live in the bucket
// (ADR 0051): beside the volumes' repositories, under a name no app ID can
// take, since app IDs never hold an underscore.
func ControlPlaneRoot(t Target) string { return t.Prefix + "_control-plane/" }

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
		return nil, errors.New("the backup key does not match the one this repository's backups were made with")
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
	// Files, Bytes, and Node (where it was taken) are known after a
	// backup or when the snapshot was read.
	Files int
	Bytes int64
	Node  string
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
	enc, err := newEncoder()
	if err != nil {
		return Snapshot{}, Stats{}, err
	}
	defer enc.Close()

	up := newUploader(ctx, r)
	pk, err := newPacker(up, packers())
	if err != nil {
		return Snapshot{}, Stats{}, err
	}
	// One buffer for every file's chunks: most files are far smaller than
	// a chunk.
	buf := make([]byte, maxChunk)
	var st Stats
	m := manifest{Version: repoVersion, Time: now.UTC(), Node: node}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Snapshot{}, Stats{}, err
	}
	defer root.Close()
	walkErr := Walk(ctx, root, func(p string, fi fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if err := up.failed(); err != nil {
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
			var err error
			if e.Target, err = root.Readlink(p); err != nil {
				return EntryError(p, err)
			}
		case mode.IsRegular():
			e.Type = "f"
			f, err := OpenFile(root, p, fi)
			if err != nil {
				return err
			}
			defer f.Close()
			c := newChunker(f, &r.k.gear, buf)
			for {
				chunk, err := c.next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return fmt.Errorf("read %q: %w", p, err)
				}
				id := r.k.chunkID(chunk)
				e.Chunks = append(e.Chunks, id)
				e.Size += int64(len(chunk))
				if have[id] {
					continue
				}
				have[id] = true
				st.NewBytes += int64(len(chunk))
				if err := pk.add(r.chunkKey(id), chunk); err != nil {
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
	st.Uploaded = pk.close()
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
	return Snapshot{ID: id, Time: m.Time, Files: m.Files, Bytes: m.Bytes, Node: m.Node}, st, nil
}

func (r *Repo) chunkKey(id string) string { return r.root + chunksDir + id[:2] + "/" + id }

// newEncoder makes a zstd encoder for chunks and manifests.
func newEncoder() (*zstd.Encoder, error) {
	return zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1))
}

// packers is how many chunks a backup compresses and seals at once: up to
// maxPackers, leaving a CPU to the node's apps.
func packers() int { return max(1, min(runtime.GOMAXPROCS(0)-1, maxPackers)) }

// packer compresses and seals chunks on a few goroutines, each with its
// own encoder, and hands them to the uploader. Chunks are named by their
// content, so the order they are written in does not matter.
type packer struct {
	up       *uploader
	jobs     chan packJob
	wg       sync.WaitGroup
	uploaded atomic.Int64
}

type packJob struct {
	key   string
	chunk []byte
}

func newPacker(up *uploader, n int) (*packer, error) {
	p := &packer{up: up, jobs: make(chan packJob)}
	for range n {
		enc, err := newEncoder()
		if err != nil {
			p.close()
			return nil, err
		}
		p.wg.Go(func() {
			defer enc.Close()
			for j := range p.jobs {
				if up.failed() != nil {
					continue // the backup fails; let add return
				}
				sealed := up.r.k.seal(j.key, enc.EncodeAll(j.chunk, nil))
				p.uploaded.Add(int64(len(sealed)))
				_ = up.put(j.key, sealed) // a failure is kept by the uploader
			}
		})
	}
	return p, nil
}

// add hands a chunk over, waiting while every packer is busy.
func (p *packer) add(key string, chunk []byte) error {
	select {
	case p.jobs <- packJob{key, chunk}:
		return nil
	case <-p.up.ctx.Done():
		if err := p.up.failed(); err != nil {
			return err
		}
		return p.up.ctx.Err()
	}
}

// close waits for the chunks handed over and returns the bytes sealed.
func (p *packer) close() int64 {
	close(p.jobs)
	p.wg.Wait()
	return p.uploaded.Load()
}

// uploader writes objects many at a time, within uploadBytes, and keeps
// the first error.
type uploader struct {
	ctx  context.Context
	r    *Repo
	sem  *semaphore.Weighted
	n    chan struct{}
	wg   sync.WaitGroup
	mu   sync.Mutex
	err  error
	stop context.CancelFunc
}

func newUploader(ctx context.Context, r *Repo) *uploader {
	ctx, cancel := context.WithCancel(ctx)
	return &uploader{ctx: ctx, r: r, sem: semaphore.NewWeighted(uploadBytes), n: make(chan struct{}, uploads), stop: cancel}
}

func (u *uploader) failed() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.err
}

func (u *uploader) put(key string, data []byte) error {
	size := min(int64(len(data)), uploadBytes)
	if err := u.sem.Acquire(u.ctx, size); err != nil {
		if err := u.failed(); err != nil {
			return err
		}
		return u.ctx.Err()
	}
	select {
	case u.n <- struct{}{}:
	case <-u.ctx.Done():
		u.sem.Release(size)
		if err := u.failed(); err != nil {
			return err
		}
		return u.ctx.Err()
	}
	u.wg.Go(func() {
		defer func() {
			<-u.n
			u.sem.Release(size)
		}()
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
		return "", fmt.Errorf("there are no backups yet: %w", ErrNotExist)
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
		return nil, fmt.Errorf("backup %q: %w", id, ErrNotExist)
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
	var ids []chunkRef
	for _, e := range m.Entries {
		if e.Type == "f" {
			// No chunk is larger than its file.
			size := max(min(e.Size, maxChunk), 0) + 1<<10
			for _, id := range e.Chunks {
				ids = append(ids, chunkRef{id, size})
			}
		}
	}
	f, err := r.fetchAhead(ctx, ids)
	if err != nil {
		return Snapshot{}, err
	}
	defer f.stop()
	for _, e := range m.Entries {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		var content io.Reader
		var cs *chunkStream
		if e.Type == "f" {
			cs = &chunkStream{ctx: ctx, f: f, left: len(e.Chunks)}
			content = cs
		}
		if err := write(e, content); err != nil {
			return Snapshot{}, err
		}
		if cs != nil {
			// Chunks write did not read are read ahead all the same.
			cs.skip()
		}
	}
	return Snapshot{ID: id, Time: m.Time, Files: m.Files, Bytes: m.Bytes, Node: m.Node}, nil
}

// Info reads snapshot id's manifest: its time, size, and node.
func (r *Repo) Info(ctx context.Context, id string) (Snapshot, error) {
	m, err := r.manifest(ctx, id)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{ID: id, Time: m.Time, Files: m.Files, Bytes: m.Bytes, Node: m.Node}, nil
}

// fetcher reads a restore's chunks ahead, many at a time within
// fetchBytes, and hands them over in order.
type fetcher struct {
	order  chan fetchSlot
	sem    *semaphore.Weighted
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// chunkRef is a chunk to read and the most it can take.
type chunkRef struct {
	id   string
	size int64
}

type fetchSlot struct {
	out  chan fetched
	size int64
}

type fetched struct {
	plain []byte
	err   error
}

type fetchJob struct {
	id  string
	out chan fetched
}

// fetchAhead starts reading ids in order.
func (r *Repo) fetchAhead(ctx context.Context, ids []chunkRef) (*fetcher, error) {
	dec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(maxChunk), zstd.WithDecoderConcurrency(decoders))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	f := &fetcher{order: make(chan fetchSlot, fetches), sem: semaphore.NewWeighted(fetchBytes), cancel: cancel}
	jobs := make(chan fetchJob)
	var workers sync.WaitGroup
	for range fetches {
		workers.Go(func() {
			for j := range jobs {
				plain, err := r.fetchChunk(ctx, dec, j.id)
				j.out <- fetched{plain, err}
			}
		})
	}
	f.wg.Go(func() {
		defer func() {
			close(jobs)
			workers.Wait()
			dec.Close()
		}()
		for _, c := range ids {
			size := min(c.size, fetchBytes)
			if f.sem.Acquire(ctx, size) != nil {
				return
			}
			slot := fetchSlot{make(chan fetched, 1), size}
			select {
			case f.order <- slot:
			case <-ctx.Done():
				return
			}
			select {
			case jobs <- fetchJob{c.id, slot.out}:
			case <-ctx.Done():
				return
			}
		}
	})
	return f, nil
}

// next returns the next chunk in order.
func (f *fetcher) next(ctx context.Context) ([]byte, error) {
	select {
	case slot := <-f.order:
		select {
		case got := <-slot.out:
			f.sem.Release(slot.size)
			return got.plain, got.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fetcher) stop() {
	f.cancel()
	f.wg.Wait()
}

// fetchChunk reads, opens, and checks chunk id.
func (r *Repo) fetchChunk(ctx context.Context, dec *zstd.Decoder, id string) ([]byte, error) {
	if !chunkRe.MatchString(id) {
		return nil, errSealed
	}
	key := r.chunkKey(id)
	sealed, err := r.obj.Get(ctx, key, maxSealedChunk)
	if errors.Is(err, ErrNotExist) {
		return nil, fmt.Errorf("a chunk of the backup is missing from the bucket")
	}
	if err != nil {
		return nil, err
	}
	z, err := r.k.open(key, sealed)
	if err != nil {
		return nil, err
	}
	plain, err := dec.DecodeAll(z, nil)
	if err != nil || len(plain) > maxChunk || r.k.chunkID(plain) != id {
		return nil, errSealed
	}
	return plain, nil
}

// chunkStream reads a file's chunks in order.
type chunkStream struct {
	ctx  context.Context
	f    *fetcher
	left int
	buf  []byte
}

func (c *chunkStream) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		if c.left == 0 {
			return 0, io.EOF
		}
		c.left--
		plain, err := c.f.next(c.ctx)
		if err != nil {
			c.left = 0
			return 0, err
		}
		c.buf = plain
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

// skip passes the file's chunks that were not read.
func (c *chunkStream) skip() {
	for ; c.left > 0; c.left-- {
		_, _ = c.f.next(c.ctx)
	}
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
