package volbackup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// jitterObjects answers after a random pause, so chunks written and read
// at the same time finish out of order, and can fail every call after a
// number of them.
type jitterObjects struct {
	*Memory
	failAfter int
	calls     chan struct{}
}

var errBucket = errors.New("bucket unavailable")

func (j *jitterObjects) pause() error {
	time.Sleep(time.Duration(rand.IntN(3)) * time.Millisecond)
	if j.failAfter > 0 {
		select {
		case j.calls <- struct{}{}:
		default:
			return errBucket
		}
	}
	return nil
}

func (j *jitterObjects) Put(ctx context.Context, k string, b []byte) error {
	if err := j.pause(); err != nil {
		return err
	}
	return j.Memory.Put(ctx, k, b)
}

func (j *jitterObjects) Get(ctx context.Context, k string, max int64) ([]byte, error) {
	if err := j.pause(); err != nil {
		return nil, err
	}
	return j.Memory.Get(ctx, k, max)
}

// Chunks are compressed, written, and read many at a time; every file
// still gets its own content, in order, also when write leaves some
// unread, and a failing bucket ends a backup or restore with its error.
func TestParallelBackupAndRestore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	want := map[string]string{}
	for i := range 300 {
		// Small files, and some of several chunks.
		n := 1 + i*37
		if i%50 == 0 {
			n = 3<<20 + i
		}
		b := []byte(strings.Repeat(fmt.Sprintf("file %d ", i), n/6+1))[:n]
		if i%7 == 0 {
			b = randomBytes(t, n)
		}
		name := fmt.Sprintf("f%03d", i)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
		want[name] = string(b)
	}
	obj := &jitterObjects{Memory: NewMemory()}
	r, err := Open(ctx, obj, "p/", testKey)
	if err != nil {
		t.Fatal(err)
	}
	snap, _, err := r.Backup(ctx, dir, "n1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := restoreAll(t, r, snap.ID)
	for name, w := range want {
		if got[name] != w {
			t.Fatalf("%s restored with %d bytes, want %d", name, len(got[name]), len(w))
		}
	}

	// write reads only every third file; the others still line up.
	seen := 0
	_, err = r.Restore(ctx, snap.ID, func(e Entry, content io.Reader) error {
		if e.Type != "f" {
			return nil
		}
		seen++
		if seen%3 != 0 {
			return nil
		}
		b, err := io.ReadAll(content)
		if err != nil {
			return err
		}
		if string(b) != want[e.Path] {
			return fmt.Errorf("%s: wrong content after a skipped file", e.Path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// A bucket that fails part way.
	for _, after := range []int{5, 60} {
		bad := &jitterObjects{Memory: NewMemory(), failAfter: after, calls: make(chan struct{}, after)}
		br, err := Open(ctx, bad.Memory, "p/", testKey)
		if err != nil {
			t.Fatal(err)
		}
		br.obj = bad
		if _, _, err := br.Backup(ctx, dir, "n1", time.Now()); !errors.Is(err, errBucket) {
			t.Errorf("backup after %d calls: %v", after, err)
		}
		// The good repository, read through a failing bucket.
		bad = &jitterObjects{Memory: obj.Memory, failAfter: after, calls: make(chan struct{}, after)}
		rr := *r
		rr.obj = bad
		_, err = rr.Restore(ctx, snap.ID, func(_ Entry, c io.Reader) error {
			if c != nil {
				_, err := io.Copy(io.Discard, c)
				return err
			}
			return nil
		})
		if !errors.Is(err, errBucket) {
			t.Errorf("restore after %d calls: %v", after, err)
		}
	}
}
