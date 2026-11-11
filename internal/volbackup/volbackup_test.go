package volbackup

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/spec"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// restoreAll reads a snapshot into a map of path to content ("" for
// directories, "->target" for links).
func restoreAll(t *testing.T, r *Repo, id string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_, err := r.Restore(context.Background(), id, func(e Entry, content io.Reader) error {
		if _, err := CleanPath(e.Path); err != nil {
			return err
		}
		switch e.Type {
		case "d":
			out[e.Path] = ""
		case "l":
			out[e.Path] = "->" + e.Target
		case "f":
			b, err := io.ReadAll(content)
			if err != nil {
				return err
			}
			if int64(len(b)) != e.Size {
				t.Errorf("%s: %d bytes, entry says %d", e.Path, len(b), e.Size)
			}
			out[e.Path] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestBackupRestoreAndDeduplication(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	big := randomBytes(t, 6<<20)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "big.bin"), big, 0o640))
	must(os.WriteFile(filepath.Join(dir, "sub", "small.txt"), []byte("hello"), 0o600))
	must(os.WriteFile(filepath.Join(dir, "empty"), nil, 0o600))
	must(os.Symlink("sub/small.txt", filepath.Join(dir, "link")))

	b := NewMemory()
	r, err := Open(ctx, b, "p/web/data/", testKey)
	must(err)
	s1, st1, err := r.Backup(ctx, dir, "n1", time.Now())
	must(err)
	if s1.Files != 3 || s1.Bytes != int64(len(big)+5) || st1.NewBytes != s1.Bytes {
		t.Fatalf("first backup = %+v %+v", s1, st1)
	}
	got := restoreAll(t, r, s1.ID)
	if got["big.bin"] != string(big) || got["sub/small.txt"] != "hello" || got["link"] != "->sub/small.txt" || got["empty"] != "" {
		t.Fatalf("restored %d entries, wrong content", len(got))
	}
	for _, k := range b.Keys() {
		if strings.Contains(k, "big") || strings.Contains(k, "small") {
			t.Errorf("object key %q names a file", k)
		}
	}
	for k, v := range b.objs {
		if strings.HasPrefix(k, "p/web/data/chunks/") && bytes.Contains(v.data, []byte("hello")) {
			t.Errorf("chunk %s holds plaintext", k)
		}
	}

	// Insert bytes near the start of the big file: only the chunks around
	// the insertion are new.
	changed := append(append(append([]byte{}, big[:100]...), []byte("inserted")...), big[100:]...)
	must(os.WriteFile(filepath.Join(dir, "big.bin"), changed, 0o640))
	s2, st2, err := r.Backup(ctx, dir, "n1", time.Now().Add(time.Second))
	must(err)
	if st2.NewBytes > 4*maxChunk/2 || st2.NewBytes >= s2.Bytes {
		t.Errorf("second backup uploaded %d new bytes of %d", st2.NewBytes, s2.Bytes)
	}
	if restoreAll(t, r, s2.ID)["big.bin"] != string(changed) {
		t.Error("second backup restores other content")
	}
	if restoreAll(t, r, s1.ID)["big.bin"] != string(big) {
		t.Error("first backup changed")
	}

	// Unchanged: nothing but the snapshot is written.
	_, st3, err := r.Backup(ctx, dir, "n1", time.Now().Add(2*time.Second))
	must(err)
	if st3.NewBytes != 0 {
		t.Errorf("an unchanged volume wrote %d new bytes", st3.NewBytes)
	}
}

func TestOpenRefusesAnotherKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := NewMemory()
	if _, err := Open(ctx, b, "r/", testKey); err != nil {
		t.Fatal(err)
	}
	_, err := Open(ctx, b, "r/", []byte("another key that is long enough!!"))
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("other key: %v", err)
	}
	if _, err := Open(ctx, NewMemory(), "r/", []byte("short")); err == nil {
		t.Fatal("a short key was accepted")
	}
}

func TestRestoreRefusesDamagedObjects(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), randomBytes(t, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	b := NewMemory()
	r, err := Open(ctx, b, "r/", testKey)
	if err != nil {
		t.Fatal(err)
	}
	s, _, err := r.Backup(ctx, dir, "n1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var chunks []string
	for _, k := range b.Keys() {
		if strings.HasPrefix(k, "r/chunks/") {
			chunks = append(chunks, k)
		}
	}
	// A chunk swapped for another valid chunk under the wrong name.
	b2 := NewMemory()
	r2, _ := Open(ctx, b2, "r/", testKey)
	_ = os.WriteFile(filepath.Join(dir, "f"), randomBytes(t, 1<<20), 0o600)
	if _, _, err := r2.Backup(ctx, dir, "n1", time.Now()); err != nil {
		t.Fatal(err)
	}
	read := func() error {
		_, err := r.Restore(ctx, s.ID, func(e Entry, c io.Reader) error {
			if c != nil {
				_, err := io.Copy(io.Discard, c)
				return err
			}
			return nil
		})
		return err
	}
	orig, _ := b.Get(ctx, chunks[0], maxSealedChunk)
	flipped := bytes.Clone(orig)
	flipped[len(flipped)-1] ^= 1
	b.Set(chunks[0], flipped)
	if err := read(); !errors.Is(err, errSealed) {
		t.Errorf("flipped bit: %v", err)
	}
	b.Set(chunks[0], orig)
	if err := read(); err != nil {
		t.Fatalf("restored: %v", err)
	}
	_ = b.Delete(ctx, chunks[0])
	if err := read(); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("missing chunk: %v", err)
	}
}

func TestPruneKeepsPolicyAndReferencedChunks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	b := NewMemory()
	clock := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	b.Now = func() time.Time { return clock }
	r, err := Open(ctx, b, "r/", testKey)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	contents := map[string][]byte{}
	for i := range 6 {
		data := randomBytes(t, 700<<10)
		if err := os.WriteFile(filepath.Join(dir, "f"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		s, _, err := r.Backup(ctx, dir, "n1", clock)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, s.ID)
		contents[s.ID] = data
		_ = i
		clock = clock.Add(time.Hour)
	}
	u, err := r.Prune(ctx, spec.BackupKeep{Last: 2}, time.UTC, clock.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if u.Snapshots != 2 || u.DeletedSnapshots != 4 || u.DeletedChunks == 0 {
		t.Fatalf("prune = %+v", u)
	}
	left, _ := r.Snapshots(ctx)
	if len(left) != 2 || left[0].ID != ids[4] || left[1].ID != ids[5] {
		t.Fatalf("left %v", left)
	}
	for _, id := range ids[4:] {
		if restoreAll(t, r, id)["f"] != string(contents[id]) {
			t.Errorf("%s does not restore after pruning", id)
		}
	}
	var stored int64
	_ = b.List(ctx, "r/", func(o Object) error { stored += o.Size; return nil })
	if u.Stored != stored {
		t.Errorf("stored %d, bucket holds %d", u.Stored, stored)
	}

	// Young unreferenced chunks stay: a backup elsewhere may name them.
	if err := b.Put(ctx, r.chunkKey(strings.Repeat("ab", 32)), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if u, _ := r.Prune(ctx, spec.BackupKeep{Last: 2}, time.UTC, clock.Add(10*time.Minute)); u.DeletedChunks != 0 {
		t.Errorf("deleted %d young chunks", u.DeletedChunks)
	}
}

func TestSelectKept(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 11, 2, 0, 30, 0, 0, time.UTC) // a Monday
	var times []time.Time
	for i := range 72 { // every hour for three days
		times = append(times, start.Add(time.Duration(i)*time.Hour))
	}
	count := func(k []bool) int {
		n := 0
		for _, v := range k {
			if v {
				n++
			}
		}
		return n
	}
	if n := count(selectKept(times, spec.BackupKeep{Last: 5}, time.UTC)); n != 5 {
		t.Errorf("last 5 kept %d", n)
	}
	kept := selectKept(times, spec.BackupKeep{Hourly: 3, Daily: 3}, time.UTC)
	// Hours 71, 70, 69, plus the newest of each day: 71 (counted), 47, 23.
	want := map[int]bool{71: true, 70: true, 69: true, 47: true, 23: true}
	for i, k := range kept {
		if k != want[i] {
			t.Errorf("snapshot %d kept=%v", i, k)
		}
	}
	jakarta, _ := time.LoadLocation("Asia/Jakarta")
	kept = selectKept(times, spec.BackupKeep{Daily: 1, Weekly: 1, Monthly: 1}, jakarta)
	if count(kept) != 1 || !kept[71] {
		t.Errorf("one day, week, month kept %d", count(kept))
	}
}

func TestChunkBoundariesFollowContent(t *testing.T) {
	t.Parallel()
	k, err := deriveKeys(testKey, []byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	data := randomBytes(t, 20<<20)
	cut := func(b []byte) []string {
		c := newChunker(bytes.NewReader(b), &k.gear)
		var ids []string
		for {
			chunk, err := c.next()
			if errors.Is(err, io.EOF) {
				return ids
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(chunk) > maxChunk {
				t.Fatalf("chunk of %d bytes", len(chunk))
			}
			ids = append(ids, k.chunkID(chunk))
		}
	}
	a := cut(data)
	b := cut(append([]byte("prefix"), data...))
	shared := 0
	in := map[string]bool{}
	for _, id := range a {
		in[id] = true
	}
	for _, id := range b {
		if in[id] {
			shared++
		}
	}
	if shared < len(a)-2 {
		t.Errorf("%d of %d chunks shared after a 6-byte insertion", shared, len(a))
	}
}

func TestParseTarget(t *testing.T) {
	t.Parallel()
	good, err := ParseTarget("https://AK:s3cr%2Ft@s3.example.com:9000/backups/team/prod?region=ap-southeast-3")
	if err != nil {
		t.Fatal(err)
	}
	if good.Endpoint != "s3.example.com:9000" || !good.Secure || good.Bucket != "backups" || good.Prefix != "team/prod/" ||
		good.Region != "ap-southeast-3" || good.AccessKey != "AK" || good.SecretKey != "s3cr/t" {
		t.Errorf("parsed %+v", good)
	}
	if strings.Contains(good.String(), "s3cr") || strings.Contains(good.LogValue(), "AK") {
		t.Error("the target prints its credentials")
	}
	if _, err := ParseTarget("http://AK:SK@10.0.0.5:9000/bk1"); err != nil {
		t.Errorf("http to a private IP: %v", err)
	}
	for _, bad := range []string{
		"http://AK:SK@s3.example.com/bucket",
		"https://s3.example.com/bucket",
		"https://AK@s3.example.com/bucket",
		"https://AK:SK@s3.example.com/",
		"https://AK:SK@s3.example.com/Bad_Bucket",
		"https://AK:SK@s3.example.com/bucket/../x",
		"https://AK:SK@s3.example.com/bucket?acl=1",
		"ftp://AK:SK@s3.example.com/bucket",
		"https://AK:SK@s3.example.com/bucket?region=US%20East",
	} {
		_, err := ParseTarget(bad)
		if err == nil {
			t.Errorf("%s accepted", bad)
		} else if strings.Contains(err.Error(), "SK") || strings.Contains(err.Error(), "s3.example") {
			t.Errorf("error repeats the URL: %v", err)
		}
	}
}

func TestCleanPath(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{".", "a", "a/b"} {
		if _, err := CleanPath(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "..", "../x", "/etc", "a/../b", "a//b", "a/", "x\x00"} {
		if _, err := CleanPath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
