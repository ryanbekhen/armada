package volbackup

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// swapForPipe replaces the entry at p with a named pipe.
func swapForPipe(t *testing.T, p string) {
	t.Helper()
	if err := os.RemoveAll(p); err != nil {
		t.Error(err)
	}
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Error(err)
	}
}

// within runs f and fails the test if it does not return in time: a read
// that opened a pipe blocks until a writer appears, which then frees it.
func within(t *testing.T, pipe string, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		if w, err := os.OpenFile(pipe, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = w.Close()
		}
		t.Fatal("blocked opening a pipe")
		return nil
	}
}

// setWalkHook swaps an entry for a pipe between its lookup and its open.
func setWalkHook(t *testing.T, dir, entry string) {
	t.Helper()
	walkHook = func(p string) {
		if p == entry {
			swapForPipe(t, filepath.Join(dir, entry))
		}
	}
	t.Cleanup(func() { walkHook = nil })
}

func TestOpenFileRefusesAPipeSwappedIn(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fi, err := root.Lstat("f")
	if err != nil {
		t.Fatal(err)
	}
	swapForPipe(t, filepath.Join(dir, "f"))
	err = within(t, filepath.Join(dir, "f"), func() error {
		f, err := OpenFile(root, "f", fi)
		if err == nil {
			_ = f.Close()
		}
		return err
	})
	if !errors.Is(err, ErrChanged) {
		t.Fatalf("err = %v", err)
	}

	// Another regular file in its place is refused too.
	if err := os.Remove(filepath.Join(dir, "f")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(root, "f", fi); !errors.Is(err, ErrChanged) {
		t.Fatalf("a replaced file: %v", err)
	}
}

func backupRepo(t *testing.T) *Repo {
	t.Helper()
	r, err := Open(context.Background(), NewMemory(), "p/web/data/", testKey)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Not parallel: the hook is shared by the package.
func TestBackupFailsOnAPipeSwappedForAFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data\x1b[2K"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	setWalkHook(t, dir, "data\x1b[2K")
	r := backupRepo(t)
	err := within(t, filepath.Join(dir, "data\x1b[2K"), func() error {
		_, _, err := r.Backup(context.Background(), dir, "n1", time.Now())
		return err
	})
	if !errors.Is(err, ErrChanged) {
		t.Fatalf("err = %v", err)
	}
	if strings.ContainsRune(err.Error(), 0x1b) || !strings.Contains(err.Error(), `"data\x1b[2K"`) {
		t.Errorf("the entry is not quoted: %q", err)
	}
}

// Not parallel: the hook is shared by the package.
func TestBackupFailsOnAPipeSwappedForADirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	setWalkHook(t, dir, "sub")
	r := backupRepo(t)
	err := within(t, filepath.Join(dir, "sub"), func() error {
		_, _, err := r.Backup(context.Background(), dir, "n1", time.Now())
		return err
	})
	if !errors.Is(err, ErrChanged) {
		t.Fatalf("err = %v", err)
	}
}

func TestBackupSkipsPipes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := backupRepo(t)
	s, _, err := r.Backup(context.Background(), dir, "n1", time.Now())
	if err != nil || s.Files != 1 {
		t.Fatalf("snapshot %v, %v", s, err)
	}
}

func TestEntryErrorQuotesTheName(t *testing.T) {
	t.Parallel()
	name := "g\x1b]0;title\x07"
	err := EntryError(name, &fs.PathError{Op: "statat", Path: name, Err: syscall.ENOENT})
	if strings.ContainsAny(err.Error(), "\x1b\x07") || !errors.Is(err, syscall.ENOENT) {
		t.Errorf("err = %q", err)
	}
	if err := EntryError(name, errors.New("short read")); strings.ContainsAny(err.Error(), "\x1b\x07") {
		t.Errorf("err = %q", err)
	}
}
