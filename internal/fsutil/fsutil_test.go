package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "secret.pem")

	if err := WriteFileAtomic(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "two" {
		t.Errorf("content = %q", got)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %04o", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
}

func TestWriteFileAtomicMissingDir(t *testing.T) {
	t.Parallel()

	if err := WriteFileAtomic(filepath.Join(t.TempDir(), "nope", "f"), nil, 0o600); err == nil {
		t.Error("want error for missing directory")
	}
}

func TestReadPrivateFileRejectsLoosePermissions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { // umask may have narrowed it
		t.Fatal(err)
	}
	_, err := ReadPrivateFile(path)
	if !errors.Is(err, ErrInsecurePermissions) {
		t.Errorf("err = %v, want ErrInsecurePermissions", err)
	}
	if _, err := ReadPrivateFile(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file err = %v", err)
	}
}

func TestMkdirPrivate(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "data")
	if err := MkdirPrivate(dir); err != nil {
		t.Fatal(err)
	}
	if err := MkdirPrivate(dir); err != nil {
		t.Fatalf("second call: %v", err)
	}

	loose := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := MkdirPrivate(loose); !errors.Is(err, ErrInsecurePermissions) {
		t.Errorf("err = %v, want ErrInsecurePermissions", err)
	}
}
