// Package fsutil writes and reads sensitive files with strict permissions.
package fsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrInsecurePermissions is returned when a sensitive file or directory is
// readable or writable by group or others.
var ErrInsecurePermissions = errors.New("insecure permissions")

// WriteFileAtomic writes data to path via a temporary file in the same
// directory and an atomic rename, so readers never see a partial file.
func WriteFileAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if name != "" {
			_ = os.Remove(name)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	name = ""
	return nil
}

// WriteFileExclusive creates path with perm and writes data, failing if the
// file already exists. Use it for keys that must never be overwritten.
func WriteFileExclusive(path string, data []byte, perm fs.FileMode) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) //nolint:gosec // path comes from operator configuration
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(path)
		}
	}()
	if err := f.Chmod(perm); err != nil { // not subject to umask
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

// ReadPrivateFile reads a file only if it is not accessible by group or others.
func ReadPrivateFile(path string) ([]byte, error) {
	if err := CheckPrivate(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path) //nolint:gosec // path comes from operator configuration, permissions verified above
}

// CheckPrivate verifies that path exists and has no group/other permissions.
func CheckPrivate(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has mode %04o, want no group/other access (chmod go-rwx): %w",
			path, fi.Mode().Perm(), ErrInsecurePermissions)
	}
	return nil
}

// MkdirPrivate creates dir with mode 0700 if missing and verifies the mode of
// an existing directory.
func MkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return CheckPrivate(dir)
}
