package volbackup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"syscall"
)

// A volume is walked while its app may keep running and change it: an
// entry seen as a regular file or a directory can be something else by the
// time it is opened. Opening a pipe for reading blocks until a writer
// appears, so every entry is opened without blocking, and its type is taken
// from the opened descriptor, never from an earlier lookup. Every lookup
// goes through an os.Root, which never resolves outside the volume.

// walkHook, when set by a test, runs after an entry was looked up and
// before it is opened.
var walkHook func(p string)

// ErrChanged reports an entry that changed while it was read.
var ErrChanged = errors.New("changed while it was read; try again, or stop the app while backing up (--stop, backup.stop)")

// WalkFunc is called by Walk for each entry with its Lstat, or with the
// error that looking the entry up or reading the directory gave (fi nil).
// A non-nil return ends the walk; returning nil after an error skips the
// entry.
type WalkFunc func(p string, fi fs.FileInfo, err error) error

// Walk calls fn for "." and then every entry below it, depth first in
// lexical order. Links are reported, never followed. A directory that is
// no longer the one just looked up when Walk opens it is an ErrChanged
// error. Errors name entries quoted, since the app chooses its file names.
func Walk(ctx context.Context, root *os.Root, fn WalkFunc) error {
	return walk(ctx, root, ".", fn)
}

func walk(ctx context.Context, root *os.Root, p string, fn WalkFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fi, err := root.Lstat(p)
	if err != nil {
		return fn(p, nil, EntryError(p, err))
	}
	if err := fn(p, fi, nil); err != nil {
		return err
	}
	if !fi.IsDir() {
		return nil
	}
	if walkHook != nil {
		walkHook(p)
	}
	f, err := openSame(root, p, fi, syscall.O_DIRECTORY)
	if err != nil {
		return fn(p, nil, err)
	}
	names, err := f.Readdirnames(-1)
	_ = f.Close()
	if err != nil {
		return fn(p, nil, EntryError(p, err))
	}
	slices.Sort(names)
	for _, name := range names {
		if err := walk(ctx, root, path.Join(p, name), fn); err != nil {
			return err
		}
	}
	return nil
}

// OpenFile opens p, which fi (its Lstat) says is a regular file, for
// reading without blocking, and refuses it with ErrChanged unless the file
// opened is that same regular file. The caller closes it.
func OpenFile(root *os.Root, p string, fi fs.FileInfo) (*os.File, error) {
	if walkHook != nil {
		walkHook(p)
	}
	return openSame(root, p, fi, 0)
}

func openSame(root *os.Root, p string, fi fs.FileInfo, flag int) (*os.File, error) {
	f, err := root.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK|flag, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP) {
			err = ErrChanged // replaced by something else, or a link
		}
		return nil, EntryError(p, err)
	}
	ofi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, EntryError(p, err)
	}
	if ofi.Mode().Type() != fi.Mode().Type() || !os.SameFile(fi, ofi) {
		_ = f.Close()
		return nil, EntryError(p, ErrChanged)
	}
	return f, nil
}

// EntryError names the volume entry p, quoted, with what went wrong,
// leaving out the path an os error repeats unquoted.
func EntryError(p string, err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s %q: %w", pe.Op, p, pe.Err)
	}
	return fmt.Errorf("%q: %w", p, err)
}
