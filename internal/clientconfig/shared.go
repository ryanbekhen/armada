package clientconfig

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/ryanbekhen/armada/internal/fsutil"
)

// SystemPath is the admin config `armadad init` writes on the first server:
// owned by root, readable by the members of Group, so every administrator
// on the machine uses armada without root and without a copy (ADR 0027).
const SystemPath = "/etc/armada/admin.config"

// systemPath is SystemPath; tests point it elsewhere.
var systemPath = SystemPath

// Group is the system group whose members may read SystemPath. Membership
// is full control of the cluster.
const Group = "armada"

// sharedMode is the only mode besides 0600 a client config may have.
const sharedMode fs.FileMode = 0o640

// readConfig reads a client config that is private to its owner, or shared
// on purpose: owned by root, mode 0640, group Group.
func readConfig(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 && !sharedOK(fi) {
		return nil, fmt.Errorf("%s has mode %04o, want 0600 (or 0640, owned by root, group %s): %w",
			path, fi.Mode().Perm(), Group, fsutil.ErrInsecurePermissions)
	}
	return os.ReadFile(path) //nolint:gosec // path comes from the operator, permissions verified above
}

// sharedOK reports whether fi is a config root shares with Group.
func sharedOK(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || fi.Mode().Perm() != sharedMode || st.Uid != 0 {
		return false
	}
	gid, err := groupID()
	return err == nil && uint32(gid) == st.Gid //nolint:gosec // gids fit in 32 bits
}

// groupID looks Group up.
func groupID() (int, error) {
	g, err := user.LookupGroup(Group)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

// SaveShared writes the config to path for the members of Group: the
// directory is created 0711 (or given search permission, so the file can
// be reached by name but the directory not listed), the file 0640 root:Group.
// Without the group it stays 0600 and shared is false.
func (c *Config) SaveShared(path string) (shared bool, err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o711); err != nil { //nolint:gosec // search only: the file is reached by name, the directory is not listable
		return false, err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return false, err
	}
	if fi.Mode().Perm()&0o011 != 0o011 {
		if err := os.Chmod(dir, fi.Mode().Perm()|0o011); err != nil {
			return false, err
		}
	}
	if err := c.SaveFile(path); err != nil {
		return false, err
	}
	gid, err := groupID()
	if err != nil {
		var unknown user.UnknownGroupError
		if errors.As(err, &unknown) {
			return false, nil
		}
		return false, err
	}
	if err := os.Chown(path, 0, gid); err != nil {
		return false, err
	}
	return true, os.Chmod(path, sharedMode)
}

// keepShared gives a rewritten config back the group and mode it had when
// it was shared with Group.
func keepShared(path string, old fs.FileInfo) error {
	if !sharedOK(old) {
		return nil
	}
	st := old.Sys().(*syscall.Stat_t)
	if err := os.Chown(path, int(st.Uid), int(st.Gid)); err != nil {
		return err
	}
	return os.Chmod(path, sharedMode)
}
