package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// secretsDisk is the RAM disk for secret files: 64 MiB in 512-byte
// sectors.
const secretsDisk = "ram://131072" //nolint:gosec // a disk image URL, not a credential

// CheckTmpfs verifies that dir is the mount point of a RAM disk, so secret
// files written there never reach a disk (ADR 0016). The RAM disk ignores
// file ownership, so its parent directory must belong to this user and be
// closed to others.
func CheckTmpfs(dir string) error {
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	if err := checkPrivateParent(filepath.Dir(dir)); err != nil {
		return err
	}
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return err
	}
	if on := unix.ByteSliceToString(st.Mntonname[:]); on != dir {
		return fmt.Errorf("%s is not a RAM disk (it is on the file system mounted at %s)", dir, on)
	}
	dev := unix.ByteSliceToString(st.Mntfromname[:])
	if !diskRe.MatchString(dev) {
		return fmt.Errorf("%s is mounted from %s, not a RAM disk", dir, dev)
	}
	ram, err := ramDisks(context.Background())
	if err != nil {
		return err
	}
	if !ram[dev] {
		return fmt.Errorf("%s is mounted from %s, which is not a RAM disk", dir, dev)
	}
	return nil
}

func checkPrivateParent(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !ok:
		return fmt.Errorf("%s: no owner information", dir)
	case int(st.Uid) != os.Geteuid():
		return fmt.Errorf("%s belongs to uid %d, not this user", dir, st.Uid)
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%s is open to other users (mode %o); the RAM disk below it ignores file ownership", dir, fi.Mode().Perm())
	}
	return nil
}

// ramDisks returns the devices of attached RAM disks, from hdiutil.
func ramDisks(ctx context.Context) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/hdiutil", "info", "-plist").Output()
	if err != nil {
		return nil, fmt.Errorf("hdiutil info: %w", err)
	}
	return parseRAMDisks(out)
}

// PrepareSecretsDisk mounts a new RAM disk on dir, which must exist and be
// empty, unless one is mounted there already.
func PrepareSecretsDisk(dir string) error {
	if CheckTmpfs(dir) == nil {
		return nil
	}
	if err := checkPrivateParent(filepath.Dir(dir)); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/hdiutil", "attach", "-nomount", secretsDisk).Output()
	if err != nil {
		return fmt.Errorf("create RAM disk: %w", err)
	}
	dev := strings.TrimSpace(string(out))
	if !diskRe.MatchString(dev) {
		return fmt.Errorf("create RAM disk: unexpected device %q", dev)
	}
	run := func(name string, args ...string) error {
		// Fixed system tools; the device matched diskRe and dir is the
		// agent's own secrets directory.
		if b, err := exec.CommandContext(ctx, name, args...).CombinedOutput(); err != nil { //nolint:gosec // see above
			return fmt.Errorf("%s: %w: %s", filepath.Base(name), err, strings.TrimSpace(string(b)))
		}
		return nil
	}
	err = run("/sbin/newfs_hfs", "-v", "armada-secrets", dev)
	if err == nil {
		err = run("/usr/sbin/diskutil", "mount", "-mountPoint", dir, dev)
	}
	if err != nil {
		_ = run("/usr/sbin/diskutil", "eject", dev)
		return fmt.Errorf("mount RAM disk on %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory needs the search bit
		return err
	}
	return CheckTmpfs(dir)
}
