package agent

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/ryanbekhen/armada/internal/fsutil"
)

// PrepareVolumesDir makes dir, the root of the node's volumes (ADR 0025),
// a mount with nosuid and nodev: it is bound onto itself and remounted
// with those flags unless its filesystem already has them. Every runtime
// bind-mounts volumes from below it, and a bind mount keeps the flags of
// the mount it comes from, so no volume can hold setuid programs or device
// files that work on the host or in a container, whatever the driver.
func PrepareVolumesDir(dir string) error {
	if err := fsutil.MkdirPrivate(dir); err != nil {
		return err
	}
	ok, err := nosuidNodev(dir)
	if err != nil || ok {
		return err
	}
	if err := unix.Mount(dir, dir, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind %s: %w", dir, err)
	}
	if err := unix.Mount("", dir, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		_ = unix.Unmount(dir, unix.MNT_DETACH)
		return fmt.Errorf("remount %s nosuid,nodev: %w", dir, err)
	}
	if ok, err := nosuidNodev(dir); err != nil || !ok {
		return fmt.Errorf("%s is not nosuid,nodev after remounting it", dir)
	}
	return nil
}

func nosuidNodev(dir string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false, err
	}
	return st.Flags&unix.ST_NOSUID != 0 && st.Flags&unix.ST_NODEV != 0, nil
}
