//go:build linux

package embedded

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ryanbekhen/armada/internal/fsutil"
)

// Exec prepares the bundle and configuration and replaces the current
// process with containerd, so systemd supervises containerd directly.
// pack is the embedded bundle; without one, binDir (development) must hold
// the binaries.
func Exec(p Paths, pack []byte, binDir string) error {
	if err := CheckHost(); err != nil {
		return err
	}
	switch {
	case len(pack) > 0:
		if _, _, err := Install(p.Bundle(), pack); err != nil {
			return err
		}
	case binDir != "":
		if err := UseBinDir(p.Bundle(), binDir); err != nil {
			return err
		}
	default:
		return errors.New("this binary has no runtime bundle; build with `make build-bundle` or pass --bin-dir")
	}
	for _, d := range []string{p.Root(), p.State(), p.Logs(), p.Containers(), p.CNI()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	if err := fsutil.WriteFileAtomic(p.Config(), []byte(ContainerdConfig(p)), 0o600); err != nil {
		return err
	}
	bin := filepath.Join(p.Bin(), BinContainerd)
	env := []string{"PATH=" + p.Bin() + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	if err := syscall.Exec(bin, []string{"containerd", "--config", p.Config()}, env); err != nil {
		return fmt.Errorf("exec containerd: %w", err)
	}
	return nil
}

// CheckHost verifies what the embedded runtime needs from the kernel.
func CheckHost() error {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return errors.New("cgroup v2 is required (unified hierarchy at /sys/fs/cgroup)")
	}
	return nil
}
