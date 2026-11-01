//go:build linux

package containerd

import (
	"github.com/opencontainers/selinux/go-selinux"
	"github.com/opencontainers/selinux/go-selinux/label"
)

// roFileType is the container policy's type for files every container may
// read; policies without it get the plain container file type.
const roFileType = "container_ro_file_t"

// SELinux reports whether containers can be confined by SELinux on this
// host.
func SELinux() SELinuxState {
	if !selinux.GetEnabled() {
		return SELinuxDisabled
	}
	p, _, err := label.InitLabels(nil)
	if err != nil || p == "" {
		return SELinuxNoPolicy
	}
	selinux.ReleaseLabel(p)
	if selinux.SecurityCheckContext(p) != nil {
		return SELinuxNoPolicy
	}
	return SELinuxConfined
}

// newLabels returns a process and mount label with categories no other
// container of this process holds, or empty labels when containers cannot
// be confined (see SELinux).
func newLabels() (selinuxLabels, error) {
	p, m, err := label.InitLabels(nil)
	if err != nil || p == "" {
		return selinuxLabels{}, err
	}
	if err := selinux.SecurityCheckContext(p); err != nil {
		selinux.ReleaseLabel(p)
		return selinuxLabels{}, nil
	}
	return selinuxLabels{process: p, mount: m}, nil
}

// reserveLabel keeps the categories of an existing container from being
// handed out again.
func reserveLabel(process string) {
	if process != "" {
		_ = selinux.ReserveLabelV2(process) // already reserved is fine
	}
}

func releaseLabel(process string) {
	if process != "" {
		selinux.ReleaseLabel(process)
	}
}

// relabel gives path, recursively, the container's mount label, so only
// that container can use it.
func relabel(path string, l selinuxLabels) error {
	if l.mount == "" {
		return nil
	}
	return selinux.Chcon(path, l.mount, true)
}

// relabelShared gives path the label every container may read but not
// write.
func relabelShared(path string, l selinuxLabels) error {
	if l.mount == "" {
		return nil
	}
	c, err := selinux.NewContext(l.mount)
	if err != nil {
		return err
	}
	c["level"] = "s0"
	plain := c.Get()
	c["type"] = roFileType
	if ro := c.Get(); selinux.SecurityCheckContext(ro) == nil {
		return selinux.SetFileLabel(path, ro)
	}
	return selinux.SetFileLabel(path, plain)
}
