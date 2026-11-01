//go:build !linux

package containerd

// SELinux reports whether containers can be confined by SELinux on this
// host; never on this platform.
func SELinux() SELinuxState                     { return SELinuxDisabled }
func newLabels() (selinuxLabels, error)         { return selinuxLabels{}, nil }
func reserveLabel(string)                       {}
func releaseLabel(string)                       {}
func relabel(string, selinuxLabels) error       { return nil }
func relabelShared(string, selinuxLabels) error { return nil }
