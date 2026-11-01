package containerd

import (
	"context"
	"strings"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
)

// On SELinux hosts every container runs as container_t with its own MCS
// categories (ADR 0011). Its root filesystem is mounted with the matching
// file label and the files Armada bind-mounts into it are relabelled, so a
// container can reach neither the host's files nor another container's.

// SELinuxState is the SELinux support of a host.
type SELinuxState int

const (
	// SELinuxDisabled means SELinux is off; there is nothing to label.
	SELinuxDisabled SELinuxState = iota
	// SELinuxConfined means containers run as container_t with their own
	// categories.
	SELinuxConfined
	// SELinuxNoPolicy means SELinux is on but the policy has no container
	// types, so containers run with the runtime's own label.
	SELinuxNoPolicy
)

// selinuxLabels are a container's labels; empty when it is not confined.
type selinuxLabels struct {
	process string // e.g. system_u:system_r:container_t:s0:c1,c2
	mount   string // e.g. system_u:object_r:container_file_t:s0:c1,c2
}

// withSELinux sets the process label and the mount label. containerd
// mounts the root filesystem with the mount label as its context, which
// covers every file in the image whatever its label on disk; runc uses it
// for the mounts it creates (tmpfs, /dev, mqueue).
func withSELinux(l selinuxLabels) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		if l.process == "" {
			return nil
		}
		if s.Process != nil {
			s.Process.SelinuxLabel = l.process
		}
		if s.Linux != nil {
			s.Linux.MountLabel = l.mount
		}
		return nil
	}
}

// processLabel returns the SELinux process label of a container spec.
func processLabel(s *oci.Spec) string {
	if s == nil || s.Process == nil || !strings.Contains(s.Process.SelinuxLabel, ":") {
		return ""
	}
	return s.Process.SelinuxLabel
}
