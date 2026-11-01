//go:build linux

package containerd

import (
	ctdapparmor "github.com/containerd/containerd/v2/contrib/apparmor"
	"github.com/containerd/containerd/v2/contrib/seccomp"
	"github.com/containerd/containerd/v2/pkg/apparmor"
	"github.com/containerd/containerd/v2/pkg/oci"
)

// apparmorProfile is generated and loaded on first use.
const apparmorProfile = "armada-default"

func seccompOpt() oci.SpecOpts { return seccomp.WithDefaultProfile() }

func apparmorOpt() oci.SpecOpts {
	if !apparmor.HostSupports() {
		return nil
	}
	return ctdapparmor.WithDefaultProfile(apparmorProfile)
}
