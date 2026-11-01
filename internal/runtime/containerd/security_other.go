//go:build !linux

package containerd

import "github.com/containerd/containerd/v2/pkg/oci"

func seccompOpt() oci.SpecOpts  { return nil }
func apparmorOpt() oci.SpecOpts { return nil }
