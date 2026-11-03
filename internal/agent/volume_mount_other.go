//go:build !linux

package agent

import "github.com/ryanbekhen/armada/internal/fsutil"

// PrepareVolumesDir creates dir, the root of the node's volumes. On macOS
// nodes the drivers run containers in virtual machines with kernels of
// their own, so no mount flags are needed on the host (ADR 0016, 0025).
func PrepareVolumesDir(dir string) error { return fsutil.MkdirPrivate(dir) }
