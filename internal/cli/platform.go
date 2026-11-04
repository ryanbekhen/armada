package cli

import (
	"fmt"
	goruntime "runtime"
)

// goos is the system the CLI runs on; tests replace it.
var goos = goruntime.GOOS

// Data and secrets directories of a node.
const (
	defaultDataDir    = "/var/lib/armada"
	defaultSecretsDir = "/run/armada/secrets" //nolint:gosec // a directory path, not a credential
)

// linuxOnly refuses what only nodes do: the control plane, the agent, etcd,
// and the embedded runtime run on Linux (ADR 0011). On other systems the
// binary is a client of a cluster.
func linuxOnly(what string) error { return linuxOnlyOn(goos, what) }

func linuxOnlyOn(system, what string) error {
	if system != "linux" {
		return fmt.Errorf("%s runs on Linux only: Armada's nodes are Linux machines, and on %s this binary manages a cluster as a client", what, system)
	}
	return nil
}
