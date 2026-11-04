//go:build !linux

package clusternet

import (
	"context"
	"errors"
	"net/netip"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// Net is the cluster network; only Linux nodes have one.
type Net struct{}

// New fails: the cluster network needs Linux (macOS nodes stay on
// published ports, ADR 0027).
func New(Config) (*Net, error) {
	return nil, errors.New("the cluster network needs Linux")
}

// Apply does nothing.
func (*Net) Apply(context.Context, *armadav1.NetworkConfig) error { return nil }

// ContainerMTU fails: the cluster network needs Linux.
func ContainerMTU(string, netip.Addr) (int, error) {
	return 0, errors.New("the cluster network needs Linux")
}

// Diagnose reports that the cluster network needs Linux.
func Diagnose(string, netip.Addr) []Check {
	return []Check{{Name: "network", Level: CheckFail, Detail: "the cluster network needs Linux"}}
}

// Remove does nothing: only Linux nodes have a cluster network.
func Remove() error { return nil }
