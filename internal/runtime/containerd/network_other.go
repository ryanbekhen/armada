//go:build !linux

package containerd

import (
	"errors"
	"net/netip"

	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

func newNetwork(embedded.Paths, netip.Prefix) (network, error) {
	return nil, errors.New("the embedded runtime needs Linux")
}
