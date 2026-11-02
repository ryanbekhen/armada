//go:build !linux && !darwin

package remote

import (
	"errors"
	"net"
)

func peerUID(*net.UnixConn) (int, error) {
	return 0, errors.New("peer credentials are not supported on this platform")
}
