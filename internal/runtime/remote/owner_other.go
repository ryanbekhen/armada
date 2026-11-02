//go:build !linux && !darwin

package remote

import (
	"errors"
	"os"
)

func ownerUID(os.FileInfo) (int, error) {
	return 0, errors.New("file owners are not supported on this platform")
}
