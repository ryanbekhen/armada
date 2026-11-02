//go:build linux || darwin

package remote

import (
	"errors"
	"os"
	"syscall"
)

func ownerUID(fi os.FileInfo) (int, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("no owner information")
	}
	return int(st.Uid), nil
}
