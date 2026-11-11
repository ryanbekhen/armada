//go:build unix

package volbackup

import (
	"io/fs"
	"syscall"
)

func init() {
	owner = func(fi fs.FileInfo) (int, int) {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			return int(st.Uid), int(st.Gid)
		}
		return 0, 0
	}
}
