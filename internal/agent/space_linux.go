package agent

import "golang.org/x/sys/unix"

// fsSpace returns the bytes and inodes free to unprivileged writers on the
// file system holding path, and its totals.
func fsSpace(path string) (s fsFree, ok bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return fsFree{}, false
	}
	bs := uint64(st.Bsize) //nolint:gosec // block sizes are positive
	return fsFree{Bytes: st.Bavail * bs, TotalBytes: st.Blocks * bs, Inodes: st.Ffree, TotalInodes: st.Files}, true
}
