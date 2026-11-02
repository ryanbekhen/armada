package agent

import (
	"fmt"
	"syscall"
)

const (
	tmpfsMagic = 0x01021994
	ramfsMagic = 0x858458f6
)

// CheckTmpfs verifies that dir is on a memory-backed file system, so secret
// files written there never reach a disk.
func CheckTmpfs(dir string) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return err
	}
	if st.Type != tmpfsMagic && st.Type != ramfsMagic {
		return fmt.Errorf("%s is not on tmpfs (file system type %#x)", dir, st.Type)
	}
	return nil
}

// PrepareSecretsDisk does nothing on Linux: the secrets directory lives on
// a tmpfs the system provides (/run).
func PrepareSecretsDisk(string) error { return nil }
