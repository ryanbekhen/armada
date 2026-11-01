//go:build !linux

package agent

import "errors"

// CheckTmpfs verifies that dir is on a memory-backed file system. Only Linux
// is supported.
func CheckTmpfs(string) error {
	return errors.New("secret files need a Linux tmpfs")
}
