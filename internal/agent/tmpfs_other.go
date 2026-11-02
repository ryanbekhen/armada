//go:build !linux && !darwin

package agent

import "errors"

// CheckTmpfs verifies that dir is on a memory-backed file system. Only Linux
// and macOS are supported.
func CheckTmpfs(string) error {
	return errors.New("secret files need a Linux tmpfs or a macOS RAM disk")
}

// PrepareSecretsDisk is not supported on this system.
func PrepareSecretsDisk(string) error {
	return errors.New("secret files need a Linux tmpfs or a macOS RAM disk")
}
