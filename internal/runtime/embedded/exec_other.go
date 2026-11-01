//go:build !linux

package embedded

import "errors"

// Exec is only supported on Linux.
func Exec(Paths, []byte, string) error { return errors.New("the embedded runtime needs Linux") }

// CheckHost is only supported on Linux.
func CheckHost() error { return errors.New("the embedded runtime needs Linux") }
