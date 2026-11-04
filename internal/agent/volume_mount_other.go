//go:build !linux

package agent

import "errors"

// PrepareVolumesDir needs Linux, where nodes run.
func PrepareVolumesDir(string) error { return errors.New("volumes need a Linux node") }
