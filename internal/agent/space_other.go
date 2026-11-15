//go:build !linux

package agent

// fsSpace is unknown off Linux: restores are not limited there.
func fsSpace(string) (fsFree, bool) { return fsFree{}, false }
