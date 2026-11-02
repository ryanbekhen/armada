package agent

import "golang.org/x/sys/unix"

// systemMemory returns the Mac's physical memory (ADR 0016).
func systemMemory() int64 {
	n, err := unix.SysctlUint64("hw.memsize")
	if err != nil || n > 1<<62 {
		return 0
	}
	return int64(n)
}
