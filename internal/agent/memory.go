package agent

import "os"

// systemMemory reads the total memory from /proc/meminfo (Linux).
func systemMemory() int64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	return parseMemTotal(b)
}
