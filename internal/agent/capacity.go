package agent

import (
	"bufio"
	"bytes"
	"os"
	goruntime "runtime"
	"slices"
	"strconv"
	"strings"
)

// detectCapacity returns the node's CPU (millicores) and memory (bytes).
// Memory is 0 where /proc/meminfo is unavailable; the scheduler treats 0 as
// unknown rather than empty.
func detectCapacity() (cpuMillis, memoryBytes int64) {
	cpuMillis = int64(goruntime.NumCPU()) * 1000
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		memoryBytes = parseMemTotal(b)
	}
	return cpuMillis, memoryBytes
}

func parseMemTotal(meminfo []byte) int64 {
	s := bufio.NewScanner(bytes.NewReader(meminfo))
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) == 3 && f[0] == "MemTotal:" && f[2] == "kB" {
			kb, err := strconv.ParseInt(f[1], 10, 64)
			if err == nil && kb > 0 {
				return kb * 1024
			}
		}
	}
	return 0
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
