package supervisor

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	cgroupstats "github.com/containerd/cgroups/v3/cgroup2/stats"
)

// cgroupRoot is where cgroup v2 is mounted.
const cgroupRoot = "/sys/fs/cgroup"

// readCgroup reads what the driver samples of a container's cgroup: CPU
// time, memory in use and inactive file pages, and out-of-memory kills.
func readCgroup(dir string) (*cgroupstats.Metrics, error) {
	cpu, err := keyed(filepath.Join(dir, "cpu.stat"))
	if err != nil {
		return nil, err
	}
	mem, err := keyed(filepath.Join(dir, "memory.stat"))
	if err != nil {
		return nil, err
	}
	events, err := keyed(filepath.Join(dir, "memory.events"))
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "memory.current")) //nolint:gosec // a cgroup file
	if err != nil {
		return nil, err
	}
	current, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return nil, errors.New("memory.current: not a number")
	}
	return &cgroupstats.Metrics{
		CPU:          &cgroupstats.CPUStat{UsageUsec: cpu["usage_usec"], UserUsec: cpu["user_usec"], SystemUsec: cpu["system_usec"]},
		Memory:       &cgroupstats.MemoryStat{Usage: current, InactiveFile: mem["inactive_file"], ActiveFile: mem["active_file"], Anon: mem["anon"], File: mem["file"]},
		MemoryEvents: &cgroupstats.MemoryEvents{Oom: events["oom"], OomKill: events["oom_kill"], Max: events["max"], High: events["high"], Low: events["low"]},
	}, nil
}

// keyed reads a cgroup file of "key value" lines.
func keyed(path string) (map[string]uint64, error) {
	f, err := os.Open(path) //nolint:gosec // a cgroup file
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			continue
		}
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			out[k] = n
		}
	}
	return out, sc.Err()
}
