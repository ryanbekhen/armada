package agent

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"time"
)

// machineRestarted is why the agent recreates a container that was started
// before the machine last booted: its process ended with the machine, not
// by itself.
const machineRestarted = "the machine restarted"

// machineBoot returns when the machine last booted, from /proc/stat
// (Linux), or the zero time where the system does not report it.
func machineBoot() time.Time {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	return parseBootTime(b)
}

func parseBootTime(stat []byte) time.Time {
	s := bufio.NewScanner(bytes.NewReader(stat))
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) == 2 && f[0] == "btime" {
			if sec, err := strconv.ParseInt(f[1], 10, 64); err == nil && sec > 0 {
				return time.Unix(sec, 0)
			}
		}
	}
	return time.Time{}
}

// startedBeforeBoot reports whether a container was started before the
// machine last booted, so its process ended when the machine went down.
// btime is whole seconds, so a start within the boot's second does not
// count.
func (a *Agent) startedBeforeBoot(started time.Time) bool {
	return !a.booted.IsZero() && !started.IsZero() && started.Before(a.booted.Truncate(time.Second))
}
