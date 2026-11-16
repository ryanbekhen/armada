package daemon

import "runtime/debug"

// gcPercent is the garbage collector target of the long-running commands
// (server and agent). Their live heap is small (about 7-14 MiB), so the
// default of 100 leaves as much garbage as live data between collections;
// 50 keeps about 4 MiB less resident for a few more short collections a
// minute. GOGC in the environment still wins.
const gcPercent = 50

// tuneGC applies gcPercent unless GOGC is set.
func tuneGC(getenv func(string) string) {
	if getenv("GOGC") != "" {
		return
	}
	debug.SetGCPercent(gcPercent)
}
