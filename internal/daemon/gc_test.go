package daemon

import (
	"runtime/debug"
	"testing"
)

func TestTuneGC(t *testing.T) {
	old := debug.SetGCPercent(100)
	t.Cleanup(func() { debug.SetGCPercent(old) })

	tuneGC(func(string) string { return "" })
	if got := debug.SetGCPercent(100); got != gcPercent {
		t.Errorf("without GOGC: %d, want %d", got, gcPercent)
	}
	tuneGC(func(k string) string {
		if k == "GOGC" {
			return "200"
		}
		return ""
	})
	if got := debug.SetGCPercent(100); got != 100 {
		t.Errorf("with GOGC set: changed to %d", got)
	}
}
