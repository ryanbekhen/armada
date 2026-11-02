package agent

import "testing"

func TestSystemMemoryOnMacOS(t *testing.T) {
	t.Parallel()
	if m := systemMemory(); m < 1<<30 {
		t.Errorf("memory = %d, want the Mac's physical memory", m)
	}
}
