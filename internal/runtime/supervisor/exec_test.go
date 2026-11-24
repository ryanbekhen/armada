package supervisor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/containerd/errdefs"
)

// Kill signals only a process's own pid: a pid file naming 0, init, or a
// value past what a pid holds (which a conversion to int would make a
// process group, or every process) is refused, and nothing is signalled.
func TestExecKillSignalsOnlyAProcess(t *testing.T) {
	for _, pid := range []string{"0", "1", "2147483648", "4294967295"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pid"), []byte(pid), 0o600); err != nil {
			t.Fatal(err)
		}
		p := &execProcess{id: "e1", dir: dir, done: make(chan struct{})}
		// Signal 0 checks a process exists without touching it, so even
		// a wrong pass would harm nothing.
		if err := p.Kill(context.Background(), syscall.Signal(0)); !errors.Is(err, errdefs.ErrNotFound) {
			t.Errorf("pid %s: Kill = %v, want NotFound", pid, err)
		}
	}
	// A process's own pid is signalled (this test's, with signal 0).
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &execProcess{id: "e1", dir: dir, done: make(chan struct{})}
	if err := p.Kill(context.Background(), syscall.Signal(0)); err != nil {
		t.Errorf("Kill of a process's own pid = %v", err)
	}
}
