package daemon

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// Units the running agent restarts after the leader moved its node: the
// control plane's on a server machine, the agent's elsewhere.
const (
	unitServer = "armada-server"
	unitAgent  = "armada-agent"
)

// fileRuntimeMove holds what the leader last said about moving this
// containerd node to the supervisor runtime (ADR 0054), for doctor. It is
// not backed up: the leader sends it again.
const fileRuntimeMove = "runtime-move.json"

// nodeMove moves the running agent's node from containerd to the supervisor
// runtime when the leader asks (ADR 0054, "The runtime's move", step 4): it
// does what `armadad runtime migrate --to supervisor` does with the agent's
// own runtime and data directory, which the agent already holds, then
// restarts the node's service, which starts again on the supervisor runtime
// (and armada-node). Tests replace systemctl and exit.
type nodeMove struct {
	dataDir string
	// mu guards ac against the agent's other writer of agent.json (the
	// control plane list).
	mu        *sync.Mutex
	ac        *agentConfig
	rt        runtime.Driver
	unit      string
	systemctl func(ctx context.Context, args ...string) error
	exit      func(code int)
	log       *slog.Logger
}

// run removes every container, records the supervisor in agent.json, and
// restarts the service. When systemd cannot restart it, the process exits
// and the unit's Restart=always starts it again. The agent has checked that
// no replica is assigned to the node.
func (m nodeMove) run(ctx context.Context, to string) error {
	if to != runtimeSupervisor {
		return fmt.Errorf("the leader asked for runtime %q; a node moves only to %s", to, runtimeSupervisor)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if cmp.Or(m.ac.Runtime, runtimeEmbedded) != runtimeEmbedded {
		return errors.New("this node does not run on containerd")
	}
	var out strings.Builder
	if err := migrateRuntime(ctx, m.dataDir, m.ac, m.rt, to, &out, &out, m.systemctl); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(m.dataDir, fileRuntimeMove))
	m.log.Warn("this node now runs containers on the supervisor runtime; restarting its service", "unit", m.unit, "output", strings.TrimSpace(out.String()))
	err := m.systemctl(ctx, "--no-block", "restart", m.unit)
	switch {
	case err == nil:
	case stoppedBySystemd(err):
		// The restart began before systemctl returned: systemd stops the
		// unit's processes, systemctl among them, and starts it again.
		m.log.Info("the service is restarting", "unit", m.unit)
	default:
		m.log.Error("could not restart the service; exiting so that it starts again", "unit", m.unit, "err", err)
		m.exit(1)
	}
	return nil
}

// stoppedBySystemd reports whether a command ended on SIGTERM or SIGKILL,
// as systemctl does when the unit it restarts is its own.
func stoppedBySystemd(err error) bool {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return false
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && (ws.Signal() == syscall.SIGTERM || ws.Signal() == syscall.SIGKILL)
}

// runtimeMoveNote is fileRuntimeMove's content.
type runtimeMoveNote struct {
	State    string    `json:"state"`
	Reason   string    `json:"reason,omitempty"`
	Operator bool      `json:"operator,omitempty"`
	At       time.Time `json:"at"`
}

// saveRuntimeMovePlan writes what the leader plans for this node, or
// removes the file when it sends nothing.
func saveRuntimeMovePlan(dataDir string, p *armadav1.RuntimeMovePlan) error {
	path := filepath.Join(dataDir, fileRuntimeMove)
	if p == nil {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	b, err := json.Marshal(runtimeMoveNote{State: p.GetState(), Reason: p.GetReason(), Operator: p.GetOperator(), At: time.Now().UTC()})
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, b, 0o600)
}

// readRuntimeMovePlan reads fileRuntimeMove; ok is false without one.
func readRuntimeMovePlan(read func(string) ([]byte, error), dataDir string) (runtimeMoveNote, bool) {
	var n runtimeMoveNote
	if read == nil || dataDir == "" {
		return n, false
	}
	b, err := read(filepath.Join(dataDir, fileRuntimeMove))
	if err != nil || json.Unmarshal(b, &n) != nil || n.State == "" {
		return n, false
	}
	return n, true
}
