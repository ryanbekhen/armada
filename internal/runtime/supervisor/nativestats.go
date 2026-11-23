package supervisor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// StatResult is armada-node's sample of one container (ADR 0054 step 4,
// fifth part): what the driver's Stats returns for it, its NotFound, or
// Redo when Go must sample it itself (an error Go words, or a shim Go
// would find gone and end the containers of).
type StatResult struct {
	Stats    runtime.Stats
	NotFound bool
	Redo     bool
}

// nativeStats is what `runtime stats` reads.
type nativeStats struct {
	Dir        string   `json:"dir"`
	ShimDir    string   `json:"shimDir"`
	CgroupRoot string   `json:"cgroupRoot"`
	Proc       string   `json:"proc"`
	IDs        []string `json:"ids"`
	TimeoutMs  int64    `json:"timeoutMs,omitempty"`
}

// NativeStats samples the containers ids in one call to armada-node, as
// the driver samples each: its shim's state, its cgroup, the counters of
// its network namespace (under procRoot), and a replica's members added.
// ok is false when Go must sample every one: the node is not on
// armada-node, or the call failed (logged once per distinct failure).
func (s *Store) NativeStats(ctx context.Context, ids []string, procRoot string) ([]StatResult, bool) {
	n := s.Native
	if n == nil {
		return nil, false
	}
	var out struct {
		Stats []struct {
			CPU         int64   `json:"cpu"`
			Memory      int64   `json:"memory"`
			Egress      int64   `json:"egress"`
			NetworkLost bool    `json:"networkLost"`
			OOMKills    int64   `json:"oomKills"`
			NotFound    bool    `json:"notFound"`
			Redo        *string `json:"redo"`
		} `json:"stats"`
	}
	req := nativeStats{Dir: s.Bundles.Dir, ShimDir: s.Shims.Dir, CgroupRoot: s.cgroupRoot(), Proc: procRoot, IDs: ids, TimeoutMs: timeoutMs(ctx)}
	err := n.run(ctx, req, &out, "runtime", "stats")
	if err == nil && len(out.Stats) != len(ids) {
		err = programError{fmt.Errorf("%d samples for %d containers", len(out.Stats), len(ids))}
	}
	if err != nil {
		if ctx.Err() == nil {
			var perr programError
			if !errors.As(err, &perr) {
				err = programError{err}
			}
			n.fallback("stats", err)
		}
		return nil, false
	}
	n.fallback("stats", nil)
	res := make([]StatResult, len(ids))
	for i, a := range out.Stats {
		switch {
		case a.Redo != nil:
			res[i].Redo = true
			n.mu.Lock()
			n.standIn("stats")
			n.mu.Unlock()
		case a.NotFound:
			res[i].NotFound = true
		default:
			res[i].Stats = runtime.Stats{
				CPU: time.Duration(a.CPU), MemoryBytes: a.Memory, EgressBytes: a.Egress,
				NetworkLost: a.NetworkLost, OOMKills: a.OOMKills,
			}
		}
	}
	return res, true
}
