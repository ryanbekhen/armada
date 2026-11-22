package server

import (
	"context"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/store"
)

// A drain a previous leader began is counted from this leader's start, so
// nodes whose agent was away during the change get a configuration without
// the replica before it is removed.
func TestFinishDrainCountsFromTermStart(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 11, 22, 9, 31, 43, 0, time.UTC)
	s := &Server{termStart: start, drainTimeout: 10 * time.Second}
	r := store.Replica{ID: "web-r6-aaaaa", DrainingSince: start.Add(-time.Minute)}
	all := []store.Replica{r}

	rc := &reconcileRun{now: start.Add(9 * time.Second)}
	got, err := s.finishDrain(context.Background(), rc, all, r, true)
	if err != nil || len(got) != 1 {
		t.Fatalf("removed %v (%v) before the drain counted from the term start ended", got, err)
	}
	if rc.wake != time.Second {
		t.Errorf("wake in %s, want 1s", rc.wake)
	}

	// A drain this leader began counts from its own start, as before.
	mine := store.Replica{ID: "web-r6-bbbbb", DrainingSince: start.Add(5 * time.Second)}
	rc = &reconcileRun{now: start.Add(12 * time.Second)}
	if got, _ := s.finishDrain(context.Background(), rc, []store.Replica{mine}, mine, true); len(got) != 1 || rc.wake != 3*time.Second {
		t.Errorf("own drain: %v, wake %s", got, rc.wake)
	}

	// While a node is away, a drained replica waits up to awayHold for it.
	rc = &reconcileRun{now: start.Add(30 * time.Second), away: true}
	if got, _ := s.finishDrain(context.Background(), rc, all, r, true); len(got) != 1 || rc.wake != 40*time.Second {
		t.Errorf("node away: %v, wake %s", got, rc.wake)
	}
	// Without hold (apps with volumes) only the drain counts.
	rc = &reconcileRun{now: start.Add(5 * time.Second), away: true}
	if got, _ := s.finishDrain(context.Background(), rc, all, r, false); len(got) != 1 || rc.wake != 5*time.Second {
		t.Errorf("volume app: %v, wake %s", got, rc.wake)
	}
}
