package store

import (
	"context"
	"testing"
	"time"
)

// A report that only says the node is still there writes nothing for a
// while; anything else it changes is written at once.
func TestSetNodeStatusSkipsHeartbeats(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.UpsertNode(ctx, Node{ID: "hb", PrivateIP: "10.0.0.9"}); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	st := NodeStatus{State: NodeReady, LastSeen: t0, CPUMillis: 1000, MemoryBytes: 1 << 30}
	if err := s.SetNodeStatus(ctx, "hb", st); err != nil {
		t.Fatal(err)
	}
	var ops int
	s.onCommit = func(n int) { ops++ }
	defer func() { s.onCommit = nil }()
	st.LastSeen = t0.Add(10 * time.Second)
	if err := s.SetNodeStatus(ctx, "hb", st); err != nil || ops != 0 {
		t.Errorf("heartbeat wrote %d transactions (%v)", ops, err)
	}
	st.LastSeen = t0.Add(time.Minute)
	if err := s.SetNodeStatus(ctx, "hb", st); err != nil || ops != 1 {
		t.Errorf("a stale LastSeen was not refreshed: %d (%v)", ops, err)
	}
	st.CPUMillis = 2000
	st.LastSeen = t0.Add(time.Minute + time.Second)
	if err := s.SetNodeStatus(ctx, "hb", st); err != nil || ops != 2 {
		t.Errorf("a capacity change was not written: %d (%v)", ops, err)
	}
	n, _ := s.GetNode(ctx, "hb")
	if n.CPUMillis != 2000 {
		t.Errorf("stored %+v", n)
	}
}
