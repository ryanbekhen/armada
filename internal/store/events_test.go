package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/etcd"
)

func TestEvents(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	t0 := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
	put := func(e Event, replace string) string {
		t.Helper()
		k, err := s.PutEvent(ctx, e, replace)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	crash := put(Event{Kind: "replica", Object: "web-1", App: "web", Node: "n1", Reason: "Crashed", Message: "exit 1", Count: 1, First: t0, Last: t0}, "")
	put(Event{Kind: "node", Object: "n2", Node: "n2", Reason: "Lost", Count: 1, First: t0.Add(time.Minute), Last: t0.Add(time.Minute)}, "")
	// The crash happens again: it moves to the end with its count.
	put(Event{Kind: "replica", Object: "web-1", App: "web", Node: "n1", Reason: "Crashed", Message: "exit 2", Count: 2, First: t0, Last: t0.Add(2 * time.Minute)}, crash)

	all, err := s.ListEvents(ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].Reason != "Lost" || all[1].Count != 2 || all[1].Message != "exit 2" || !all[1].First.Equal(t0) || all[1].App != "web" {
		t.Fatalf("events %+v", all)
	}
	if recent, _ := s.ListEvents(ctx, t0.Add(90*time.Second)); len(recent) != 1 || recent[0].Reason != "Crashed" {
		t.Errorf("since: %+v", recent)
	}

	// Events expire through a lease.
	resp, err := s.c.Get(ctx, s.prefix+all[0].Key)
	if err != nil || len(resp.Kvs) != 1 || resp.Kvs[0].Lease == 0 {
		t.Errorf("event without a lease: %v %v", resp, err)
	}

	if err := s.TrimEvents(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.ListEvents(ctx, time.Time{}); len(left) != 1 || left[0].Reason != "Crashed" {
		t.Errorf("after trim: %+v", left)
	}
}

func TestEventsFenced(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	l, err := etcd.Campaign(ctx, testMember.Client(), 5*time.Second, "cp-events")
	if err != nil {
		t.Fatal(err)
	}
	f := s.Fenced(l.Fence())
	now := time.Now()
	if _, err := f.PutEvent(ctx, Event{Kind: "node", Object: "n1", Reason: "Ready", Count: 1, First: now, Last: now}, ""); err != nil {
		t.Fatal(err)
	}
	if err := l.Resign(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.PutEvent(ctx, Event{Kind: "node", Object: "n1", Reason: "Lost", Count: 1, First: now, Last: now}, ""); !errors.Is(err, ErrNotLeader) {
		t.Errorf("event after the term: %v", err)
	}
}

// Trimming keeps the newest and drops the rest in one range delete.
func TestTrimEventsKeepsNewest(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	t0 := time.Now().Add(-time.Hour)
	for i := range 300 {
		at := t0.Add(time.Duration(i) * time.Second)
		if _, err := s.PutEvent(ctx, Event{Kind: "replica", Object: fmt.Sprintf("r%d", i), Reason: "Started", Count: 1, First: at, Last: at}, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.TrimEvents(ctx, 50); err != nil {
		t.Fatal(err)
	}
	left, err := s.ListEvents(ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 50 || left[0].Object != "r250" || left[49].Object != "r299" {
		t.Errorf("kept %d, first %s", len(left), left[0].Object)
	}
}
