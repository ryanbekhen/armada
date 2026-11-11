package cli

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

func TestAutoscaleNote(t *testing.T) {
	as := &armadav1.Autoscale{Min: 2, Max: 10, Message: "steady: http 34 of 50 per replica\x1b[2J", Rules: []*armadav1.AutoscaleRule{
		{Type: "http", Target: 50, Current: 34, Measured: true},
		{Type: "cpu", Target: 70},
	}}
	got := autoscaleNote(as)
	want := "2-10 replicas, http 34/50, cpu -/70%: steady: http 34 of 50 per replica [2J"
	if got != want {
		t.Errorf("note = %q, want %q", got, want)
	}
}

func TestAutoscaleNoteQueueSchedule(t *testing.T) {
	as := &armadav1.Autoscale{Min: 1, Max: 6, Rules: []*armadav1.AutoscaleRule{
		{Type: "queue", Target: 100, Current: 450, Measured: true},
		{Type: "schedule", Target: 3},
	}}
	if got, want := autoscaleNote(as), "1-6 replicas, queue 450/100 per replica, schedule 3 (closed)"; got != want {
		t.Errorf("note = %q, want %q", got, want)
	}
	as.Rules[0].Measured = false
	as.Rules[1].Until = timestamppb.New(time.Date(2026, 11, 11, 18, 0, 0, 0, time.Local))
	if got, want := autoscaleNote(as), "1-6 replicas, queue -/100 per replica, schedule 3 until Wed 18:00"; got != want {
		t.Errorf("note = %q, want %q", got, want)
	}
}
