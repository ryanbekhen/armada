package cli

import (
	"testing"

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
