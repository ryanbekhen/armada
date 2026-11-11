package spec

import (
	"testing"
	"time"
)

func TestScheduleWindow(t *testing.T) {
	t.Parallel()
	jkt, _ := time.LoadLocation("Asia/Jakarta")
	r := ScaleRule{Type: ScaleSchedule, Schedule: "0 8 * * 1-5", TimeZone: "Asia/Jakarta", Duration: Duration(10 * time.Hour), Replicas: 3}
	at := func(day, h, m int) time.Time { return time.Date(2026, 11, day, h, m, 0, 0, jkt) } // 2026-11-11 is a Wednesday
	for _, tt := range []struct {
		name  string
		now   time.Time
		open  bool
		until time.Time
	}{
		{"before", at(11, 7, 59), false, time.Time{}},
		{"at the fire", at(11, 8, 0), true, at(11, 18, 0)},
		{"inside", at(11, 17, 59), true, at(11, 18, 0)},
		{"closed", at(11, 18, 0), false, time.Time{}},
		{"saturday", at(14, 9, 0), false, time.Time{}},
		{"utc clock", at(11, 12, 0).UTC(), true, at(11, 18, 0)},
	} {
		open, until := r.Window(tt.now)
		if open != tt.open || !until.Equal(tt.until) {
			t.Errorf("%s: open=%v until=%v, want %v %v", tt.name, open, until, tt.open, tt.until)
		}
	}
	// Fires inside an open window keep it open: every 30 minutes for an hour.
	chain := ScaleRule{Type: ScaleSchedule, Schedule: "*/30 * * * *", Duration: Duration(time.Hour), Replicas: 2}
	now := time.Date(2026, 11, 11, 10, 5, 0, 0, time.UTC)
	if open, until := chain.Window(now); !open || until.Before(now.Add(time.Hour)) {
		t.Errorf("chained window: open=%v until=%v", open, until)
	}
	if open, _ := (ScaleRule{Type: ScaleCPU}).Window(now); open {
		t.Error("a cpu rule has a window")
	}
}
