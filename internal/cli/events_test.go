package cli

import (
	"testing"
	"time"
)

func TestEventTime(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.Local)
	if got := eventTime(now.Add(-time.Hour), now); got != "11:00:00" {
		t.Errorf("today: %q", got)
	}
	if got := eventTime(now.Add(-24*time.Hour), now); got != "Nov 02 12:00:00" {
		t.Errorf("yesterday: %q", got)
	}
}

func TestPrintable(t *testing.T) {
	t.Parallel()
	if got := printable("a\x1b]0;x\x07\nb"); got != "a ]0;x  b" {
		t.Errorf("%q", got)
	}
}
