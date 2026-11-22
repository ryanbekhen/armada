package agent

import (
	"testing"
	"time"
)

// After a session ends, the agent asks every second while the servers
// elect a new leader, then backs off as before.
func TestReconnectWait(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 22, 9, 31, 30, 0, time.UTC)
	wait, backoff, lost := reconnectWait(true, 8*time.Second, time.Time{}, now)
	if wait != reconnectDelay || backoff != time.Second || !lost.Equal(now) {
		t.Errorf("after an accepted session: %s %s %s", wait, backoff, lost)
	}
	for i := range 20 {
		at := now.Add(time.Duration(i) * 5 * time.Second)
		if wait, backoff, _ = reconnectWait(false, backoff, lost, at); wait < failoverRetry || wait > failoverRetry*5/4 || backoff != time.Second {
			t.Fatalf("%s into a failover: wait %s, backoff %s", at.Sub(now), wait, backoff)
		}
	}
	// Past the window, failures back off up to maxBackoff.
	at := now.Add(failoverWindow)
	var waits []time.Duration
	for range 7 {
		wait, backoff, _ = reconnectWait(false, backoff, lost, at)
		waits = append(waits, wait)
	}
	if waits[0] != time.Second || waits[1] != 2*time.Second || waits[6] != maxBackoff {
		t.Errorf("backoff after the window: %v", waits)
	}
	// Before any session (a machine starting), failures back off at once.
	if wait, backoff, _ = reconnectWait(false, time.Second, time.Time{}, now); wait != time.Second || backoff != 2*time.Second {
		t.Errorf("first connection: %s %s", wait, backoff)
	}
}
