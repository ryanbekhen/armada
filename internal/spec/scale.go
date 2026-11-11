package spec

import "time"

// maxWindowChain bounds how many back-to-back fires extend one schedule
// window: a window that starts again before it ends runs on.
const maxWindowChain = 64

// IsQueue reports whether the rule reads a queue's length (ADR 0034).
func (r ScaleRule) IsQueue() bool {
	return r.Type == ScaleQueue || r.Type == ScaleRedis || r.Type == ScaleRabbitMQ
}

// QueueRules returns the app's rules that read a queue's length.
func (a *App) QueueRules() []ScaleRule {
	if !a.Autoscaled() {
		return nil
	}
	var out []ScaleRule
	for _, r := range a.Scale.Rules {
		if r.IsQueue() {
			out = append(out, r)
		}
	}
	return out
}

// Window reports whether a schedule rule's window is open at now, and when
// it closes: each fire of the schedule opens a window of Duration, and a
// fire inside an open window keeps it open for Duration from that fire. It
// assumes a validated rule; any other rule is never open.
func (r ScaleRule) Window(now time.Time) (open bool, until time.Time) {
	if r.Type != ScaleSchedule {
		return false, time.Time{}
	}
	s, loc, err := parseSchedule(r.Schedule, r.TimeZone)
	if err != nil {
		return false, time.Time{}
	}
	d := r.Duration.D()
	// The first fire after now-d is the earliest that can still be open.
	start := s.Next(now.Add(-d).In(loc))
	if start.After(now) {
		return false, time.Time{}
	}
	until = start.Add(d)
	for range maxWindowChain {
		next := s.Next(start)
		if !next.Before(until) {
			break
		}
		start, until = next, next.Add(d)
	}
	return true, until
}
