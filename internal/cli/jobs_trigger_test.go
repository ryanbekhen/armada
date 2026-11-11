package cli

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

func TestJobTriggerLines(t *testing.T) {
	t.Parallel()
	now := time.Now()
	tr := &armadav1.JobTrigger{Type: "redis", Name: "mail:outbox", PerRun: 50, Parallelism: 5, PollingIntervalSeconds: 30}
	if got := jobSchedule(&armadav1.JobInfo{Trigger: tr}); got != "queue (redis mail:outbox)" {
		t.Errorf("list column = %q", got)
	}
	if got := triggerLine(tr); got != "redis list mail:outbox, 50 per run, at most 5 at once, read every 30s" {
		t.Errorf("trigger = %q", got)
	}
	if got := triggerLine(&armadav1.JobTrigger{Type: "rabbitmq", Name: "emails", PerRun: 1, Parallelism: 1, PollingIntervalSeconds: 600}); got != "rabbitmq queue emails, 1 per run, at most 1 at once, read every 10m" {
		t.Errorf("trigger = %q", got)
	}
	for want, q := range map[string]*armadav1.JobTrigger{
		"not read: no node can (see armada cluster events)": {},
		"not read yet, from n1":                             {Node: "n1"},
		"120 waiting, read 5s ago from n1":                  {Node: "n1", Measured: true, Length: 120, MeasuredAt: timestamppb.New(now.Add(-5 * time.Second))},
	} {
		if got := queueLine(q, now); got != want {
			t.Errorf("queue = %q, want %q", got, want)
		}
	}
}
