package spec

import (
	"slices"
	"strings"
	"testing"
)

const triggerJob = "kind: job\nname: mailer\nimage: busybox\n"

func TestParseQueueTrigger(t *testing.T) {
	t.Parallel()
	a, err := Parse([]byte(triggerJob + "trigger:\n  queue:\n    type: redis\n    urlSecretRef: redis-url\n    list: mail:outbox\n    perRun: 50\n  pollingInterval: 15s\n  parallelism: 5\n"))
	if err != nil {
		t.Fatal(err)
	}
	q := a.QueueTrigger()
	if q == nil || q.Name() != "mail:outbox" || a.Trigger.PollEvery().Seconds() != 15 || a.Trigger.MaxRuns() != 5 {
		t.Fatalf("trigger = %+v", a.Trigger)
	}
	if !slices.Contains(a.SecretRefs(), "redis-url") {
		t.Errorf("refs %v: the URL's secret is not pinned", a.SecretRefs())
	}
	for length, want := range map[int64]int{0: 0, -3: 0, 1: 1, 50: 1, 51: 2, 249: 5, 10_000: 5} {
		if got := a.Trigger.RunsWanted(length); got != want {
			t.Errorf("RunsWanted(%d) = %d, want %d", length, got, want)
		}
	}

	r, err := Parse([]byte(triggerJob + "trigger:\n  queue:\n    type: rabbitmq\n    urlSecretRef: amqp-url\n    queue: emails\n    perRun: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r.QueueTrigger().Name() != "emails" || r.Trigger.PollEvery() != DefaultPollingInterval || r.Trigger.MaxRuns() != 1 {
		t.Errorf("defaults: %+v", r.Trigger)
	}
	out, err := r.Export()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(out)
	if err != nil || back.QueueTrigger() == nil || back.QueueTrigger().Queue != "emails" {
		t.Errorf("export round trip: %s %v", out, err)
	}
}

func TestQueueTriggerValidation(t *testing.T) {
	t.Parallel()
	redis := "trigger:\n  queue:\n    type: redis\n    urlSecretRef: redis-url\n    list: jobs\n    perRun: 10\n"
	for name, c := range map[string]struct{ doc, field string }{
		"app":           {"name: x\nimage: y\n" + redis, "trigger"},
		"no queue":      {triggerJob + "trigger:\n  parallelism: 2\n", "trigger.queue"},
		"with schedule": {triggerJob + "schedule: \"* * * * *\"\n" + redis, "trigger"},
		"concurrency":   {triggerJob + "concurrency: replace\n" + redis, "concurrency"},
		"tasks":         {triggerJob + "tasks: 2\n" + redis, "tasks"},
		"command type":  {triggerJob + "trigger:\n  queue:\n    type: queue\n    perRun: 1\n", "trigger.queue.type"},
		"no secret":     {triggerJob + "trigger:\n  queue:\n    type: redis\n    list: jobs\n    perRun: 1\n", "trigger.queue.urlSecretRef"},
		"bad secret":    {triggerJob + "trigger:\n  queue:\n    type: redis\n    urlSecretRef: Bad_Name\n    list: jobs\n    perRun: 1\n", "trigger.queue.urlSecretRef"},
		"no list":       {triggerJob + "trigger:\n  queue:\n    type: redis\n    urlSecretRef: u\n    perRun: 1\n", "trigger.queue.list"},
		"queue on redis": {triggerJob + "trigger:\n  queue:\n    type: redis\n    urlSecretRef: u\n    list: a\n    queue: b\n    perRun: 1\n",
			"trigger.queue.queue"},
		"control list":  {triggerJob + "trigger:\n  queue:\n    type: redis\n    urlSecretRef: u\n    list: \"a\\nb\"\n    perRun: 1\n", "trigger.queue.list"},
		"long queue":    {triggerJob + "trigger:\n  queue:\n    type: rabbitmq\n    urlSecretRef: u\n    queue: " + strings.Repeat("q", MaxRabbitMQQueueLen+1) + "\n    perRun: 1\n", "trigger.queue.queue"},
		"no perRun":     {triggerJob + "trigger:\n  queue:\n    type: redis\n    urlSecretRef: u\n    list: a\n", "trigger.queue.perRun"},
		"fast polling":  {triggerJob + redis + "  pollingInterval: 1s\n", "trigger.pollingInterval"},
		"slow polling":  {triggerJob + redis + "  pollingInterval: 1h\n", "trigger.pollingInterval"},
		"parallelism":   {triggerJob + redis + "  parallelism: 51\n", "trigger.parallelism"},
		"negative runs": {triggerJob + redis + "  parallelism: -1\n", "trigger.parallelism"},
		"unknown field": {triggerJob + redis + "  stream: x\n", "stream"},
	} {
		_, err := Parse([]byte(c.doc))
		if err == nil || !strings.Contains(err.Error(), c.field) {
			t.Errorf("%s: err = %v, want one about %s", name, err, c.field)
		}
	}
}

func TestJobTasks(t *testing.T) {
	t.Parallel()
	for doc, want := range map[string][2]int{
		"":                            {1, 1},
		"tasks: 10\n":                 {10, 10},
		"tasks: 10\nparallelism: 3\n": {10, 3},
	} {
		a, err := Parse([]byte(triggerJob + doc))
		if err != nil {
			t.Fatalf("%q: %v", doc, err)
		}
		if got := [2]int{a.JobTasks(), a.JobParallelism()}; got != want {
			t.Errorf("%q: tasks, parallelism = %v, want %v", doc, got, want)
		}
	}
}
