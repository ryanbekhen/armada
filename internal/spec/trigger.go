package spec

import (
	"slices"
	"time"
)

// Trigger starts runs of a job from outside the cluster's own clock: while
// a queue holds work, runs start, each taking a batch (ADR 0040).
type Trigger struct {
	Queue *QueueTrigger `yaml:"queue,omitempty" json:"queue,omitempty"`
	// PollingInterval is how often the queue's length is read; zero means
	// DefaultPollingInterval.
	PollingInterval Duration `yaml:"pollingInterval,omitempty" json:"pollingInterval,omitempty"`
	// Parallelism is the most runs at once; zero means 1.
	Parallelism int `yaml:"parallelism,omitempty" json:"parallelism,omitempty"`
}

// QueueTrigger names the queue: a Redis list or a RabbitMQ queue, with the
// broker's URL in one of the job's secrets, as queue rules do (ADR 0034).
type QueueTrigger struct {
	Type         string `yaml:"type" json:"type"`
	URLSecretRef string `yaml:"urlSecretRef,omitempty" json:"urlSecretRef,omitempty"`
	List         string `yaml:"list,omitempty" json:"list,omitempty"`
	Queue        string `yaml:"queue,omitempty" json:"queue,omitempty"`
	// PerRun is how many messages one run handles: the job wants
	// ⌈length ÷ PerRun⌉ runs.
	PerRun int64 `yaml:"perRun,omitempty" json:"perRun,omitempty"`
}

// Queue trigger bounds (ADR 0040).
const (
	DefaultPollingInterval = 30 * time.Second
	MinPollingInterval     = 10 * time.Second
	MaxPollingInterval     = 10 * time.Minute
	// MaxJobParallelism bounds the runs a trigger keeps at once.
	MaxJobParallelism = 50
)

// QueueTrigger returns the job's queue trigger, or nil.
func (a *App) QueueTrigger() *QueueTrigger {
	if a.Trigger == nil {
		return nil
	}
	return a.Trigger.Queue
}

// Name is the Redis list or the RabbitMQ queue the trigger reads.
func (q *QueueTrigger) Name() string {
	if q.Type == ScaleRabbitMQ {
		return q.Queue
	}
	return q.List
}

// PollEvery is how often the trigger's queue is read.
func (t *Trigger) PollEvery() time.Duration {
	if t == nil || t.PollingInterval == 0 {
		return DefaultPollingInterval
	}
	return t.PollingInterval.D()
}

// MaxRuns is the most runs the trigger keeps at once.
func (t *Trigger) MaxRuns() int {
	if t == nil || t.Parallelism == 0 {
		return 1
	}
	return t.Parallelism
}

// RunsWanted is how many runs a queue of length wants: ⌈length ÷ perRun⌉,
// at most the trigger's parallelism.
func (t *Trigger) RunsWanted(length int64) int {
	q := t.Queue
	if q == nil || length <= 0 || q.PerRun <= 0 {
		return 0
	}
	n := (length + q.PerRun - 1) / q.PerRun
	return int(min(n, int64(t.MaxRuns())))
}

func (v *validator) trigger(a *App) {
	t := a.Trigger
	if t == nil {
		return
	}
	q := t.Queue
	if q == nil {
		v.add("trigger.queue", "is required: the queue whose messages start runs")
		return
	}
	if a.Schedule != "" {
		v.add("trigger", "a job starts runs on a schedule or from a queue, not both; leave schedule out")
	}
	if a.Concurrency != "" {
		v.add("concurrency", "jobs with a trigger keep up to trigger.parallelism runs at once; leave concurrency out")
	}
	set := map[string]bool{"urlSecretRef": q.URLSecretRef != "", "list": q.List != "", "queue": q.Queue != ""}
	allowed := map[string][]string{ScaleRedis: {"urlSecretRef", "list"}, ScaleRabbitMQ: {"urlSecretRef", "queue"}}
	switch q.Type {
	case ScaleRedis:
		v.secretName("trigger.queue.urlSecretRef", q.URLSecretRef)
		v.brokerName("trigger.queue.list", q.List, MaxRedisListLen)
	case ScaleRabbitMQ:
		v.secretName("trigger.queue.urlSecretRef", q.URLSecretRef)
		v.brokerName("trigger.queue.queue", q.Queue, MaxRabbitMQQueueLen)
	default:
		v.add("trigger.queue.type", "must be %q or %q", ScaleRedis, ScaleRabbitMQ)
	}
	if fields, ok := allowed[q.Type]; ok {
		for _, name := range []string{"list", "queue", "urlSecretRef"} {
			if set[name] && !slices.Contains(fields, name) {
				v.add("trigger.queue."+name, "is not valid for %s queues", q.Type)
			}
		}
	}
	if q.PerRun < 1 || q.PerRun > MaxQueueLength {
		v.add("trigger.queue.perRun", "must be between 1 and %d (messages one run handles)", MaxQueueLength)
	}
	if d := t.PollingInterval.D(); d != 0 && (d < MinPollingInterval || d > MaxPollingInterval) {
		v.add("trigger.pollingInterval", "must be between %s and %s", MinPollingInterval, MaxPollingInterval)
	}
	if t.Parallelism != 0 && (t.Parallelism < 1 || t.Parallelism > MaxJobParallelism) {
		v.add("trigger.parallelism", "must be between 1 and %d", MaxJobParallelism)
	}
}
