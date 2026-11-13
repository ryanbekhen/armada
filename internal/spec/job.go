package spec

import (
	"fmt"
	"strings"
	"time"

	// Time zones must not depend on what the machine has installed.
	_ "time/tzdata"

	"github.com/robfig/cron/v3"
)

// Job settings (ADR 0019).
const (
	DefaultJobTimeout = time.Hour
	MaxJobTimeout     = 24 * time.Hour
	MinJobTimeout     = time.Second
	MaxJobRetries     = 10
	DefaultJobHistory = 5
	MaxJobHistory     = 50
	MaxJobTasks       = 100
	maxScheduleLen    = 128
	maxTimeZoneLen    = 64
)

// Job concurrency policies: what a scheduled run does while the previous
// one still runs.
const (
	ConcurrencyForbid  = "forbid"
	ConcurrencyReplace = "replace"
)

// cronParser accepts the five standard fields only: no seconds, no
// descriptors, no CRON_TZ prefix (timeZone sets the zone).
var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// Schedule is a parsed job schedule in its time zone.
type Schedule struct {
	s   cron.Schedule
	loc *time.Location
}

// Next returns the first time after t that the schedule fires.
func (s Schedule) Next(t time.Time) time.Time { return s.s.Next(t.In(s.loc)) }

// JobSchedule parses the job's schedule; ok is false for jobs without one.
// It assumes a validated spec.
func (a *App) JobSchedule() (Schedule, bool) {
	if a.Schedule == "" {
		return Schedule{}, false
	}
	s, loc, err := parseSchedule(a.Schedule, a.TimeZone)
	if err != nil {
		return Schedule{}, false
	}
	return Schedule{s: s, loc: loc}, true
}

func parseSchedule(expr, zone string) (cron.Schedule, *time.Location, error) {
	loc := time.UTC
	if zone != "" {
		l, err := time.LoadLocation(zone)
		if err != nil {
			return nil, nil, fmt.Errorf("unknown time zone %q", zone)
		}
		loc = l
	}
	if strings.HasPrefix(expr, "@") || strings.Contains(expr, "TZ=") {
		return nil, nil, fmt.Errorf("use five fields (minute hour day-of-month month day-of-week), and timeZone for the zone")
	}
	s, err := cronParser.Parse(expr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid schedule: %w", err)
	}
	return s, loc, nil
}

// IsJob reports whether the spec is a job.
func (a *App) IsJob() bool { return a.Kind == KindJob }

// JobTimeout is how long one attempt of a run may take.
func (a *App) JobTimeout() time.Duration {
	if a.Timeout == 0 {
		return DefaultJobTimeout
	}
	return a.Timeout.D()
}

// JobHistory is how many finished runs are kept.
func (a *App) JobHistory() int {
	if a.History == nil {
		return DefaultJobHistory
	}
	return *a.History
}

// JobTasks is how many tasks each run has (1 unless tasks is set).
func (a *App) JobTasks() int { return max(a.Tasks, 1) }

// JobParallelism is how many tasks of a run may run at once.
func (a *App) JobParallelism() int {
	if a.Parallelism == 0 {
		return a.JobTasks()
	}
	return min(a.Parallelism, a.JobTasks())
}

// JobConcurrency is the job's concurrency policy.
func (a *App) JobConcurrency() string {
	if a.Concurrency == "" {
		return ConcurrencyForbid
	}
	return a.Concurrency
}

func (v *validator) job(a *App) {
	if !a.IsJob() {
		for field, set := range map[string]bool{
			"schedule": a.Schedule != "", "timeZone": a.TimeZone != "", "timeout": a.Timeout != 0,
			"retries": a.Retries != 0, "concurrency": a.Concurrency != "", "history": a.History != nil,
			"trigger": a.Trigger != nil, "tasks": a.Tasks != 0, "parallelism": a.Parallelism != 0,
		} {
			if set {
				v.add(field, "is only valid for kind: job")
			}
		}
		return
	}
	if a.Ingress != nil && a.Ingress.Type != IngressNone {
		v.add("ingress", "jobs take no traffic; leave ingress out")
	}
	if a.Probes != nil {
		v.add("probes", "jobs have no health checks; leave probes out")
	}
	if a.Drain != 0 {
		v.add("drain", "jobs take no requests; leave drain out")
	}
	if a.Scale != nil {
		v.add("scale", "a job runs one container per run, or per task with tasks; leave scale out")
	}
	if a.Revisions != nil && (a.Revisions.Mode != RevisionsSingle || len(a.Revisions.Traffic) > 0) {
		v.add("revisions", "jobs have no traffic to split; leave revisions out")
	}
	switch {
	case len(a.Schedule) > maxScheduleLen:
		v.add("schedule", "must be at most %d characters", maxScheduleLen)
	case len(a.TimeZone) > maxTimeZoneLen:
		v.add("timeZone", "must be at most %d characters", maxTimeZoneLen)
	case a.Schedule == "" && a.TimeZone != "":
		v.add("timeZone", "needs a schedule")
	case a.Schedule != "":
		if _, _, err := parseSchedule(a.Schedule, a.TimeZone); err != nil {
			v.add("schedule", "%v", err)
		}
	}
	if a.Timeout != 0 && (a.Timeout.D() < MinJobTimeout || a.Timeout.D() > MaxJobTimeout) {
		v.add("timeout", "must be between %s and %s", MinJobTimeout, MaxJobTimeout)
	}
	if a.Retries < 0 || a.Retries > MaxJobRetries {
		v.add("retries", "must be between 0 and %d", MaxJobRetries)
	}
	switch a.Concurrency {
	case "", ConcurrencyForbid, ConcurrencyReplace:
	default:
		v.add("concurrency", "must be %q or %q", ConcurrencyForbid, ConcurrencyReplace)
	}
	if a.History != nil && (*a.History < 1 || *a.History > MaxJobHistory) {
		v.add("history", "must be between 1 and %d", MaxJobHistory)
	}
	switch {
	case a.Tasks < 0 || a.Tasks > MaxJobTasks:
		v.add("tasks", "must be between 1 and %d", MaxJobTasks)
	case a.Parallelism < 0 || a.Parallelism > a.JobTasks():
		v.add("parallelism", "must be between 1 and tasks (%d)", a.JobTasks())
	case a.Tasks > 1 && a.Trigger != nil:
		v.add("tasks", "a job its queue starts runs one task per run; set trigger.parallelism and trigger.perRun instead")
	}
	v.trigger(a)
}
