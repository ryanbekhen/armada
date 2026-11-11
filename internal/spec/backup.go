package spec

import (
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"
)

// VolumeBackup schedules backups of a volume to an S3-compatible bucket
// (ADR 0041).
type VolumeBackup struct {
	// Every is the interval between backups; or Schedule (cron) with
	// TimeZone, as jobs.
	Every    Duration `yaml:"every,omitempty" json:"every,omitempty"`
	Schedule string   `yaml:"schedule,omitempty" json:"schedule,omitempty"`
	TimeZone string   `yaml:"timeZone,omitempty" json:"timeZone,omitempty"`
	// Keep says which backups stay.
	Keep BackupKeep `yaml:"keep" json:"keep"`
	// URLSecretRef names the app's secret holding the bucket URL;
	// KeySecretRef the one holding the encryption key.
	URLSecretRef string `yaml:"urlSecretRef" json:"urlSecretRef"`
	KeySecretRef string `yaml:"keySecretRef" json:"keySecretRef"`
	// Stop stops the app's container while the volume is read.
	Stop bool `yaml:"stop,omitempty" json:"stop,omitempty"`
}

// BackupKeep keeps the latest Last backups, and the newest of each of the
// latest Hourly hours, Daily days, Weekly ISO weeks, and Monthly months.
// A plain number in YAML is Last.
type BackupKeep struct {
	Last    int `yaml:"last,omitempty" json:"last,omitempty"`
	Hourly  int `yaml:"hourly,omitempty" json:"hourly,omitempty"`
	Daily   int `yaml:"daily,omitempty" json:"daily,omitempty"`
	Weekly  int `yaml:"weekly,omitempty" json:"weekly,omitempty"`
	Monthly int `yaml:"monthly,omitempty" json:"monthly,omitempty"`
}

// Volume backup bounds.
const (
	MinBackupEvery = 5 * time.Minute
	MaxBackupEvery = 7 * 24 * time.Hour
	// MaxBackupKeep bounds each count of BackupKeep.
	MaxBackupKeep = 1000
	// MinBackupKeyLen is the shortest encryption key.
	MinBackupKeyLen = 32
)

// UnmarshalYAML accepts a number (Last) or a mapping.
func (k *BackupKeep) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		var last int
		if err := n.Decode(&last); err != nil {
			return fmt.Errorf("keep: must be a number or a mapping of last, hourly, daily, weekly, monthly")
		}
		*k = BackupKeep{Last: last}
		return nil
	}
	type plain BackupKeep
	var v plain
	if err := decodeStrict(n, &v); err != nil {
		return err
	}
	*k = BackupKeep(v)
	return nil
}

// MarshalYAML writes a policy of Last alone as its number.
func (k BackupKeep) MarshalYAML() (any, error) {
	if k == (BackupKeep{Last: k.Last}) {
		return k.Last, nil
	}
	type plain BackupKeep
	return plain(k), nil
}

// Next returns when the backup after one at last is due: Every after it,
// or the schedule's first fire after it.
func (b *VolumeBackup) Next(last time.Time) time.Time {
	if b.Every != 0 {
		return last.Add(b.Every.D())
	}
	s, loc, err := parseSchedule(b.Schedule, b.TimeZone)
	if err != nil {
		return time.Time{}
	}
	return s.Next(last.In(loc))
}

// Location is the time zone backups are counted in by Keep.
func (b *VolumeBackup) Location() *time.Location {
	if b.TimeZone != "" {
		if l, err := time.LoadLocation(b.TimeZone); err == nil {
			return l
		}
	}
	return time.UTC
}

func (v *validator) volumeBackup(field string, b *VolumeBackup) {
	switch {
	case b.Every == 0 && b.Schedule == "":
		v.add(field, "needs every or schedule")
	case b.Every != 0 && b.Schedule != "":
		v.add(field, "takes every or schedule, not both")
	case b.Every != 0 && (b.Every.D() < MinBackupEvery || b.Every.D() > MaxBackupEvery):
		v.add(field+".every", "must be from %s to %s", MinBackupEvery, "168h")
	case b.Every != 0 && b.TimeZone != "":
		if len(b.TimeZone) > maxTimeZoneLen {
			v.add(field+".timeZone", "must be at most %d characters", maxTimeZoneLen)
		} else if _, err := time.LoadLocation(b.TimeZone); err != nil {
			v.add(field+".timeZone", "unknown time zone %q", b.TimeZone)
		}
	case b.Schedule != "":
		if len(b.Schedule) > maxScheduleLen {
			v.add(field+".schedule", "must be at most %d characters", maxScheduleLen)
		} else if len(b.TimeZone) > maxTimeZoneLen {
			v.add(field+".timeZone", "must be at most %d characters", maxTimeZoneLen)
		} else if _, _, err := parseSchedule(b.Schedule, b.TimeZone); err != nil {
			v.add(field+".schedule", "%v", err)
		}
	}
	k := b.Keep
	counts := []int{k.Last, k.Hourly, k.Daily, k.Weekly, k.Monthly}
	total := 0
	for _, n := range counts {
		if n < 0 || n > MaxBackupKeep {
			v.add(field+".keep", "each count must be from 0 to %d", MaxBackupKeep)
			total = -1
			break
		}
		total += n
	}
	if total == 0 {
		v.add(field+".keep", "must keep at least one backup")
	}
	v.secretName(field+".urlSecretRef", b.URLSecretRef)
	v.secretName(field+".keySecretRef", b.KeySecretRef)
	if b.URLSecretRef != "" && b.URLSecretRef == b.KeySecretRef {
		v.add(field+".keySecretRef", "must be another secret than urlSecretRef")
	}
}
