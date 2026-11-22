package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// backupPlanFlags change when the control plane is backed up, together
// (ADR 0051).
var backupPlanFlags = []string{"backup-every", "backup-schedule", "backup-time-zone"}

// backupFlags are the control plane backup flags of cluster update.
type backupFlags struct {
	every                    time.Duration
	schedule, keep, url, key string
	off                      string
}

// backupRequest checks the backup flags of cluster update and puts the keep
// policy, the URL, and the key into the request (the plan is filled once
// the current settings are known).
func backupRequest(cmd *cobra.Command, req *armadav1.SetClusterConfigRequest, f backupFlags) error {
	ch := cmd.Flags().Changed
	if ch("backup") && f.off != "none" {
		return errors.New("--backup takes only none, which turns control plane backups off")
	}
	if ch("backup-every") && ch("backup-schedule") {
		return errors.New("give --backup-every or --backup-schedule, not both")
	}
	if ch("backup-url") && ch("backup-key") && f.url == "-" && f.key == "-" {
		return errors.New("only one of --backup-url and --backup-key can read stdin")
	}
	if ch("backup-keep") {
		k, err := parseBackupKeep(f.keep)
		if err != nil {
			return err
		}
		req.Config.BackupKeep = k
	}
	if ch("backup-url") {
		// Never from an argument: the URL holds the bucket's keys.
		v, err := readTokenArg(cmd, "--backup-url", f.url)
		if err != nil {
			return err
		}
		req.BackupUrl = v
	}
	if ch("backup-key") {
		v, err := readTokenArg(cmd, "--backup-key", f.key)
		if err != nil {
			return err
		}
		req.BackupKey = v
	}
	return nil
}

// parseBackupKeep reads a keep policy: a number of the latest backups, or
// last=N,hourly=N,daily=N,weekly=N,monthly=N.
func parseBackupKeep(s string) (*armadav1.BackupKeep, error) {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseInt(s, 10, 32); err == nil {
		return &armadav1.BackupKeep{Last: int32(n)}, nil
	}
	k := &armadav1.BackupKeep{}
	for part := range strings.SplitSeq(s, ",") {
		name, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		n, err := strconv.ParseInt(v, 10, 32)
		if !ok || err != nil {
			return nil, fmt.Errorf("--backup-keep %q: want a number, or last=N,hourly=N,daily=N,weekly=N,monthly=N", s)
		}
		switch name {
		case "last":
			k.Last = int32(n)
		case "hourly":
			k.Hourly = int32(n)
		case "daily":
			k.Daily = int32(n)
		case "weekly":
			k.Weekly = int32(n)
		case "monthly":
			k.Monthly = int32(n)
		default:
			return nil, fmt.Errorf("--backup-keep: unknown %q (want last, hourly, daily, weekly, or monthly)", name)
		}
	}
	return k, nil
}

// keepText says what a keep policy keeps.
func keepText(k *armadav1.BackupKeep) string {
	var parts []string
	for _, p := range []struct {
		n    int32
		what string
	}{{k.GetLast(), "latest"}, {k.GetHourly(), "hourly"}, {k.GetDaily(), "daily"}, {k.GetWeekly(), "weekly"}, {k.GetMonthly(), "monthly"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.what))
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// backupWhen says when the control plane is backed up.
func backupWhen(cc *armadav1.ClusterConfig) string {
	when := "every " + humanDuration(time.Duration(cc.BackupEverySeconds)*time.Second)
	if cc.BackupSchedule != "" {
		when = "on " + cc.BackupSchedule
	}
	if cc.BackupTimeZone != "" {
		when += " (" + cc.BackupTimeZone + ")"
	}
	return when
}

// backupStatusLine says how the control plane's backups go.
func backupStatusLine(b *armadav1.ControlPlaneBackupStatus) string {
	at := func(t interface{ AsTime() time.Time }) string { return t.AsTime().Local().Format(time.DateTime) }
	line := "backups: to " + b.Bucket
	if b.LastAt != nil {
		line += fmt.Sprintf(", last %s on %s (%s, %d kept, %s stored)", at(b.LastAt), dash(b.LastServer), diskBytes(b.LastSizeBytes), b.Snapshots, diskBytes(b.StoredBytes))
	} else {
		line += ", none yet"
	}
	if b.NextAt != nil {
		line += ", next " + at(b.NextAt)
	}
	if b.Error != "" {
		line += fmt.Sprintf("\nbackup failed at %s: %s", at(b.FailedAt), printable(b.Error))
	}
	return line
}
