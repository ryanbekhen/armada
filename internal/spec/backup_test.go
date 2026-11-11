package spec

import (
	"strings"
	"testing"
	"time"
)

const backupBase = `name: db
image: postgres:18
volumes:
  - name: data
    path: /var/lib/postgresql/data
    backup:
`

func TestVolumeBackupParsesAndExports(t *testing.T) {
	t.Parallel()
	a, err := Parse([]byte(backupBase + "      every: 1h\n      keep: 24\n      urlSecretRef: backup-url\n      keySecretRef: backup-key\n"))
	if err != nil {
		t.Fatal(err)
	}
	b := a.Volumes[0].Backup
	if b.Every.D() != time.Hour || b.Keep != (BackupKeep{Last: 24}) {
		t.Fatalf("backup = %+v", b)
	}
	out, err := a.Export()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "keep: 24\n") {
		t.Errorf("keep not exported as a number:\n%s", out)
	}
	if refs := strings.Join(a.SecretRefs(), ","); refs != "backup-key,backup-url" {
		t.Errorf("secret refs = %s", refs)
	}
	last := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	if b.Next(last) != last.Add(time.Hour) {
		t.Errorf("next = %v", b.Next(last))
	}

	a, err = Parse([]byte(backupBase + "      schedule: \"0 2 * * *\"\n      timeZone: Asia/Jakarta\n      keep: {hourly: 24, daily: 7}\n      urlSecretRef: backup-url\n      keySecretRef: backup-key\n      stop: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	b = a.Volumes[0].Backup
	if b.Keep != (BackupKeep{Hourly: 24, Daily: 7}) || !b.Stop || b.Location().String() != "Asia/Jakarta" {
		t.Fatalf("backup = %+v", b)
	}
	// 02:00 in Jakarta is 19:00 UTC.
	if got := b.Next(last).UTC(); got != time.Date(2026, 11, 11, 19, 0, 0, 0, time.UTC) {
		t.Errorf("next = %v", got)
	}
	out, _ = a.Export()
	back, err := Parse(out)
	if err != nil || back.Volumes[0].Backup.Keep != b.Keep {
		t.Errorf("round trip: %v\n%s", err, out)
	}
}

func TestVolumeBackupValidation(t *testing.T) {
	t.Parallel()
	secrets := "      urlSecretRef: backup-url\n      keySecretRef: backup-key\n"
	for _, tc := range []struct{ body, want string }{
		{"      keep: 3\n" + secrets, "needs every or schedule"},
		{"      every: 1h\n      schedule: \"0 * * * *\"\n      keep: 3\n" + secrets, "not both"},
		{"      every: 1m\n      keep: 3\n" + secrets, "every: must be from"},
		{"      every: 200h\n      keep: 3\n" + secrets, "every: must be from"},
		{"      every: 1h\n" + secrets, "keep: must keep at least one"},
		{"      every: 1h\n      keep: 1001\n" + secrets, "keep: each count"},
		{"      every: 1h\n      keep: {last: -1, daily: 2}\n" + secrets, "keep: each count"},
		{"      every: 1h\n      keep: {yearly: 2}\n" + secrets, "yearly"},
		{"      every: 1h\n      keep: lots\n" + secrets, "keep: must be a number"},
		{"      every: 1h\n      keep: 3\n      urlSecretRef: backup-url\n", "keySecretRef"},
		{"      every: 1h\n      keep: 3\n      urlSecretRef: same\n      keySecretRef: same\n", "must be another secret"},
		{"      schedule: \"0 2 * * *\"\n      timeZone: Mars/Base\n      keep: 3\n" + secrets, "unknown time zone"},
		{"      every: 1h\n      timeZone: Mars/Base\n      keep: 3\n" + secrets, "unknown time zone"},
	} {
		_, err := Parse([]byte(backupBase + tc.body))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v, want %q", tc.body, err, tc.want)
		}
	}
}

func TestEnvFromLeavesBackupSecretsOut(t *testing.T) {
	t.Parallel()
	a, err := Parse([]byte("name: db\nimage: postgres:18\nenvFrom: secrets\nvolumes:\n  - name: data\n    path: /data\n    backup:\n      every: 1h\n      keep: 3\n      urlSecretRef: backup-url\n      keySecretRef: backup-key\n"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.WithSecretEnv([]string{"backup-url", "backup-key", "password"})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Env) != 1 || c.Env[0].Name != "PASSWORD" {
		t.Errorf("env = %+v", c.Env)
	}
}
