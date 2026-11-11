package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/agent"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/volbackup"
)

const backupSpec = `name: web
image: nginx:1
ingress:
  type: external
  port: 80
volumes:
  - name: data
    path: /data
    backup:
      every: 1h
      keep: 2
      urlSecretRef: backup-url
      keySecretRef: backup-key
`

// backupCluster runs one node whose agent writes backups to bucket.
func backupCluster(t *testing.T, bucket *volbackup.Memory) *cluster {
	t.Helper()
	keys := withKeys(t)
	c := newCluster(t, func(cfg *Config) { keys(cfg); cfg.BackupInterval = 50 * time.Millisecond })
	c.agentConfig = func(_ string, cfg *agent.Config) {
		cfg.Buckets = func(volbackup.Target) (volbackup.Objects, error) { return bucket, nil }
	}
	c.addNode("n1", "127.0.0.1")
	for name, v := range map[string]string{"backup-url": "https://AK:SK@s3.example.com/backups/armada", "backup-key": strings.Repeat("k", 32)} {
		if _, err := c.admin.SetSecret(c.ctx, &armadav1.SetSecretRequest{App: "web", Name: name, Value: []byte(v)}); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func volumeOf(c *cluster) *armadav1.Volume {
	resp, err := c.admin.ListVolumes(c.ctx, &armadav1.ListVolumesRequest{App: "web"})
	if err != nil || len(resp.Volumes) != 1 {
		return nil
	}
	return resp.Volumes[0]
}

func TestVolumeBackupsRunAndRestore(t *testing.T) {
	t.Parallel()
	bucket := volbackup.NewMemory()
	c := backupCluster(t, bucket)
	c.deploy(backupSpec)
	c.eventually("web running", func() bool { return len(c.running("web")) == 1 })
	dir := filepath.Join(c.nodes["n1"].volumes, "web", "data")
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The first backup is due at once.
	c.eventually("backed up on schedule", func() bool {
		v := volumeOf(c)
		return v != nil && v.Backup && v.LastBackupAt != nil && v.BackupSnapshots == 1 && v.BackupStoredBytes > 0
	})
	for _, k := range bucket.Keys() {
		if !strings.HasPrefix(k, "armada/web/data/") {
			t.Errorf("object outside the volume's repository: %s", k)
		}
	}
	if v := volumeOf(c); v.NextBackupAt.AsTime().Sub(v.LastBackupAt.AsTime()) != time.Hour {
		t.Errorf("next backup at %v, last at %v", v.NextBackupAt.AsTime(), v.LastBackupAt.AsTime())
	}

	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	made, err := c.admin.CreateVolumeSnapshot(c.ctx, &armadav1.CreateVolumeSnapshotRequest{App: "web", Name: "data"})
	if err != nil {
		t.Fatal(err)
	}
	if made.Snapshot.Files != 1 || made.Snapshots != 2 || made.NewBytes != int64(len("second")) {
		t.Errorf("snapshot = %v", made)
	}
	list, err := c.admin.ListVolumeSnapshots(c.ctx, &armadav1.ListVolumeSnapshotsRequest{App: "web", Name: "data"})
	if err != nil || len(list.Snapshots) != 2 || list.Snapshots[1].Id != made.Snapshot.Id {
		t.Fatalf("list = %v, %v", list, err)
	}
	first := list.Snapshots[0].Id

	// keep: 2 drops the oldest.
	if _, err := c.admin.CreateVolumeSnapshot(c.ctx, &armadav1.CreateVolumeSnapshotRequest{App: "web", Name: "data"}); err != nil {
		t.Fatal(err)
	}
	if list, _ := c.admin.ListVolumeSnapshots(c.ctx, &armadav1.ListVolumeSnapshotsRequest{App: "web", Name: "data"}); len(list.Snapshots) != 2 || list.Snapshots[0].Id == first {
		t.Errorf("after a third backup: %v", list.Snapshots)
	}

	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("lost"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.admin.RestoreVolumeSnapshot(c.ctx, &armadav1.RestoreVolumeSnapshotRequest{App: "web", Name: "data", Snapshot: made.Snapshot.Id}); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "notes.txt")); err != nil || string(b) != "second" {
		t.Fatalf("restored %q, %v", b, err)
	}
	c.eventually("running again after the restore", func() bool { return runningContainers(c, "web") == 1 })
}

func TestVolumeBackupFailureIsRecorded(t *testing.T) {
	t.Parallel()
	bucket := volbackup.NewMemory()
	bucket.FailPut = func(string) bool { return true }
	c := backupCluster(t, bucket)
	c.deploy(backupSpec)
	c.eventually("the failure is on the volume", func() bool {
		v := volumeOf(c)
		return v != nil && v.BackupFailedAt != nil && strings.Contains(v.BackupError, "refused") && v.LastBackupAt == nil
	})
	c.eventually("a VolumeBackupFailed event", func() bool {
		ev, err := c.store.ListEvents(c.ctx, time.Time{})
		if err != nil {
			return false
		}
		for _, e := range ev {
			if e.Reason == "VolumeBackupFailed" && e.App == "web" {
				return true
			}
		}
		return false
	})
	// Retried after backupRetry, not every pass.
	v := volumeOf(c)
	if got := v.NextBackupAt.AsTime().Sub(v.BackupFailedAt.AsTime()); got != backupRetry {
		t.Errorf("retry after %v", got)
	}

	bucket.FailPut = nil
	if _, err := c.admin.CreateVolumeSnapshot(c.ctx, &armadav1.CreateVolumeSnapshotRequest{App: "web", Name: "data"}); err != nil {
		t.Fatal(err)
	}
	if v := volumeOf(c); v.BackupFailedAt != nil || v.BackupError != "" || v.LastBackupAt == nil {
		t.Errorf("a success did not clear the failure: %v", v)
	}
}

func TestVolumeSnapshotNeedsBackupSpec(t *testing.T) {
	t.Parallel()
	c := backupCluster(t, volbackup.NewMemory())
	c.deploy(volumeSpec("nginx:1"))
	c.eventually("web running", func() bool { return len(c.running("web")) == 1 })
	_, err := c.admin.CreateVolumeSnapshot(c.ctx, &armadav1.CreateVolumeSnapshotRequest{App: "web", Name: "data"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "no backup") {
		t.Errorf("snapshot without backup: %v", err)
	}
	if v := volumeOf(c); v.Backup || v.LastBackupAt != nil {
		t.Errorf("volume = %v", v)
	}
	if _, err := c.admin.RestoreVolumeSnapshot(c.ctx, &armadav1.RestoreVolumeSnapshotRequest{App: "web", Name: "data", Snapshot: ""}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("restore without a backup name: %v", err)
	}
	_ = store.ErrNotFound
}
