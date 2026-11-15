package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/agent"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/volbackup"
)

const failoverSpec = backupSpec + "    failover: restore\n"

// failoverCluster runs a node sharing one bucket; tests add more.
func failoverCluster(t *testing.T, bucket *volbackup.Memory) *cluster {
	t.Helper()
	return failoverClusterWith(t, bucket, nil)
}

// failoverClusterWith is failoverCluster with more agent settings.
func failoverClusterWith(t *testing.T, bucket *volbackup.Memory, more func(*agent.Config)) *cluster {
	t.Helper()
	keys := withKeys(t)
	c := newCluster(t, func(cfg *Config) {
		keys(cfg)
		cfg.BackupInterval = 50 * time.Millisecond
		cfg.NodeLostTimeout = 300 * time.Millisecond
	})
	c.agentConfig = func(_ string, cfg *agent.Config) {
		cfg.Buckets = func(volbackup.Target) (volbackup.Objects, error) { return bucket, nil }
		if more != nil {
			more(cfg)
		}
	}
	c.addNode("n1", "127.0.0.1")
	for name, v := range map[string]string{"backup-url": "https://AK:SK@s3.example.com/backups", "backup-key": strings.Repeat("k", 32)} {
		if _, err := c.admin.SetSecret(c.ctx, &armadav1.SetSecretRequest{App: "web", Name: name, Value: []byte(v)}); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func webEvent(c *cluster, reason string) bool {
	evs, _ := c.store.ListEvents(c.ctx, time.Time{})
	for _, e := range evs {
		if e.Reason == reason && e.App == "web" {
			return true
		}
	}
	return false
}

func TestVolumeFailsOverToAnotherNode(t *testing.T) {
	t.Parallel()
	bucket := volbackup.NewMemory()
	c := failoverCluster(t, bucket)
	c.deploy(failoverSpec)
	c.eventually("web running on n1", func() bool { r := c.running("web"); return len(r) == 1 && r[0].NodeId == "n1" })
	c.addNode("n2", "127.0.0.2")
	c.addNode("n3", "127.0.0.3")

	cs, _ := c.nodes["n1"].d.List(c.ctx, map[string]string{runtime.LabelApp: "web"})
	if len(cs) != 1 || cs[0].Labels[runtime.LabelFenceAfter] != "1" {
		t.Fatalf("the replica has no fence time: %v", cs)
	}
	if err := os.WriteFile(filepath.Join(c.nodes["n1"].volumes, "web", "data", "notes.txt"), []byte("saved"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.admin.CreateVolumeSnapshot(c.ctx, &armadav1.CreateVolumeSnapshotRequest{App: "web", Name: "data"}); err != nil {
		t.Fatal(err)
	}

	c.stopAgent("n1")
	c.eventually("the volume moved", func() bool {
		v := volumeOf(c)
		return v != nil && v.Node != "n1"
	})
	to := volumeOf(c).Node
	c.eventually("web running on "+to, func() bool { r := c.running("web"); return len(r) == 1 && r[0].NodeId == to })
	b, err := os.ReadFile(filepath.Join(c.nodes[to].volumes, "web", "data", "notes.txt"))
	if err != nil || string(b) != "saved" {
		t.Fatalf("restored %q, %v", b, err)
	}
	if !webEvent(c, "VolumeFailedOver") {
		t.Error("no VolumeFailedOver event")
	}
	audit, _ := c.store.ListAudit(c.ctx, 50)
	found := false
	for _, a := range audit {
		if a.Actor == failoverActor && a.Action == "volume.bind" {
			found = true
		}
	}
	if !found {
		t.Error("the rebinding is not in the audit log")
	}
}

// An NFS volume next to failing-over local ones has no backup: failover
// restores and binds only the local ones and the server keeps running.
func TestVolumeFailoverSkipsNFSVolumes(t *testing.T) {
	t.Parallel()
	bucket := volbackup.NewMemory()
	c := failoverClusterWith(t, bucket, func(cfg *agent.Config) {
		cfg.NFSDir = t.TempDir()
		cfg.MountNFS = func(context.Context, string, string, string, bool) error { return nil }
	})
	c.deploy(strings.Replace(failoverSpec, "volumes:\n", "volumes:\n  - name: shared\n    path: /shared\n    nfs:\n      server: 10.0.0.21\n      path: /exports/shared\n", 1))
	c.eventually("web running on n1", func() bool { r := c.running("web"); return len(r) == 1 && r[0].NodeId == "n1" })
	c.addNode("n2", "127.0.0.2")
	if err := os.WriteFile(filepath.Join(c.nodes["n1"].volumes, "web", "data", "notes.txt"), []byte("saved"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The scheduled first backup may still be running.
	c.eventually("a backup holding the file", func() bool {
		_, err := c.admin.CreateVolumeSnapshot(c.ctx, &armadav1.CreateVolumeSnapshotRequest{App: "web", Name: "data"})
		return err == nil
	})

	c.stopAgent("n1")
	c.eventually("the local volume moved to n2", func() bool {
		v := volumeOf(c)
		return v != nil && v.Name == "data" && v.Node == "n2"
	})
	c.eventually("web running on n2", func() bool { r := c.running("web"); return len(r) == 1 && r[0].NodeId == "n2" })
	if b, err := os.ReadFile(filepath.Join(c.nodes["n2"].volumes, "web", "data", "notes.txt")); err != nil || string(b) != "saved" {
		t.Fatalf("restored %q, %v", b, err)
	}
	if !webEvent(c, "VolumeFailedOver") {
		t.Error("no VolumeFailedOver event")
	}
}

func TestBackupTargetRefusesNoBackup(t *testing.T) {
	t.Parallel()
	s := &Server{}
	if _, err := s.backupTarget(context.Background(), nil, store.Revision{}); err == nil {
		t.Fatal("a volume without a backup got a target")
	}
}

func TestVolumeFailoverWithoutBackupsWaits(t *testing.T) {
	t.Parallel()
	bucket := volbackup.NewMemory()
	bucket.FailPut = func(string) bool { return true }
	c := failoverCluster(t, bucket)
	c.deploy(failoverSpec)
	c.eventually("web running on n1", func() bool { r := c.running("web"); return len(r) == 1 && r[0].NodeId == "n1" })
	c.addNode("n2", "127.0.0.2")
	c.addNode("n3", "127.0.0.3")
	c.stopAgent("n1")
	c.eventually("VolumeFailoverFailed", func() bool { return webEvent(c, "VolumeFailoverFailed") })
	time.Sleep(300 * time.Millisecond)
	if v := volumeOf(c); v == nil || v.Node != "n1" {
		t.Errorf("the volume moved without a backup: %v", v)
	}
}

func TestFenceAfterIsHalfTheNodeLostTimeout(t *testing.T) {
	t.Parallel()
	s := &Server{nodeLostTimeout: 5 * time.Minute}
	if got := s.fenceAfter(); got != 150 {
		t.Errorf("fence after %d s", got)
	}
	s.nodeLostTimeout = 10 * time.Second
	if got := s.fenceAfter(); got != 5 {
		t.Errorf("fence after %d s", got)
	}
	_ = context.Background
}
