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
	"github.com/ryanbekhen/armada/internal/volbackup"
)

const failoverSpec = backupSpec + "    failover: restore\n"

// failoverCluster runs three nodes sharing one bucket.
func failoverCluster(t *testing.T, bucket *volbackup.Memory) *cluster {
	t.Helper()
	keys := withKeys(t)
	c := newCluster(t, func(cfg *Config) {
		keys(cfg)
		cfg.BackupInterval = 50 * time.Millisecond
		cfg.NodeLostTimeout = 300 * time.Millisecond
	})
	c.agentConfig = func(_ string, cfg *agent.Config) {
		cfg.Buckets = func(volbackup.Target) (volbackup.Objects, error) { return bucket, nil }
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
