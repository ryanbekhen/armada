package store

import (
	"context"
	"errors"
	"testing"
)

func TestVolumes(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	for _, id := range []string{"n1", "n2"} {
		if err := s.UpsertNode(ctx, Node{ID: id, PrivateIP: "10.0.0.1"}); err != nil {
			t.Fatal(err)
		}
	}
	r1 := deployJob(t, s, "name: db\nimage: postgres:17\nvolumes:\n  - name: data\n    path: /var/lib/postgresql/data\n")

	// The first replica binds the volume to its node; others must follow.
	if err := s.CreateReplica(ctx, Replica{ID: "db-1", App: "db", Revision: r1.Name, NodeID: "n1"}); err != nil {
		t.Fatal(err)
	}
	v, err := s.GetVolume(ctx, "db", "data")
	if err != nil || v.Node != "n1" || v.CreatedAt.IsZero() {
		t.Fatalf("bound: %+v %v", v, err)
	}
	if err := s.CreateReplica(ctx, Replica{ID: "db-2", App: "db", Revision: r1.Name, NodeID: "n2"}); !errors.Is(err, ErrPrecondition) {
		t.Errorf("replica on another node: %v", err)
	}
	if err := s.CreateReplica(ctx, Replica{ID: "db-3", App: "db", Revision: r1.Name, NodeID: "n1"}); err != nil {
		t.Errorf("replica on the volume's node: %v", err)
	}

	// Removing is refused while the spec mounts it, and the node keeps it.
	if err := s.DeleteVolume(ctx, "db", "data", "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("delete in use: %v", err)
	}
	if err := s.RemoveNode(ctx, "n1", false, "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("remove node with replicas: %v", err)
	}

	// Rebinding for a restore elsewhere.
	if err := s.BindVolume(ctx, "db", "data", "ghost", "admin:test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("bind to unknown node: %v", err)
	}
	if err := s.BindVolume(ctx, "db", "data", "n2", "admin:test"); err != nil {
		t.Fatal(err)
	}
	if v2, _ := s.GetVolume(ctx, "db", "data"); v2.Node != "n2" || !v2.CreatedAt.Equal(v.CreatedAt) {
		t.Errorf("after bind: %+v", v2)
	}

	// Redeployed without the volume: it stays until removed.
	deployJob(t, s, "name: db\nimage: postgres:17\n")
	if err := s.CompleteRollout(ctx, "db", "db--r2"); err != nil {
		t.Fatal(err)
	}
	vols, _ := s.ListVolumes(ctx, "")
	if len(vols) != 1 {
		t.Fatalf("volumes %+v", vols)
	}
	if err := s.DeleteVolume(ctx, "db", "data", "admin:test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetVolume(ctx, "db", "data"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
	if err := s.DeleteVolume(ctx, "db", "data", "admin:test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete twice: %v", err)
	}
}

func TestRemoveNodeWithVolumes(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	if err := s.UpsertNode(ctx, Node{ID: "n1", PrivateIP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.BindVolume(ctx, "db", "data", "n1", "admin:test"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveNode(ctx, "n1", false, "admin:test"); !errors.Is(err, ErrPrecondition) {
		t.Errorf("remove node holding a volume: %v", err)
	}
	if err := s.RemoveNode(ctx, "n1", true, "admin:test"); err != nil {
		t.Fatal(err)
	}
	if v, err := s.GetVolume(ctx, "db", "data"); err != nil || v.Node != "n1" {
		t.Errorf("forced removal dropped the record: %+v %v", v, err)
	}
}

func TestRecordVolumeBackup(t *testing.T) {
	t.Parallel()
	s, ctx := open(t), context.Background()
	for _, id := range []string{"n1", "n2"} {
		if err := s.UpsertNode(ctx, Node{ID: id, PrivateIP: "10.0.0.1"}); err != nil {
			t.Fatal(err)
		}
	}
	r1 := deployJob(t, s, "name: db\nimage: postgres:17\nvolumes:\n  - name: data\n    path: /var/lib/postgresql/data\n")
	if err := s.CreateReplica(ctx, Replica{ID: "db-1", App: "db", Revision: r1.Name, NodeID: "n1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordVolumeBackup(ctx, "db", "data", "", 0, 0, "bucket: write: AccessDenied"); err != nil {
		t.Fatal(err)
	}
	v, _ := s.GetVolume(ctx, "db", "data")
	if b := v.Backup; b.FailedAt.IsZero() || b.Error != "bucket: write: AccessDenied" || !b.LastAt.IsZero() {
		t.Fatalf("after a failure: %+v", b)
	}
	if err := s.RecordVolumeBackup(ctx, "db", "data", "s1", 4096, 3, ""); err != nil {
		t.Fatal(err)
	}
	v, _ = s.GetVolume(ctx, "db", "data")
	if b := v.Backup; b.LastAt.IsZero() || b.LastID != "s1" || b.Stored != 4096 || b.Snapshots != 3 || !b.FailedAt.IsZero() || b.Error != "" {
		t.Fatalf("after a success: %+v", b)
	}
	// Worked, but cleaning up failed: both are kept.
	if err := s.RecordVolumeBackup(ctx, "db", "data", "s2", 5000, 4, "removing old backups failed"); err != nil {
		t.Fatal(err)
	}
	v, _ = s.GetVolume(ctx, "db", "data")
	if b := v.Backup; b.LastID != "s2" || b.Error == "" {
		t.Fatalf("after a partial success: %+v", b)
	}
	// Rebinding keeps the volume's backups.
	if err := s.BindVolume(ctx, "db", "data", "n2", "admin:test"); err != nil {
		t.Fatal(err)
	}
	if v2, _ := s.GetVolume(ctx, "db", "data"); v2.Node != "n2" || v2.Backup.LastID != "s2" {
		t.Errorf("after bind: %+v", v2)
	}
	if err := s.RecordVolumeBackup(ctx, "db", "nope", "s1", 0, 0, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown volume: %v", err)
	}
}
