package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/store"
)

func volumeSpec(image string) string {
	return "name: web\nimage: " + image + "\ningress:\n  type: external\n  port: 80\nvolumes:\n  - name: data\n    path: /data\n"
}

// runningContainers counts the app's running containers on every node.
func runningContainers(c *cluster, app string) int {
	n := 0
	for _, tn := range c.nodes {
		cs, _ := tn.d.List(context.Background(), map[string]string{runtime.LabelApp: app})
		for _, ct := range cs {
			if ct.State == runtime.StateRunning {
				n++
			}
		}
	}
	return n
}

func TestVolumeAppRecreatesOnItsNode(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	c.addNode("n1", "127.0.0.1")
	c.addNode("n2", "127.0.0.2")

	c.deploy(volumeSpec("nginx:1"))
	c.eventually("v1 running", func() bool { return len(c.running("web")) == 1 })
	v, err := c.store.GetVolume(c.ctx, "web", "data")
	if err != nil {
		t.Fatal(err)
	}
	node := c.running("web")[0].NodeId
	if v.Node != node {
		t.Fatalf("volume on %s, replica on %s", v.Node, node)
	}
	if fi, err := os.Stat(filepath.Join(c.nodes[node].volumes, "web", "data")); err != nil || !fi.IsDir() {
		t.Fatalf("volume directory: %v", err)
	}

	// Never two containers writing the volume.
	var most atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if n := int64(runningContainers(c, "web")); n > most.Load() {
				most.Store(n)
			}
			time.Sleep(2 * time.Millisecond)
		}
	})
	c.deploy(volumeSpec("nginx:2"))
	c.eventually("v2 serving", func() bool {
		a := c.app("web")
		return a.ActiveRevision == "web--r2" && a.RolloutState == "" && len(c.running("web")) == 1 && c.running("web")[0].Revision == "web--r2"
	})
	close(stop)
	wg.Wait()
	if most.Load() > 1 {
		t.Errorf("%d containers ran at once during the rollout", most.Load())
	}
	if got := c.running("web")[0].NodeId; got != node {
		t.Errorf("v2 on %s, its volume on %s", got, node)
	}

	// Cordoning the node does not move it.
	if _, err := c.admin.CordonNode(c.ctx, &armadav1.CordonNodeRequest{Node: node, Cordoned: true}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if r := c.running("web"); len(r) != 1 || r[0].NodeId != node {
		t.Errorf("after cordon: %v", r)
	}

	// Scaling is refused.
	if _, err := c.admin.Scale(c.ctx, &armadav1.ScaleRequest{App: "web", Replicas: 2}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("scale: %v", err)
	}
}

func TestVolumeAppStaysOnLostNode(t *testing.T) {
	t.Parallel()
	c := newCluster(t, func(cfg *Config) { cfg.NodeLostTimeout = 200 * time.Millisecond })
	c.addNode("n1", "127.0.0.1")
	c.deploy(volumeSpec("nginx:1"))
	c.eventually("running", func() bool { return len(c.running("web")) == 1 })
	c.addNode("n2", "127.0.0.2")
	c.addNode("n3", "127.0.0.3") // more ready than lost

	c.stopAgent("n1")
	c.eventually("VolumeUnavailable", func() bool {
		evs, _ := c.store.ListEvents(c.ctx, time.Time{})
		for _, e := range evs {
			if e.Reason == "VolumeUnavailable" && e.App == "web" {
				return true
			}
		}
		return false
	})
	time.Sleep(300 * time.Millisecond)
	rs, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "web"})
	for _, r := range rs {
		if r.NodeID != "n1" {
			t.Errorf("replica %s moved to %s without its volume", r.ID, r.NodeID)
		}
	}
}

func TestVolumeAppNeedsCapableNode(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	c.addNode("n1", "127.0.0.1")
	c.stopAgent("n1")
	c.nodes["n1"].d.NoVolumes = true
	c.startAgent("n1")
	c.deploy(volumeSpec("nginx:1"))
	c.eventually("Unschedulable", func() bool {
		evs, _ := c.store.ListEvents(c.ctx, time.Time{})
		for _, e := range evs {
			if e.Reason == "Unschedulable" && e.App == "web" {
				return true
			}
		}
		return false
	})
	if rs, _ := c.store.ListReplicas(c.ctx, store.ReplicaFilter{App: "web"}); len(rs) != 0 {
		t.Errorf("replicas on a node that cannot mount volumes: %v", rs)
	}
}

func backupVolume(t *testing.T, c *cluster, stop bool) []byte {
	t.Helper()
	st, err := c.admin.BackupVolume(c.ctx, &armadav1.BackupVolumeRequest{App: "web", Name: "data", Stop: stop})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	for {
		m, err := st.Recv()
		if err != nil {
			t.Fatalf("backup: %v", err)
		}
		buf.Write(m.GetData())
		if m.GetDone() {
			return buf.Bytes()
		}
	}
}

func restoreVolume(c *cluster, archive []byte, node string) (*armadav1.RestoreVolumeResponse, error) {
	st, err := c.admin.RestoreVolume(c.ctx)
	if err != nil {
		return nil, err
	}
	if err := st.Send(&armadav1.RestoreVolumeMessage{Msg: &armadav1.RestoreVolumeMessage_Start{Start: &armadav1.RestoreVolumeStart{App: "web", Name: "data", Node: node}}}); err != nil {
		return nil, err
	}
	for len(archive) > 0 {
		n := min(len(archive), volumeChunk)
		if err := st.Send(&armadav1.RestoreVolumeMessage{Msg: &armadav1.RestoreVolumeMessage_Data{Data: archive[:n]}}); err != nil {
			break // the error comes with CloseAndRecv
		}
		archive = archive[n:]
	}
	return st.CloseAndRecv()
}

func archiveNames(t *testing.T, b []byte) map[string]string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(tr)
		out[h.Name] = string(data)
	}
}

func TestVolumeBackupRestoreRemove(t *testing.T) {
	t.Parallel()
	c := newCluster(t, func(cfg *Config) { cfg.NodeLostTimeout = 200 * time.Millisecond })
	c.addNode("n1", "127.0.0.1")
	c.deploy(volumeSpec("nginx:1"))
	c.eventually("running", func() bool { return len(c.running("web")) == 1 })
	dir := filepath.Join(c.nodes["n1"].volumes, "web", "data")
	if err := os.WriteFile(filepath.Join(dir, "db"), []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Live and stopped backups.
	archive := backupVolume(t, c, false)
	if got := archiveNames(t, archive); got["db"] != "v1" {
		t.Fatalf("archive: %v", got)
	}
	if got := archiveNames(t, backupVolume(t, c, true)); got["db"] != "v1" {
		t.Fatalf("stopped archive: %v", got)
	}
	c.eventually("running again after a stopped backup", func() bool { return runningContainers(c, "web") == 1 })

	// Restore replaces the contents.
	if err := os.WriteFile(filepath.Join(dir, "db"), []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "extra"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, err := restoreVolume(c, archive, "")
	if err != nil || resp.GetNode() != "n1" {
		t.Fatalf("restore: %v %v", resp, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "db")); string(b) != "v1" {
		t.Errorf("after restore db = %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "extra")); err == nil {
		t.Error("restore kept a file the archive does not have")
	}
	c.eventually("running after restore", func() bool { return runningContainers(c, "web") == 1 })

	// A bad archive changes nothing.
	if _, err := restoreVolume(c, []byte("not a tarball"), ""); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("bad archive: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "db")); string(b) != "v1" {
		t.Errorf("after a bad restore db = %q", b)
	}

	// --node is refused while the volume's node is connected.
	c.addNode("n2", "127.0.0.2")
	c.addNode("n3", "127.0.0.3")
	if _, err := restoreVolume(c, archive, "n2"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("restore elsewhere with the node up: %v", err)
	}

	// Recovering from a lost node: restore elsewhere, the app follows.
	c.stopAgent("n1")
	if resp, err := restoreVolume(c, archive, "n2"); err != nil || resp.GetNode() != "n2" {
		t.Fatalf("restore on n2: %v %v", resp, err)
	}
	c.eventually("running on n2", func() bool {
		r := c.running("web")
		return len(r) == 1 && r[0].NodeId == "n2"
	})
	if b, _ := os.ReadFile(filepath.Join(c.nodes["n2"].volumes, "web", "data", "db")); string(b) != "v1" {
		t.Errorf("on n2 db = %q", b)
	}

	// Listing, then removing once the spec no longer mounts it.
	c.eventually("volume measured", func() bool {
		l, err := c.admin.ListVolumes(c.ctx, &armadav1.ListVolumesRequest{App: "web"})
		return err == nil && len(l.Volumes) == 1 && l.Volumes[0].Node == "n2" && l.Volumes[0].InUse && l.Volumes[0].UsedBytes == 2
	})
	top, err := c.admin.Top(c.ctx, &armadav1.TopRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if p := top.GetProjects()[0]; p.GetName() != "default" || p.GetVolumeBytes() != 2 {
		t.Errorf("project usage: %v", p)
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(&clusterCollector{s: c.srv})
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() != "armada_volume_used_bytes" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			found = labels["app"] == "web" && labels["volume"] == "data" && labels["node"] == "n2" && m.GetGauge().GetValue() == 2
		}
	}
	if !found {
		t.Errorf("armada_volume_used_bytes missing: %v", mfs)
	}
	if _, err := c.admin.RemoveVolume(c.ctx, &armadav1.RemoveVolumeRequest{App: "web", Name: "data"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("remove in use: %v", err)
	}
	c.deploy("name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\n")
	c.eventually("redeployed without the volume", func() bool { return c.app("web").ActiveRevision == "web--r2" && c.app("web").RolloutState == "" })
	if _, err := os.Stat(filepath.Join(c.nodes["n2"].volumes, "web", "data", "db")); err != nil {
		t.Error("the volume went with the spec")
	}
	c.eventually("volume removed once the old replica is gone", func() bool {
		_, err := c.admin.RemoveVolume(c.ctx, &armadav1.RemoveVolumeRequest{App: "web", Name: "data"})
		return err == nil
	})
	if _, err := os.Stat(filepath.Join(c.nodes["n2"].volumes, "web", "data")); err == nil {
		t.Error("data left on the node")
	}
	if l, _ := c.admin.ListVolumes(c.ctx, &armadav1.ListVolumesRequest{}); len(l.GetVolumes()) != 0 {
		t.Errorf("volumes left: %v", l.GetVolumes())
	}
}
