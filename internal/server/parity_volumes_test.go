package server

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

// Scenarios of volumes (ADR 0055, pull request 12), run against both
// servers by runParity: apps with local volumes recreated on their node
// with held replicas, pulls that fail, agents without holds, lost and
// cordoned nodes, volumes split across nodes, the volume methods through
// fake agents that answer volume sessions, volume sizes from usage
// reports, scheduled backups and their methods, the bucket checks of
// deploys, rollbacks, restarts, and secret changes, and failover with
// fencing. They move what volumes_test.go, backups_test.go,
// failover_test.go, and nfs_test.go check onto both servers; those tests
// stay.

const parityVolume = "name: web\nimage: nginx:%s\ningress:\n  type: external\n  port: 80\nvolumes:\n  - name: data\n    path: /data\n"

func volumeYAML(image string) string { return fmt.Sprintf(parityVolume, image) }

const parityBackup = parityVolume + "    backup:\n      every: 1h\n      keep: 2\n      urlSecretRef: backup-url\n      keySecretRef: backup-key\n"

func backupYAML(image string) string { return fmt.Sprintf(parityBackup, image) }

// volumeBucket is the bucket a scenario's fake agents back volumes up to,
// shared by every node: snapshots and their contents by app/volume.
type volumeBucket struct {
	mu      sync.Mutex
	snaps   map[string][]*armadav1.VolumeSnapshot
	data    map[string]string
	seq     int
	failPut bool
}

func newVolumeBucket() *volumeBucket {
	return &volumeBucket{snaps: map[string][]*armadav1.VolumeSnapshot{}, data: map[string]string{}}
}

// volumeAgent is a fake agent that serves volume sessions: the contents
// of its node's volumes, and the shared bucket.
type volumeAgent struct {
	*parityAgent
	client armadav1.AgentServiceClient
	bucket *volumeBucket
	mu     sync.Mutex
	disk   map[string]string
	seen   []string
}

// volumeCaps is what a volume agent's Hello announces.
type volumeCaps struct{ noHolds, noBackups, nfs bool }

// volumeAgent connects node id's agent, serving volume requests.
func (sc *scenario) volumeAgent(id, ip string, bucket *volumeBucket, caps volumeCaps) *volumeAgent {
	sc.t.Helper()
	sc.node(id, ip, 4000, 8<<30, nil)
	client := sc.nodeAgent(id)
	a, err := sc.connectAgent(id, client, &armadav1.Hello{PrivateIp: ip, CpuMillis: 4000, MemoryBytes: 8 << 30, Containers: true,
		Volumes: true, HeldReplicas: !caps.noHolds, VolumeBackups: !caps.noBackups, Nfs: caps.nfs})
	if err != nil {
		sc.t.Fatal(err)
	}
	va := &volumeAgent{parityAgent: a, client: client, bucket: bucket, disk: map[string]string{}}
	h := va.serve
	a.volume.Store(&h)
	return va
}

// requests returns what the agent was asked since the last call, sorted.
func (va *volumeAgent) requests() []string {
	va.mu.Lock()
	defer va.mu.Unlock()
	out := va.seen
	va.seen = nil
	slices.Sort(out)
	return out
}

func (va *volumeAgent) write(app, vol, contents string) {
	va.mu.Lock()
	defer va.mu.Unlock()
	va.disk[app+"/"+vol] = contents
}

func (va *volumeAgent) read(app, vol string) string {
	va.mu.Lock()
	defer va.mu.Unlock()
	return va.disk[app+"/"+vol]
}

// serve answers one volume request as an agent does: the attach message
// first, then the operation's messages.
func (va *volumeAgent) serve(req *armadav1.VolumeRequest) {
	key := req.GetApp() + "/" + req.GetVolume()
	line := fmt.Sprintf("%s %s stop=%t", req.GetOp(), key, req.GetStop())
	if b := req.GetBackup(); b != nil {
		line += fmt.Sprintf(" url=%s key=%d keep=%v tz=%q", b.GetUrl(), len(b.GetKey()), b.GetKeep().GetLast(), b.GetTimeZone())
	}
	if req.GetSnapshot() != "" {
		line += " snapshot=" + req.GetSnapshot()
	}
	va.mu.Lock()
	va.seen = append(va.seen, line)
	va.mu.Unlock()
	stream, err := va.client.VolumeSession(va.sc.ctx)
	if err != nil {
		return
	}
	first := &armadav1.VolumeData{RequestId: req.GetRequestId()}
	if req.GetOp() == armadav1.VolumeRequest_OP_REMOVE {
		va.mu.Lock()
		delete(va.disk, key)
		va.mu.Unlock()
		first.Done = true
	}
	if err := stream.Send(first); err != nil {
		return
	}
	send := func(m *armadav1.VolumeData) { _ = stream.Send(m) }
	b := va.bucket
	switch req.GetOp() {
	case armadav1.VolumeRequest_OP_BACKUP:
		send(&armadav1.VolumeData{Data: []byte(va.read(req.GetApp(), req.GetVolume()))})
		send(&armadav1.VolumeData{Done: true})
	case armadav1.VolumeRequest_OP_RESTORE:
		var got []byte
		for {
			m, err := stream.Recv()
			if err != nil {
				return
			}
			got = append(got, m.GetData()...)
			if m.GetDone() {
				break
			}
		}
		if string(got) == "bad" {
			send(&armadav1.VolumeData{Error: "the archive is not a gzipped tar"})
			break
		}
		va.write(req.GetApp(), req.GetVolume(), string(got))
		send(&armadav1.VolumeData{Done: true})
	case armadav1.VolumeRequest_OP_SNAPSHOT:
		b.mu.Lock()
		if b.failPut {
			b.mu.Unlock()
			send(&armadav1.VolumeData{Error: "bucket: put: AccessDenied (HTTP 403): refused"})
			break
		}
		b.seq++
		contents := va.read(req.GetApp(), req.GetVolume())
		s := &armadav1.VolumeSnapshot{Id: fmt.Sprintf("snap-%d", b.seq), Files: 1, Bytes: int64(len(contents))}
		b.snaps[key] = append(b.snaps[key], s)
		b.data[s.Id] = contents
		if keep := int(req.GetBackup().GetKeep().GetLast()); keep > 0 && len(b.snaps[key]) > keep {
			b.snaps[key] = b.snaps[key][len(b.snaps[key])-keep:]
		}
		res := &armadav1.CreateVolumeSnapshotResponse{Snapshot: s, NewBytes: int64(len(contents)), StoredBytes: int64(10 * len(b.snaps[key])), Snapshots: int32(len(b.snaps[key]))}
		b.mu.Unlock()
		send(&armadav1.VolumeData{Done: true, Snapshot: res})
	case armadav1.VolumeRequest_OP_SNAPSHOTS:
		b.mu.Lock()
		list := slices.Clone(b.snaps[key])
		b.mu.Unlock()
		send(&armadav1.VolumeData{Done: true, Snapshots: list})
	case armadav1.VolumeRequest_OP_RESTORE_SNAPSHOT:
		b.mu.Lock()
		var found *armadav1.VolumeSnapshot
		for _, s := range b.snaps[key] {
			if s.GetId() == req.GetSnapshot() || req.GetSnapshot() == "latest" {
				found = s
			}
		}
		var contents string
		if found != nil {
			contents = b.data[found.GetId()]
		}
		b.mu.Unlock()
		if found == nil {
			send(&armadav1.VolumeData{Error: "no backup " + req.GetSnapshot() + " in the bucket"})
			break
		}
		va.write(req.GetApp(), req.GetVolume(), contents)
		send(&armadav1.VolumeData{Done: true, Snapshot: &armadav1.CreateVolumeSnapshotResponse{Snapshot: found}})
	}
	// Held until the server is done with the session.
	_ = stream.CloseSend()
	for {
		if _, err := stream.Recv(); err != nil {
			return
		}
	}
}

// measure reports the sizes of the agent's volumes in a usage report.
func (sc *scenario) measure(va *volumeAgent) {
	sc.t.Helper()
	va.mu.Lock()
	u := &armadav1.UsageReport{VolumesMeasured: true}
	for k, v := range va.disk {
		app, vol, _ := strings.Cut(k, "/")
		u.Volumes = append(u.Volumes, &armadav1.VolumeUsage{App: app, Volume: vol, Bytes: int64(len(v))})
	}
	va.mu.Unlock()
	sc.usage(va.parityAgent, u)
}

// volumes records ListVolumes for app ("" for all) as admin.
func (sc *scenario) volumes(label, app string) {
	sc.t.Helper()
	resp, err := sc.admin.ListVolumes(sc.ctx, &armadav1.ListVolumesRequest{App: app})
	sc.answer(label, resp, err)
}

// heldList is replicaList with each replica's held flag.
func (sc *scenario) heldList() []string {
	sc.t.Helper()
	rs, err := sc.st.ListReplicas(sc.ctx, store.ReplicaFilter{})
	if err != nil {
		sc.t.Fatal(err)
	}
	var out []string
	for _, r := range rs {
		line := fmt.Sprintf("%s %s on %s %s", r.ID, r.Revision, r.NodeID, r.State)
		if r.Held {
			line += " held"
		}
		if r.Draining() {
			line += " draining"
		}
		out = append(out, line)
	}
	return out
}

// volPass runs a pass and records the apps, replicas with held flags, and
// volume bindings.
func (sc *scenario) volPass(label string) {
	sc.t.Helper()
	sc.sut.reconcile(sc.t)
	vols, err := sc.st.ListVolumes(sc.ctx, "")
	if err != nil {
		sc.t.Fatal(err)
	}
	var bound []string
	for _, v := range vols {
		bound = append(bound, v.App+"/"+v.Name+" on "+v.Node)
	}
	sc.note(label, map[string]any{"apps": sc.appList(), "replicas": sc.heldList(), "volumes": bound})
}

func (sc *scenario) volLater(label string, d time.Duration) {
	sc.t.Helper()
	sc.advance(d)
	sc.volPass(label)
}

// assigned records what node's agent was assigned last: each replica's
// ID, hold, and fence time.
func (sc *scenario) assigned(label string, a *parityAgent) {
	sc.t.Helper()
	var out []string
	for _, r := range a.assignment().GetReplicas() {
		out = append(out, fmt.Sprintf("%s hold=%t fence=%d volumes=%d", r.GetId(), r.GetHold(), r.GetFenceAfterSeconds(), len(r.GetVolumes())))
	}
	sc.note(label, out)
}

// waitEvent waits until object has at least n events for reason.
func (sc *scenario) waitEvent(object, reason string, n int) {
	sc.t.Helper()
	sc.eventually(fmt.Sprintf("%d %s of %s", n, reason, object), func() bool { return sc.eventCount(object, reason) >= n })
}

// disconnect ends a's session and waits until the server saw it; the
// node was last seen now on the scenario's clock (servers record the wall
// clock's).
func (sc *scenario) disconnect(a *parityAgent) {
	sc.t.Helper()
	before := sc.eventCount(a.id, "Disconnected")
	a.cancel()
	sc.waitEvent(a.id, "Disconnected", before+1)
	n, err := sc.st.GetNode(sc.ctx, a.id)
	if err != nil {
		sc.t.Fatal(err)
	}
	if err := sc.st.SetNodeStatus(sc.ctx, a.id, store.NodeStatus{State: store.NodeUnknown, LastSeen: sc.clock.now(), CPUMillis: n.CPUMillis,
		MemoryBytes: n.MemoryBytes, Volumes: n.Volumes, Containers: n.Containers, NFS: n.NFS, Jobs: n.Jobs}); err != nil {
		sc.t.Fatal(err)
	}
}

// Recreate on the volume's node (TestVolumeAppRecreatesOnItsNode,
// TestVolumeAppPullsBeforeTheOldReplicaStops,
// TestVolumeAppKeepsServingWhenThePullFails): the volume binds where the
// first replica goes, a rollout pulls into a held replica while the old
// one serves, the old one drains once the pull is done, the held one
// starts once nothing else uses the volume, a failed pull fails the
// rollout and keeps the old replica, and a cordoned node keeps the app.
func TestParityVolumeRecreate(t *testing.T) {
	runParity(t, parityConfig{drain: time.Second, warmup: time.Second, progress: 30 * time.Second}, func(sc *scenario) {
		bucket := newVolumeBucket()
		n1 := sc.volumeAgent("n1", "10.0.0.11", bucket, volumeCaps{})
		sc.volumeAgent("n2", "10.0.0.12", bucket, volumeCaps{})
		sc.deploy("v1", volumeYAML("1"))
		sc.volPass("placed")
		sc.serve("web")
		sc.volLater("v1 serves", 2*time.Second)
		sc.assigned("n1 assignment", n1.parityAgent)

		sc.deploy("v2", volumeYAML("2"))
		sc.volPass("held while pulling")
		sc.assigned("n1 assignment with the held replica", n1.parityAgent)
		held := sc.replicaOf("web-r2-")
		sc.report(held, store.ReplicaPulling, false, "")
		sc.volLater("still pulling", time.Second)
		sc.report(held, store.ReplicaPulled, false, "")
		sc.volPass("pulled: the old one drains")
		sc.volLater("drained: the held one starts", 2*time.Second)
		sc.assigned("n1 assignment released", n1.parityAgent)
		sc.serve("web")
		sc.volLater("v2 serves", 2*time.Second)

		sc.deploy("v3", volumeYAML("missing"))
		sc.volPass("v3 held")
		sc.report(sc.replicaOf("web-r3-"), store.ReplicaFailed, false, "pull nginx:missing: not found")
		sc.volLater("pull failed, the old one serves", time.Second)
		sc.volLater("the rollout fails", 31*time.Second)
		sc.volPass("only the old replica is left")

		_, err := sc.admin.CordonNode(sc.ctx, &armadav1.CordonNodeRequest{Node: "n1", Cordoned: true})
		sc.note("cordon n1", err)
		sc.volPass("cordoned: it stays")
		sc.deploy("v4", volumeYAML("4"))
		sc.volPass("a rollout on a cordoned node")
		// pickNode never picks a cordoned node, so neither the held
		// replica nor the new one is placed there (a Go bug the Rust
		// server keeps for now).
		sc.volLater("drained: nothing placed on the cordoned node", 2*time.Second)
		sc.status("status", "web")
		sc.keyspace("keyspace")
	})
}

// TestVolumeAppStartsHeldReplicaForAgentsWithoutHolds: an agent that does
// not keep held replicas gets none; the old replica stops first.
func TestParityVolumeWithoutHolds(t *testing.T) {
	runParity(t, parityConfig{drain: time.Second, warmup: time.Second}, func(sc *scenario) {
		n1 := sc.volumeAgent("n1", "10.0.0.11", newVolumeBucket(), volumeCaps{noHolds: true})
		sc.deploy("v1", volumeYAML("1"))
		sc.volPass("placed")
		sc.serve("web")
		sc.volLater("serves", 2*time.Second)
		sc.deploy("v2", volumeYAML("2"))
		sc.volPass("the old one drains first")
		sc.volLater("then the new one", 2*time.Second)
		sc.assigned("n1 assignment", n1.parityAgent)
		sc.serve("web")
		sc.volLater("v2 serves", 2*time.Second)
	})
}

// TestVolumeAppStaysOnLostNode and TestVolumeAppNeedsCapableNode, with
// volumes split across nodes and a node that cannot mount volumes.
func TestParityVolumeLostAndSplit(t *testing.T) {
	runParity(t, parityConfig{nodeLost: time.Minute, drain: time.Second}, func(sc *scenario) {
		sc.node("plain", "10.0.0.10", 4000, 8<<30, nil, "containers")
		sc.deploy("v1", volumeYAML("1"))
		sc.volPass("no node mounts volumes")
		sc.node("n1", "10.0.0.11", 4000, 8<<30, nil, "containers", "volumes")
		sc.node("n2", "10.0.0.12", 4000, 8<<30, nil, "containers", "volumes")
		sc.node("n3", "10.0.0.13", 4000, 8<<30, nil, "containers", "volumes")
		sc.volPass("placed")
		sc.serve("web")
		r := sc.replicaOf("web-r1-")
		if err := sc.st.SetNodeStatus(sc.ctx, r.NodeID, store.NodeStatus{State: store.NodeUnknown, LastSeen: sc.clock.now(), Volumes: true, Containers: true}); err != nil {
			t.Fatal(err)
		}
		sc.volLater("away", 30*time.Second)
		sc.volLater("lost: it stays", 31*time.Second)
		sc.status("status", "web")
		// A second volume bound to another node: split.
		sc.deploy("v2", strings.Replace(volumeYAML("2"), "volumes:\n", "volumes:\n  - name: logs\n    path: /logs\n", 1))
		other := "n2"
		if r.NodeID == "n2" {
			other = "n3"
		}
		if err := sc.st.BindVolume(sc.ctx, "web", "logs", other, "user:ryan"); err != nil {
			t.Fatal(err)
		}
		sc.volPass("split")
		sc.status("status split", "web")
		sc.keyspace("keyspace")
	})
}

// TestVolumeBackupRestoreRemove through fake agents: listing with sizes,
// archives streamed out and in, a bad archive, a restore onto another
// node refused while the volume's node is connected and accepted once it
// is not, removal refused while mounted, and the checks of each method.
func TestParityVolumeMethods(t *testing.T) {
	runParity(t, parityConfig{drain: time.Second, warmup: time.Second}, func(sc *scenario) {
		bucket := newVolumeBucket()
		n1 := sc.volumeAgent("n1", "10.0.0.11", bucket, volumeCaps{})
		n2 := sc.volumeAgent("n2", "10.0.0.12", bucket, volumeCaps{})
		sc.deploy("v1", volumeYAML("1"))
		sc.volPass("placed")
		sc.serve("web")
		sc.volLater("serves", 2*time.Second)
		home, away := n1, n2
		if sc.replicaOf("web-r1-").NodeID == "n2" {
			home, away = n2, n1
		}
		sc.volumes("not measured", "web")
		home.write("web", "data", "v1")
		sc.measure(home)
		sc.volumes("measured", "")
		sc.volumes("invalid app", "Web!")

		backup := func(label string, req *armadav1.BackupVolumeRequest) {
			st, err := sc.admin.BackupVolume(sc.ctx, req)
			if err != nil {
				sc.note(label, err)
				return
			}
			var data []byte
			for {
				m, err := st.Recv()
				if err != nil {
					sc.note(label, map[string]any{"data": string(data), "err": errOf(err)})
					return
				}
				data = append(data, m.GetData()...)
			}
		}
		backup("backup", &armadav1.BackupVolumeRequest{App: "web", Name: "data"})
		backup("stopped backup", &armadav1.BackupVolumeRequest{App: "web", Name: "data", Stop: true})
		backup("unknown volume", &armadav1.BackupVolumeRequest{App: "web", Name: "nope"})
		backup("invalid name", &armadav1.BackupVolumeRequest{App: "web", Name: "No!"})
		sc.waitEvent("web", "VolumeBackedUp", 2)

		restore := func(label string, c armadav1.AdminServiceClient, start *armadav1.RestoreVolumeStart, chunks ...string) {
			st, err := c.RestoreVolume(sc.ctx)
			if err != nil {
				sc.note(label, err)
				return
			}
			if start != nil {
				_ = st.Send(&armadav1.RestoreVolumeMessage{Msg: &armadav1.RestoreVolumeMessage_Start{Start: start}})
			}
			for _, c := range chunks {
				if st.Send(&armadav1.RestoreVolumeMessage{Msg: &armadav1.RestoreVolumeMessage_Data{Data: []byte(c)}}) != nil {
					break
				}
			}
			resp, err := st.CloseAndRecv()
			sc.answer(label, resp, err)
		}
		restore("restore", sc.admin, &armadav1.RestoreVolumeStart{App: "web", Name: "data"}, "v", "0")
		sc.note("restored", home.read("web", "data"))
		restore("bad archive", sc.admin, &armadav1.RestoreVolumeStart{App: "web", Name: "data"}, "b", "ad")
		sc.note("after the bad archive", home.read("web", "data"))
		restore("no start", sc.admin, nil, "x")
		restore("unknown volume", sc.admin, &armadav1.RestoreVolumeStart{App: "web", Name: "nope"})
		restore("unknown volume on a node", sc.admin, &armadav1.RestoreVolumeStart{App: "web", Name: "nope", Node: away.id})
		restore("elsewhere while connected", sc.admin, &armadav1.RestoreVolumeStart{App: "web", Name: "data", Node: away.id}, "v2")
		restore("onto an unknown node", sc.admin, &armadav1.RestoreVolumeStart{App: "web", Name: "data", Node: "nope"}, "v2")

		// Requests the server never sent are refused.
		for _, from := range []*volumeAgent{home, away} {
			st, err := from.client.VolumeSession(sc.ctx)
			if err == nil {
				_ = st.Send(&armadav1.VolumeData{RequestId: "made-up"})
				_, err = st.Recv()
			}
			sc.note("unknown request from "+from.id, err)
		}

		// A space's people.
		if _, err := sc.st.CreateSpace(sc.ctx, "team", "user:ryan", nil); err != nil {
			t.Fatal(err)
		}
		if _, err := sc.st.CreateUser(sc.ctx, store.Principal{Name: "dev", Roles: []store.Grant{{Role: "admin", Space: "team"}}}, "user:ryan"); err != nil {
			t.Fatal(err)
		}
		dev := sc.adminClient(pki.Identity{Kind: pki.KindUser, Name: "dev"})
		l, err := dev.ListVolumes(sc.ctx, &armadav1.ListVolumesRequest{})
		sc.answer("a space admin lists", l, err)
		l, err = dev.ListVolumes(sc.ctx, &armadav1.ListVolumesRequest{App: "web"})
		sc.answer("a space admin lists web", l, err)
		restore("a space admin restores elsewhere", dev, &armadav1.RestoreVolumeStart{App: "web.team", Name: "data", Node: "n1"})
		_, err = dev.RemoveVolume(sc.ctx, &armadav1.RemoveVolumeRequest{App: "web", Name: "data"})
		sc.note("a space admin removes web's", err)

		_, err = sc.admin.RemoveVolume(sc.ctx, &armadav1.RemoveVolumeRequest{App: "web", Name: "data"})
		sc.note("remove while mounted", err)
		_, err = sc.admin.RemoveVolume(sc.ctx, &armadav1.RemoveVolumeRequest{App: "web", Name: "nope"})
		sc.note("remove unknown", err)

		// The volume's node goes: restore elsewhere, the app follows.
		sc.disconnect(home.parityAgent)
		restore("elsewhere once disconnected", sc.admin, &armadav1.RestoreVolumeStart{App: "web", Name: "data", Node: away.id}, "v", "1")
		sc.note("restored elsewhere", away.read("web", "data"))
		sc.volPass("the app follows")
		sc.volLater("the old replica drains", 2*time.Second)
		sc.serve("web")
		sc.volLater("serves on the new node", 2*time.Second)
		sc.measure(away)
		sc.volumes("moved", "web")

		sc.deploy("without the volume", "name: web\nimage: nginx:9\ningress:\n  type: external\n  port: 80\n")
		_, err = sc.admin.RemoveVolume(sc.ctx, &armadav1.RemoveVolumeRequest{App: "web", Name: "data"})
		sc.note("remove while a replica uses it", err)
		sc.volPass("v2 placed")
		sc.serve("web")
		sc.volLater("v2 serves", 2*time.Second)
		sc.volLater("the old one is gone", time.Minute+2*time.Second)
		_, err = sc.admin.RemoveVolume(sc.ctx, &armadav1.RemoveVolumeRequest{App: "web", Name: "data"})
		sc.note("removed", err)
		sc.waitEvent("web", "VolumeRemoved", 1)
		sc.volumes("none left", "")
		sc.note("home was asked", home.requests())
		sc.note("away was asked", away.requests())
		sc.keyspace("keyspace")
	})
}

// setBackupSecrets sets the bucket URL and key of app.
func (sc *scenario) setBackupSecrets(c armadav1.AdminServiceClient, app, url string) {
	sc.t.Helper()
	for _, kv := range [][2]string{{"backup-url", url}, {"backup-key", strings.Repeat("k", 32)}} {
		if _, err := c.SetSecret(sc.ctx, &armadav1.SetSecretRequest{App: app, Name: kv[0], Value: []byte(kv[1])}); err != nil {
			sc.t.Fatal(err)
		}
	}
}

// TestVolumeBackupsRunAndRestore, TestVolumeBackupFailureIsRecorded,
// TestVolumeSnapshotNeedsBackupSpec, and
// TestVolumeSnapshotListingSkipsNodesTheAppMayNotUse through fake agents:
// the first backup is due once the volume is measured, keep, a listing
// and a restore, a failure kept on the volume and retried after five
// minutes, a success clearing it, an agent too old, and a listing through
// another node that may run the app while the volume's node is away.
func TestParityVolumeBackups(t *testing.T) {
	runParity(t, parityConfig{masterKey: true, drain: time.Second, warmup: time.Second}, func(sc *scenario) {
		bucket := newVolumeBucket()
		n1 := sc.volumeAgent("n1", "10.0.0.11", bucket, volumeCaps{})
		sc.setBackupSecrets(sc.admin, "web", "https://AK:SK@s3.example.com/backups/armada")
		sc.deploy("deploy", backupYAML("1"))
		sc.volPass("placed")
		sc.serve("web")
		sc.volLater("serves", 2*time.Second)
		sc.sut.backups(sc.t)
		sc.volumes("not measured: no backup yet", "web")
		n1.write("web", "data", "first")
		sc.measure(n1)
		sc.sut.backups(sc.t)
		sc.volumes("backed up", "web")
		sc.sut.backups(sc.t)
		sc.note("not due again", n1.requests())

		made, err := sc.admin.CreateVolumeSnapshot(sc.ctx, &armadav1.CreateVolumeSnapshotRequest{App: "web", Name: "data"})
		sc.answer("snapshot", made, err)
		made, err = sc.admin.CreateVolumeSnapshot(sc.ctx, &armadav1.CreateVolumeSnapshotRequest{App: "web", Name: "data"})
		sc.answer("keep 2", made, err)
		list, err := sc.admin.ListVolumeSnapshots(sc.ctx, &armadav1.ListVolumeSnapshotsRequest{App: "web", Name: "data"})
		sc.answer("list", list, err)
		n1.write("web", "data", "lost")
		res, err := sc.admin.RestoreVolumeSnapshot(sc.ctx, &armadav1.RestoreVolumeSnapshotRequest{App: "web", Name: "data", Snapshot: "snap-2"})
		sc.answer("restore", res, err)
		sc.note("restored", n1.read("web", "data"))
		for _, req := range []*armadav1.RestoreVolumeSnapshotRequest{
			{App: "web", Name: "data", Snapshot: ""},
			{App: "web", Name: "data", Snapshot: strings.Repeat("x", 65)},
			{App: "web", Name: "data", Snapshot: "snap-9"},
			{App: "web", Name: "data", Snapshot: "latest", Node: "n2"},
		} {
			res, err := sc.admin.RestoreVolumeSnapshot(sc.ctx, req)
			sc.answer("restore "+req.GetSnapshot()+" "+req.GetNode(), res, err)
		}

		// A failing bucket: kept, an event, retried after five minutes.
		bucket.mu.Lock()
		bucket.failPut = true
		bucket.mu.Unlock()
		sc.advance(time.Hour)
		sc.measure(n1)
		sc.sut.backups(sc.t)
		sc.waitEvent("web", "VolumeBackupFailed", 1)
		sc.volumes("failed", "web")
		sc.advance(time.Minute)
		sc.measure(n1)
		sc.sut.backups(sc.t)
		sc.note("not retried yet", n1.requests())
		bucket.mu.Lock()
		bucket.failPut = false
		bucket.mu.Unlock()
		sc.advance(5 * time.Minute)
		sc.measure(n1)
		sc.sut.backups(sc.t)
		sc.volumes("retried", "web")

		// Without a backup in the spec.
		sc.deploy("api", strings.Replace(volumeYAML("1"), "name: web", "name: api", 1))
		sc.volPass("api placed")
		_, err = sc.admin.CreateVolumeSnapshot(sc.ctx, &armadav1.CreateVolumeSnapshotRequest{App: "api", Name: "data"})
		sc.note("snapshot without a backup", err)
		_, err = sc.admin.ListVolumeSnapshots(sc.ctx, &armadav1.ListVolumeSnapshotsRequest{App: "api", Name: "data"})
		sc.note("list without a backup", err)

		// While n1 is away, a listing goes through a node that may run
		// the app, never a restricted one.
		sc.disconnect(n1.parityAgent)
		_, err = sc.admin.CreateVolumeSnapshot(sc.ctx, &armadav1.CreateVolumeSnapshotRequest{App: "web", Name: "data"})
		sc.note("snapshot while away", err)
		a0 := sc.volumeAgent("a0", "10.0.0.20", bucket, volumeCaps{})
		if _, err := sc.admin.RestrictNode(sc.ctx, &armadav1.RestrictNodeRequest{Node: "a0", Restricted: true}); err != nil {
			t.Fatal(err)
		}
		_, err = sc.admin.ListVolumeSnapshots(sc.ctx, &armadav1.ListVolumeSnapshotsRequest{App: "web", Name: "data"})
		sc.note("list through a restricted node", err)
		_, err = sc.admin.RestoreVolumeSnapshot(sc.ctx, &armadav1.RestoreVolumeSnapshotRequest{App: "web", Name: "data", Snapshot: "latest", Node: "a0"})
		sc.note("restore onto a restricted node", err)
		old := sc.volumeAgent("old", "10.0.0.21", bucket, volumeCaps{noBackups: true})
		_, err = sc.admin.ListVolumeSnapshots(sc.ctx, &armadav1.ListVolumeSnapshotsRequest{App: "web", Name: "data"})
		sc.note("list with only an old agent", err)
		n2 := sc.volumeAgent("n2", "10.0.0.12", bucket, volumeCaps{})
		list, err = sc.admin.ListVolumeSnapshots(sc.ctx, &armadav1.ListVolumeSnapshotsRequest{App: "web", Name: "data"})
		sc.answer("list through n2", list, err)
		res, err = sc.admin.RestoreVolumeSnapshot(sc.ctx, &armadav1.RestoreVolumeSnapshotRequest{App: "web", Name: "data", Snapshot: "latest", Node: "n2"})
		sc.answer("restore onto n2", res, err)
		sc.note("on n2", n2.read("web", "data"))
		for _, va := range []*volumeAgent{n1, a0, old, n2} {
			sc.note(va.id+" was asked", va.requests())
		}

		// An agent too old to back up holds the volume now.
		if err := sc.st.BindVolume(sc.ctx, "web", "data", "old", "user:ryan"); err != nil {
			t.Fatal(err)
		}
		old.write("web", "data", "x")
		sc.volPass("moved to old")
		sc.volLater("the replica on n1 is gone", 2*time.Second)
		sc.volLater("placed on old", time.Second)
		sc.measure(old)
		sc.advance(2 * time.Hour)
		sc.measure(old)
		sc.sut.backups(sc.t)
		sc.waitEvent("web", "VolumeBackupUnsupported", 1)
		sc.keyspace("keyspace")
	})
}

// TestBackupTargetsNeedClusterAdmin: only cluster-admins point backups at
// a bucket on a private address; deploys, rollbacks, restarts, and secret
// changes that keep the address are anyone's who may deploy the app.
func TestParityBackupTargets(t *testing.T) {
	runParity(t, parityConfig{masterKey: true}, func(sc *scenario) {
		if _, err := sc.st.CreateSpace(sc.ctx, "a", "user:ryan", nil); err != nil {
			t.Fatal(err)
		}
		if _, err := sc.st.CreateUser(sc.ctx, store.Principal{Name: "dan", Roles: []store.Grant{{Role: "deployer", Space: "a"}}}, "user:ryan"); err != nil {
			t.Fatal(err)
		}
		dan := sc.adminClient(pki.Identity{Kind: pki.KindUser, Name: "dan"})
		set := func(label string, c armadav1.AdminServiceClient, name, v string) {
			_, err := c.SetSecret(sc.ctx, &armadav1.SetSecretRequest{App: "web.a", Name: name, Value: []byte(v)})
			sc.note(label, err)
		}
		dep := func(label string, c armadav1.AdminServiceClient, image string) {
			resp, err := c.Deploy(sc.ctx, &armadav1.DeployRequest{Space: "a", Spec: []byte(backupYAML(image))})
			sc.answer(label, resp, err)
		}
		dep("before its secrets", dan, "0")
		set("key", dan, "backup-key", strings.Repeat("k", 32))
		set("loopback", dan, "backup-url", "http://k:s@127.0.0.1:2379/bk1")
		dep("a loopback bucket", dan, "1")
		set("private", dan, "backup-url", "http://k:s@10.0.0.9:9000/bk1")
		dep("a deployer picks a private bucket", dan, "1")
		dep("cluster-admin", sc.admin, "1")
		dep("keeping the bucket", dan, "2")
		set("another private address", dan, "backup-url", "http://k:s@10.0.0.10:9000/bk1")
		set("the same address", dan, "backup-url", "http://k:s@10.0.0.9:9000/bk2")
		set("an invalid URL", dan, "backup-url", "ftp://k:s@x/bk1")
		set("a bucket by name", dan, "backup-url", "https://k:s@s3.example.com/bk1")
		dep("with a bucket by name", dan, "3")
		rb, err := dan.Rollback(sc.ctx, &armadav1.RollbackRequest{App: "web.a", Revision: "web.a--r1"})
		sc.answer("a deployer rolls back to the private bucket", rb, err)
		rs, err := dan.RestartApp(sc.ctx, &armadav1.RestartAppRequest{App: "web.a"})
		sc.answer("restart", rs, err)
		set("back to the private address as admin", sc.admin, "backup-url", "http://k:s@10.0.0.11:9000/bk1")
		rs, err = dan.RestartApp(sc.ctx, &armadav1.RestartAppRequest{App: "web.a"})
		sc.answer("a deployer restarts with the admin's new private bucket", rs, err)
		sc.keyspace("keyspace")
	})
}

// TestVolumeFailsOverToAnotherNode, TestVolumeFailoverSkipsNFSVolumes,
// and TestVolumeFailoverWithoutBackupsWaits: a replica that fails over
// carries its fence time, a lost node's volumes are restored from their
// latest backups on another node that backs volumes up and bound there
// (NFS volumes stay), the app follows, and a failover with no backup to
// restore fails and waits five minutes.
func TestParityVolumeFailover(t *testing.T) {
	runParity(t, parityConfig{masterKey: true, nodeLost: time.Minute, drain: time.Second, warmup: time.Second}, func(sc *scenario) {
		bucket := newVolumeBucket()
		n1 := sc.volumeAgent("n1", "10.0.0.11", bucket, volumeCaps{nfs: true})
		sc.setBackupSecrets(sc.admin, "web", "https://AK:SK@s3.example.com/backups")
		sc.setBackupSecrets(sc.admin, "api", "https://AK:SK@s3.example.com/backups")
		failover := backupYAML("1") + "    failover: restore\n"
		sc.deploy("web", strings.Replace(failover, "volumes:\n", "volumes:\n  - name: shared\n    path: /shared\n    nfs:\n      server: 10.0.0.21\n      path: /exports/shared\n", 1))
		sc.deploy("api", strings.Replace(failover, "name: web", "name: api", 1))
		sc.volPass("placed")
		sc.serve("web")
		sc.serve("api")
		sc.volLater("serve", 2*time.Second)
		sc.assigned("fence times", n1.parityAgent)
		n1.write("web", "data", "saved")
		made, err := sc.admin.CreateVolumeSnapshot(sc.ctx, &armadav1.CreateVolumeSnapshotRequest{App: "web", Name: "data"})
		sc.answer("web backed up", made, err)
		n2 := sc.volumeAgent("n2", "10.0.0.12", bucket, volumeCaps{nfs: true})
		sc.volumeAgent("n3", "10.0.0.13", bucket, volumeCaps{noBackups: true, nfs: true})

		sc.disconnect(n1.parityAgent)
		sc.volLater("away", 30*time.Second)
		sc.volLater("lost: failing over", 31*time.Second)
		sc.waitEvent("web", "VolumeFailedOver", 1)
		sc.waitEvent("api", "VolumeFailoverFailed", 1)
		sc.note("restored on n2", n2.read("web", "data"))
		sc.note("n2 was asked", n2.requests())
		sc.volPass("web follows; api waits")
		sc.volLater("api still waits", time.Minute)
		sc.note("n2 was asked again", n2.requests())
		sc.volLater("api tried again", 5*time.Minute)
		sc.eventually("the retry's request", func() bool {
			n2.mu.Lock()
			defer n2.mu.Unlock()
			return len(n2.seen) > 0
		})
		sc.note("n2 was asked after the retry", n2.requests())
		sc.serve("web")
		sc.volLater("web serves on n2", 2*time.Second)
		sc.assigned("n2 assignment", n2.parityAgent)
		sc.keyspace("keyspace")
	})
}

// TestNFSVolumeAppSpreadsAcrossNodes: an app with only NFS volumes is
// bound to no node, spreads over the nodes that mount NFS, and rolls out
// like any app.
func TestParityNFSVolumes(t *testing.T) {
	runParity(t, parityConfig{drain: time.Second, warmup: time.Second}, func(sc *scenario) {
		bucket := newVolumeBucket()
		sc.volumeAgent("n1", "10.0.0.11", bucket, volumeCaps{nfs: true})
		sc.volumeAgent("n2", "10.0.0.12", bucket, volumeCaps{nfs: true})
		sc.volumeAgent("n3", "10.0.0.13", bucket, volumeCaps{})
		nfs := "name: web\nimage: nginx:%s\ningress:\n  type: external\n  port: 80\nscale:\n  min: 2\nvolumes:\n  - name: uploads\n    path: /uploads\n    nfs:\n      server: 10.0.0.20\n      path: /exports/up\n"
		sc.deploy("v1", fmt.Sprintf(nfs, "1"))
		sc.volPass("spread over the NFS nodes")
		sc.serve("web")
		sc.volLater("serves", 2*time.Second)
		sc.deploy("v2", fmt.Sprintf(nfs, "2"))
		sc.volPass("a rolling update")
		sc.serve("web")
		sc.volLater("rolling", 2*time.Second)
		sc.serve("web")
		sc.volLater("v2 serves", 2*time.Second)
		sc.volumes("no volume records", "")
	})
}
