package server

import (
	"context"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/agent"
	"github.com/ryanbekhen/armada/internal/store"
)

func TestNFSVolumeAppSpreadsAcrossNodes(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	var mu sync.Mutex
	mounted := map[string]int{}
	c.agentConfig = func(id string, cfg *agent.Config) {
		if id == "n3" {
			return // this node cannot mount NFS
		}
		cfg.NFSDir = t.TempDir()
		cfg.MountNFS = func(_ context.Context, server, export, _ string, _ bool) error {
			mu.Lock()
			defer mu.Unlock()
			if server == "10.0.0.20" && export == "/exports/up" {
				mounted[id]++
			}
			return nil
		}
	}
	c.addNode("n1", "127.0.0.1")
	c.addNode("n2", "127.0.0.2")
	c.addNode("n3", "127.0.0.3")
	if n, _ := c.store.GetNode(c.ctx, "n3"); n.NFS {
		t.Fatal("n3 says it mounts NFS")
	}
	c.deploy("name: web\nimage: nginx:1\ningress:\n  type: external\n  port: 80\nscale:\n  min: 2\n  max: 2\nvolumes:\n  - name: uploads\n    path: /uploads\n    nfs:\n      server: 10.0.0.20\n      path: /exports/up\n")
	c.eventually("two replicas on the NFS nodes", func() bool {
		r := c.running("web")
		return len(r) == 2 && r[0].NodeId != r[1].NodeId && r[0].NodeId != "n3" && r[1].NodeId != "n3"
	})
	mu.Lock()
	if mounted["n1"] == 0 || mounted["n2"] == 0 {
		t.Errorf("mounts = %v", mounted)
	}
	mu.Unlock()
	if vols, _ := c.store.ListVolumes(c.ctx, "web"); len(vols) != 0 {
		t.Errorf("NFS volumes are bound to nodes: %+v", vols)
	}

	// Rolling updates, not recreate: there is no node to wait for.
	c.deploy("name: web\nimage: nginx:2\ningress:\n  type: external\n  port: 80\nscale:\n  min: 2\n  max: 2\nvolumes:\n  - name: uploads\n    path: /uploads\n    nfs:\n      server: 10.0.0.20\n      path: /exports/up\n")
	c.eventually("v2 serving", func() bool {
		a := c.app("web")
		return a.ActiveRevision == "web--r2" && a.RolloutState == "" && len(c.running("web")) == 2
	})
	if _, err := c.admin.Scale(c.ctx, &armadav1.ScaleRequest{App: "web", Replicas: 1}); err != nil {
		t.Errorf("scaling an NFS app: %v", err)
	}
	_ = store.ErrNotFound
}

func TestNFSExportsNeedClusterAdmin(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	ctx := c.ctx
	if _, err := c.admin.CreateSpace(ctx, &armadav1.CreateSpaceRequest{Name: "a"}); err != nil {
		t.Fatal(err)
	}
	deployer := c.newUser("dan", &armadav1.RoleAssignment{Role: "deployer", Space: "a"})
	nfsApp := func(image, path string, readOnly bool) []byte {
		ro := ""
		if readOnly {
			ro = "      readOnly: true\n"
		}
		return []byte("name: web\nimage: " + image + "\nvolumes:\n  - name: up\n    path: /up\n    nfs:\n      server: 10.0.0.20\n      path: " + path + "\n" + ro)
	}
	_, err := deployer.Deploy(ctx, &armadav1.DeployRequest{Spec: nfsApp("nginx:1", "/exports/a", true), Space: "a"})
	wantCode(t, "a deployer adds an export", err, codes.PermissionDenied)

	if _, err := c.admin.Deploy(ctx, &armadav1.DeployRequest{Spec: nfsApp("nginx:1", "/exports/a", false), Space: "a"}); err != nil {
		t.Fatal(err)
	}
	// Same exports, or read-only: the deployer may.
	if _, err := deployer.Deploy(ctx, &armadav1.DeployRequest{Spec: nfsApp("nginx:2", "/exports/a", false), Space: "a"}); err != nil {
		t.Errorf("same export: %v", err)
	}
	if _, err := deployer.Deploy(ctx, &armadav1.DeployRequest{Spec: nfsApp("nginx:3", "/exports/a", true), Space: "a"}); err != nil {
		t.Errorf("read-only: %v", err)
	}
	_, err = deployer.Deploy(ctx, &armadav1.DeployRequest{Spec: nfsApp("nginx:4", "/exports/other-team", false), Space: "a"})
	wantCode(t, "a deployer changes the export", err, codes.PermissionDenied)
}

// A rollback deploys a stored spec, so it passes Deploy's checks: a
// deployer cannot bring back an NFS export or a node label a cluster-admin
// has since removed, and may still roll back to anything they could deploy.
func TestRollbackKeepsDeployChecks(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	ctx := c.ctx
	if _, err := c.admin.CreateSpace(ctx, &armadav1.CreateSpaceRequest{Name: "a"}); err != nil {
		t.Fatal(err)
	}
	c.addNode("n1", "127.0.0.1")
	deployer := c.newUser("eve", &armadav1.RoleAssignment{Role: "deployer", Space: "a"})
	settled := func(app, rev string) {
		t.Helper()
		c.eventually(app+" on "+rev, func() bool {
			a := c.app(app)
			return a.ActiveRevision == rev && a.TargetRevision == rev
		})
	}

	nfs := []byte("name: api\nimage: nginx:1\nvolumes:\n  - name: d\n    path: /d\n    nfs:\n      server: 10.0.0.30\n      path: /exports/b\n")
	r1, err := c.admin.Deploy(ctx, &armadav1.DeployRequest{Spec: nfs, Space: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.admin.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte("name: api\nimage: nginx:2\n"), Space: "a"}); err != nil {
		t.Fatal(err)
	}
	settled("api.a", "api.a--r2")
	_, err = deployer.Rollback(ctx, &armadav1.RollbackRequest{App: "api.a", Revision: r1.GetRevision()})
	wantCode(t, "a deployer rolls back to a removed export", err, codes.PermissionDenied)
	if a := c.app("api.a"); a.TargetRevision != "api.a--r2" {
		t.Errorf("target %s after a refused rollback", a.TargetRevision)
	}
	if _, err := c.admin.Rollback(ctx, &armadav1.RollbackRequest{App: "api.a", Revision: r1.GetRevision()}); err != nil {
		t.Errorf("cluster-admin rollback: %v", err)
	}

	pl := []byte("name: gpu\nimage: nginx:1\nplacement:\n  require:\n    pool: [gpu]\n")
	p1, err := c.admin.Deploy(ctx, &armadav1.DeployRequest{Spec: pl, Space: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.admin.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte("name: gpu\nimage: nginx:2\n"), Space: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.Deploy(ctx, &armadav1.DeployRequest{Spec: []byte("name: gpu\nimage: nginx:3\n"), Space: "a"}); err != nil {
		t.Fatal(err)
	}
	settled("gpu.a", "gpu.a--r3")
	_, err = deployer.Rollback(ctx, &armadav1.RollbackRequest{App: "gpu.a", Revision: p1.GetRevision()})
	wantCode(t, "a deployer rolls back to a restricted label", err, codes.PermissionDenied)
	if _, err := deployer.Rollback(ctx, &armadav1.RollbackRequest{App: "gpu.a", Revision: "gpu.a--r2"}); err != nil {
		t.Errorf("rollback to a revision the deployer could deploy: %v", err)
	}
}
