package agent

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/store"
)

type nfsCall struct {
	server, export, target string
	readOnly               bool
}

func nfsAgent(t *testing.T) (*Agent, *[]nfsCall) {
	t.Helper()
	a, _ := volumeAgent(t)
	var mu sync.Mutex
	calls := &[]nfsCall{}
	a.cfg.NFSDir = filepath.Join(t.TempDir(), "nfs")
	a.cfg.MountNFS = func(_ context.Context, server, export, target string, readOnly bool) error {
		mu.Lock()
		defer mu.Unlock()
		*calls = append(*calls, nfsCall{server, export, target, readOnly})
		return nil
	}
	return a, calls
}

func TestNFSVolumeMounts(t *testing.T) {
	t.Parallel()
	a, calls := nfsAgent(t)
	if !a.mountsNFS() {
		t.Fatal("the agent does not mount NFS volumes")
	}
	s := replica("web-r1-a", "nginx:1", 80)
	s.Volumes = []*armadav1.VolumeSpec{{Name: "uploads", Path: "/uploads", Nfs: &armadav1.NfsSource{Server: "10.0.0.20", Path: "/exports/up", ReadOnly: true}}}
	a.setDesired([]*armadav1.ReplicaSpec{s}, nil)
	r, err := a.Reconcile(context.Background())
	if err != nil || r.Replicas[0].State != store.ReplicaRunning {
		t.Fatalf("start: %v %v", r, err)
	}
	target := filepath.Join(a.cfg.NFSDir, "web", "uploads")
	if len(*calls) != 1 || (*calls)[0] != (nfsCall{"10.0.0.20", "/exports/up", target, true}) {
		t.Fatalf("mounts = %+v", *calls)
	}
	mounts, err := a.prepareVolumes(s)
	if err != nil || len(mounts) != 1 || mounts[0].Source != target || !mounts[0].Shared || !mounts[0].ReadOnly || mounts[0].Target != "/uploads" {
		t.Fatalf("mounts = %+v, %v", mounts, err)
	}
	if fi, err := os.Stat(target); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("mount point: %v %v", fi, err)
	}

	// No replica names it any more: the mount point goes.
	a.setDesired(nil, nil)
	if _, err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("mount point left: %v", err)
	}
}

func TestNFSVolumeRefusesForgedSources(t *testing.T) {
	t.Parallel()
	a, calls := nfsAgent(t)
	for _, n := range []*armadav1.NfsSource{
		{Server: "8.8.8.8", Path: "/x"},
		{Server: "10.0.0.20", Path: "/x,addr=8.8.8.8"},
		{Server: "10.0.0.20", Path: "../etc"},
	} {
		if _, err := a.prepareNFS(context.Background(), "web", &armadav1.VolumeSpec{Name: "u", Path: "/u", Nfs: n}); err == nil {
			t.Errorf("%+v accepted", n)
		}
	}
	if _, err := a.prepareNFS(context.Background(), "../web", &armadav1.VolumeSpec{Name: "u", Path: "/u", Nfs: &armadav1.NfsSource{Server: "10.0.0.20", Path: "/x"}}); err == nil {
		t.Error("a crafted app ID was accepted")
	}
	if len(*calls) != 0 {
		t.Errorf("mounted %+v", *calls)
	}
}
