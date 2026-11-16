//go:build integration

package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/core/remotes/docker/config"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
)

// TestRunIntegration runs a container with no containerd at all: the image
// store pulls and unpacks it, a bundle mounts it, and armada-shim (started
// as a systemd unit) runs it with runc and logs through armada-log.
//
//	sudo ARMADA_IMAGES_DIR=/var/tmp/imgs ARMADA_SHIM_BIN=/root/armada-shim \
//	  ARMADA_RUNC=/var/lib/armada/runtime/current/bin/runc \
//	  ARMADA_LOG_BIN=/var/lib/armada/runtime/current/bin/armada-log ./t -test.run RunIntegration -test.v
func TestRunIntegration(t *testing.T) {
	dir, shimBin, runc, logger := os.Getenv("ARMADA_IMAGES_DIR"), os.Getenv("ARMADA_SHIM_BIN"), os.Getenv("ARMADA_RUNC"), os.Getenv("ARMADA_LOG_BIN")
	if dir == "" || shimBin == "" || runc == "" || logger == "" || os.Geteuid() != 0 {
		t.Skip("needs root, ARMADA_IMAGES_DIR, ARMADA_SHIM_BIN, ARMADA_RUNC, ARMADA_LOG_BIN")
	}
	ctx := namespaces.WithNamespace(context.Background(), "armada")
	imgs, err := OpenImages(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer imgs.Close()
	resolver := docker.NewResolver(docker.ResolverOptions{Hosts: config.ConfigureHosts(ctx, config.HostOptions{DefaultScheme: "https"})})
	img, err := imgs.Pull(ctx, "docker.io/traefik/whoami:v1.10", resolver, nil)
	if err != nil {
		t.Fatal(err)
	}

	const id = "itest-r1-0a1b2c3d"
	rootfs, err := imgs.Prepare(ctx, id, img)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = imgs.Release(ctx, id) }()
	oimg, oclient := imgs.OCI(img)
	spec, err := oci.GenerateSpec(ctx, oclient, &containers.Container{ID: id, SnapshotKey: id, Snapshotter: "overlayfs"},
		oci.WithImageConfig(oimg), oci.WithCgroup("/armada-itest/"+id), oci.WithNoNewPrivileges)
	if err != nil {
		t.Fatal(err)
	}
	bundles := Bundles{Dir: filepath.Join(dir, "containers")}
	bundle, err := bundles.Create(Record{ID: id, Image: img.Name, Group: "itest@1", Created: time.Now()}, spec, rootfs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := bundles.Remove(id); err != nil {
			t.Error(err)
		}
	}()

	shims := &Shims{Dir: "/run/armada-itest-shim", Bin: shimBin, Runc: runc, Logger: logger}
	sh, err := shims.For(ctx, "itest@1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exec.Command("systemctl", "stop", "armada-shim-"+shimName("itest@1")).Run() }()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	pid, err := sh.Create(ctx, id, bundle, logs)
	if err != nil {
		t.Fatal(err)
	}
	if err := sh.Start(ctx, id); err != nil {
		t.Fatal(err)
	}
	t.Logf("started %s as pid %d", id, pid)
	waitFor(t, "the container's log line", func() bool {
		b, _ := os.ReadFile(filepath.Join(logs, id+".log"))
		return strings.Contains(string(b), "Starting up on port 80")
	})
	if st, err := sh.State(ctx, id); err != nil || st.Status != "running" || st.Pid != pid {
		t.Fatalf("state %+v %v", st, err)
	}
	if recs, err := bundles.Records(); err != nil || len(recs) != 1 || recs[0].ID != id {
		t.Fatalf("records %+v %v", recs, err)
	}
	if out, err := exec.Command("systemctl", "show", "-p", "MainPID", "--value", "armada-shim-"+shimName("itest@1")).Output(); err == nil {
		t.Logf("shim: %s", memory(strings.TrimSpace(string(out))))
	}
	if err := sh.Kill(ctx, id, 9); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "exit after SIGKILL (no init: PID 1 ignores SIGTERM)", func() bool {
		st, err := sh.State(ctx, id)
		return err == nil && st.Status == "exited" && st.Exit == 137
	})
	if err := sh.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.State(ctx, id); !NotFound(err) {
		t.Fatalf("state after delete: %v", err)
	}

	// A shim that dies leaves its containers without a supervisor: the
	// next shim of the group ends them before it starts.
	if _, err := sh.Create(ctx, id, bundle, logs); err != nil {
		t.Fatal(err)
	}
	if err := sh.Start(ctx, id); err != nil {
		t.Fatal(err)
	}
	st, err := sh.State(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("systemctl", "stop", "armada-shim-"+shimName("itest@1")).CombinedOutput(); err != nil {
		t.Fatalf("stop shim: %v: %s", err, out)
	}
	if _, err := shims.For(ctx, "itest@1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", st.Pid)); err == nil {
		t.Errorf("process %d of the stopped shim's container still runs", st.Pid)
	}
	if out, _ := exec.Command(runc, "--root", sh.Root, "list", "-q").Output(); len(strings.TrimSpace(string(out))) != 0 {
		t.Errorf("runc still lists %q", out)
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func memory(pid string) string {
	b, err := os.ReadFile("/proc/" + pid + "/smaps_rollup")
	if err != nil {
		return err.Error()
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "Pss:") || strings.HasPrefix(l, "Pss_Anon:") {
			out = append(out, strings.Join(strings.Fields(l), " "))
		}
	}
	return strings.Join(out, ", ")
}
