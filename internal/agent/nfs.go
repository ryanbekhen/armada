package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/spec"
)

// NFS volumes (ADR 0042): the agent mounts an export once per node and
// volume under NFSDir, with nosuid and nodev, and bind-mounts it into each
// replica that names it, like a volume. The data stays on the NFS server,
// so these volumes bind an app to no node and allow any number of replicas.

// nfsMountTimeout bounds one mount; an unreachable server must not hold a
// start forever.
const nfsMountTimeout = 2 * time.Minute

// NFSSupported reports whether the kernel has an NFSv4 client.
func NFSSupported() bool { return nfsSupported() }

// mountsNFS reports whether this node mounts NFS volumes.
func (a *Agent) mountsNFS() bool {
	return a.cfg.NFSDir != "" && runtime.CanMountVolumes(a.cfg.Driver) && (a.cfg.MountNFS != nil || nfsSupported())
}

// nfsTarget is where volume name of app is mounted on this node.
func (a *Agent) nfsTarget(app, name string) (string, error) {
	if a.cfg.NFSDir == "" {
		return "", errors.New("this node does not mount NFS volumes")
	}
	if !spec.ValidAppID(app) || !spec.ValidName(name) {
		return "", fmt.Errorf("invalid volume name %q of app %q", name, app)
	}
	return filepath.Join(a.cfg.NFSDir, app, name), nil
}

// prepareNFS mounts v's export unless it is mounted, and returns the
// replica's mount of it.
func (a *Agent) prepareNFS(ctx context.Context, app string, v *armadav1.VolumeSpec) (runtime.VolumeMount, error) {
	n := v.GetNfs()
	if !a.mountsNFS() {
		return runtime.VolumeMount{}, errors.New("this node does not mount NFS volumes")
	}
	// The server checked these; a node checks again before calling the
	// kernel with them.
	if err := spec.CheckNFSServer(n.GetServer()); err != nil {
		return runtime.VolumeMount{}, fmt.Errorf("NFS server: %w", err)
	}
	if err := spec.CheckNFSPath(n.GetPath()); err != nil {
		return runtime.VolumeMount{}, fmt.Errorf("NFS path: %w", err)
	}
	if err := spec.ValidateVolumePath(v.GetPath()); err != nil {
		return runtime.VolumeMount{}, fmt.Errorf("path: %w", err)
	}
	target, err := a.nfsTarget(app, v.GetName())
	if err != nil {
		return runtime.VolumeMount{}, err
	}
	unlock := a.nfsMounts.lock(target)
	defer unlock()
	if err := fsutil.MkdirPrivate(filepath.Dir(target)); err != nil {
		return runtime.VolumeMount{}, err
	}
	if err := os.Mkdir(target, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return runtime.VolumeMount{}, err
	}
	want := nfsSource(n.GetServer(), n.GetPath())
	have, mounted, err := mountedSource(target)
	if err != nil {
		return runtime.VolumeMount{}, err
	}
	if mounted && (have != want || mountedReadOnly(target) != n.GetReadOnly()) {
		// The spec moved to another export: replicas still on the old one
		// keep it through their own bind mounts.
		if err := unmountNFS(target); err != nil {
			return runtime.VolumeMount{}, err
		}
		mounted = false
	}
	if !mounted {
		ctx, cancel := context.WithTimeout(ctx, nfsMountTimeout)
		defer cancel()
		mount := a.cfg.MountNFS
		if mount == nil {
			mount = mountNFS
		}
		if err := mount(ctx, n.GetServer(), n.GetPath(), target, n.GetReadOnly()); err != nil {
			return runtime.VolumeMount{}, fmt.Errorf("mount NFS export %s: %w", want, err)
		}
		a.log.Info("mounted NFS volume", "app", app, "volume", v.GetName(), "export", want)
	}
	return runtime.VolumeMount{Source: target, Target: v.GetPath(), Shared: true, ReadOnly: n.GetReadOnly()}, nil
}

// nfsSource is the export as the kernel names it.
func nfsSource(server, path string) string {
	if ip, err := netipParse(server); err == nil && ip.Is6() {
		return "[" + server + "]:" + path
	}
	return server + ":" + path
}

// cleanNFS unmounts the NFS volumes no desired replica names any more.
func (a *Agent) cleanNFS(desired map[string]*armadav1.ReplicaSpec) {
	if a.cfg.NFSDir == "" {
		return
	}
	used := map[string]bool{}
	for _, s := range desired {
		for _, v := range s.GetVolumes() {
			if v.GetNfs() != nil {
				if t, err := a.nfsTarget(s.GetApp(), v.GetName()); err == nil {
					used[t] = true
				}
			}
		}
	}
	apps, err := os.ReadDir(a.cfg.NFSDir)
	if err != nil {
		return
	}
	for _, app := range apps {
		dir := filepath.Join(a.cfg.NFSDir, app.Name())
		vols, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, v := range vols {
			target := filepath.Join(dir, v.Name())
			if used[target] {
				continue
			}
			unlock := a.nfsMounts.lock(target)
			if _, mounted, err := mountedSource(target); err == nil && mounted {
				if err := unmountNFS(target); err != nil {
					a.log.Warn("unmount NFS volume", "dir", target, "err", err)
					unlock()
					continue
				}
				a.log.Info("unmounted NFS volume", "dir", target)
			}
			_ = os.Remove(target) // only an empty mount point
			unlock()
		}
		_ = os.Remove(dir)
	}
}
