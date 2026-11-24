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
	"github.com/ryanbekhen/armada/internal/nodeprog"
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
	have, mounted, readOnly, err := a.nfsMounted(ctx, target, want)
	if err != nil {
		return runtime.VolumeMount{}, err
	}
	if mounted && (have != want || readOnly != n.GetReadOnly()) {
		// The spec moved to another export: replicas still on the old one
		// keep it through their own bind mounts.
		if err := a.unmountNFS(ctx, target); err != nil {
			return runtime.VolumeMount{}, err
		}
		mounted = false
	}
	if !mounted {
		ctx, cancel := context.WithTimeout(ctx, nfsMountTimeout)
		defer cancel()
		mount := a.cfg.MountNFS
		if mount == nil {
			mount = a.mountNFS
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
			if _, mounted, _, err := a.nfsMounted(context.Background(), target, ""); err == nil && mounted {
				if err := a.unmountNFS(context.Background(), target); err != nil {
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

// nfsRequest is what `armada-node nfs` reads.
type nfsRequest struct {
	Server    string `json:"server,omitempty"`
	Path      string `json:"path,omitempty"`
	Target    string `json:"target"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
	TimeoutMs int64  `json:"timeoutMs,omitempty"`
	// Export is the source whose mount's read-only flag is asked: the
	// file system of another source is never looked at (a server that
	// does not answer would hold the call).
	Export string `json:"export,omitempty"`
	// Mountinfo replaces /proc/self/mountinfo (tests).
	Mountinfo string `json:"mountinfo,omitempty"`
}

// nfsMounted reports the NFS source mounted on target and, when it is
// want, whether the mount is read-only: armada-node's `nfs source`, else
// Go's code.
func (a *Agent) nfsMounted(ctx context.Context, target, want string) (source string, mounted, readOnly bool, err error) {
	if p := a.cfg.Node; p != nil {
		var out struct {
			Source   string `json:"source"`
			Mounted  bool   `json:"mounted"`
			ReadOnly bool   `json:"readOnly"`
		}
		err := p.Call(ctx, nfsRequest{Target: target, Export: want}, &out, "nfs", "source")
		if !p.Fallback("nfs source", err) {
			return out.Source, out.Mounted, out.ReadOnly, err
		}
	}
	source, mounted, err = mountedSource(target)
	if err != nil || !mounted || source != want {
		return source, mounted, false, err
	}
	ro, err := mountedReadOnlyWithin(ctx, target, nfsStatTimeout)
	return source, true, ro, err
}

// nfsStatTimeout bounds mountedReadOnly: statfs on a hard NFS mount whose
// server is gone waits for it without end.
const nfsStatTimeout = 10 * time.Second

// mountedReadOnlyWithin is mountedReadOnly bounded by limit and ctx; a
// statfs that does not end in time is left behind on its goroutine, and
// the mount is reported as not answering.
func mountedReadOnlyWithin(ctx context.Context, target string, limit time.Duration) (bool, error) {
	return within(ctx, limit, target, func() bool { return mountedReadOnly(target) })
}

// within runs f on a goroutine of its own and waits for it at most limit.
func within(ctx context.Context, limit time.Duration, target string, f func() bool) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- f() }()
	select {
	case v := <-done:
		return v, nil
	case <-ctx.Done():
		return false, errors.New("the NFS mount on " + target + " does not answer")
	}
}

// unmountNFS detaches target: armada-node's `nfs unmount`, else Go's code.
func (a *Agent) unmountNFS(ctx context.Context, target string) error {
	if p := a.cfg.Node; p != nil {
		err := p.Call(ctx, nfsRequest{Target: target}, nil, "nfs", "unmount")
		if !p.Fallback("nfs unmount", err) {
			return err
		}
	}
	return unmountNFS(target)
}

// mountNFS mounts server:export on target: armada-node's `nfs mount`,
// which checks the export again, else Go's code.
func (a *Agent) mountNFS(ctx context.Context, server, export, target string, readOnly bool) error {
	if p := a.cfg.Node; p != nil {
		req := nfsRequest{Server: server, Path: export, Target: target, ReadOnly: readOnly, TimeoutMs: nodeprog.TimeoutMs(ctx)}
		err := p.Call(ctx, req, nil, "nfs", "mount")
		if cerr := ctx.Err(); cerr != nil && err != nil {
			return fmt.Errorf("the server did not answer: %w", cerr)
		}
		if !p.Fallback("nfs mount", err) {
			return err
		}
	}
	return mountNFS(ctx, server, export, target, readOnly)
}
