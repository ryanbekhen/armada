//go:build linux

package containerd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strings"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/ryanbekhen/armada/internal/runtime"
)

var _ runtime.NetworkSandboxer = (*Driver)(nil)

// sandboxPrefix starts the network plugins' container ID of a sandbox, so
// that it never meets a container's ID (<name>-<hex>, names start with
// "armada-").
const sandboxPrefix = "sandbox-"

// EnsureSandbox makes a network sandbox (ADR 0040): a network namespace
// pinned at <run dir>/sandboxes/<id>, attached to the container bridge by
// the same plugins as a container, so it gets an address of the node's
// subnet, the default route through the gateway, and the plugins' firewall
// rules, but holds no process. An existing sandbox is returned as it is;
// one half made, as an agent killed while making it leaves, is made again.
func (d *Driver) EnsureSandbox(ctx context.Context, id string) (runtime.Sandbox, error) {
	if err := runtime.CheckSandboxID(id); err != nil {
		return runtime.Sandbox{}, err
	}
	d.sandboxMu.Lock()
	defer d.sandboxMu.Unlock()
	if err := d.net.Ensure(ctx); err != nil {
		return runtime.Sandbox{}, err
	}
	path, cid := d.sandboxPath(id), sandboxPrefix+id
	if isNetNS(path) {
		if ip, err := d.net.Address(cid, path); err == nil {
			return runtime.Sandbox{ID: id, IP: ip}, nil
		}
	}
	// Whatever is left of an earlier try: its address and its file.
	if err := d.teardownSandbox(ctx, id); err != nil {
		return runtime.Sandbox{}, fmt.Errorf("sandbox network: %w", err)
	}
	if err := os.MkdirAll(d.paths.Sandboxes(), 0o700); err != nil {
		return runtime.Sandbox{}, err
	}
	if err := newPinnedNetNS(path); err != nil {
		return runtime.Sandbox{}, fmt.Errorf("sandbox namespace: %w", err)
	}
	ip, err := d.net.SetupAt(ctx, cid, path)
	if err != nil {
		_ = d.net.Teardown(context.WithoutCancel(ctx), cid, path, nil)
		return runtime.Sandbox{}, fmt.Errorf("sandbox network: %w", err)
	}
	return runtime.Sandbox{ID: id, IP: ip}, nil
}

// RemoveSandbox releases the sandbox's address and firewall rules and
// removes its namespace.
func (d *Driver) RemoveSandbox(ctx context.Context, id string) error {
	if err := runtime.CheckSandboxID(id); err != nil {
		return err
	}
	d.sandboxMu.Lock()
	defer d.sandboxMu.Unlock()
	return d.teardownSandbox(ctx, id)
}

// teardownSandbox releases what the plugins gave the sandbox and removes its
// namespace. A file left unpinned (an agent killed while making it) is
// removed first: the plugins release the address without a namespace.
func (d *Driver) teardownSandbox(ctx context.Context, id string) error {
	path := d.sandboxPath(id)
	if !isNetNS(path) {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := d.net.Teardown(ctx, sandboxPrefix+id, path, nil); err != nil {
		return fmt.Errorf("sandbox network: %w", err)
	}
	return nil
}

// ListSandboxes returns every sandbox whose namespace is pinned, with its
// address; one whose address is unknown is listed without, so that the
// agent removes or remakes it.
func (d *Driver) ListSandboxes(context.Context) ([]runtime.Sandbox, error) {
	d.sandboxMu.Lock()
	defer d.sandboxMu.Unlock()
	entries, err := os.ReadDir(d.paths.Sandboxes())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []runtime.Sandbox
	for _, e := range entries {
		id := e.Name()
		if runtime.CheckSandboxID(id) != nil {
			continue
		}
		s := runtime.Sandbox{ID: id}
		if path := d.sandboxPath(id); isNetNS(path) {
			s.IP, _ = d.net.Address(sandboxPrefix+id, path)
		}
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b runtime.Sandbox) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// DialSandbox dials address from the sandbox's namespace, as DialContainer
// does from a container's: only IP addresses, over TCP or UDP.
func (d *Driver) DialSandbox(ctx context.Context, id, network, address string) (net.Conn, error) {
	if err := runtime.CheckSandboxID(id); err != nil {
		return nil, err
	}
	if err := checkDial(network, address); err != nil {
		return nil, err
	}
	path := d.sandboxPath(id)
	if !isNetNS(path) {
		return nil, fmt.Errorf("sandbox %s: %w", id, runtime.ErrNotFound)
	}
	target, err := netns.GetFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("sandbox namespace: %w", err)
	}
	return dialIn(ctx, target, network, address)
}

func (d *Driver) sandboxPath(id string) string { return filepath.Join(d.paths.Sandboxes(), id) }

// isNetNS reports whether path is a pinned network namespace.
func isNetNS(path string) bool {
	var st unix.Statfs_t
	return unix.Statfs(path, &st) == nil && st.Type == unix.NSFS_MAGIC
}

// newPinnedNetNS makes a network namespace and pins it with a bind mount on
// path, which must not exist. The namespace is made on a locked thread that
// is never unlocked: the thread ends with its goroutine, so no other
// goroutine ever runs in the new namespace.
func newPinnedNetNS(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the sandboxes directory and a checked ID (runtime.CheckSandboxID)
	if err != nil {
		return err
	}
	_ = f.Close()
	errc := make(chan error, 1)
	go func() {
		goruntime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errc <- err
			return
		}
		self := fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
		errc <- unix.Mount(self, path, "none", unix.MS_BIND, "")
	}()
	if err := <-errc; err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
