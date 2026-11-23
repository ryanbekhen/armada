package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/errdefs"
	clog "github.com/containerd/log"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// Native hands the supervisor runtime's work below the driver to
// armada-node (ADR 0054 step 4, fourth part): images (pulled into, and
// read from, armada-node's store under Images), containers' root
// filesystems on its unpacked layers, OCI bundles, and the requests to
// armada-shim. The driver still builds every container's spec and runs
// its network, logs, and exec.
//
// The files are those Go keeps (Bundles, the shims' sockets and runc
// state), so a node can switch between Go and armada-node either way and
// each adopts the containers the other made. A call armada-node fails
// (it does not run, or its answer cannot be read) is done by Go's code on
// the same files where Go can: bundles and shims. Images and root
// filesystems live in armada-node's store, which Go only reads, so their
// calls have no Go fallback.
type Native struct {
	// Bin is the runtime pack's armada-node.
	Bin string
	// Images is armada-node's image store (<data dir>/node/images).
	Images string

	content content.Store

	mu   sync.Mutex
	errs map[string]string
}

// OpenNative opens armada-node's image store under images for reading.
func OpenNative(bin, images string) (*Native, error) {
	if err := os.MkdirAll(filepath.Join(images, "content"), 0o700); err != nil {
		return nil, err
	}
	level := clog.GetLevel()
	_ = clog.SetLevel(clog.ErrorLevel)
	cs, err := local.NewStore(filepath.Join(images, "content"))
	_ = clog.SetLevel(level)
	if err != nil {
		return nil, fmt.Errorf("armada-node's content store: %w", err)
	}
	return &Native{Bin: bin, Images: images, content: cs}, nil
}

// programError is armada-node failing to do a call: it did not run, or
// its answer could not be read. Errors it answered with are plain.
type programError struct{ err error }

func (e programError) Error() string { return "armada-node: " + e.err.Error() }
func (e programError) Unwrap() error { return e.err }

// programLimit bounds every call but a shim's wait, which lasts as long
// as its container.
const programLimit = 5 * time.Minute

// programGrace is how long armada-node may run past the caller's
// deadline: the deadline travels in the request (timeoutMs), and the
// program answers with what Go's code answers once its time is up rather
// than being killed first.
const programGrace = 2 * time.Second

// exec runs armada-node with args and stdin (JSON), returning its output.
// A cancelled caller kills it at once; one whose deadline passes, after
// programGrace.
func (n *Native) exec(ctx context.Context, bounded bool, stdin any, args ...string) ([]byte, error) {
	in, err := json.Marshal(stdin)
	if err != nil {
		return nil, err
	}
	run := ctx
	if dl, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		run, cancel = context.WithDeadline(context.WithoutCancel(ctx), dl.Add(programGrace))
		defer cancel()
		stop := context.AfterFunc(ctx, func() {
			if errors.Is(ctx.Err(), context.Canceled) {
				cancel()
			}
		})
		defer stop()
	}
	if bounded {
		var cancel context.CancelFunc
		run, cancel = context.WithTimeout(run, programLimit)
		defer cancel()
	}
	cmd := exec.CommandContext(run, n.Bin, args...) //nolint:gosec // the runtime pack's armada-node
	cmd.Stdin = bytes.NewReader(in)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if run.Err() != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			return nil, run.Err()
		}
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			err = fmt.Errorf("%w: %s", err, msg)
		}
		return nil, programError{err}
	}
	return out, nil
}

// run runs a call and reads its answer into out: {"error": TEXT} is that
// error.
func (n *Native) run(ctx context.Context, stdin, out any, args ...string) error {
	b, err := n.exec(ctx, true, stdin, args...)
	if err != nil {
		return err
	}
	var answer struct {
		Error *string `json:"error"`
	}
	if err := json.Unmarshal(b, &answer); err != nil {
		return programError{fmt.Errorf("unreadable answer: %w", err)}
	}
	if answer.Error != nil {
		return errors.New(*answer.Error)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return programError{fmt.Errorf("unreadable answer: %w", err)}
		}
	}
	return nil
}

// fallback reports whether Go must do a call armada-node failed (op names
// it), logging each distinct failure once.
func (n *Native) fallback(op string, err error) bool {
	var perr programError
	failed := errors.As(err, &perr)
	msg := ""
	if failed {
		msg = err.Error()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.errs == nil {
		n.errs = map[string]string{}
	}
	prev, seen := n.errs[op]
	n.errs[op] = msg
	switch {
	case !failed && seen && prev != "":
		slog.Info("armada-node works again", "op", op)
	case failed && (!seen || prev != msg):
		slog.Warn("armada-node failed; Go did it instead", "op", op, "err", err)
	}
	return failed
}

// note logs a failure of a call Go cannot do instead.
func (n *Native) note(op string, err error) {
	var perr programError
	if !errors.As(err, &perr) {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.errs == nil {
		n.errs = map[string]string{}
	}
	if n.errs[op] != err.Error() {
		slog.Warn("armada-node failed", "op", op, "err", err)
	}
	n.errs[op] = err.Error()
}

// Prepare makes container key's root filesystem on image's layers (the
// one it has when it exists) and returns its mounts.
func (n *Native) Prepare(ctx context.Context, key, image string) ([]mount.Mount, error) {
	var out struct{ Mounts []mount.Mount }
	err := n.run(ctx, map[string]string{"key": key, "image": image}, &out, "runtime", "prepare", n.Images)
	n.note("prepare", err)
	return out.Mounts, err
}

// Release removes container key's root filesystem; Go removes the
// directory itself when armada-node fails.
func (n *Native) Release(ctx context.Context, key string) error {
	err := n.run(ctx, nil, nil, "runtime", "release", n.Images, key)
	if n.fallback("release", err) {
		return removeNodeSnapshot(n.Images, key)
	}
	return err
}

// removeNodeSnapshot removes the root filesystem armada-node made for
// container key (<images>/active/<key>), as its release does.
func removeNodeSnapshot(images, key string) error {
	if key == "" || key == "." || key == ".." || strings.ContainsAny(key, "/\x00") || strings.HasPrefix(key, ".") {
		return nil
	}
	return os.RemoveAll(filepath.Join(images, "active", key))
}

// nativeCreate is what `runtime bundle create` reads.
type nativeCreate struct {
	Dir    string            `json:"dir"`
	ID     string            `json:"id"`
	Image  string            `json:"image"`
	Labels map[string]string `json:"labels,omitempty"`
	Spec   json.RawMessage   `json:"spec"`
	Mounts []mount.Mount     `json:"mounts"`
}

type nativeRecord struct {
	Record Record `json:"record"`
}

// CreateBundle writes container id's bundle under dir as Bundles.Create
// does, its root filesystem mounted from rootfs.
func (n *Native) CreateBundle(ctx context.Context, dir, id, image string, labels map[string]string, spec *specs.Spec, rootfs []mount.Mount) (Record, error) {
	b, err := json.Marshal(spec)
	if err != nil {
		return Record{}, err
	}
	var out nativeRecord
	err = n.run(ctx, nativeCreate{Dir: dir, ID: id, Image: image, Labels: labels, Spec: b, Mounts: rootfs}, &out, "runtime", "bundle", "create")
	return out.Record, err
}

// RemoveBundle unmounts and removes container id's bundle.
func (n *Native) RemoveBundle(ctx context.Context, dir, id string) error {
	return n.run(ctx, nil, nil, "runtime", "bundle", "remove", dir, id)
}

// Records lists the finished bundles' records under dir.
func (n *Native) Records(ctx context.Context, dir string) ([]Record, error) {
	var out struct{ Records []Record }
	err := n.run(ctx, nil, &out, "runtime", "bundle", "records", dir)
	return out.Records, err
}

// SetLabels merges labels into container id's record.
func (n *Native) SetLabels(ctx context.Context, dir, id string, labels map[string]string) (Record, error) {
	var out nativeRecord
	err := n.run(ctx, map[string]map[string]string{"labels": labels}, &out, "runtime", "bundle", "labels", dir, id)
	return out.Record, err
}

// shimRequest is what `runtime shim call|start|abandon` read.
type shimRequest struct {
	Dir        string   `json:"dir"`
	Bin        string   `json:"bin,omitempty"`
	Runc       string   `json:"runc,omitempty"`
	Logger     string   `json:"logger,omitempty"`
	Group      string   `json:"group"`
	SystemdRun string   `json:"systemdRun,omitempty"`
	Systemctl  string   `json:"systemctl,omitempty"`
	TimeoutMs  int64    `json:"timeoutMs,omitempty"`
	Words      []string `json:"words,omitempty"`
}

func timeoutMs(ctx context.Context) int64 {
	dl, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	return max(time.Until(dl).Milliseconds(), 1)
}

// shimConnError is a shim that could not be reached or did not answer, as
// armada-node reports it: the text Go's call gives, and the errno of a
// failed connection, which errors.Is finds.
type shimConnError struct {
	text  string
	errno syscall.Errno
}

func (e *shimConnError) Error() string { return e.text }
func (e *shimConnError) Unwrap() error {
	if e.errno == 0 {
		return nil
	}
	return e.errno
}

// shimCall sends one request to a shim through armada-node.
func (n *Native) shimCall(ctx context.Context, req shimRequest) (string, error) {
	req.TimeoutMs = timeoutMs(ctx)
	b, err := n.exec(ctx, req.Words[0] != "wait", req, "runtime", "shim", "call")
	if err != nil {
		var perr programError
		if !errors.As(err, &perr) {
			// The caller's context ended: Go's call closes its connection.
			return "", fmt.Errorf("shim: %w", err)
		}
		return "", err
	}
	var a struct {
		Answer *string `json:"answer"`
		Shim   *string `json:"shim"`
		Error  *string `json:"error"`
		Errno  int     `json:"errno"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return "", programError{fmt.Errorf("unreadable answer: %w", err)}
	}
	switch {
	case a.Answer != nil:
		return *a.Answer, nil
	case a.Shim != nil:
		return "", errShim(*a.Shim)
	case a.Error != nil:
		return "", &shimConnError{text: *a.Error, errno: syscall.Errno(a.Errno)}
	}
	return "", programError{errors.New("unreadable answer: none of answer, shim, error")}
}

// abandon ends the containers of a group's shim once it is gone, and
// reports whether it was (also with an error: gone, but not every
// container ended).
func (n *Native) abandon(ctx context.Context, req shimRequest) (bool, error) {
	b, err := n.exec(ctx, true, req, "runtime", "shim", "abandon")
	if err != nil {
		return false, err
	}
	var a struct {
		Gone  *bool   `json:"gone"`
		Error *string `json:"error"`
	}
	if err := json.Unmarshal(b, &a); err != nil || (a.Gone == nil && a.Error == nil) {
		return false, programError{fmt.Errorf("unreadable answer: %s", b)}
	}
	gone := a.Gone != nil && *a.Gone
	if a.Error != nil {
		return gone, errors.New(*a.Error)
	}
	return gone, nil
}

// Pull pulls image into armada-node's store as Driver.Pull pulls it.
func (n *Native) Pull(ctx context.Context, image string, auth *runtime.RegistryAuth) (runtime.Image, error) {
	req := map[string]any{"image": image}
	if auth != nil {
		req["auth"] = map[string]string{"Username": auth.Username, "Password": auth.Password, "ServerAddress": auth.ServerAddress}
	}
	b, err := n.exec(ctx, true, req, "runtime", "pull", n.Images)
	if err != nil {
		n.note("pull", err)
		return runtime.Image{}, err
	}
	var a struct {
		Ref       *string  `json:"ref"`
		Platforms []string `json:"platforms"`
		Error     *string  `json:"error"`
		Platform  *struct {
			Image string   `json:"image"`
			Want  string   `json:"want"`
			Have  []string `json:"have"`
		} `json:"platform"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		err = programError{fmt.Errorf("unreadable answer: %w", err)}
		n.note("pull", err)
		return runtime.Image{}, err
	}
	switch {
	case a.Platform != nil:
		return runtime.Image{}, &runtime.PlatformError{Image: a.Platform.Image, Want: a.Platform.Want, Have: a.Platform.Have}
	case a.Error != nil:
		return runtime.Image{}, errors.New(*a.Error)
	case a.Ref == nil:
		return runtime.Image{}, programError{errors.New("unreadable answer: no ref")}
	}
	return runtime.Image{Ref: *a.Ref, Platforms: a.Platforms}, nil
}

// Prune removes the images PruneImages would (keep: what the node's
// replicas name; inUse: the image names containers use).
func (n *Native) Prune(ctx context.Context, keep, inUse []string, grace time.Duration) ([]string, error) {
	var out struct{ Removed []string }
	err := n.run(ctx, map[string]any{"keep": keep, "inUse": inUse, "graceSeconds": int64(grace.Seconds())}, &out, "runtime", "prune", n.Images)
	n.note("prune", err)
	return out.Removed, err
}

// index reads armada-node's index.json (written whole and renamed, so a
// read needs no lock).
func (n *Native) index() (nodeIndex, error) {
	var idx nodeIndex
	b, err := os.ReadFile(filepath.Join(n.Images, "index.json"))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return idx, nil
	case err != nil:
		return idx, err
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		return idx, fmt.Errorf("index.json: %w", err)
	}
	if idx.Version > nodeIndexVersion {
		return idx, fmt.Errorf("index.json: version %d is newer than this program's %d", idx.Version, nodeIndexVersion)
	}
	return idx, nil
}

// record turns armada-node's record of an image into the store's.
func (r nodeImage) record() Image {
	img := Image{Name: r.Name, Target: r.Target, Config: r.Config, ChainID: digest.Digest(r.ChainID), Platforms: r.Platforms, Labels: maps.Clone(r.Labels)}
	img.Created, _ = time.Parse(time.RFC3339Nano, r.Created)
	img.Updated, _ = time.Parse(time.RFC3339Nano, r.Updated)
	return img
}

// image returns the record of a pulled image name.
func (n *Native) image(name string) (Image, error) {
	idx, err := n.index()
	if err != nil {
		return Image{}, err
	}
	r, ok := idx.Images[name]
	if !ok {
		return Image{}, fmt.Errorf("image %s: %w", name, errdefs.ErrNotFound)
	}
	return r.record(), nil
}

// list returns every image record.
func (n *Native) list() ([]images.Image, error) {
	idx, err := n.index()
	if err != nil {
		return nil, err
	}
	out := make([]images.Image, 0, len(idx.Images))
	for _, r := range idx.Images {
		out = append(out, r.record().metadata())
	}
	return out, nil
}

// mountsClient's snapshots hand containerd's spec options the mounts of a
// root filesystem armada-node prepared, so the options that read the
// image's users and groups find them as on Go's store.
type mountsClient struct{ mounts []mount.Mount }

func (c mountsClient) SnapshotService(string) snapshots.Snapshotter { return mountsSnapshots(c) }

type mountsSnapshots struct{ mounts []mount.Mount }

func (s mountsSnapshots) Mounts(context.Context, string) ([]mount.Mount, error) {
	return s.mounts, nil
}

// The rest of snapshots.Snapshotter: the spec options use only Mounts.
func (s mountsSnapshots) Stat(context.Context, string) (snapshots.Info, error) {
	return snapshots.Info{}, errdefs.ErrNotImplemented
}

func (s mountsSnapshots) Update(context.Context, snapshots.Info, ...string) (snapshots.Info, error) {
	return snapshots.Info{}, errdefs.ErrNotImplemented
}

func (s mountsSnapshots) Usage(context.Context, string) (snapshots.Usage, error) {
	return snapshots.Usage{}, errdefs.ErrNotImplemented
}

func (s mountsSnapshots) Prepare(context.Context, string, string, ...snapshots.Opt) ([]mount.Mount, error) {
	return nil, errdefs.ErrNotImplemented
}

func (s mountsSnapshots) View(context.Context, string, string, ...snapshots.Opt) ([]mount.Mount, error) {
	return nil, errdefs.ErrNotImplemented
}

func (s mountsSnapshots) Commit(context.Context, string, string, ...snapshots.Opt) error {
	return errdefs.ErrNotImplemented
}

func (s mountsSnapshots) Remove(context.Context, string) error { return errdefs.ErrNotImplemented }

func (s mountsSnapshots) Walk(context.Context, snapshots.WalkFunc, ...string) error {
	return errdefs.ErrNotImplemented
}

func (s mountsSnapshots) Close() error { return nil }
