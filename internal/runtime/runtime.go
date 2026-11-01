// Package runtime abstracts the container engine. The implementation is
// the embedded containerd (package containerd, ADR 0011).
package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"time"
)

// ErrNotFound is returned when a container or image does not exist.
var ErrNotFound = errors.New("not found")

// Labels set on every container Armada manages.
const (
	LabelManaged  = "armada.managed"
	LabelApp      = "armada.app"
	LabelRevision = "armada.revision"
	LabelReplica  = "armada.replica"
	LabelSpecHash = "armada.spec-hash"
)

// Container states.
const (
	StateCreated    = "created"
	StateRunning    = "running"
	StateRestarting = "restarting"
	StateExited     = "exited"
	StatePaused     = "paused"
	StateDead       = "dead"
)

// Driver runs containers on the local node.
type Driver interface {
	// Ping verifies that the engine is reachable and supported.
	Ping(ctx context.Context) error
	// Pull fetches image for this node's platform. It returns a
	// *PlatformError when the image has no variant for it.
	Pull(ctx context.Context, image string, auth *RegistryAuth) (Image, error)
	// Run creates and starts a container.
	Run(ctx context.Context, spec ContainerSpec) (string, error)
	Stop(ctx context.Context, id string, grace time.Duration) error
	Remove(ctx context.Context, id string) error
	// List returns containers (running or not) carrying all given labels.
	List(ctx context.Context, labels map[string]string) ([]Container, error)
	Inspect(ctx context.Context, id string) (Container, error)
	Logs(ctx context.Context, id string, opts LogOptions) (LogStream, error)
}

// Image is a pulled image.
type Image struct {
	// Ref is the digest-pinned reference ("repo@sha256:..."), or "" if the
	// engine reports no digest.
	Ref string
	// Platforms lists the image's platforms as "os/arch" (sorted, no
	// duplicates); empty if the engine cannot tell.
	Platforms []string
}

// PlatformError reports an image without a variant for the node's
// platform.
type PlatformError struct {
	Image string
	// Want is the node's platform, Have the image's, both as "os/arch".
	Want string
	Have []string
}

func (e *PlatformError) Error() string {
	return fmt.Sprintf("image %s has no %s variant (it has %s)", e.Image, e.Want, strings.Join(e.Have, ", "))
}

// RegistryAuth holds credentials for a private registry. It prints without
// the password.
type RegistryAuth struct {
	Username      string
	Password      string
	ServerAddress string
}

// String implements fmt.Stringer without the password.
func (a RegistryAuth) String() string {
	return a.Username + "@" + a.ServerAddress + " (password redacted)"
}

// GoString implements fmt.GoStringer without the password.
func (a RegistryAuth) GoString() string { return a.String() }

// LogValue implements slog.LogValuer without the password.
func (a RegistryAuth) LogValue() slog.Value { return slog.StringValue(a.String()) }

// FileMount bind-mounts a single host file read-only into a container.
type FileMount struct {
	Source string // absolute path of a regular file on the node
	Target string // absolute path in the container
}

// ContainerSpec describes a container to run. Security defaults
// (no-new-privileges, dropped capabilities, no privileged mode) are applied
// by the driver and cannot be loosened through this struct.
type ContainerSpec struct {
	Name        string
	Image       string
	Entrypoint  []string
	Cmd         []string
	Env         []string
	Labels      map[string]string
	Port        int    // container TCP port to publish; 0 for none
	HostIP      string // address to publish on; must be a private IP
	MemoryBytes int64
	NanoCPUs    int64
	PidsLimit   int64
	// Files are mounted read-only; the driver refuses sources that are not
	// regular files (e.g. a runtime socket).
	Files []FileMount
	// DNS overrides the container's nameservers (private IPs only); empty
	// keeps the engine default.
	DNS []string
}

// Container is the observed state of a container.
type Container struct {
	ID       string
	Name     string
	Image    string
	Labels   map[string]string
	State    string
	ExitCode int
	HostIP   string
	HostPort int
	// IP is the container's address on its bridge network, reachable from
	// the node for health checks; empty if unknown.
	IP        string
	StartedAt time.Time
}

// LogOptions controls log retrieval.
type LogOptions struct {
	Follow bool
	Tail   int // 0 means all
}

// Stream identifies stdout or stderr.
type Stream int

// Streams.
const (
	Stdout Stream = 1
	Stderr Stream = 2
)

// LogFrame is one chunk of container output.
type LogFrame struct {
	Stream Stream
	Data   []byte
}

// LogStream yields log frames until io.EOF.
type LogStream interface {
	Next() (LogFrame, error)
	io.Closer
}

// Bridge describes the network app containers are attached to.
type Bridge struct {
	// Gateway is the host's address on the bridge, reachable only from the
	// node itself and its containers.
	Gateway netip.Addr
	Subnet  netip.Prefix
}

// BridgeInspector reports the app container network. It is optional:
// internal ingress and DNS need it.
type BridgeInspector interface {
	Bridge(ctx context.Context) (Bridge, error)
}

// LabelSystem marks Armada's own infrastructure containers (e.g. HAProxy).
const LabelSystem = "armada.system"

// SystemSpec describes an Armada infrastructure container. Unlike
// ContainerSpec it allows host networking and bind mounts, so it must never
// be built from user input.
type SystemSpec struct {
	Name   string
	Image  string
	Cmd    []string
	Labels map[string]string
	Mounts []Mount
	// CapAdd lists the only capabilities granted; all others are dropped.
	CapAdd []string
	User   string
}

// Mount is a bind mount from the host.
type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}

// SystemRunner runs and controls Armada's infrastructure containers. It is
// separate from Driver so the app code path can never reach host networking
// or bind mounts.
type SystemRunner interface {
	// RunSystem creates and starts a host-network container with all
	// capabilities dropped except CapAdd.
	RunSystem(ctx context.Context, spec SystemSpec) (string, error)
	// Exec runs cmd in a running container and returns combined output.
	Exec(ctx context.Context, id string, cmd []string) (output string, exitCode int, err error)
	// Signal sends a signal (e.g. "SIGUSR2") to the container's main process.
	Signal(ctx context.Context, id, signal string) error
}
