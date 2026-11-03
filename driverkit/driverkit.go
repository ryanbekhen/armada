// Package driverkit is for writing Armada runtime drivers (ADR 0015): a
// driver implements Driver, and Serve exposes it to the Armada agent over
// the armada.driver.v1 protocol on a Unix socket, checking every request
// first. Package conformance tests that a driver keeps Armada's security
// defaults.
//
// A driver runs as root with the agent's trust. It must apply every field
// of ContainerSpec.Security or refuse the container, and never give an app
// container host networking, privileged mode, devices, or directory mounts.
package driverkit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"time"
)

// ProtocolVersion is the armada.driver.v1 major version this package
// serves.
const ProtocolVersion = 1

// SocketDir is where drivers listen on Linux, as NAME.sock. Use
// DefaultSocketDir for the directory on the current system.
const SocketDir = "/run/armada/drivers"

// macOSSocketDir is where drivers listen on macOS, below the home of the
// user that runs the agent and the driver (ADR 0016).
const macOSSocketDir = "Library/Application Support/Armada/run/drivers"

// DefaultSocketDir returns where drivers listen on this system: SocketDir
// on Linux, and below the user's home on macOS, where the agent and its
// driver run as one user.
func DefaultSocketDir() string {
	if goruntime.GOOS != "darwin" {
		return SocketDir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return SocketDir
	}
	return filepath.Join(home, macOSSocketDir)
}

// ErrNotFound is returned when a container or image does not exist.
var ErrNotFound = errors.New("not found")

// Driver runs app containers on the node. Implement SystemRunner,
// BridgeInspector, Execer, and StatsReader as well to offer those
// capabilities.
type Driver interface {
	// Ping verifies that the engine is reachable and supported.
	Ping(ctx context.Context) error
	// Pull fetches image for the node's platform. It returns a
	// *PlatformError when the image has no variant for it.
	Pull(ctx context.Context, image string, auth *RegistryAuth) (Image, error)
	// Run creates and starts a container and returns its ID.
	Run(ctx context.Context, spec ContainerSpec) (string, error)
	// Stop stops a container, killing it after grace.
	Stop(ctx context.Context, id string, grace time.Duration) error
	// Remove deletes a container, stopping it first if needed.
	Remove(ctx context.Context, id string) error
	// List returns containers (running or not) carrying all given labels.
	List(ctx context.Context, labels map[string]string) ([]Container, error)
	Inspect(ctx context.Context, id string) (Container, error)
	// Logs returns a container's output; with Follow, until ctx ends or the
	// container stops.
	Logs(ctx context.Context, id string, opts LogOptions) (LogStream, error)
}

// SystemRunner runs Armada's infrastructure containers (the node's
// HAProxy): host network, every capability dropped but CapAdd.
type SystemRunner interface {
	RunSystem(ctx context.Context, spec SystemSpec) (string, error)
	// Exec runs cmd in a running container and returns combined output.
	Exec(ctx context.Context, id string, cmd []string) (output string, exitCode int, err error)
	// Signal sends a signal (e.g. "SIGUSR2") to the container's main process.
	Signal(ctx context.Context, id, signal string) error
}

// BridgeInspector reports the network app containers share with the host.
type BridgeInspector interface {
	Bridge(ctx context.Context) (Bridge, error)
}

// Execer runs commands in app containers for `armada exec` (ADR 0017). The
// command must get the container's own security context: user,
// capabilities, no-new-privileges, seccomp, limits, and namespaces. Serve
// only passes it running app containers and commands that pass
// CheckExecCommand.
type Execer interface {
	// ExecApp runs opts.Cmd in container id and returns its exit code once
	// it has ended and its output has been written.
	ExecApp(ctx context.Context, id string, opts ExecOptions) (exitCode int, err error)
}

// TermSize is a terminal's size in character cells.
type TermSize struct {
	Rows, Cols uint16
}

// ExecOptions describes a command for Execer.
type ExecOptions struct {
	Cmd []string
	// TTY allocates a terminal; output then goes to Stdout only.
	TTY bool
	// Size is the terminal's initial size, applied before the command
	// starts or, if the engine cannot, at most a moment after; Resize
	// carries changes until the command ends.
	Size   TermSize
	Resize <-chan TermSize
	// Stdin is the command's standard input, nil for none; EOF must close
	// the command's standard input.
	Stdin io.Reader
	// Stdout and Stderr receive the command's output.
	Stdout, Stderr io.Writer
}

// Info identifies a driver in the handshake.
type Info struct {
	// Name is the driver's name, as in its socket NAME.sock.
	Name    string
	Version string
	// OS and Arch are the node's platform as the engine sees it ("linux",
	// "arm64").
	OS, Arch string
	// VMIsolation declares that every container runs in its own virtual
	// machine with its own kernel, so the driver may leave out
	// no-new-privileges and the PID limit (ADR 0016). The conformance suite
	// checks it.
	VMIsolation bool
	// MinMemoryBytes is the smallest memory limit the driver accepts; the
	// scheduler places no replica with a smaller limit on the node. 0: none.
	MinMemoryBytes int64
	// CPUMillis and MemoryBytes are what the engine can give containers
	// when that is less than the machine has (a virtual machine of fixed
	// size, say); the node reports the smaller of the two. 0: the
	// machine's.
	CPUMillis, MemoryBytes int64
}

// Image is a pulled image.
type Image struct {
	// Ref is the digest-pinned reference ("repo@sha256:..."), or "".
	Ref string
	// Platforms lists the image's platforms as "os/arch", if known.
	Platforms []string
}

// PlatformError reports an image without a variant for the node.
type PlatformError struct {
	Image string
	// Want is the node's platform, Have the image's, as "os/arch".
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

func (a RegistryAuth) String() string {
	return a.Username + "@" + a.ServerAddress + " (password redacted)"
}

// GoString implements fmt.GoStringer without the password.
func (a RegistryAuth) GoString() string { return a.String() }

// LogValue implements slog.LogValuer without the password.
func (a RegistryAuth) LogValue() slog.Value { return slog.StringValue(a.String()) }

// Security holds the defaults every app container gets. A driver applies
// every field or refuses the container.
type Security struct {
	// NoNewPrivileges is always true.
	NoNewPrivileges bool
	// DropCapabilities are removed from the engine's default set, without
	// the "CAP_" prefix ("NET_RAW").
	DropCapabilities []string
}

// FileMount bind-mounts a regular host file read-only into a container.
type FileMount struct {
	Source string
	Target string
}

// ContainerSpec describes an app container. Env may hold secret values:
// never log a ContainerSpec.
type ContainerSpec struct {
	Name       string
	Image      string
	Entrypoint []string
	Cmd        []string
	Env        []string
	Labels     map[string]string
	// Port is the TCP port to publish on HostIP, a private address; 0 for
	// none.
	Port   int
	HostIP string
	// MemoryBytes is the memory limit (no swap beyond it).
	MemoryBytes int64
	// NanoCPUs is the CPU limit; 0 for none.
	NanoCPUs int64
	// CPUReserveMillis sets the CPU weight in proportion; 0 for the default.
	CPUReserveMillis int64
	PidsLimit        int64
	Files            []FileMount
	// DNS sets the nameservers (private addresses); empty keeps the
	// engine's default.
	DNS      []string
	Security Security
}

// Container is the observed state of a container.
type Container struct {
	ID     string
	Name   string
	Image  string
	Labels map[string]string
	// State is one of the State constants.
	State    string
	ExitCode int
	HostIP   string
	HostPort int
	// IP is the container's address on its bridge, reachable from the node.
	IP        string
	StartedAt time.Time
}

// Container states.
const (
	StateCreated    = "created"
	StateRunning    = "running"
	StateRestarting = "restarting"
	StateExited     = "exited"
	StatePaused     = "paused"
	StateDead       = "dead"
)

// LogOptions controls log retrieval.
type LogOptions struct {
	Follow bool
	// Tail is the number of lines to show; 0 for all.
	Tail int
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

// Mount is a bind mount from the host into a system container.
type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}

// SystemSpec describes an Armada infrastructure container. Only Armada
// builds these, never from user input.
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

// Bridge describes the network app containers are attached to.
type Bridge struct {
	// Gateway is the host's address on the bridge, reachable only from the
	// node and its containers.
	Gateway netip.Addr
	Subnet  netip.Prefix
}
