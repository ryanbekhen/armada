// Package remote is the agent's side of an external runtime driver (ADR
// 0015): a runtime.Driver that forwards to a driver process over the
// armada.driver.v1 protocol on a root-only Unix socket.
package remote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	driverv1 "github.com/ryanbekhen/armada/api/armada/driver/v1"
	"github.com/ryanbekhen/armada/driverkit"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// Config selects a driver.
type Config struct {
	// Name is the driver's name; it listens on Dir/Name.sock.
	Name string
	// Dir defaults to driverkit.DefaultSocketDir.
	Dir string
	// UID is the user that must own the socket and run the driver: the
	// agent's own user (root on Linux, the node's user on macOS, ADR 0016).
	UID int
}

// Driver forwards to an external driver. It implements runtime.Driver,
// runtime.SystemRunner, and runtime.BridgeInspector; which of the optional
// ones work is known after the first successful Ping (CanRunSystem,
// HasBridge).
type Driver struct {
	cfg    Config
	path   string
	conn   *grpc.ClientConn
	client driverv1.DriverClient

	mu   sync.Mutex
	info *driverv1.InfoResponse
}

// New returns a Driver for cfg. It does not connect: Ping checks the socket,
// connects, and performs the handshake, so the agent can wait for a driver
// that starts after it.
func New(cfg Config) (*Driver, error) {
	if err := driverkit.CheckName(cfg.Name); err != nil {
		return nil, err
	}
	if cfg.Dir == "" {
		cfg.Dir = driverkit.DefaultSocketDir()
	}
	d := &Driver{cfg: cfg, path: filepath.Join(cfg.Dir, cfg.Name+".sock")}
	conn, err := grpc.NewClient("passthrough:///"+cfg.Name,
		grpc.WithContextDialer(d.dial),
		grpc.WithTransportCredentials(peerCreds{uid: cfg.UID}),
	)
	if err != nil {
		return nil, err
	}
	d.conn, d.client = conn, driverv1.NewDriverClient(conn)
	return d, nil
}

// Close closes the connection.
func (d *Driver) Close() error { return d.conn.Close() }

// dial connects to the socket after checking that it and its directory
// belong to the driver's user and are closed to everyone else.
func (d *Driver) dial(ctx context.Context, _ string) (net.Conn, error) {
	if err := checkPrivate(d.cfg.Dir, os.ModeDir, d.cfg.UID); err != nil {
		return nil, err
	}
	if err := checkPrivate(d.path, os.ModeSocket, d.cfg.UID); err != nil {
		return nil, err
	}
	var nd net.Dialer
	return nd.DialContext(ctx, "unix", d.path)
}

func checkPrivate(path string, typ os.FileMode, uid int) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Type() != typ {
		return fmt.Errorf("%s: not a %s", path, map[os.FileMode]string{os.ModeDir: "directory", os.ModeSocket: "socket"}[typ])
	}
	owner, err := ownerUID(fi)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if owner != uid {
		return fmt.Errorf("%s is owned by uid %d, want %d", path, owner, uid)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is accessible to other users (mode %o)", path, fi.Mode().Perm())
	}
	return nil
}

// peerCreds is the transport security of the driver connection: the
// connection never leaves the machine, and the handshake accepts it only
// when the process on the other end runs as the expected user.
type peerCreds struct{ uid int }

type peerInfo struct{ credentials.CommonAuthInfo }

func (peerInfo) AuthType() string { return "unix-peer" }

func (p peerCreds) ClientHandshake(_ context.Context, _ string, c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, nil, errors.New("driver connections must be Unix sockets")
	}
	uid, err := peerUID(uc)
	if err != nil {
		return nil, nil, fmt.Errorf("driver peer credentials: %w", err)
	}
	if uid != p.uid {
		return nil, nil, fmt.Errorf("driver runs as uid %d, want %d", uid, p.uid)
	}
	// The kernel keeps a local socket's traffic from other users.
	return c, peerInfo{credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity}}, nil
}

func (peerCreds) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("client only")
}

func (p peerCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "unix-peer"}
}

func (p peerCreds) Clone() credentials.TransportCredentials { return p }

func (peerCreds) OverrideServerName(string) error { return nil }

// Ping checks the driver and, the first time, performs the handshake: the
// protocol version and name must match.
func (d *Driver) Ping(ctx context.Context) error {
	if err := d.handshake(ctx); err != nil {
		return err
	}
	_, err := d.client.Ping(ctx, &driverv1.PingRequest{})
	return wrap(err)
}

func (d *Driver) handshake(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.info != nil {
		return nil
	}
	info, err := d.client.Info(ctx, &driverv1.InfoRequest{})
	if err != nil {
		return wrap(err)
	}
	if info.GetProtocol() != driverv1.ProtocolVersion_PROTOCOL_VERSION_1 {
		return fmt.Errorf("driver %s speaks protocol version %d; this agent needs %d", d.cfg.Name, info.GetProtocol(), driverkit.ProtocolVersion)
	}
	if info.GetName() != d.cfg.Name {
		return fmt.Errorf("the driver on %s calls itself %q", d.path, info.GetName())
	}
	d.info = info
	return nil
}

// Info returns the handshake result, or nil before the first successful
// Ping.
func (d *Driver) Info() *driverv1.InfoResponse {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.info
}

func (d *Driver) has(c driverv1.Capability) bool {
	info := d.Info()
	return info != nil && slices.Contains(info.GetCapabilities(), c)
}

// CanRunSystem reports whether the driver runs system containers.
func (d *Driver) CanRunSystem() bool { return d.has(driverv1.Capability_CAPABILITY_SYSTEM_CONTAINERS) }

// HasBridge reports whether the driver reports a bridge network.
func (d *Driver) HasBridge() bool { return d.has(driverv1.Capability_CAPABILITY_BRIDGE) }

// Pull pulls an image through the driver.
func (d *Driver) Pull(ctx context.Context, image string, auth *runtime.RegistryAuth) (runtime.Image, error) {
	req := &driverv1.PullRequest{Image: image}
	if auth != nil {
		req.Auth = &driverv1.RegistryAuth{Username: auth.Username, Password: auth.Password, ServerAddress: auth.ServerAddress}
	}
	resp, err := d.client.Pull(ctx, req)
	if err != nil {
		return runtime.Image{}, wrap(err)
	}
	return runtime.Image{Ref: resp.GetRef(), Platforms: resp.GetPlatforms()}, nil
}

// Run checks the spec and sends it with Armada's security defaults.
func (d *Driver) Run(ctx context.Context, s runtime.ContainerSpec) (string, error) {
	if err := runtime.CheckContainerSpec(s); err != nil {
		return "", err
	}
	// The driver protocol has no sandbox: refuse rather than run the
	// container with less isolation than asked for.
	if s.Sandbox {
		return "", errors.New("the runtime driver does not run sandboxed containers (isolation: sandbox needs the embedded runtime)")
	}
	ks := driverkit.ContainerSpec{
		Name: s.Name, Image: s.Image, Entrypoint: s.Entrypoint, Cmd: s.Cmd, Env: s.Env, Labels: s.Labels,
		Port: s.Port, HostIP: s.HostIP, MemoryBytes: s.MemoryBytes, NanoCPUs: s.NanoCPUs,
		CPUReserveMillis: s.CPUReserveMillis, PidsLimit: s.PidsLimit, DNS: s.DNS,
		Security: driverkit.Security{NoNewPrivileges: true, DropCapabilities: slices.Clone(runtime.DroppedCaps)},
	}
	for _, f := range s.Files {
		ks.Files = append(ks.Files, driverkit.FileMount{Source: f.Source, Target: f.Target})
	}
	if len(s.Volumes) > 0 && !d.CanMountVolumes() {
		return "", errors.New("the runtime driver does not mount volumes")
	}
	for _, v := range s.Volumes {
		ks.Volumes = append(ks.Volumes, driverkit.VolumeMount{Source: v.Source, Target: v.Target})
	}
	resp, err := d.client.Run(ctx, &driverv1.RunRequest{Spec: driverkit.ContainerSpecToProto(ks)})
	if err != nil {
		return "", wrap(err)
	}
	return resp.GetId(), nil
}

// Stop stops a container within grace.
func (d *Driver) Stop(ctx context.Context, id string, grace time.Duration) error {
	_, err := d.client.Stop(ctx, &driverv1.StopRequest{Id: id, GraceMillis: grace.Milliseconds()})
	return wrap(err)
}

// Remove stops and removes a container.
func (d *Driver) Remove(ctx context.Context, id string) error {
	_, err := d.client.Remove(ctx, &driverv1.RemoveRequest{Id: id})
	return wrap(err)
}

// List returns the containers that carry every given label.
func (d *Driver) List(ctx context.Context, labels map[string]string) ([]runtime.Container, error) {
	resp, err := d.client.List(ctx, &driverv1.ListRequest{Labels: labels})
	if err != nil {
		return nil, wrap(err)
	}
	out := make([]runtime.Container, 0, len(resp.GetContainers()))
	for _, c := range resp.GetContainers() {
		out = append(out, container(c))
	}
	return out, nil
}

// Inspect returns one container.
func (d *Driver) Inspect(ctx context.Context, id string) (runtime.Container, error) {
	c, err := d.client.Inspect(ctx, &driverv1.InspectRequest{Id: id})
	if err != nil {
		return runtime.Container{}, wrap(err)
	}
	return container(c), nil
}

func container(p *driverv1.Container) runtime.Container {
	c := driverkit.ContainerFromProto(p)
	return runtime.Container{
		ID: c.ID, Name: c.Name, Image: c.Image, Labels: c.Labels, State: c.State, ExitCode: c.ExitCode,
		HostIP: c.HostIP, HostPort: c.HostPort, IP: c.IP, StartedAt: c.StartedAt,
	}
}

// Logs streams a container's output.
func (d *Driver) Logs(ctx context.Context, id string, opts runtime.LogOptions) (runtime.LogStream, error) {
	ctx, cancel := context.WithCancel(ctx)
	stream, err := d.client.Logs(ctx, &driverv1.LogsRequest{Id: id, Follow: opts.Follow, Tail: int32(opts.Tail)}) //nolint:gosec // tail is a line count
	if err != nil {
		cancel()
		return nil, wrap(err)
	}
	return &logStream{stream: stream, cancel: cancel}, nil
}

type logStream struct {
	stream driverv1.Driver_LogsClient
	cancel context.CancelFunc
}

func (l *logStream) Next() (runtime.LogFrame, error) {
	f, err := l.stream.Recv()
	if errors.Is(err, io.EOF) {
		return runtime.LogFrame{}, io.EOF
	}
	if err != nil {
		return runtime.LogFrame{}, wrap(err)
	}
	return runtime.LogFrame{Stream: runtime.Stream(f.GetStream()), Data: f.GetData()}, nil
}

func (l *logStream) Close() error {
	l.cancel()
	return nil
}

// RunSystem starts a system container such as HAProxy.
func (d *Driver) RunSystem(ctx context.Context, s runtime.SystemSpec) (string, error) {
	if !d.CanRunSystem() {
		return "", fmt.Errorf("driver %s cannot run system containers", d.cfg.Name)
	}
	ks := driverkit.SystemSpec{Name: s.Name, Image: s.Image, Cmd: s.Cmd, Labels: s.Labels, CapAdd: s.CapAdd, User: s.User}
	for _, m := range s.Mounts {
		ks.Mounts = append(ks.Mounts, driverkit.Mount{Source: m.Source, Target: m.Target, ReadOnly: m.ReadOnly})
	}
	resp, err := d.client.RunSystem(ctx, &driverv1.RunSystemRequest{Spec: driverkit.SystemSpecToProto(ks)})
	if err != nil {
		return "", wrap(err)
	}
	return resp.GetId(), nil
}

// Exec runs a command in a system container.
func (d *Driver) Exec(ctx context.Context, id string, cmd []string) (string, int, error) {
	resp, err := d.client.Exec(ctx, &driverv1.ExecRequest{Id: id, Cmd: cmd})
	if err != nil {
		return "", 0, wrap(err)
	}
	return resp.GetOutput(), int(resp.GetExitCode()), nil
}

// Signal sends a signal to a system container.
func (d *Driver) Signal(ctx context.Context, id, signal string) error {
	_, err := d.client.Signal(ctx, &driverv1.SignalRequest{Id: id, Signal: signal})
	return wrap(err)
}

// Bridge returns the container bridge.
func (d *Driver) Bridge(ctx context.Context) (runtime.Bridge, error) {
	if !d.HasBridge() {
		return runtime.Bridge{}, fmt.Errorf("driver %s has no bridge network", d.cfg.Name)
	}
	resp, err := d.client.Bridge(ctx, &driverv1.BridgeRequest{})
	if err != nil {
		return runtime.Bridge{}, wrap(err)
	}
	gw, err := netip.ParseAddr(resp.GetGateway())
	if err != nil {
		return runtime.Bridge{}, fmt.Errorf("driver bridge gateway: %w", err)
	}
	subnet, err := netip.ParsePrefix(resp.GetSubnet())
	if err != nil {
		return runtime.Bridge{}, fmt.Errorf("driver bridge subnet: %w", err)
	}
	if !subnet.Contains(gw) {
		return runtime.Bridge{}, fmt.Errorf("driver bridge gateway %s is outside its subnet %s", gw, subnet)
	}
	return runtime.Bridge{Gateway: gw, Subnet: subnet.Masked()}, nil
}

// wrap maps driver errors to the runtime package's: ErrNotFound and
// *PlatformError.
func wrap(err error) error {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		return fmt.Errorf("%s: %w", st.Message(), runtime.ErrNotFound)
	}
	err = driverkit.FromStatus(err)
	var pe *driverkit.PlatformError
	switch {
	case errors.As(err, &pe):
		return &runtime.PlatformError{Image: pe.Image, Want: pe.Want, Have: pe.Have}
	}
	return err
}
