package driverkit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	driverv1 "github.com/ryanbekhen/armada/api/armada/driver/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// RequiredDroppedCaps are the capabilities every app container must lose;
// the agent asks for at least these, and Serve refuses specs that do not.
var RequiredDroppedCaps = slices.Clone(runtime.DroppedCaps)

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// CheckName reports whether name is a valid driver name: lowercase letters,
// digits, and '-', up to 32 characters. "embedded" is reserved for
// Armada's built-in runtime.
func CheckName(name string) error {
	switch {
	case !nameRe.MatchString(name):
		return fmt.Errorf("driver name %q must be 1-32 lowercase letters, digits, or '-', starting and ending with a letter or digit", name)
	case name == "embedded":
		return errors.New(`driver name "embedded" is reserved for the built-in runtime`)
	}
	return nil
}

// SocketPath returns the socket a driver named name listens on.
func SocketPath(name string) string {
	return filepath.Join(DefaultSocketDir(), name+".sock")
}

// Listen creates the socket for driver name in DefaultSocketDir, which it
// creates with mode 0700, replacing a stale socket; the socket gets mode
// 0600. Run it as the agent's user (root on Linux): the agent only connects
// to sockets its own user owns.
func Listen(name string) (net.Listener, error) {
	return ListenIn(DefaultSocketDir(), name)
}

// ListenIn is Listen with the socket in dir instead of DefaultSocketDir.
func ListenIn(dir, name string) (net.Listener, error) {
	if err := CheckName(name); err != nil {
		return nil, err
	}
	return listenAt(dir, name)
}

func listenAt(dir, name string) (net.Listener, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory needs the search bit
		return nil, err
	}
	path := filepath.Join(dir, name+".sock")
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != os.ModeSocket {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

// Serve serves d on l until ctx ends. Every request is checked before it
// reaches d: app container specs must carry the security defaults and only
// private publish addresses, regular files as mounts, and so on. Serve
// never logs request contents.
func Serve(ctx context.Context, l net.Listener, d Driver, info Info) error {
	if err := CheckName(info.Name); err != nil {
		return err
	}
	if info.MinMemoryBytes < 0 {
		return errors.New("negative minimum memory")
	}
	srv := grpc.NewServer()
	driverv1.RegisterDriverServer(srv, &server{d: d, info: info})
	stop := context.AfterFunc(ctx, srv.GracefulStop)
	defer stop()
	if err := srv.Serve(l); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

type server struct {
	driverv1.UnimplementedDriverServer
	d    Driver
	info Info
}

func (s *server) Info(context.Context, *driverv1.InfoRequest) (*driverv1.InfoResponse, error) {
	r := &driverv1.InfoResponse{
		Protocol: driverv1.ProtocolVersion_PROTOCOL_VERSION_1,
		Name:     s.info.Name, Version: s.info.Version, Os: s.info.OS, Arch: s.info.Arch,
		VmIsolation: s.info.VMIsolation, MinMemoryBytes: s.info.MinMemoryBytes,
	}
	if _, ok := s.d.(SystemRunner); ok {
		r.Capabilities = append(r.Capabilities, driverv1.Capability_CAPABILITY_SYSTEM_CONTAINERS)
	}
	if _, ok := s.d.(BridgeInspector); ok {
		r.Capabilities = append(r.Capabilities, driverv1.Capability_CAPABILITY_BRIDGE)
	}
	return r, nil
}

func (s *server) Ping(ctx context.Context, _ *driverv1.PingRequest) (*driverv1.PingResponse, error) {
	if err := s.d.Ping(ctx); err != nil {
		return nil, toStatus(err)
	}
	return &driverv1.PingResponse{}, nil
}

func (s *server) Pull(ctx context.Context, req *driverv1.PullRequest) (*driverv1.PullResponse, error) {
	if req.GetImage() == "" {
		return nil, status.Error(codes.InvalidArgument, "image is empty")
	}
	var auth *RegistryAuth
	if a := req.GetAuth(); a != nil {
		auth = &RegistryAuth{Username: a.GetUsername(), Password: a.GetPassword(), ServerAddress: a.GetServerAddress()}
	}
	img, err := s.d.Pull(ctx, req.GetImage(), auth)
	if err != nil {
		return nil, toStatus(err)
	}
	return &driverv1.PullResponse{Ref: img.Ref, Platforms: img.Platforms}, nil
}

func (s *server) Run(ctx context.Context, req *driverv1.RunRequest) (*driverv1.RunResponse, error) {
	spec, err := ContainerSpecFromProto(req.GetSpec())
	if err == nil {
		err = CheckContainerSpec(spec)
	}
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	id, err := s.d.Run(ctx, spec)
	if err != nil {
		return nil, toStatus(err)
	}
	return &driverv1.RunResponse{Id: id}, nil
}

func (s *server) Stop(ctx context.Context, req *driverv1.StopRequest) (*driverv1.StopResponse, error) {
	if err := checkID(req.GetId()); err != nil {
		return nil, err
	}
	grace := time.Duration(max(0, req.GetGraceMillis())) * time.Millisecond
	if err := s.d.Stop(ctx, req.GetId(), grace); err != nil {
		return nil, toStatus(err)
	}
	return &driverv1.StopResponse{}, nil
}

func (s *server) Remove(ctx context.Context, req *driverv1.RemoveRequest) (*driverv1.RemoveResponse, error) {
	if err := checkID(req.GetId()); err != nil {
		return nil, err
	}
	if err := s.d.Remove(ctx, req.GetId()); err != nil {
		return nil, toStatus(err)
	}
	return &driverv1.RemoveResponse{}, nil
}

func (s *server) List(ctx context.Context, req *driverv1.ListRequest) (*driverv1.ListResponse, error) {
	cs, err := s.d.List(ctx, req.GetLabels())
	if err != nil {
		return nil, toStatus(err)
	}
	r := &driverv1.ListResponse{}
	for _, c := range cs {
		r.Containers = append(r.Containers, ContainerToProto(c))
	}
	return r, nil
}

func (s *server) Inspect(ctx context.Context, req *driverv1.InspectRequest) (*driverv1.Container, error) {
	if err := checkID(req.GetId()); err != nil {
		return nil, err
	}
	c, err := s.d.Inspect(ctx, req.GetId())
	if err != nil {
		return nil, toStatus(err)
	}
	return ContainerToProto(c), nil
}

func (s *server) Logs(req *driverv1.LogsRequest, stream driverv1.Driver_LogsServer) error {
	if err := checkID(req.GetId()); err != nil {
		return err
	}
	ls, err := s.d.Logs(stream.Context(), req.GetId(), LogOptions{Follow: req.GetFollow(), Tail: int(max(0, req.GetTail()))})
	if err != nil {
		return toStatus(err)
	}
	defer ls.Close()
	stop := context.AfterFunc(stream.Context(), func() { _ = ls.Close() })
	defer stop()
	for {
		f, err := ls.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if stream.Context().Err() != nil {
				return status.FromContextError(stream.Context().Err()).Err()
			}
			return toStatus(err)
		}
		if err := stream.Send(&driverv1.LogFrame{Stream: driverv1.LogStream(f.Stream), Data: f.Data}); err != nil { //nolint:gosec // Stream is 0, 1, or 2
			return err
		}
	}
}

func (s *server) system() (SystemRunner, error) {
	sys, ok := s.d.(SystemRunner)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this driver cannot run system containers")
	}
	return sys, nil
}

func (s *server) RunSystem(ctx context.Context, req *driverv1.RunSystemRequest) (*driverv1.RunResponse, error) {
	sys, err := s.system()
	if err != nil {
		return nil, err
	}
	spec := SystemSpecFromProto(req.GetSpec())
	if err := CheckSystemSpec(spec); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	id, err := sys.RunSystem(ctx, spec)
	if err != nil {
		return nil, toStatus(err)
	}
	return &driverv1.RunResponse{Id: id}, nil
}

func (s *server) Exec(ctx context.Context, req *driverv1.ExecRequest) (*driverv1.ExecResponse, error) {
	sys, err := s.system()
	if err != nil {
		return nil, err
	}
	if err := checkID(req.GetId()); err != nil {
		return nil, err
	}
	if len(req.GetCmd()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "command is empty")
	}
	out, code, err := sys.Exec(ctx, req.GetId(), req.GetCmd())
	if err != nil {
		return nil, toStatus(err)
	}
	return &driverv1.ExecResponse{Output: out, ExitCode: int32(code)}, nil //nolint:gosec // exit codes fit
}

func (s *server) Signal(ctx context.Context, req *driverv1.SignalRequest) (*driverv1.SignalResponse, error) {
	sys, err := s.system()
	if err != nil {
		return nil, err
	}
	if err := checkID(req.GetId()); err != nil {
		return nil, err
	}
	if err := sys.Signal(ctx, req.GetId(), req.GetSignal()); err != nil {
		return nil, toStatus(err)
	}
	return &driverv1.SignalResponse{}, nil
}

func (s *server) Bridge(ctx context.Context, _ *driverv1.BridgeRequest) (*driverv1.BridgeResponse, error) {
	bi, ok := s.d.(BridgeInspector)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this driver has no bridge network")
	}
	b, err := bi.Bridge(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	return &driverv1.BridgeResponse{Gateway: b.Gateway.String(), Subnet: b.Subnet.String()}, nil
}

func checkID(id string) error {
	if id == "" {
		return status.Error(codes.InvalidArgument, "container ID is empty")
	}
	return nil
}

// toStatus maps a driver error to a gRPC status: ErrNotFound to NOT_FOUND
// and *PlatformError to FAILED_PRECONDITION with its detail.
func toStatus(err error) error {
	var pe *PlatformError
	switch {
	case errors.Is(err, ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.As(err, &pe):
		st, derr := status.New(codes.FailedPrecondition, pe.Error()).WithDetails(&driverv1.PlatformError{Image: pe.Image, Want: pe.Want, Have: pe.Have})
		if derr != nil {
			return status.Error(codes.FailedPrecondition, pe.Error())
		}
		return st.Err()
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	}
	return status.Error(codes.Unknown, err.Error())
}

// FromStatus maps a gRPC error from a driver back: NOT_FOUND to
// ErrNotFound and a PlatformError detail to *PlatformError.
func FromStatus(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.NotFound:
		return fmt.Errorf("%s: %w", st.Message(), ErrNotFound)
	case codes.FailedPrecondition:
		for _, d := range st.Details() {
			if pe, ok := d.(*driverv1.PlatformError); ok {
				return &PlatformError{Image: pe.GetImage(), Want: pe.GetWant(), Have: pe.GetHave()}
			}
		}
	}
	return errors.New(st.Message())
}

// ContainerToProto converts a Container for the wire.
func ContainerToProto(c Container) *driverv1.Container {
	p := &driverv1.Container{
		Id: c.ID, Name: c.Name, Image: c.Image, Labels: c.Labels, State: c.State,
		ExitCode: int32(c.ExitCode), HostIp: c.HostIP, HostPort: int32(c.HostPort), Ip: c.IP, //nolint:gosec // exit codes and ports fit
	}
	if !c.StartedAt.IsZero() {
		p.StartedAt = timestamppb.New(c.StartedAt)
	}
	return p
}

// ContainerFromProto converts a Container from the wire.
func ContainerFromProto(p *driverv1.Container) Container {
	c := Container{
		ID: p.GetId(), Name: p.GetName(), Image: p.GetImage(), Labels: p.GetLabels(), State: p.GetState(),
		ExitCode: int(p.GetExitCode()), HostIP: p.GetHostIp(), HostPort: int(p.GetHostPort()), IP: p.GetIp(),
	}
	if p.GetStartedAt() != nil {
		c.StartedAt = p.GetStartedAt().AsTime()
	}
	return c
}

// ContainerSpecToProto converts a ContainerSpec for the wire.
func ContainerSpecToProto(s ContainerSpec) *driverv1.ContainerSpec {
	p := &driverv1.ContainerSpec{
		Name: s.Name, Image: s.Image, Entrypoint: s.Entrypoint, Cmd: s.Cmd, Env: s.Env, Labels: s.Labels,
		Port: int32(s.Port), HostIp: s.HostIP, MemoryBytes: s.MemoryBytes, NanoCpus: s.NanoCPUs, //nolint:gosec // ports are checked
		CpuReserveMillis: s.CPUReserveMillis, PidsLimit: s.PidsLimit, Dns: s.DNS,
		Security: &driverv1.Security{NoNewPrivileges: s.Security.NoNewPrivileges, DropCapabilities: s.Security.DropCapabilities},
	}
	for _, f := range s.Files {
		p.Files = append(p.Files, &driverv1.FileMount{Source: f.Source, Target: f.Target})
	}
	return p
}

// ContainerSpecFromProto converts a ContainerSpec from the wire; a spec
// without one is an error.
func ContainerSpecFromProto(p *driverv1.ContainerSpec) (ContainerSpec, error) {
	if p == nil {
		return ContainerSpec{}, errors.New("spec is missing")
	}
	s := ContainerSpec{
		Name: p.GetName(), Image: p.GetImage(), Entrypoint: p.GetEntrypoint(), Cmd: p.GetCmd(), Env: p.GetEnv(), Labels: p.GetLabels(),
		Port: int(p.GetPort()), HostIP: p.GetHostIp(), MemoryBytes: p.GetMemoryBytes(), NanoCPUs: p.GetNanoCpus(),
		CPUReserveMillis: p.GetCpuReserveMillis(), PidsLimit: p.GetPidsLimit(), DNS: p.GetDns(),
		Security: Security{NoNewPrivileges: p.GetSecurity().GetNoNewPrivileges(), DropCapabilities: p.GetSecurity().GetDropCapabilities()},
	}
	for _, f := range p.GetFiles() {
		s.Files = append(s.Files, FileMount{Source: f.GetSource(), Target: f.GetTarget()})
	}
	return s, nil
}

// SystemSpecToProto converts a SystemSpec for the wire.
func SystemSpecToProto(s SystemSpec) *driverv1.SystemSpec {
	p := &driverv1.SystemSpec{Name: s.Name, Image: s.Image, Cmd: s.Cmd, Labels: s.Labels, CapAdd: s.CapAdd, User: s.User}
	for _, m := range s.Mounts {
		p.Mounts = append(p.Mounts, &driverv1.Mount{Source: m.Source, Target: m.Target, ReadOnly: m.ReadOnly})
	}
	return p
}

// SystemSpecFromProto converts a SystemSpec from the wire.
func SystemSpecFromProto(p *driverv1.SystemSpec) SystemSpec {
	s := SystemSpec{Name: p.GetName(), Image: p.GetImage(), Cmd: p.GetCmd(), Labels: p.GetLabels(), CapAdd: p.GetCapAdd(), User: p.GetUser()}
	for _, m := range p.GetMounts() {
		s.Mounts = append(s.Mounts, Mount{Source: m.GetSource(), Target: m.GetTarget(), ReadOnly: m.GetReadOnly()})
	}
	return s
}

// CheckContainerSpec checks an app container spec: a name and an image,
// the security defaults (no new privileges, RequiredDroppedCaps dropped),
// and Armada's spec rules (private publish address and nameservers,
// regular files as the only mounts).
func CheckContainerSpec(s ContainerSpec) error {
	switch {
	case s.Name == "":
		return errors.New("container name is empty")
	case s.Image == "":
		return errors.New("image is empty")
	case !s.Security.NoNewPrivileges:
		return errors.New("no_new_privileges must be set")
	case s.MemoryBytes <= 0:
		return errors.New("memory limit is missing")
	case s.PidsLimit <= 0:
		return errors.New("PID limit is missing")
	}
	for _, c := range RequiredDroppedCaps {
		if !slices.Contains(s.Security.DropCapabilities, c) {
			return fmt.Errorf("capability %s must be dropped", c)
		}
	}
	rs := runtime.ContainerSpec{Port: s.Port, HostIP: s.HostIP, DNS: s.DNS}
	for _, f := range s.Files {
		rs.Files = append(rs.Files, runtime.FileMount{Source: f.Source, Target: f.Target})
	}
	return runtime.CheckContainerSpec(rs)
}

// CheckSystemSpec checks a system container spec: a name, an image, the
// system label, and mounts without separator characters.
func CheckSystemSpec(s SystemSpec) error {
	switch {
	case s.Name == "":
		return errors.New("container name is empty")
	case s.Image == "":
		return errors.New("image is empty")
	case s.Labels[runtime.LabelSystem] == "":
		return fmt.Errorf("system containers carry the %s label", runtime.LabelSystem)
	}
	for _, m := range s.Mounts {
		if err := runtime.CheckSystemMount(runtime.Mount{Source: m.Source, Target: m.Target, ReadOnly: m.ReadOnly}); err != nil {
			return err
		}
	}
	return nil
}
