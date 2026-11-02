package remote

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	driverv1 "github.com/ryanbekhen/armada/api/armada/driver/v1"
	"github.com/ryanbekhen/armada/driverkit"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// memDriver is an in-memory driverkit.Driver that records what it runs.
type memDriver struct {
	mu         sync.Mutex
	containers map[string]driverkit.Container
	specs      []driverkit.ContainerSpec
}

func newMem() *memDriver { return &memDriver{containers: map[string]driverkit.Container{}} }

func (m *memDriver) Ping(context.Context) error { return nil }

func (m *memDriver) Pull(_ context.Context, image string, _ *driverkit.RegistryAuth) (driverkit.Image, error) {
	if strings.HasPrefix(image, "amd64only") {
		return driverkit.Image{}, &driverkit.PlatformError{Image: image, Want: "linux/arm64", Have: []string{"linux/amd64"}}
	}
	return driverkit.Image{Ref: image + "@sha256:abc", Platforms: []string{"linux/amd64", "linux/arm64"}}, nil
}

func (m *memDriver) Run(_ context.Context, s driverkit.ContainerSpec) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.specs = append(m.specs, s)
	id := s.Name + "-1"
	m.containers[id] = driverkit.Container{ID: id, Name: s.Name, Image: s.Image, Labels: s.Labels, State: driverkit.StateRunning,
		HostIP: s.HostIP, HostPort: 30000, StartedAt: time.UnixMilli(1_700_000_000_000)}
	return id, nil
}

func (m *memDriver) Stop(context.Context, string, time.Duration) error { return nil }

func (m *memDriver) Remove(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.containers[id]; !ok {
		return driverkit.ErrNotFound
	}
	delete(m.containers, id)
	return nil
}

func (m *memDriver) List(_ context.Context, labels map[string]string) ([]driverkit.Container, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []driverkit.Container
outer:
	for _, c := range m.containers {
		for k, v := range labels {
			if c.Labels[k] != v {
				continue outer
			}
		}
		out = append(out, c)
	}
	return out, nil
}

func (m *memDriver) Inspect(_ context.Context, id string) (driverkit.Container, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.containers[id]
	if !ok {
		return driverkit.Container{}, driverkit.ErrNotFound
	}
	return c, nil
}

func (m *memDriver) Logs(context.Context, string, driverkit.LogOptions) (driverkit.LogStream, error) {
	return &memLogs{frames: []driverkit.LogFrame{{Stream: driverkit.Stdout, Data: []byte("hello\n")}, {Stream: driverkit.Stderr, Data: []byte("oops\n")}}}, nil
}

type memLogs struct{ frames []driverkit.LogFrame }

func (l *memLogs) Next() (driverkit.LogFrame, error) {
	if len(l.frames) == 0 {
		return driverkit.LogFrame{}, io.EOF
	}
	f := l.frames[0]
	l.frames = l.frames[1:]
	return f, nil
}

func (l *memLogs) Close() error { return nil }

// sysDriver adds system containers.
type sysDriver struct{ *memDriver }

func (s sysDriver) RunSystem(context.Context, driverkit.SystemSpec) (string, error) {
	return "sys-1", nil
}

func (s sysDriver) Exec(context.Context, string, []string) (string, int, error) {
	return "ok", 0, nil
}

func (s sysDriver) Signal(context.Context, string, string) error { return nil }

// serve runs d as driver "test" in a private temporary directory and
// returns the directory.
func serve(t *testing.T, d driverkit.Driver, name string) string {
	t.Helper()
	// Short: socket paths are limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "drv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d")
	l, err := listenAt(t, sock, "test")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = driverkit.Serve(ctx, l, d, driverkit.Info{Name: name, Version: "t", OS: "linux", Arch: "arm64", VMIsolation: true, MinMemoryBytes: 200 << 20})
	}()
	t.Cleanup(func() { cancel(); <-done })
	return sock
}

// listenAt creates dir (0700) and dir/name.sock (0600) like driverkit.Listen.
func listenAt(t *testing.T, dir, name string) (net.Listener, error) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name+".sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	return l, os.Chmod(path, 0o600)
}

func dial(t *testing.T, dir string) *Driver {
	t.Helper()
	d, err := New(Config{Name: "test", Dir: dir, UID: os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	mem := newMem()
	d := dial(t, serve(t, sysDriver{mem}, "test"))
	ctx := context.Background()
	if err := d.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if info := d.Info(); info.GetArch() != "arm64" || !info.GetVmIsolation() || info.GetMinMemoryBytes() != 200<<20 || !d.CanRunSystem() || d.HasBridge() {
		t.Errorf("info %v, system %v, bridge %v", info, d.CanRunSystem(), d.HasBridge())
	}

	img, err := d.Pull(ctx, "nginx:1", &runtime.RegistryAuth{Username: "u", Password: "p"})
	if err != nil || img.Ref != "nginx:1@sha256:abc" || len(img.Platforms) != 2 {
		t.Errorf("pull = %+v, %v", img, err)
	}
	var pe *runtime.PlatformError
	if _, err := d.Pull(ctx, "amd64only:1", nil); !errors.As(err, &pe) || pe.Want != "linux/arm64" || !slices.Equal(pe.Have, []string{"linux/amd64"}) {
		t.Errorf("pull of a foreign image = %v", err)
	}

	id, err := d.Run(ctx, runtime.ContainerSpec{
		Name: "armada-web-1", Image: "nginx:1", Env: []string{"SECRET=x"}, Labels: map[string]string{runtime.LabelApp: "web"},
		Port: 80, HostIP: "10.0.0.2", MemoryBytes: 256 << 20, PidsLimit: 1024, CPUReserveMillis: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := mem.specs[0]
	if !got.Security.NoNewPrivileges || !slices.Equal(got.Security.DropCapabilities, runtime.DroppedCaps) {
		t.Errorf("security defaults not sent: %+v", got.Security)
	}
	if got.Env[0] != "SECRET=x" || got.CPUReserveMillis != 100 || got.HostIP != "10.0.0.2" {
		t.Errorf("spec = %+v", got)
	}
	c, err := d.Inspect(ctx, id)
	if err != nil || c.State != runtime.StateRunning || c.HostPort != 30000 || c.StartedAt.IsZero() {
		t.Errorf("inspect = %+v, %v", c, err)
	}
	if cs, err := d.List(ctx, map[string]string{runtime.LabelApp: "web"}); err != nil || len(cs) != 1 {
		t.Errorf("list = %v, %v", cs, err)
	}
	if _, err := d.Inspect(ctx, "missing"); !errors.Is(err, runtime.ErrNotFound) {
		t.Errorf("inspect of a missing container = %v", err)
	}
	if err := d.Remove(ctx, "missing"); !errors.Is(err, runtime.ErrNotFound) {
		t.Errorf("remove of a missing container = %v", err)
	}

	ls, err := d.Logs(ctx, id, runtime.LogOptions{Tail: 10})
	if err != nil {
		t.Fatal(err)
	}
	var frames []runtime.LogFrame
	for {
		f, err := ls.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, f)
	}
	_ = ls.Close()
	if len(frames) != 2 || frames[1].Stream != runtime.Stderr || string(frames[1].Data) != "oops\n" {
		t.Errorf("logs = %v", frames)
	}

	if sid, err := d.RunSystem(ctx, runtime.SystemSpec{Name: "haproxy", Image: "h", Labels: map[string]string{runtime.LabelSystem: "haproxy"}}); err != nil || sid != "sys-1" {
		t.Errorf("run system = %q, %v", sid, err)
	}
	if !runtime.CanRunSystem(d) || runtime.HasBridge(d) {
		t.Error("runtime capability helpers disagree with the handshake")
	}
}

// The agent checks specs before they leave it; the driver library checks
// them again on arrival.
func TestSpecsAreCheckedOnBothSides(t *testing.T) {
	t.Parallel()
	mem := newMem()
	sock := serve(t, mem, "test")
	d := dial(t, sock)
	ctx := context.Background()
	if err := d.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Run(ctx, runtime.ContainerSpec{Name: "x", Image: "i", Port: 80, HostIP: "203.0.113.5", MemoryBytes: 1, PidsLimit: 1}); err == nil {
		t.Error("public publish address accepted by the agent")
	}

	// A client that skips the agent's checks.
	conn, err := grpc.NewClient("unix://"+filepath.Join(sock, "test.sock"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw := driverv1.NewDriverClient(conn)
	good := driverkit.ContainerSpec{Name: "x", Image: "i", MemoryBytes: 1, PidsLimit: 1,
		Security: driverkit.Security{NoNewPrivileges: true, DropCapabilities: runtime.DroppedCaps}}
	for name, mutate := range map[string]func(*driverkit.ContainerSpec){
		"no-new-privileges off": func(s *driverkit.ContainerSpec) { s.Security.NoNewPrivileges = false },
		"capability kept":       func(s *driverkit.ContainerSpec) { s.Security.DropCapabilities = []string{"MKNOD"} },
		"public publish":        func(s *driverkit.ContainerSpec) { s.Port, s.HostIP = 80, "8.8.8.8" },
		"public DNS":            func(s *driverkit.ContainerSpec) { s.DNS = []string{"1.1.1.1"} },
		"directory mount":       func(s *driverkit.ContainerSpec) { s.Files = []driverkit.FileMount{{Source: "/", Target: "/host"}} },
		"socket mount": func(s *driverkit.ContainerSpec) {
			s.Files = []driverkit.FileMount{{Source: "/var/run/docker.sock", Target: "/s"}}
		},
		"no memory limit": func(s *driverkit.ContainerSpec) { s.MemoryBytes = 0 },
		"no PID limit":    func(s *driverkit.ContainerSpec) { s.PidsLimit = 0 },
	} {
		s := good
		s.Security.DropCapabilities = slices.Clone(good.Security.DropCapabilities)
		mutate(&s)
		_, err := raw.Run(ctx, &driverv1.RunRequest{Spec: driverkit.ContainerSpecToProto(s)})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := raw.Run(ctx, &driverv1.RunRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing spec: %v", err)
	}
	if _, err := raw.RunSystem(ctx, &driverv1.RunSystemRequest{Spec: &driverv1.SystemSpec{Name: "x", Image: "i"}}); status.Code(err) != codes.Unimplemented {
		t.Errorf("system container from a driver without them: %v", err)
	}
	if len(mem.specs) != 0 {
		t.Errorf("%d invalid specs reached the driver", len(mem.specs))
	}
	if _, err := raw.Run(ctx, &driverv1.RunRequest{Spec: driverkit.ContainerSpecToProto(good)}); err != nil {
		t.Errorf("valid spec refused: %v", err)
	}
}

func TestDriverWithoutSystemContainers(t *testing.T) {
	t.Parallel()
	d := dial(t, serve(t, newMem(), "test"))
	if err := d.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runtime.CanRunSystem(d) {
		t.Error("CanRunSystem without the capability")
	}
	if _, err := d.RunSystem(context.Background(), runtime.SystemSpec{}); err == nil {
		t.Error("RunSystem without the capability")
	}
	if _, err := d.Bridge(context.Background()); err == nil {
		t.Error("Bridge without the capability")
	}
}

func TestHandshakeRefusesAnotherName(t *testing.T) {
	t.Parallel()
	d := dial(t, serve(t, newMem(), "other"))
	if err := d.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), `calls itself "other"`) {
		t.Errorf("ping = %v", err)
	}
}

// The agent connects only to a socket in a directory that its user owns
// and others cannot open.
func TestSocketMustBePrivate(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sock := serve(t, newMem(), "test")
	if err := os.Chmod(sock, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := dial(t, sock).Ping(ctx); err == nil || !strings.Contains(err.Error(), "accessible to other users") {
		t.Errorf("open directory: %v", err)
	}

	sock = serve(t, newMem(), "test")
	if err := os.Chmod(filepath.Join(sock, "test.sock"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := dial(t, sock).Ping(ctx); err == nil || !strings.Contains(err.Error(), "accessible to other users") {
		t.Errorf("open socket: %v", err)
	}

	sock = serve(t, newMem(), "test")
	other, err := New(Config{Name: "test", Dir: sock, UID: os.Getuid() + 1})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.Ping(ctx); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("socket of another user: %v", err)
	}

	if _, err := New(Config{Name: "../x"}); err == nil {
		t.Error("invalid driver name accepted")
	}
	if _, err := New(Config{Name: "embedded"}); err == nil {
		t.Error(`"embedded" accepted as a driver name`)
	}
}

func TestPeerCredentials(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "peer")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	l, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	c, err := net.Dial("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, _, err := (peerCreds{uid: os.Getuid()}).ClientHandshake(context.Background(), "", c); err != nil {
		t.Errorf("own uid refused: %v", err)
	}
	if _, _, err := (peerCreds{uid: os.Getuid() + 1}).ClientHandshake(context.Background(), "", c); err == nil {
		t.Error("peer of another uid accepted")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, _, err := (peerCreds{}).ClientHandshake(context.Background(), "", a); err == nil {
		t.Error("a connection that is not a Unix socket accepted")
	}
}
