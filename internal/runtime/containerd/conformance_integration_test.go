//go:build integration && linux

package containerd

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/driverkit"
	"github.com/ryanbekhen/armada/driverkit/conformance"
	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/embedded"
)

// TestIntegrationConformance runs the driver conformance suite (ADR 0015)
// against the embedded runtime of an initialized node. Run it as root on
// the node, with the runtime running and the armada binary that stores
// container output:
//
//	sudo ARMADA_BIN=/usr/local/bin/armada ARMADA_HOST_IP=10.0.0.5 \
//	  go test -tags integration -run Conformance ./internal/runtime/containerd/
func TestIntegrationConformance(t *testing.T) {
	bin := os.Getenv("ARMADA_BIN")
	if bin == "" || os.Geteuid() != 0 {
		t.Skip("needs root and ARMADA_BIN")
	}
	d, err := New(Config{Paths: embedded.Paths{DataDir: "/var/lib/armada", RunDir: "/run/armada"}, Self: bin})
	if err != nil {
		t.Fatal(err)
	}
	conformance.Run(t, kit{d}, conformance.Options{HostIP: os.Getenv("ARMADA_HOST_IP")})
}

// kit presents a runtime.Driver as a driverkit.Driver.
type kit struct{ d *Driver }

func (k kit) Ping(ctx context.Context) error { return k.d.Ping(ctx) }

func (k kit) Pull(ctx context.Context, image string, auth *driverkit.RegistryAuth) (driverkit.Image, error) {
	var a *runtime.RegistryAuth
	if auth != nil {
		a = &runtime.RegistryAuth{Username: auth.Username, Password: auth.Password, ServerAddress: auth.ServerAddress}
	}
	img, err := k.d.Pull(ctx, image, a)
	return driverkit.Image{Ref: img.Ref, Platforms: img.Platforms}, kitErr(err)
}

func (k kit) Run(ctx context.Context, s driverkit.ContainerSpec) (string, error) {
	rs := runtime.ContainerSpec{
		Name: s.Name, Image: s.Image, Entrypoint: s.Entrypoint, Cmd: s.Cmd, Env: s.Env, Labels: s.Labels,
		Port: s.Port, HostIP: s.HostIP, MemoryBytes: s.MemoryBytes, NanoCPUs: s.NanoCPUs,
		CPUReserveMillis: s.CPUReserveMillis, PidsLimit: s.PidsLimit, DNS: s.DNS,
	}
	for _, f := range s.Files {
		rs.Files = append(rs.Files, runtime.FileMount{Source: f.Source, Target: f.Target})
	}
	id, err := k.d.Run(ctx, rs)
	return id, kitErr(err)
}

func (k kit) Stop(ctx context.Context, id string, grace time.Duration) error {
	return kitErr(k.d.Stop(ctx, id, grace))
}

func (k kit) Remove(ctx context.Context, id string) error { return kitErr(k.d.Remove(ctx, id)) }

func (k kit) List(ctx context.Context, labels map[string]string) ([]driverkit.Container, error) {
	cs, err := k.d.List(ctx, labels)
	out := make([]driverkit.Container, 0, len(cs))
	for _, c := range cs {
		out = append(out, kitContainer(c))
	}
	return out, kitErr(err)
}

func (k kit) Inspect(ctx context.Context, id string) (driverkit.Container, error) {
	c, err := k.d.Inspect(ctx, id)
	return kitContainer(c), kitErr(err)
}

func (k kit) Logs(ctx context.Context, id string, opts driverkit.LogOptions) (driverkit.LogStream, error) {
	ls, err := k.d.Logs(ctx, id, runtime.LogOptions{Follow: opts.Follow, Tail: opts.Tail})
	if err != nil {
		return nil, kitErr(err)
	}
	return kitLogs{ls}, nil
}

func (k kit) RunSystem(ctx context.Context, s driverkit.SystemSpec) (string, error) {
	rs := runtime.SystemSpec{Name: s.Name, Image: s.Image, Cmd: s.Cmd, Labels: s.Labels, CapAdd: s.CapAdd, User: s.User}
	for _, m := range s.Mounts {
		rs.Mounts = append(rs.Mounts, runtime.Mount{Source: m.Source, Target: m.Target, ReadOnly: m.ReadOnly})
	}
	id, err := k.d.RunSystem(ctx, rs)
	return id, kitErr(err)
}

func (k kit) Exec(ctx context.Context, id string, cmd []string) (string, int, error) {
	out, code, err := k.d.Exec(ctx, id, cmd)
	return out, code, kitErr(err)
}

func (k kit) Signal(ctx context.Context, id, signal string) error {
	return kitErr(k.d.Signal(ctx, id, signal))
}

func (k kit) Bridge(ctx context.Context) (driverkit.Bridge, error) {
	b, err := k.d.Bridge(ctx)
	return driverkit.Bridge{Gateway: b.Gateway, Subnet: b.Subnet}, kitErr(err)
}

type kitLogs struct{ ls runtime.LogStream }

func (l kitLogs) Next() (driverkit.LogFrame, error) {
	f, err := l.ls.Next()
	return driverkit.LogFrame{Stream: driverkit.Stream(f.Stream), Data: f.Data}, err
}

func (l kitLogs) Close() error { return l.ls.Close() }

func kitContainer(c runtime.Container) driverkit.Container {
	return driverkit.Container{ID: c.ID, Name: c.Name, Image: c.Image, Labels: c.Labels, State: c.State, ExitCode: c.ExitCode,
		HostIP: c.HostIP, HostPort: c.HostPort, IP: c.IP, StartedAt: c.StartedAt}
}

func kitErr(err error) error {
	if errors.Is(err, runtime.ErrNotFound) {
		return driverkit.ErrNotFound
	}
	return err
}
