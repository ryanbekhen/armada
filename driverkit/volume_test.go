package driverkit

import (
	"context"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	driverv1 "github.com/ryanbekhen/armada/api/armada/driver/v1"
)

// runDriver answers Run only; the rest of Driver is never called.
type runDriver struct {
	Driver
	ran     []ContainerSpec
	volumes bool
}

func (d *runDriver) Run(_ context.Context, s ContainerSpec) (string, error) {
	d.ran = append(d.ran, s)
	return "c1", nil
}

type volumeDriver struct{ runDriver }

func (d *volumeDriver) CanMountVolumes() bool { return d.volumes }

func TestVolumes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	s := validSpec(t)
	s.Volumes = []VolumeMount{{Source: dir, Target: "/data"}}
	if err := CheckContainerSpec(s); err != nil {
		t.Fatalf("valid volume refused: %v", err)
	}
	got, err := ContainerSpecFromProto(ContainerSpecToProto(s))
	if err != nil || len(got.Volumes) != 1 || got.Volumes[0] != s.Volumes[0] {
		t.Fatalf("round trip: %+v %v", got.Volumes, err)
	}
	for _, bad := range []VolumeMount{{Source: dir, Target: "/proc/x"}, {Source: "rel", Target: "/data"}, {Source: dir, Target: "/"}} {
		b := validSpec(t)
		b.Volumes = []VolumeMount{bad}
		if err := CheckContainerSpec(b); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}

	req := &driverv1.RunRequest{Spec: ContainerSpecToProto(s)}
	for name, c := range map[string]struct {
		d    Driver
		caps bool
	}{
		"no interface":   {&runDriver{}, false},
		"declines":       {&volumeDriver{}, false},
		"mounts volumes": {&volumeDriver{runDriver{volumes: true}}, true},
	} {
		srv := &server{d: c.d, info: Info{Name: "test"}}
		info, err := srv.Info(ctx, &driverv1.InfoRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if has := slices.Contains(info.GetCapabilities(), driverv1.Capability_CAPABILITY_VOLUMES); has != c.caps {
			t.Errorf("%s: volumes capability %t", name, has)
		}
		_, err = srv.Run(ctx, req)
		if c.caps && err != nil {
			t.Errorf("%s: Run: %v", name, err)
		}
		if !c.caps && status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s: Run with a volume: %v", name, err)
		}
	}
}
