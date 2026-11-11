package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// Init containers and sidecars (ADR 0038). The runtime runs them with the
// replica's own container and lists them with it; the agent pulls their
// images, gives them the files and volumes they name, and reads their state
// to tell a crash from a running replica.

// hasMembers reports whether s runs init containers or sidecars.
func hasMembers(s *armadav1.ReplicaSpec) bool {
	return len(s.GetInitContainers()) > 0 || len(s.GetSidecars()) > 0
}

// memberImages returns the images of s's init containers and sidecars.
func memberImages(s *armadav1.ReplicaSpec) []string {
	var out []string
	for _, c := range slices.Concat(s.GetInitContainers(), s.GetSidecars()) {
		out = append(out, c.GetImage())
	}
	return out
}

// memberSpecs converts init containers or sidecars into the runtime's
// specs. Files and volumes are filled in by withMemberMounts.
func memberSpecs(cs []*armadav1.ContainerSpec) []runtime.MemberSpec {
	out := make([]runtime.MemberSpec, 0, len(cs))
	for _, c := range cs {
		env := make([]string, 0, len(c.GetEnv()))
		for _, e := range c.GetEnv() {
			env = append(env, e.GetName()+"="+e.GetValue())
		}
		out = append(out, runtime.MemberSpec{
			Name: c.GetName(), Image: c.GetImage(), Entrypoint: c.GetCommand(), Cmd: c.GetArgs(), Env: env,
			MemoryBytes: c.GetMemoryBytes(), NanoCPUs: c.GetNanoCpus(), CPUReserveMillis: c.GetCpuReserveMillis(), PidsLimit: c.GetPidsLimit(),
		})
	}
	return out
}

// withMemberMounts gives each init container and sidecar of cs the secret
// files and volumes of the replica it names: the same mounts, at the same
// paths.
func withMemberMounts(s *armadav1.ReplicaSpec, cs *runtime.ContainerSpec) error {
	volumePath := map[string]string{}
	for _, v := range s.GetVolumes() {
		volumePath[v.GetName()] = v.GetPath()
	}
	fill := func(members []runtime.MemberSpec, specs []*armadav1.ContainerSpec) error {
		for i := range members {
			for _, path := range specs[i].GetSecretFiles() {
				j := slices.IndexFunc(cs.Files, func(f runtime.FileMount) bool { return f.Target == path })
				if j < 0 {
					return fmt.Errorf("container %s: secret file %s is not the replica's", members[i].Name, path)
				}
				members[i].Files = append(members[i].Files, cs.Files[j])
			}
			for _, name := range specs[i].GetVolumes() {
				j := slices.IndexFunc(cs.Volumes, func(v runtime.VolumeMount) bool { return v.Target == volumePath[name] })
				if volumePath[name] == "" || j < 0 {
					return fmt.Errorf("container %s: volume %s is not the replica's", members[i].Name, name)
				}
				members[i].Volumes = append(members[i].Volumes, cs.Volumes[j])
			}
		}
		return nil
	}
	return errors.Join(fill(cs.Init, s.GetInitContainers()), fill(cs.Sidecars, s.GetSidecars()))
}

// pullMembers pulls the images of s's init containers and sidecars. An
// image without a variant for the node is reported as a plain error: the
// platforms the server learns from a failed start are the replica's own
// image's.
func (a *Agent) pullMembers(ctx context.Context, s *armadav1.ReplicaSpec, pull func(context.Context, string, *runtime.RegistryAuth) (runtime.Image, error)) error {
	for _, image := range memberImages(s) {
		img, err := pull(ctx, image, registryAuth(s))
		if pe := (*runtime.PlatformError)(nil); errors.As(err, &pe) {
			return errors.New(pe.Error())
		}
		if err != nil {
			return err
		}
		if img.Ref != "" {
			a.mu.Lock()
			a.digests[image] = img.Ref
			a.mu.Unlock()
		}
	}
	return nil
}

// memberDown describes what of c's other containers stops its replica: an
// init container that failed, or, outside jobs, a sidecar that no longer
// runs. Empty when nothing does.
func memberDown(s *armadav1.ReplicaSpec, c runtime.Container) string {
	if c.State == runtime.StateStarting {
		return "" // the runtime is still bringing them up
	}
	if m, ok := c.FailedInit(); ok {
		return "init container " + m.Name + " exited with code " + strconv.Itoa(m.ExitCode)
	}
	if c.StartError != "" {
		return c.StartError
	}
	if s.GetJob() != nil {
		// A job's sidecars serve its container; the attempt ends with it.
		return ""
	}
	if m, ok := c.StoppedSidecar(); ok {
		if m.State == runtime.StateExited {
			return "sidecar " + m.Name + " exited with code " + strconv.Itoa(m.ExitCode)
		}
		return "sidecar " + m.Name + " is " + m.State
	}
	return ""
}

// containerFor returns the ID of the container of a replica that name
// names: the replica's own for "" or "app", else its init container or
// sidecar of that name.
func containerFor(cs []runtime.Container, name string) (string, error) {
	for _, c := range cs {
		if c.Labels[runtime.LabelRole] != "" {
			continue // left over from a replica's container that is gone
		}
		if name == "" || name == "app" {
			return c.ID, nil
		}
		m, ok := c.Member(name)
		if !ok {
			return "", fmt.Errorf("the replica has no container %s", name)
		}
		return m.ID, nil
	}
	return "", errors.New("no container on this node")
}
