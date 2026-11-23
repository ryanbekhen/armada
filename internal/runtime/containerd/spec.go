package containerd

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// initPath is where tini is mounted in app containers.
const initPath = "/sbin/armada-init"

// cpuPeriod is the CFS period used to express CPU limits (100ms).
const cpuPeriod = 100000

// cpuShares turns a CPU reservation into shares (1024 per core, at least
// 2, at most 262144); the runtime maps them to the cgroup v2 weight.
func cpuShares(millis int64) uint64 {
	return uint64(min(max(millis*1024/1000, 2), 262144))
}

// shimGroupAnnotation makes containerd's runc shim serve every container
// with the same value from one process.
const shimGroupAnnotation = "io.containerd.runc.v2.group"

// shimGroup is the shim an app's containers share on a node: one per app,
// and per runtime pack (tini's resolved directory names it), so containers
// started after an upgrade get the new shim instead of joining one that
// runs the old binary for as long as the app has a container on the node.
// Containers with no app get a shim of their own.
func shimGroup(app, tini string) string {
	if app == "" {
		return ""
	}
	return app + "@" + filepath.Base(filepath.Dir(filepath.Dir(tini)))
}

// nofile is the open-file limit of every container.
const nofile = 1048576

// appSpec holds what Run resolved for an app container besides the image.
type appSpec struct {
	spec   runtime.ContainerSpec
	netns  string // network namespace path
	files  containerFiles
	tini   string // host path of tini
	cgroup string
	// group names the shim the container shares (shimGroup); empty for
	// a shim of its own.
	group string
	// apparmor applies an AppArmor profile when the host supports it.
	apparmor oci.SpecOpts
	seccomp  oci.SpecOpts
	selinux  selinuxLabels
}

// appSpecOpts are every option of an app container's spec (or an init
// container's or sidecar's), in order: the image's configuration and
// command, then appOpts.
func appSpecOpts(img oci.Image, a appSpec) []oci.SpecOpts {
	return append(argsOpts(img, a.spec), appOpts(a)...)
}

// systemSpecOpts are every option of a system container's spec, in order.
func systemSpecOpts(img oci.Image, s runtime.SystemSpec, cgroup string, seccomp oci.SpecOpts, sl selinuxLabels) []oci.SpecOpts {
	return append(argsOpts(img, runtime.ContainerSpec{Cmd: s.Cmd}), systemOpts(s, cgroup, seccomp, sl)...)
}

// appOpts are applied after the image configuration. They enforce Armada's
// container defaults: dropped capabilities, no-new-privileges, seccomp,
// resource limits, and an init process.
func appOpts(a appSpec) []oci.SpecOpts {
	s := a.spec
	ro := []string{"rbind", "ro", "nosuid", "nodev", "noexec"}
	mounts := []specs.Mount{
		{Destination: "/etc/resolv.conf", Type: "bind", Source: a.files.resolv, Options: ro},
		{Destination: "/etc/hosts", Type: "bind", Source: a.files.hosts, Options: ro},
		{Destination: "/etc/hostname", Type: "bind", Source: a.files.hostname, Options: ro},
		{Destination: initPath, Type: "bind", Source: a.tini, Options: []string{"rbind", "ro", "nosuid", "nodev"}},
		// Read-only, and only the container's own cgroup (its namespace):
		// programs read their memory and CPU limits from it.
		{Destination: "/sys/fs/cgroup", Type: "cgroup", Source: "cgroup", Options: []string{"ro", "nosuid", "noexec", "nodev", "relatime"}},
	}
	for _, f := range s.Files {
		mounts = append(mounts, specs.Mount{Destination: f.Target, Type: "bind", Source: f.Source, Options: ro})
	}
	for _, v := range s.Volumes {
		rw := "rw"
		if v.ReadOnly {
			rw = "ro"
		}
		mounts = append(mounts, specs.Mount{Destination: v.Target, Type: "bind", Source: v.Source, Options: []string{"rbind", rw, "nosuid", "nodev"}})
	}
	opts := []oci.SpecOpts{
		oci.WithEnv(s.Env),
		oci.WithEnv([]string{"HOSTNAME=" + hostname(s.Name)}),
		oci.WithHostname(hostname(s.Name)),
		oci.WithLinuxNamespace(specs.LinuxNamespace{Type: specs.NetworkNamespace, Path: a.netns}),
		// Its own cgroup namespace: the container sees its cgroup (and its
		// limits) as the root, not the host's hierarchy.
		oci.WithLinuxNamespace(specs.LinuxNamespace{Type: specs.CgroupNamespace}),
		oci.WithMounts(mounts),
		oci.WithDroppedCapabilities(capNames(runtime.DroppedCaps)),
		oci.WithNoNewPrivileges,
		oci.WithCgroup(a.cgroup),
		oci.WithRlimit(&specs.POSIXRlimit{Type: "RLIMIT_NOFILE", Hard: nofile, Soft: nofile}),
		withInit,
		withSELinux(a.selinux),
		withOOMScoreAdj(appOOMScoreAdj),
	}
	if a.seccomp != nil {
		opts = append(opts, a.seccomp)
	}
	if a.group != "" {
		opts = append(opts, oci.WithAnnotations(map[string]string{shimGroupAnnotation: a.group}))
	}
	if a.apparmor != nil {
		opts = append(opts, a.apparmor)
	}
	if s.MemoryBytes > 0 {
		// Swap equal to the limit means no swap beyond the memory limit.
		opts = append(opts, oci.WithMemoryLimit(uint64(s.MemoryBytes)), oci.WithMemorySwap(s.MemoryBytes))
	}
	if s.PidsLimit > 0 {
		opts = append(opts, oci.WithPidsLimit(s.PidsLimit))
	}
	if s.NanoCPUs > 0 {
		opts = append(opts, oci.WithCPUCFS(s.NanoCPUs*cpuPeriod/1e9, cpuPeriod))
	}
	if s.CPUReserveMillis > 0 {
		opts = append(opts, oci.WithCPUShares(cpuShares(s.CPUReserveMillis)))
	}
	return opts
}

// appOOMScoreAdj is the OOM score adjustment of app containers and their
// members. Without it they inherit their shim's (-999 on both runtimes,
// which keeps the shims alive), so when a machine runs out of memory the
// kernel would kill armadad, which runs at 0, before any workload.
const appOOMScoreAdj = 0

// withOOMScoreAdj sets the container process's OOM score adjustment.
func withOOMScoreAdj(adj int) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		if s.Process == nil {
			s.Process = &specs.Process{}
		}
		s.Process.OOMScoreAdj = &adj
		return nil
	}
}

// argsOpts sets the process arguments with the usual image semantics: an
// entrypoint replaces the image's entrypoint and command; a command alone
// replaces only the image's command.
func argsOpts(img oci.Image, s runtime.ContainerSpec) []oci.SpecOpts {
	switch {
	case len(s.Entrypoint) > 0:
		return []oci.SpecOpts{oci.WithImageConfig(img), oci.WithProcessArgs(append(append([]string{}, s.Entrypoint...), s.Cmd...)...)}
	case len(s.Cmd) > 0:
		return []oci.SpecOpts{oci.WithImageConfigArgs(img, s.Cmd)}
	default:
		return []oci.SpecOpts{oci.WithImageConfig(img)}
	}
}

// withInit runs the process under tini, which reaps zombies and forwards
// signals.
func withInit(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
	if s.Process == nil || len(s.Process.Args) == 0 {
		return fmt.Errorf("image has no command; set one in the spec")
	}
	s.Process.Args = append([]string{initPath, "--"}, s.Process.Args...)
	return nil
}

func capNames(caps []string) []string {
	out := make([]string, len(caps))
	for i, c := range caps {
		out[i] = "CAP_" + c
	}
	return out
}

// systemOpts configure an infrastructure container: host network, every
// capability dropped except capAdd, read-only root filesystem.
func systemOpts(s runtime.SystemSpec, cgroup string, seccomp oci.SpecOpts, sl selinuxLabels) []oci.SpecOpts {
	var mounts []specs.Mount
	for _, f := range []string{"/etc/resolv.conf", "/etc/hosts"} {
		mounts = append(mounts, specs.Mount{Destination: f, Type: "bind", Source: f, Options: []string{"rbind", "ro", "nosuid", "nodev", "noexec"}})
	}
	for _, m := range s.Mounts {
		o := []string{"rbind", "nosuid", "nodev", "noexec"}
		if m.ReadOnly {
			o = append(o, "ro")
		} else {
			o = append(o, "rw")
		}
		mounts = append(mounts, specs.Mount{Destination: m.Target, Type: "bind", Source: m.Source, Options: o})
	}
	opts := []oci.SpecOpts{
		oci.WithHostNamespace(specs.NetworkNamespace),
		oci.WithLinuxNamespace(specs.LinuxNamespace{Type: specs.CgroupNamespace}),
		oci.WithMounts(mounts),
		oci.WithCapabilities(capNames(s.CapAdd)),
		oci.WithNoNewPrivileges,
		oci.WithRootFSReadonly(),
		oci.WithCgroup(cgroup),
		oci.WithRlimit(&specs.POSIXRlimit{Type: "RLIMIT_NOFILE", Hard: nofile, Soft: nofile}),
		withSELinux(sl),
	}
	if len(s.Cmd) > 0 {
		opts = append(opts, oci.WithProcessArgs(s.Cmd...))
	}
	if s.User != "" {
		opts = append(opts, oci.WithUser(s.User))
	}
	if seccomp != nil {
		opts = append(opts, seccomp)
	}
	return opts
}
