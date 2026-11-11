package spec

import (
	"fmt"
	"slices"
)

// Container is an init container or a sidecar of a replica (ADR 0038). It
// shares the replica's network namespace, so the app and its sidecars reach
// each other on 127.0.0.1, and gets only what it names: its own command,
// variables, and resources, and those of the app's volumes and secret files
// it lists, at the app's paths. The app's env is not inherited.
type Container struct {
	Name      string     `yaml:"name" json:"name"`
	Image     string     `yaml:"image" json:"image"`
	Command   []string   `yaml:"command,omitempty" json:"command,omitempty"`
	Args      []string   `yaml:"args,omitempty" json:"args,omitempty"`
	Env       []EnvVar   `yaml:"env,omitempty" json:"env,omitempty"`
	Resources *Resources `yaml:"resources,omitempty" json:"resources,omitempty"`
	// Volumes names the app's volumes the container mounts, at their paths.
	Volumes []string `yaml:"volumes,omitempty" json:"volumes,omitempty"`
	// SecretFiles names, by path, the app's secret files the container
	// mounts, at the same paths.
	SecretFiles []string `yaml:"secretFiles,omitempty" json:"secretFiles,omitempty"`
}

// Limits and defaults of init containers and sidecars.
const (
	MaxInitContainers = 4
	MaxSidecars       = 4
	// MainContainer is the name of the app's own container: init containers
	// and sidecars cannot take it.
	MainContainer = "app"
	// maxContainerName keeps container names short: they end up in container
	// IDs and host names.
	maxContainerName = 30
	// DefaultContainerMemory is the memory limit of an init container or a
	// sidecar that sets no resources.memory.
	DefaultContainerMemory = "64Mi"
	// DefaultContainerCPUMillis is the CPU an init container or a sidecar
	// without resources.cpu reserves; it has no CPU limit.
	DefaultContainerCPUMillis = 10
)

// HasContainers reports whether replicas run init containers or sidecars
// besides the app's own container (ADR 0038).
func (a *App) HasContainers() bool { return len(a.InitContainers) > 0 || len(a.Sidecars) > 0 }

// ContainerNames returns the names of the init containers and sidecars, in
// that order.
func (a *App) ContainerNames() []string {
	var out []string
	for _, c := range a.InitContainers {
		out = append(out, c.Name)
	}
	for _, c := range a.Sidecars {
		out = append(out, c.Name)
	}
	return out
}

// MemoryBytes returns the container's memory limit. It assumes a validated
// spec.
func (c Container) MemoryBytes() int64 {
	m := DefaultContainerMemory
	if c.Resources != nil && c.Resources.Memory != "" {
		m = c.Resources.Memory
	}
	v, _ := ParseMemory(m)
	return v
}

// NanoCPUs returns the container's CPU limit, or 0 for none.
func (c Container) NanoCPUs() int64 {
	if c.Resources == nil || c.Resources.CPU == "" {
		return 0
	}
	v, _ := ParseCPU(c.Resources.CPU)
	return v
}

// CPUMillis returns the CPU the container reserves, in millicores.
func (c Container) CPUMillis() int64 {
	if n := c.NanoCPUs(); n > 0 {
		return max(1, n/1_000_000)
	}
	return DefaultContainerCPUMillis
}

// ReservedCPUMillis is the CPU one replica reserves on its node: the app's
// container and its sidecars run together, init containers one at a time
// before them, so the larger of the two.
func (a *App) ReservedCPUMillis() int64 {
	run := a.CPUMillis()
	var init int64
	for _, c := range a.Sidecars {
		run += c.CPUMillis()
	}
	for _, c := range a.InitContainers {
		init = max(init, c.CPUMillis())
	}
	return max(run, init)
}

// ReservedMemoryBytes is the memory one replica reserves on its node, like
// ReservedCPUMillis.
func (a *App) ReservedMemoryBytes() int64 {
	run := a.MemoryBytes()
	var init int64
	for _, c := range a.Sidecars {
		run += c.MemoryBytes()
	}
	for _, c := range a.InitContainers {
		init = max(init, c.MemoryBytes())
	}
	return max(run, init)
}

func (v *validator) containers(a *App) {
	if len(a.InitContainers) > MaxInitContainers {
		v.add("initContainers", "must have at most %d entries", MaxInitContainers)
		return
	}
	if len(a.Sidecars) > MaxSidecars {
		v.add("sidecars", "must have at most %d entries", MaxSidecars)
		return
	}
	names := map[string]bool{MainContainer: true}
	volumes := map[string]bool{}
	for _, vol := range a.Volumes {
		volumes[vol.Name] = true
	}
	files := map[string]bool{}
	for _, f := range a.SecretFiles {
		files[f.Path] = true
	}
	check := func(field string, c Container) {
		v.name(field+".name", c.Name)
		switch {
		case len(c.Name) > maxContainerName:
			v.add(field+".name", "must be at most %d characters", maxContainerName)
		case c.Name == MainContainer:
			v.add(field+".name", "%q is the app's own container", MainContainer)
		case names[c.Name]:
			v.add(field+".name", "%q is used more than once", c.Name)
		}
		names[c.Name] = true
		v.image(field+".image", c.Image)
		v.args(field+".command", c.Command)
		v.args(field+".args", c.Args)
		v.envIn(field+".env", c.Env)
		v.resourcesIn(field+".resources", c.Resources)
		for i, name := range c.Volumes {
			f := fmt.Sprintf("%s.volumes[%d]", field, i)
			switch {
			case !volumes[name]:
				v.add(f, "%q is not one of the app's volumes", name)
			case slices.Index(c.Volumes, name) != i:
				v.add(f, "%q is listed twice", name)
			}
		}
		for i, path := range c.SecretFiles {
			f := fmt.Sprintf("%s.secretFiles[%d]", field, i)
			switch {
			case !files[path]:
				v.add(f, "%q is not the path of one of the app's secret files", path)
			case slices.Index(c.SecretFiles, path) != i:
				v.add(f, "%q is listed twice", path)
			}
		}
	}
	for i, c := range a.InitContainers {
		check(fmt.Sprintf("initContainers[%d]", i), c)
	}
	for i, c := range a.Sidecars {
		check(fmt.Sprintf("sidecars[%d]", i), c)
	}
}
