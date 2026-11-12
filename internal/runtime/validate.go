package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/spec"
)

// DroppedCaps are removed from the engine's default capability set for app
// containers.
var DroppedCaps = []string{"NET_RAW", "MKNOD", "AUDIT_WRITE"}

// Log limits for container output: rotation by size, and a write rate per
// container (bytes per second, with a burst) past which output is dropped
// so one container cannot take a node's disk bandwidth.
const (
	LogMaxSize  = 10 << 20
	LogMaxFiles = 3
	LogRate     = 1 << 20
	LogBurst    = 4 << 20
)

// CheckContainerSpec enforces the rules every driver applies before running
// an app container: read-only regular-file mounts, private DNS servers, and
// a port published only on a private address.
func CheckContainerSpec(s ContainerSpec) error {
	for _, f := range s.Files {
		if err := CheckFileMount(f); err != nil {
			return err
		}
	}
	if len(s.Volumes) > spec.MaxVolumes {
		return fmt.Errorf("at most %d volumes", spec.MaxVolumes)
	}
	targets := map[string]bool{}
	for _, f := range s.Files {
		targets[f.Target] = true
	}
	for _, v := range s.Volumes {
		if err := CheckVolumeMount(v); err != nil {
			return err
		}
		if targets[v.Target] {
			return fmt.Errorf("volume target %s is used twice", v.Target)
		}
		targets[v.Target] = true
	}
	for _, d := range s.DNS {
		if _, err := netutil.CheckPrivateIP(d); err != nil {
			return fmt.Errorf("DNS server: %w", err)
		}
	}
	if len(s.DNSSearch) > 1 {
		return errors.New("at most one DNS search domain")
	}
	for _, d := range s.DNSSearch {
		if !spec.ValidSearchDomain(d) {
			return fmt.Errorf("DNS search domain %q: not an internal zone", d)
		}
	}
	if s.Port != 0 {
		if s.Port < 1 || s.Port > 65535 {
			return fmt.Errorf("invalid port %d", s.Port)
		}
		if _, err := netutil.CheckPrivateIP(s.HostIP); err != nil {
			return fmt.Errorf("publish address: %w", err)
		}
	}
	return checkMembers(s)
}

// checkMembers checks a replica's init containers and sidecars (ADR 0038):
// at most as many as a spec allows, valid and unique names, and only files
// and volumes the replica's own container mounts, at the same places.
func checkMembers(s ContainerSpec) error {
	if len(s.Init) > spec.MaxInitContainers || len(s.Sidecars) > spec.MaxSidecars {
		return fmt.Errorf("at most %d init containers and %d sidecars", spec.MaxInitContainers, spec.MaxSidecars)
	}
	names := map[string]bool{spec.MainContainer: true}
	for _, m := range slices.Concat(s.Init, s.Sidecars) {
		if !ValidMemberName(m.Name) || names[m.Name] {
			return fmt.Errorf("invalid or repeated container name %q", m.Name)
		}
		names[m.Name] = true
		if m.Image == "" {
			return fmt.Errorf("container %s: no image", m.Name)
		}
		for _, f := range m.Files {
			if !slices.Contains(s.Files, f) {
				return fmt.Errorf("container %s: file %s is not one of the replica's", m.Name, f.Target)
			}
		}
		for _, v := range m.Volumes {
			if !slices.Contains(s.Volumes, v) {
				return fmt.Errorf("container %s: volume %s is not one of the replica's", m.Name, v.Target)
			}
		}
	}
	return nil
}

// ValidMemberName reports whether name can name an init container or a
// sidecar: a valid spec name of at most 30 characters, other than the
// replica's own container's.
func ValidMemberName(name string) bool {
	return spec.ValidName(name) && len(name) <= 30 && name != spec.MainContainer
}

// CheckFileMount allows only absolute, clean paths and a regular host file,
// so a mount can never expose an engine socket or a host directory.
func CheckFileMount(f FileMount) error {
	for _, p := range []string{f.Source, f.Target} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
			return fmt.Errorf("file mount %q: path must be absolute and clean", p)
		}
	}
	fi, err := os.Lstat(f.Source)
	if err != nil {
		return fmt.Errorf("file mount: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("file mount %s: not a regular file", f.Source)
	}
	return nil
}

// CheckVolumeMount allows a directory (not a link) at an absolute, clean
// host path, mounted at a target the spec would accept for a volume.
func CheckVolumeMount(v VolumeMount) error {
	if !filepath.IsAbs(v.Source) || filepath.Clean(v.Source) != v.Source || v.Source == "/" || strings.ContainsAny(v.Source, ":,\n") {
		return fmt.Errorf("volume source %q: path must be absolute and clean", v.Source)
	}
	if err := spec.ValidateVolumePath(v.Target); err != nil {
		return fmt.Errorf("volume target %q: %w", v.Target, err)
	}
	fi, err := os.Lstat(v.Source)
	if err != nil {
		return fmt.Errorf("volume: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("volume %s: not a directory", v.Source)
	}
	return nil
}

// CheckSystemMount accepts absolute paths without characters that engines
// treat as separators.
func CheckSystemMount(m Mount) error {
	if !strings.HasPrefix(m.Source, "/") || !strings.HasPrefix(m.Target, "/") || strings.ContainsAny(m.Source+m.Target, ":,\n") {
		return fmt.Errorf("invalid mount %s -> %s", m.Source, m.Target)
	}
	return nil
}

// Exec limits (ADR 0015).
const (
	MaxExecArgs   = 64
	MaxExecArgLen = 4096
	// MaxExecChunk is the most data one exec message carries.
	MaxExecChunk = 32 << 10
)

// CheckExecCommand checks a command for ExecApp: at least one argument, at
// most MaxExecArgs of at most MaxExecArgLen bytes each, and no NUL bytes,
// which cannot reach a process's arguments. Errors never repeat the
// arguments, which may hold secret values.
func CheckExecCommand(cmd []string) error {
	switch {
	case len(cmd) == 0 || cmd[0] == "":
		return errors.New("command is empty")
	case len(cmd) > MaxExecArgs:
		return fmt.Errorf("command has more than %d arguments", MaxExecArgs)
	}
	for i, a := range cmd {
		if len(a) > MaxExecArgLen {
			return fmt.Errorf("argument %d is longer than %d bytes", i, MaxExecArgLen)
		}
		if strings.ContainsRune(a, 0) {
			return fmt.Errorf("argument %d contains a NUL byte", i)
		}
	}
	return nil
}
