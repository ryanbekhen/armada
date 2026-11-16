//go:build linux

package containerd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/containerd/containerd/v2/contrib/apparmor"
	"github.com/containerd/containerd/v2/contrib/seccomp"
	"github.com/containerd/containerd/v2/core/containers"
	aa "github.com/containerd/containerd/v2/pkg/apparmor"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// apparmorProfile is generated and loaded once per process.
const apparmorProfile = "armada-default"

func seccompOpt() oci.SpecOpts { return seccomp.WithDefaultProfile() }

var (
	apparmorMu     sync.Mutex
	apparmorLoaded bool
)

// ensureAppArmorProfile loads the profile once per process; a failure is
// tried again by the next container.
func ensureAppArmorProfile() error {
	apparmorMu.Lock()
	defer apparmorMu.Unlock()
	if apparmorLoaded {
		return nil
	}
	if err := loadAppArmorProfile(apparmorProfile); err != nil {
		return err
	}
	apparmorLoaded = true
	return nil
}

// apparmorOpt confines a container with Armada's AppArmor profile, which
// the first container of the process loads (replacing a loaded one, so
// running containers get the current rules too).
func apparmorOpt() oci.SpecOpts {
	if !aa.HostSupports() {
		return nil
	}
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		if err := ensureAppArmorProfile(); err != nil {
			return err
		}
		if s.Process == nil {
			s.Process = &specs.Process{}
		}
		s.Process.ApparmorProfile = apparmorProfile
		return nil
	}
}

// appArmorProfile is containerd's default profile for name, with each rule
// that lets the container's processes signal and trace each other also
// naming the label they carry on kernels that stack a profile entered under
// no_new_privileges on top of the one they had: "name//&unconfined".
// Without that, such kernels refuse every signal between a container's own
// processes: tini forwarding SIGTERM to the app, or a runtime's threads
// signalling each other.
func appArmorProfile(name string) (string, error) {
	text, err := apparmor.DumpDefaultProfile(name)
	if err != nil {
		return "", err
	}
	stacked := `"` + name + `//&unconfined"`
	var b strings.Builder
	added := 0
	for line := range strings.Lines(text) {
		b.WriteString(line)
		trimmed := strings.TrimSpace(line)
		if (strings.HasPrefix(trimmed, "signal (send,receive) ") || strings.HasPrefix(trimmed, "ptrace (")) &&
			strings.HasSuffix(trimmed, " peer="+name+",") {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			b.WriteString(indent + strings.TrimSuffix(trimmed, "peer="+name+",") + "peer=" + stacked + ",\n")
			added++
		}
	}
	if added != 2 {
		return "", fmt.Errorf("apparmor profile %s: expected a signal and a ptrace rule for its own processes, found %d", name, added)
	}
	return b.String(), nil
}

// loadAppArmorProfile loads (or replaces) the profile with apparmor_parser.
func loadAppArmorProfile(name string) error {
	text, err := appArmorProfile(name)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "armada-apparmor-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(text); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	out, err := exec.Command("apparmor_parser", "-Kr", f.Name()).CombinedOutput() //nolint:gosec // a fixed program and the file just written
	if err != nil {
		return fmt.Errorf("load apparmor profile %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
