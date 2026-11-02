package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ryanbekhen/armada/internal/netutil"
)

// DroppedCaps are removed from the engine's default capability set for app
// containers.
var DroppedCaps = []string{"NET_RAW", "MKNOD", "AUDIT_WRITE"}

// Log rotation limits for container output, the same on every engine.
const (
	LogMaxSize  = 10 << 20
	LogMaxFiles = 3
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
	for _, d := range s.DNS {
		if _, err := netutil.CheckPrivateIP(d); err != nil {
			return fmt.Errorf("DNS server: %w", err)
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
	return nil
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

// CheckSystemMount accepts absolute paths without characters that engines
// treat as separators.
func CheckSystemMount(m Mount) error {
	if !strings.HasPrefix(m.Source, "/") || !strings.HasPrefix(m.Target, "/") || strings.ContainsAny(m.Source+m.Target, ":,\n") {
		return fmt.Errorf("invalid mount %s -> %s", m.Source, m.Target)
	}
	return nil
}

// Exec limits (ADR 0017).
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
