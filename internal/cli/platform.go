package cli

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"

	"github.com/ryanbekhen/armada/internal/fsutil"
)

// goos is the system the CLI runs on; tests replace it.
var goos = goruntime.GOOS

// macOSDataDir is the data directory on macOS, below the home of the user
// that runs the agent and its driver (ADR 0016).
const macOSDataDir = "Library/Application Support/Armada"

// Data and secrets directories: on Linux in the system's directories, on
// macOS below the user's home, where the secrets directory is a RAM disk
// the agent mounts.
var defaultDataDir, defaultSecretsDir = defaultDirs()

func defaultDirs() (data, secrets string) {
	if goruntime.GOOS == "darwin" {
		if home, err := os.UserHomeDir(); err == nil {
			data = filepath.Join(home, macOSDataDir)
			return data, filepath.Join(data, "secrets")
		}
	}
	return "/var/lib/armada", "/run/armada/secrets"
}

// defaultProxy is the agent's ingress proxy: none on macOS, whose drivers
// cannot run HAProxy (ADR 0016).
func defaultProxy() string {
	if goos == "darwin" {
		return "none"
	}
	return "haproxy"
}

// linuxOnly refuses what only Linux machines do: the control plane, etcd,
// and the embedded runtime. A Mac is a compute node with a driver.
func linuxOnly(what string) error { return linuxOnlyOn(goos, what) }

func linuxOnlyOn(system, what string) error {
	if system == "darwin" {
		return fmt.Errorf("%s runs on Linux only; a Mac joins a cluster as a compute node with `armada join TOKEN --runtime NAME` (ADR 0016)", what)
	}
	return nil
}

// launchdLabel names a LaunchAgent of Armada's on macOS: "agent", or
// "driver.NAME" for a driver.
func launchdLabel(name string) string { return "io.github.ryanbekhen.armada." + name }

// needsDriverOn refuses the embedded runtime on macOS, which cannot run
// it.
func needsDriverOn(system, runtimeName string) error {
	if system == "darwin" && (runtimeName == "" || runtimeName == runtimeEmbedded) {
		return errors.New("a Mac runs containers through a driver: install one and pass --runtime NAME (ADR 0016)")
	}
	return nil
}

// launchAgentPlist is the LaunchAgent that runs `armada agent` in the
// node user's login session on macOS, logging to logFile.
func launchAgentPlist(exe, logFile string) []byte {
	esc := func(s string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	return fmt.Appendf(nil, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>agent</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, launchdLabel("agent"), esc(exe), esc(logFile), esc(logFile))
}

// installLaunchAgent writes the agent's LaunchAgent for the current user
// and returns the command that starts it.
func installLaunchAgent() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	logs := filepath.Join(home, "Library", "Logs", "Armada")
	if err := fsutil.MkdirPrivate(logs); err != nil {
		return "", err
	}
	dir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // the system's per-user LaunchAgents directory
		return "", err
	}
	path := filepath.Join(dir, launchdLabel("agent")+".plist")
	if err := fsutil.WriteFileAtomic(path, launchAgentPlist(exe, filepath.Join(logs, "agent.log")), 0o644); err != nil {
		return "", err
	}
	return "launchctl bootstrap gui/$(id -u) " + path, nil
}
