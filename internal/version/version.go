// Package version exposes build metadata for the armada binary.
//
// Release builds inject version, commit, and date through -ldflags -X. Builds
// produced by `go install` fall back to the module and VCS information that the
// Go toolchain embeds in the binary.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Name is the binary and product name. Keep every user-facing reference to the
// space name pointing here so a rename touches one line.
const Name = "armada"

const (
	defaultVersion = "dev"
	defaultCommit  = "unknown"
	defaultDate    = "unknown"
)

// Set at link time, e.g.
// -ldflags "-X github.com/ryanbekhen/armada/internal/version.version=v0.1.0".
var (
	version = defaultVersion
	commit  = defaultCommit
	date    = defaultDate
)

// Info describes the running binary.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"goVersion"`
	Platform  string `json:"platform"`
}

// Get returns build metadata for the running binary.
func Get() Info {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		bi = nil
	}
	return resolve(version, commit, date, bi)
}

// resolve merges link-time values with embedded build info. Link-time values
// win whenever they were set.
func resolve(v, c, d string, bi *debug.BuildInfo) Info {
	info := Info{
		Version:   v,
		Commit:    c,
		Date:      d,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if bi == nil {
		return info
	}

	if info.Version == defaultVersion && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		info.Version = bi.Main.Version
	}

	var modified bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if info.Commit == defaultCommit {
				info.Commit = s.Value
			}
		case "vcs.time":
			if info.Date == defaultDate {
				info.Date = s.Value
			}
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if modified && c == defaultCommit && info.Commit != defaultCommit {
		info.Commit += "-dirty"
	}
	return info
}

// String returns a single human-readable line.
func (i Info) String() string {
	return fmt.Sprintf("%s %s (commit %s, built %s, %s, %s)",
		Name, i.Version, i.Commit, i.Date, i.GoVersion, i.Platform)
}
