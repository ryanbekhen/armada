package spec

import "strings"

// DefaultSpace holds every app created before spaces, and every app
// deployed without one (ADR 0026).
const DefaultSpace = "default"

// maxSpaceLen keeps app IDs, and the replica and container names built
// from them, within every limit downstream.
const maxSpaceLen = 30

// ValidSpace reports whether s is a valid space name: an app name of
// at most 30 characters.
func ValidSpace(s string) bool { return len(s) <= maxSpaceLen && nameRe.MatchString(s) }

// AppID is how the control plane, agents, and proxies name an app: its
// name in the default space, <name>.<space> in any other. App names
// have no dots, so IDs never collide, and the default space's IDs are
// the names apps had before spaces existed.
func AppID(space, name string) string {
	if space == "" || space == DefaultSpace {
		return name
	}
	return name + "." + space
}

// SplitAppID returns the space and name of an app ID, and whether id is
// a valid one.
func SplitAppID(id string) (space, name string, ok bool) {
	name, space, dotted := strings.Cut(id, ".")
	if !dotted {
		space = DefaultSpace
	} else if space == DefaultSpace || !ValidSpace(space) {
		return "", "", false
	}
	if !ValidName(name) {
		return "", "", false
	}
	return space, name, true
}

// ValidAppID reports whether id is a valid app ID.
func ValidAppID(id string) bool {
	_, _, ok := SplitAppID(id)
	return ok
}

// ID returns the app's ID (see AppID).
func (a *App) ID() string { return AppID(a.Space, a.Name) }

func (v *validator) space(s string) {
	switch {
	case s == "" || s == DefaultSpace:
	case len(s) > maxSpaceLen:
		v.add("space", "must be at most %d characters", maxSpaceLen)
	case !nameRe.MatchString(s):
		v.add("space", "must be lowercase letters, digits, and single hyphens, starting with a letter and not ending with a hyphen")
	}
}
