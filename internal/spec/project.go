package spec

import "strings"

// DefaultProject holds every app created before projects, and every app
// deployed without one (ADR 0026).
const DefaultProject = "default"

// maxProjectLen keeps app IDs, and the replica and container names built
// from them, within every limit downstream.
const maxProjectLen = 30

// ValidProject reports whether s is a valid project name: an app name of
// at most 30 characters.
func ValidProject(s string) bool { return len(s) <= maxProjectLen && nameRe.MatchString(s) }

// AppID is how the control plane, agents, and proxies name an app: its
// name in the default project, <name>.<project> in any other. App names
// have no dots, so IDs never collide, and the default project's IDs are
// the names apps had before projects existed.
func AppID(project, name string) string {
	if project == "" || project == DefaultProject {
		return name
	}
	return name + "." + project
}

// SplitAppID returns the project and name of an app ID, and whether id is
// a valid one.
func SplitAppID(id string) (project, name string, ok bool) {
	name, project, dotted := strings.Cut(id, ".")
	if !dotted {
		project = DefaultProject
	} else if project == DefaultProject || !ValidProject(project) {
		return "", "", false
	}
	if !ValidName(name) {
		return "", "", false
	}
	return project, name, true
}

// ValidAppID reports whether id is a valid app ID.
func ValidAppID(id string) bool {
	_, _, ok := SplitAppID(id)
	return ok
}

// ID returns the app's ID (see AppID).
func (a *App) ID() string { return AppID(a.Project, a.Name) }

func (v *validator) project(s string) {
	switch {
	case s == "" || s == DefaultProject:
	case len(s) > maxProjectLen:
		v.add("project", "must be at most %d characters", maxProjectLen)
	case !nameRe.MatchString(s):
		v.add("project", "must be lowercase letters, digits, and single hyphens, starting with a letter and not ending with a hyphen")
	}
}
