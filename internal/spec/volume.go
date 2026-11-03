package spec

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Volume is a persistent directory on the node that runs the app's replica
// (ADR 0025). It is created on first use, bound to that node, and kept
// until it is removed with `armada volume rm`.
type Volume struct {
	Name string `yaml:"name" json:"name"`
	// Path is where the volume appears in the container.
	Path string `yaml:"path" json:"path"`
	// Owner is "uid:gid" for the volume's directory, applied whenever a
	// replica starts; empty leaves it (root when created).
	Owner string `yaml:"owner,omitempty" json:"owner,omitempty"`
}

// MaxVolumes is the most volumes an app may have.
const MaxVolumes = 8

// maxOwnerID bounds uid and gid.
const maxOwnerID = 1<<31 - 1

// ParseOwner reads a volume's "uid:gid".
func ParseOwner(s string) (uid, gid int, err error) {
	u, g, ok := strings.Cut(s, ":")
	if !ok {
		return 0, 0, fmt.Errorf("must be uid:gid, e.g. 999:999")
	}
	ids := [2]int{}
	for i, part := range []string{u, g} {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > maxOwnerID || strconv.Itoa(n) != part {
			return 0, 0, fmt.Errorf("must be uid:gid with numbers from 0 to %d", maxOwnerID)
		}
		ids[i] = n
	}
	return ids[0], ids[1], nil
}

func (v *validator) volumes(a *App) {
	if len(a.Volumes) == 0 {
		return
	}
	if a.IsJob() {
		v.add("volumes", "jobs cannot have volumes yet")
		return
	}
	if len(a.Volumes) > MaxVolumes {
		v.add("volumes", "must have at most %d entries", MaxVolumes)
		return
	}
	names := map[string]bool{}
	var paths []string
	for _, f := range a.SecretFiles {
		paths = append(paths, f.Path)
	}
	for i, vol := range a.Volumes {
		field := fmt.Sprintf("volumes[%d]", i)
		v.name(field+".name", vol.Name)
		if names[vol.Name] {
			v.add(field+".name", "%q is used more than once", vol.Name)
		}
		names[vol.Name] = true
		if msg := checkSecretFilePath(vol.Path); msg != "" {
			v.add(field+".path", "%s", msg)
		} else {
			for _, p := range paths {
				if p == vol.Path || strings.HasPrefix(vol.Path, p+"/") || strings.HasPrefix(p, vol.Path+"/") {
					v.add(field+".path", "%q and %q overlap", p, vol.Path)
				}
			}
			paths = append(paths, vol.Path)
		}
		if vol.Owner != "" {
			if _, _, err := ParseOwner(vol.Owner); err != nil {
				v.add(field+".owner", "%v", err)
			}
		}
	}
	// One replica: two containers never write to the same volume.
	if s := a.Scale; s != nil {
		if (s.Min != nil && *s.Min != 1) || (s.Max != nil && *s.Max != 1) || len(s.Rules) > 0 {
			v.add("scale", "an app with volumes runs exactly one replica (min and max 1, no rules)")
		}
	}
	if a.MultipleRevisions() {
		v.add("revisions.mode", "an app with volumes runs one revision at a time; use single mode")
	}
}

// ValidateVolumePath checks where a volume appears in a container: an
// absolute path of safe characters, outside the runtime's own files and
// /proc, /sys, and /dev.
func ValidateVolumePath(p string) error {
	if msg := checkSecretFilePath(p); msg != "" {
		return errors.New(msg)
	}
	return nil
}

// HasVolumes reports whether the app keeps data in volumes (ADR 0025).
func (a *App) HasVolumes() bool { return len(a.Volumes) > 0 }
