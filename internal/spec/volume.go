package spec

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Volume is a persistent directory on the node that runs the app's replica
// (ADR 0023). It is created on first use, bound to that node, and kept
// until it is removed with `armada volume delete`.
type Volume struct {
	Name string `yaml:"name" json:"name"`
	// Path is where the volume appears in the container.
	Path string `yaml:"path" json:"path"`
	// Owner is "uid:gid" for the volume's directory, applied whenever a
	// replica starts; empty leaves it (root when created).
	Owner string `yaml:"owner,omitempty" json:"owner,omitempty"`
	// Backup schedules backups to an S3-compatible bucket (ADR 0041).
	Backup *VolumeBackup `yaml:"backup,omitempty" json:"backup,omitempty"`
	// Failover "restore" restores the latest backup on another node when
	// the volume's node is lost (ADR 0041).
	Failover string `yaml:"failover,omitempty" json:"failover,omitempty"`
	// NFS mounts an export of an NFS server the operator runs instead of a
	// directory on the node (ADR 0042).
	NFS *NFSSource `yaml:"nfs,omitempty" json:"nfs,omitempty"`
}

// NFSSource is an NFSv4 export.
type NFSSource struct {
	// Server is the NFS server's private IP address.
	Server string `yaml:"server" json:"server"`
	// Path is the exported directory, absolute.
	Path     string `yaml:"path" json:"path"`
	ReadOnly bool   `yaml:"readOnly,omitempty" json:"readOnly,omitempty"`
}

// maxNFSPath bounds an export's path.
const maxNFSPath = 256

var nfsPathRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]*$`)

// Local reports whether the volume is a directory on its node.
func (v Volume) Local() bool { return v.NFS == nil }

// CheckNFSServer checks an NFS server address: an IP address in a private
// range (or IPv6 unique local), never loopback, link-local, or public.
func CheckNFSServer(s string) error {
	ip, err := netip.ParseAddr(s)
	if err != nil || ip.Zone() != "" {
		return errors.New("must be an IP address")
	}
	ip = ip.Unmap()
	if !ip.IsPrivate() && !sharedRange.Contains(ip) {
		return errors.New("must be a private address (10/8, 172.16/12, 192.168/16, 100.64/10, or fc00::/7)")
	}
	return nil
}

// sharedRange is the shared address space (RFC 6598), private to a
// provider's network.
var sharedRange = netip.MustParsePrefix("100.64.0.0/10")

// CheckNFSPath checks an export's path: absolute, clean, of safe
// characters.
func CheckNFSPath(p string) error {
	if len(p) > maxNFSPath || !nfsPathRe.MatchString(p) || path.Clean(p) != p {
		return fmt.Errorf("must be an absolute, clean path of letters, digits, '.', '_', '-', and '/', at most %d characters", maxNFSPath)
	}
	return nil
}

// FailoverRestore is the failover that restores the latest backup elsewhere.
const FailoverRestore = "restore"

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
		if n := vol.NFS; n != nil {
			if err := CheckNFSServer(n.Server); err != nil {
				v.add(field+".nfs.server", "%v", err)
			}
			if err := CheckNFSPath(n.Path); err != nil {
				v.add(field+".nfs.path", "%v", err)
			}
			if vol.Owner != "" {
				v.add(field+".owner", "is set on the NFS server for an NFS volume")
			}
			if vol.Backup != nil || vol.Failover != "" {
				v.add(field+".backup", "an NFS volume is backed up by its server; leave backup and failover out")
			}
		}
		if vol.Backup != nil {
			v.volumeBackup(field+".backup", vol.Backup)
		}
		switch {
		case vol.Failover == "":
		case vol.Failover != FailoverRestore:
			v.add(field+".failover", "must be %q or left out", FailoverRestore)
		case vol.Backup == nil:
			v.add(field+".failover", "restores the latest backup, so the volume needs backup")
		}
		if first := slices.IndexFunc(a.Volumes, Volume.Local); vol.Local() && (vol.Failover == "") != (a.Volumes[first].Failover == "") {
			v.add(field+".failover", "must be set on every volume of the app on its node, or on none: the app moves with all of them")
		}
	}
	// One replica: two containers never write to the same volume on a node.
	// NFS volumes are shared by design.
	if !a.HasLocalVolumes() {
		return
	}
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

// FailsOver reports whether the app's volumes are restored on another node
// when theirs is lost (ADR 0041).
func (a *App) FailsOver() bool {
	return a.HasLocalVolumes() && !slices.ContainsFunc(a.Volumes, func(v Volume) bool { return v.Local() && v.Failover != FailoverRestore })
}

// HasVolumes reports whether the app keeps data in volumes (ADR 0023).
func (a *App) HasVolumes() bool { return len(a.Volumes) > 0 }

// HasLocalVolumes reports whether some of the app's volumes are directories
// on its node, which bind it to that node and to one replica (ADR 0023).
func (a *App) HasLocalVolumes() bool { return slices.ContainsFunc(a.Volumes, Volume.Local) }

// HasNFSVolumes reports whether the app mounts NFS exports (ADR 0042).
func (a *App) HasNFSVolumes() bool {
	return slices.ContainsFunc(a.Volumes, func(v Volume) bool { return !v.Local() })
}
