package clientconfig

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/ryanbekhen/armada/internal/fsutil"
)

// ServersPath lists the control plane's API addresses on every Armada
// machine, one per line. The machine's agent keeps it current, so a client
// config on that machine still finds the leader after the servers it lists
// went away or stopped leading. It holds no secret: the client still
// verifies every server against the config's CA.
const ServersPath = "/etc/armada/servers"

// ServersHeader is the response header in which the leader sends the
// control plane's API addresses to AdminService clients, comma-separated, so
// a client config learns of servers added and removed as it is used.
const ServersHeader = "armada-servers"

// serversPath is ServersPath; tests point it elsewhere.
var serversPath = ServersPath

// serversTrusted reports whether the file may extend a config's list:
// root's, and writable by nobody else. Tests replace it.
var serversTrusted = func(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && fi.Mode().Perm()&0o022 == 0
}

// maxServersFile bounds what is read from the file.
const maxServersFile = 64 << 10

// MachineServers returns the addresses in ServersPath, or nil when the file
// is missing, not root's, writable by others, or holds an invalid address.
func MachineServers() []string {
	f, err := os.Open(serversPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxServersFile || !serversTrusted(fi) {
		return nil
	}
	b := make([]byte, fi.Size())
	if _, err := f.ReadAt(b, 0); err != nil && fi.Size() > 0 {
		return nil
	}
	addrs := ParseServers(string(b))
	if _, err := CheckServers(addrs); err != nil {
		return nil
	}
	return addrs
}

// ParseServers reads addresses separated by commas or new lines, skipping
// empty entries and repeats.
func ParseServers(s string) []string {
	var out []string
	for _, a := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		a = strings.TrimSpace(a)
		if a != "" && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// WriteMachineServers replaces ServersPath with addrs (0644, root's
// directory left as it is or created 0711).
func WriteMachineServers(addrs []string) error {
	if _, err := CheckServers(addrs); err != nil {
		return err
	}
	dir := filepath.Dir(serversPath)
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o711); err != nil { //nolint:gosec // search only, like SaveShared
			return err
		}
	}
	if err := fsutil.WriteFileAtomic(serversPath, []byte(strings.Join(addrs, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("%s: %w", serversPath, err)
	}
	return nil
}

// withMachineServers returns servers followed by the machine's addresses
// that servers lacks, so the config's own order is tried first.
func withMachineServers(servers []string) []string {
	out := slices.Clone(servers)
	for _, a := range MachineServers() {
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// SameServers reports whether a and b hold the same addresses in any order.
func SameServers(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}
