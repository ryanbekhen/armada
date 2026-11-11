package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/selinux/go-selinux"
	"golang.org/x/sys/unix"
)

var netipParse = netip.ParseAddr

// nfsContext labels NFS mounts on SELinux systems so containers may use
// them; every container of the app on the node shares the mount.
const nfsContext = "system_u:object_r:container_file_t:s0"

// nfsSupported reports whether the kernel has an NFSv4 client, loaded or
// as a module.
func nfsSupported() bool {
	if b, err := os.ReadFile("/proc/filesystems"); err == nil && strings.Contains(string(b), "\tnfs4\n") {
		return true
	}
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return false
	}
	release := unix.ByteSliceToString(u.Release[:])
	b, err := os.ReadFile(filepath.Join("/lib/modules", filepath.Base(release), "modules.dep"))
	return err == nil && strings.Contains(string(b), "/nfsv4.ko")
}

// mountNFS mounts server:export on target with the kernel's NFSv4 client:
// nosuid and nodev, hard, over TCP, trying 4.2, then 4.1, then 4.0. It
// needs no helper program.
func mountNFS(ctx context.Context, server, export, target string, readOnly bool) error {
	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV)
	if readOnly {
		flags |= unix.MS_RDONLY
	}
	var last error
	for _, vers := range []string{"4.2", "4.1", "4.0"} {
		opts := "vers=" + vers + ",proto=tcp,hard,timeo=600,retrans=2,addr=" + server
		if selinux.GetEnabled() {
			opts += `,context="` + nfsContext + `"`
		}
		done := make(chan error, 1)
		go func() { done <- unix.Mount(nfsSource(server, export), target, "nfs4", flags, opts) }()
		select {
		case err := <-done:
			if err == nil {
				return nil
			}
			last = err
			if !errors.Is(err, unix.EPROTONOSUPPORT) && !errors.Is(err, unix.EINVAL) {
				return err
			}
		case <-ctx.Done():
			return fmt.Errorf("the server did not answer: %w", ctx.Err())
		}
	}
	return last
}

// unmountNFS detaches target: replicas that still bind it keep it, and a
// server that does not answer does not hold the agent.
func unmountNFS(target string) error {
	err := unix.Unmount(target, unix.MNT_DETACH)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT) {
		return nil // not mounted
	}
	return err
}

// mountedSource reads /proc/self/mountinfo for the NFS mount on target.
func mountedSource(target string) (string, bool, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	var source string
	found := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		// ID PARENT MAJ:MIN ROOT MOUNTPOINT OPTS [OPTIONAL...] - FSTYPE SOURCE SUPEROPTS
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 || unescapeMount(fields[4]) != target {
			continue
		}
		for i, f := range fields {
			if f == "-" && i+2 < len(fields) {
				if strings.HasPrefix(fields[i+1], "nfs") {
					source, found = fields[i+2], true // the last mount on target wins
				} else {
					source, found = "", false
				}
				break
			}
		}
	}
	return source, found, sc.Err()
}

// mountedReadOnly reports whether target is mounted read-only.
func mountedReadOnly(target string) bool {
	var st unix.Statfs_t
	return unix.Statfs(target, &st) == nil && st.Flags&unix.ST_RDONLY != 0
}

// unescapeMount undoes mountinfo's octal escapes of spaces and the like.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var c byte
			if _, err := fmt.Sscanf(s[i+1:i+4], "%03o", &c); err == nil {
				b.WriteByte(c)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
