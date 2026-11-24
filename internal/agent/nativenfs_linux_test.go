package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ryanbekhen/armada/internal/nodeprog"
	"github.com/ryanbekhen/armada/internal/spec"
)

// nodeProgram is armada-node for the parity tests (ARMADA_NODE_BIN).
func nodeProgram(t *testing.T) *nodeprog.Program {
	t.Helper()
	bin := os.Getenv("ARMADA_NODE_BIN")
	if bin == "" {
		t.Skip("ARMADA_NODE_BIN is not set (make node)")
	}
	return nodeprog.New(bin)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// armada-node nfs source reads mountinfo as mountedSource does.
func TestArmadaNodeNFSSourceMatchesGo(t *testing.T) {
	prog := nodeProgram(t)
	const target = "/var/lib/armada/nfs/web/files"
	line := func(id int, mnt, fstype, source string) string {
		return fmt.Sprintf("%d 35 0:52 / %s rw,nosuid,nodev,relatime shared:1 - %s %s rw,vers=4.2\n", id, mnt, fstype, source)
	}
	cases := map[string]string{
		"empty":         "",
		"one":           line(36, target, "nfs4", "10.0.0.5:/exports/a"),
		"last wins":     line(36, target, "nfs4", "10.0.0.5:/exports/a") + line(37, target, "nfs4", "[fd00::5]:/exports/b"),
		"other on top":  line(36, target, "nfs4", "10.0.0.5:/exports/a") + line(37, target, "ext4", "/dev/sda1"),
		"nfs3":          line(36, target, "nfs", "10.0.0.5:/x"),
		"escaped":       line(36, "/var/lib/armada/nfs/web/fi\\154es", "nfs4", "10.0.0.5:/e"),
		"odd escapes":   line(36, "/var/lib/armada/nfs/web/files\\04x", "nfs4", "10.0.0.5:/e") + line(37, "/var/lib/armada/nfs/web/fil\\777es", "nfs4", "s:/f"),
		"short":         "36 35 0:52 / " + target + " rw - nfs4\n",
		"no separator":  "36 35 0:52 / " + target + " rw a b c d e f g\n",
		"crlf":          strings.ReplaceAll(line(36, target, "nfs4", "10.0.0.5:/exports/a"), "\n", "\r\n"),
		"no newline":    strings.TrimSuffix(line(36, target, "nfs4", "10.0.0.5:/exports/a"), "\n"),
		"tabs":          strings.ReplaceAll(line(36, target, "nfs4", "10.0.0.5:/t"), " ", "\t"),
		"long line":     line(36, target, "nfs4", "10.0.0.5:/a") + strings.Repeat("x", 1<<20) + "\n",
		"almost long":   strings.Repeat("y", 1<<20-1) + "\n" + line(36, target, "nfs4", "10.0.0.5:/a"),
		"invalid UTF-8": line(36, target, "nfs4", "10.0.0.5:/\xff"),
	}
	dir := t.TempDir()
	a := &Agent{cfg: Config{Node: prog}}
	for name, info := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(path, []byte(info), 0o600); err != nil {
			t.Fatal(err)
		}
		gs, gm, gerr := mountedSourceIn(path, target)
		var out struct {
			Source   string `json:"source"`
			Mounted  bool   `json:"mounted"`
			ReadOnly bool   `json:"readOnly"`
		}
		rerr := a.cfg.Node.Call(context.Background(), nfsRequest{Target: target, Mountinfo: path}, &out, "nfs", "source")
		if gerr != nil {
			gs, gm = "", false // the caller reads nothing else then
		}
		// JSON carries text: a source that is not UTF-8 arrives with
		// U+FFFD, and differs from every export (all ASCII) either way.
		gs = strings.ToValidUTF8(gs, "�")
		if gs != out.Source || gm != out.Mounted || errString(gerr) != errString(rerr) || out.ReadOnly {
			t.Errorf("%s: Go %q %v %v, armada-node %q %v %v (read-only %v)", name, gs, gm, gerr, out.Source, out.Mounted, rerr, out.ReadOnly)
		}
	}
	missing := filepath.Join(dir, "missing")
	_, _, gerr := mountedSourceIn(missing, target)
	rerr := a.cfg.Node.Call(context.Background(), nfsRequest{Target: target, Mountinfo: missing}, nil, "nfs", "source")
	if errString(gerr) != errString(rerr) {
		t.Errorf("missing file: Go %v, armada-node %v", gerr, rerr)
	}
	// This machine's own mountinfo, for a directory that is no mount.
	gs, gm, _, gerr := (&Agent{}).nfsMounted(context.Background(), dir, "")
	rs, rm, rro, rerr := a.nfsMounted(context.Background(), dir, "")
	if gs != rs || gm != rm || rro || errString(gerr) != errString(rerr) {
		t.Errorf("this machine: Go %q %v %v, armada-node %q %v %v", gs, gm, gerr, rs, rm, rerr)
	}
	if n := prog.StoodIn("nfs source"); n != 0 {
		t.Errorf("Go stood in %d times", n)
	}
}

// mountCall is one mount(2) call.
type mountCall struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Fstype string `json:"fstype"`
	Flags  uint64 `json:"flags"`
	Data   string `json:"data"`
}

// armada-node nfs mount makes the mount calls mountNFS makes, falling
// back through the versions on the same errors, and fails with the same
// texts (nfs plan: the calls with the kernel's answers given, no mount).
func TestArmadaNodeNFSMountPlanMatchesGo(t *testing.T) {
	prog := nodeProgram(t)
	type planCase struct {
		server, export string
		readOnly       bool
		selinux        bool
		errnos         []syscall.Errno
	}
	var cases []planCase
	for _, server := range []string{"10.0.0.5", "fd00::5", "::ffff:10.0.0.9"} {
		for _, ro := range []bool{false, true} {
			for _, se := range []bool{false, true} {
				for _, errs := range [][]syscall.Errno{
					nil,
					{syscall.EPROTONOSUPPORT},
					{syscall.EINVAL, syscall.EPROTONOSUPPORT},
					{syscall.EINVAL, syscall.EINVAL, syscall.EINVAL},
					{syscall.EPROTONOSUPPORT, syscall.EPROTONOSUPPORT, syscall.EPROTONOSUPPORT},
					{syscall.ECONNREFUSED},
					{syscall.EINVAL, syscall.EACCES},
					{syscall.ETIMEDOUT},
					{syscall.EPERM},
					{syscall.Errno(200)},
				} {
					cases = append(cases, planCase{server, "/exports/data", ro, se, errs})
				}
			}
		}
	}
	for _, c := range cases {
		var goCalls []mountCall
		i := 0
		gerr := mountNFSWith(context.Background(), c.server, c.export, "/mnt/t", c.readOnly, c.selinux,
			func(source, target, fstype string, flags uintptr, data string) error {
				goCalls = append(goCalls, mountCall{source, target, fstype, uint64(flags), data})
				defer func() { i++ }()
				if i < len(c.errnos) {
					return c.errnos[i]
				}
				return nil
			})
		errnos := make([]int, len(c.errnos))
		for i, e := range c.errnos {
			errnos[i] = int(e)
		}
		req := map[string]any{"server": c.server, "path": c.export, "target": "/mnt/t", "readOnly": c.readOnly, "selinux": c.selinux, "errnos": errnos}
		var out struct {
			Calls []mountCall `json:"calls"`
			Error string      `json:"error"`
		}
		b, err := prog.Exec(context.Background(), req, "nfs", "plan")
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(goCalls) != fmt.Sprint(out.Calls) || errString(gerr) != out.Error {
			t.Errorf("%+v:\nGo %+v %v\narmada-node %+v %q", c, goCalls, gerr, out.Calls, out.Error)
		}
	}
}

// armada-node nfs mount checks the export again before calling the
// kernel, with the texts prepareNFS's checks give.
func TestArmadaNodeNFSMountChecks(t *testing.T) {
	prog := nodeProgram(t)
	target := t.TempDir()
	for _, c := range []struct{ server, path string }{
		{"8.8.8.8", "/exports"},
		{"nfs.example", "/exports"},
		{"fe80::1%eth0", "/exports"},
		{"10.0.0.5", "relative"},
		{"10.0.0.5", "/a/../b"},
		{"10.0.0.5", "/a b"},
		{"10.0.0.5", "/" + strings.Repeat("a", 300)},
	} {
		var want string
		if err := spec.CheckNFSServer(c.server); err != nil {
			want = "NFS server: " + err.Error()
		} else if err := spec.CheckNFSPath(c.path); err != nil {
			want = "NFS path: " + err.Error()
		}
		err := prog.Call(context.Background(), nfsRequest{Server: c.server, Path: c.path, Target: target}, nil, "nfs", "mount")
		if errString(err) != want {
			t.Errorf("%s:%s: armada-node %v, want %q", c.server, c.path, err, want)
		}
	}
}

// armada-node nfs unmount answers what unmountNFS answers (without root:
// the kernel refuses both).
func TestArmadaNodeNFSUnmountMatchesGo(t *testing.T) {
	prog := nodeProgram(t)
	a := &Agent{cfg: Config{Node: prog}}
	dir := t.TempDir()
	for _, target := range []string{dir, filepath.Join(dir, "missing")} {
		gerr := unmountNFS(target)
		rerr := a.unmountNFS(context.Background(), target)
		if errString(gerr) != errString(rerr) {
			t.Errorf("%s: Go %v, armada-node %v", target, gerr, rerr)
		}
	}
	if n := prog.StoodIn("nfs unmount"); n != 0 {
		t.Errorf("Go stood in %d times", n)
	}
}

// A program that fails leaves NFS calls to Go, which counts them.
func TestNFSProgramFallsBack(t *testing.T) {
	t.Parallel()
	bin := filepath.Join(t.TempDir(), "armada-node")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho broken >&2\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	prog := nodeprog.New(bin)
	a := &Agent{cfg: Config{Node: prog}}
	dir := t.TempDir()
	if _, mounted, _, err := a.nfsMounted(context.Background(), dir, ""); mounted || err != nil {
		t.Errorf("nfsMounted: %v %v", mounted, err)
	}
	gerr := unmountNFS(dir)
	if err := a.unmountNFS(context.Background(), dir); errString(err) != errString(gerr) {
		t.Errorf("unmountNFS: %v, Go %v", err, gerr)
	}
	if prog.StoodIn("nfs source") != 1 || prog.StoodIn("nfs unmount") != 1 {
		t.Errorf("stood in: source %d, unmount %d", prog.StoodIn("nfs source"), prog.StoodIn("nfs unmount"))
	}
	var perr nodeprog.Error
	if err := prog.Call(context.Background(), nil, nil, "nfs", "source"); !errors.As(err, &perr) || !strings.Contains(err.Error(), "broken") {
		t.Errorf("the program's failure: %v", err)
	}
}
