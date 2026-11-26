package daemon

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

// Recording the daemon's parity cases for the Rust replay (ADR 0055, item
// 20). With -record-fixtures, TestDaemonParity writes
// daemon/tests/testdata/parity.jsonl.gz: a first line with the blobs the
// cases share (file contents by SHA-256) and the control plane bucket's
// objects, then one line per case with what the Rust armadad is run with
// (its arguments and environment, standard input, the case directory as
// prepared: every directory, file, and link with its mode, the stand-ins
// it is given, the state it needs: a server's member, the bucket, the
// pinned etcd; the time the case ran, which doctor's clock starts at) and
// the outcome it must give: Go's, through rustWants, or for the cases of
// the Rust armadad alone (rustOnly), the Rust armadad's own once the case's
// checks passed (recording them needs ARMADA_DAEMON_BIN). daemon/tests/
// parity.rs replays every line against the Rust armadad (test-hooks build)
// and compares as compareDaemon does.
//
// What differs from run to run is written as a placeholder: the case
// directory {DIR}, the stand-ins' directory {STANDINS}, the pinned etcd's
// {ETCD_DIR}, the bucket's address {BUCKET}, the member's ports {PORT0}
// and {PORT1}, and the inherited PATH {PATH}.

var recordFixtures = flag.Bool("record-fixtures", false,
	"write daemon/tests/testdata/parity.jsonl.gz (each case and the outcome it must give) for the Rust replay")

const daemonFixtures = "../../daemon/tests/testdata/parity.jsonl.gz"

// recordPath is the PATH the recording runs with, after the stand-ins
// (the replay's {PATH}): what any Linux machine has, so a command that
// looks for a program (doctor's iptables) finds the same on both.
const recordPath = "/usr/bin:/bin"

// treeEntry is one path of a case directory as prepared.
type treeEntry struct {
	Path string `json:"path"`
	// Kind is dir, file, or link.
	Kind string      `json:"kind"`
	Mode fs.FileMode `json:"mode,omitempty"`
	// Blob names a file's content among the blobs; Text is a content
	// holding a placeholder; Target is a link's.
	Blob   string `json:"blob,omitempty"`
	Text   string `json:"text,omitempty"`
	Target string `json:"target,omitempty"`
}

type daemonRecorder struct {
	h     *daemonHarness
	blobs map[string][]byte
	lines [][]byte
	tree  []treeEntry
	now   time.Time
	dir   string
	// addrs are the machine's addresses' stand-ins (machineAddresses).
	addrs map[string]string
}

func newDaemonRecorder(t *testing.T, h *daemonHarness) *daemonRecorder {
	t.Helper()
	if !*recordFixtures {
		return nil
	}
	if h.bin == "" {
		t.Fatal("recording needs ARMADA_DAEMON_BIN: the cases of the Rust armadad alone record its outcome")
	}
	if h.etcdDir == "" {
		t.Fatal("recording needs ARMADA_ETCD_DIR (sh scripts/etcd-cache.sh)")
	}
	r := &daemonRecorder{h: h, blobs: map[string][]byte{}}
	r.machineAddresses(t)
	return r
}

func (r *daemonRecorder) blob(b []byte) string {
	sum := sha256.Sum256(b)
	k := hex.EncodeToString(sum[:])
	r.blobs[k] = b
	return k
}

// placeholders replaces what differs from run to run in s.
func (r *daemonRecorder) placeholders(s string, c daemonCase) string {
	s = r.sanitize(s)
	s = strings.ReplaceAll(s, r.dir, "{DIR}")
	s = strings.ReplaceAll(s, r.h.standins, "{STANDINS}")
	if r.h.etcdDir != "" {
		s = strings.ReplaceAll(s, r.h.etcdDir, "{ETCD_DIR}")
	}
	s = strings.ReplaceAll(s, r.h.bucket.addr(), "{BUCKET}")
	if st := c.state; st != nil && st.ports[0] != 0 {
		s = strings.ReplaceAll(s, fmt.Sprintf("%d,%d", st.ports[0], st.ports[1]), "{PORT0},{PORT1}")
		for i, p := range st.ports {
			s = strings.ReplaceAll(s, fmt.Sprintf(":%d", p), fmt.Sprintf(":{PORT%d}", i))
		}
	}
	return s
}

// snapshot notes the case directory as prepared, before the command runs.
func (r *daemonRecorder) snapshot(t *testing.T, dir string) {
	if r == nil {
		return
	}
	t.Helper()
	r.tree, r.dir, r.now = nil, dir, time.Now()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		e := treeEntry{Path: rel, Mode: fi.Mode().Perm()}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			e.Kind, e.Mode = "link", 0
			e.Target, _ = os.Readlink(p)
		case fi.IsDir():
			e.Kind = "dir"
		default:
			e.Kind = "file"
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if utf8.Valid(b) && strings.Contains(string(b), dir) {
				e.Text = string(b)
			} else {
				e.Blob = r.blob(b)
			}
		}
		r.tree = append(r.tree, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// add records a case with the outcome the Rust armadad must give.
func (r *daemonRecorder) add(t *testing.T, c daemonCase, want daemonResult) {
	if r == nil {
		return
	}
	t.Helper()
	args, env := r.h.rustInvocation(r.dir, c)
	path := env["PATH"]
	if !strings.HasSuffix(path, string(os.PathListSeparator)+os.Getenv("PATH")) {
		t.Fatalf("PATH %q does not end with the test's", path)
	}
	env["PATH"] = strings.TrimSuffix(path, os.Getenv("PATH")) + "{PATH}"
	for k, v := range env {
		env[k] = r.placeholders(v, c)
	}
	for i, a := range args {
		args[i] = r.placeholders(a, c)
	}
	tree := slices.Clone(r.tree)
	for i := range tree {
		tree[i].Text = r.placeholders(tree[i].Text, c)
		tree[i].Target = r.placeholders(tree[i].Target, c)
	}
	files := slices.Clone(want.Files)
	for i := range files {
		files[i] = r.placeholders(files[i], c)
	}
	line := map[string]any{
		"name": c.name,
		"args": args,
		"env":  env,
		"tree": tree,
		"now":  r.now.UnixNano(),
		"want": map[string]any{
			"code":   want.Code,
			"stdout": r.placeholders(want.Stdout, c),
			"stderr": r.placeholders(want.Stderr, c),
			"files":  files,
		},
	}
	if c.stdin != "" {
		line["stdin"] = r.blob([]byte(c.stdin))
	}
	if c.during != nil {
		// holdDB, the only one: the member's database held as a running
		// member holds it.
		line["holdDB"] = true
	}
	if c.rustOnly != nil {
		line["rustOnly"] = true
	}
	if s := c.state; s != nil {
		line["state"] = map[string]bool{"member": s.member, "loopback": s.loopback, "etcd": s.etcd,
			"bucket": s.bucket, "emptyBucket": s.emptyBucket, "archiveOut": s.archiveOut}
	}
	b, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}
	r.lines = append(r.lines, b)
}

// machineInterfaces is this machine's addresses as Go reads them (the
// member certificate names them, doctor and the endpoint commands look for
// one): the replay hands them to the Rust armadad
// (ARMADA_DAEMON_TEST_INTERFACES), so a case gives the same outcome on
// another machine. Each is `INDEX NAME FLAGS IP`, FLAGS u for up and l for
// loopback, its address as machineAddress names it.
func (r *daemonRecorder) machineInterfaces(t *testing.T) string {
	t.Helper()
	var out []string
	for _, e := range r.interfaces(t) {
		out = append(out, fmt.Sprintf("%d %s %s %s", e.index, e.name, e.flags, r.sanitize(e.ip.String())))
	}
	return strings.Join(out, ";")
}

type ifaceEntry struct {
	index       int
	name, flags string
	ip          net.IP
}

func (r *daemonRecorder) interfaces(t *testing.T) []ifaceEntry {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var out []ifaceEntry
	for _, i := range ifs {
		addrs, err := i.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		flags := "-"
		if i.Flags&net.FlagUp != 0 {
			flags += "u"
		}
		if i.Flags&net.FlagLoopback != 0 {
			flags += "l"
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				out = append(out, ifaceEntry{i.Index, i.Name, flags, n.IP})
			}
		}
	}
	return out
}

// machineAddresses gives each address of this machine but loopback a
// stand-in of the same kind (private or public, IPv4 or IPv6) that sorts
// as the real ones do among themselves and among the fixtures' (10.0.0.x),
// so a recording names no machine's addresses: the member certificate
// lists them sorted.
func (r *daemonRecorder) machineAddresses(t *testing.T) {
	t.Helper()
	var ips []netip.Addr
	for _, e := range r.interfaces(t) {
		if a, ok := netip.AddrFromSlice(e.ip); ok && !a.Unmap().IsLoopback() && !slices.Contains(ips, a.Unmap()) {
			ips = append(ips, a.Unmap())
		}
	}
	slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
	r.addrs = map[string]string{}
	var n [5]int
	for _, a := range ips {
		var kind int
		var stand string
		switch {
		case a.Is4() && a.As4()[0] == 10:
			kind, stand = 0, "10.200.0.%d"
		case a.Is4() && a.IsPrivate() && a.As4()[0] == 172:
			kind, stand = 1, "172.20.0.%d"
		case a.Is4() && a.IsPrivate():
			kind, stand = 2, "192.168.200.%d"
		case a.Is4():
			kind, stand = 3, "203.0.113.%d"
		default:
			kind, stand = 4, "fd00:db8::%d"
			if !a.IsPrivate() {
				stand = "2001:db8::%d"
			}
		}
		n[kind]++
		r.addrs[a.String()] = fmt.Sprintf(stand, n[kind])
	}
}

// sanitize replaces the machine's addresses with their stand-ins, whole
// addresses only.
func (r *daemonRecorder) sanitize(s string) string {
	for real, stand := range r.addrs {
		v4 := !strings.Contains(real, ":")
		edge := func(c byte) bool {
			if v4 {
				return c >= '0' && c <= '9' || c == '.'
			}
			return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == ':'
		}
		var b strings.Builder
		for {
			i := strings.Index(s, real)
			if i < 0 {
				b.WriteString(s)
				break
			}
			j := i + len(real)
			if (i > 0 && edge(s[i-1])) || (j < len(s) && edge(s[j])) {
				b.WriteString(s[:j])
				s = s[j:]
				continue
			}
			b.WriteString(s[:i] + stand)
			s = s[j:]
		}
		s = b.String()
	}
	return s
}

// fsType is the file system type of the case directories (doctor tells
// whether secret files land on tmpfs): the replay hands it to the Rust
// armadad (ARMADA_DAEMON_TEST_FS_TYPE).
func fsType(t *testing.T) string {
	t.Helper()
	var st syscall.Statfs_t
	if err := syscall.Statfs(os.TempDir(), &st); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%#x", st.Type)
}

func (r *daemonRecorder) write(t *testing.T) {
	if r == nil || t.Failed() {
		return
	}
	t.Helper()
	bucket := map[string]string{}
	for k, v := range r.h.sf.objects {
		bucket[k] = r.blob(v)
	}
	blobs := map[string]string{}
	for k, v := range r.blobs {
		blobs[k] = base64.StdEncoding.EncodeToString(v)
	}
	// The stand-ins first in PATH, and the master key's ID the member's
	// state is seeded with (seedState).
	standins := map[string]string{}
	entries, err := os.ReadDir(r.h.standins)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(r.h.standins, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		standins[e.Name()] = string(b)
	}
	head, err := json.Marshal(map[string]any{"blobs": blobs, "bucket": bucket, "standins": standins, "masterKeyId": r.h.sf.masterKeyID,
		"interfaces": r.machineInterfaces(t), "fsType": fsType(t)})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	for _, l := range append([][]byte{head}, r.lines...) {
		_, _ = zw.Write(l)
		_, _ = zw.Write([]byte("\n"))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(daemonFixtures), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(daemonFixtures, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("recorded %d cases into %s (%d bytes, %d blobs)", len(r.lines), daemonFixtures, buf.Len(), len(r.blobs))
}
