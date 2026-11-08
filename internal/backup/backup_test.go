package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/store"
)

// newDataDir builds a control plane data directory like `armadad init`.
func newDataDir(t *testing.T) (string, *clientv3.Client) {
	t.Helper()
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "armada")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	caKey, _ := ca.KeyPEM()
	srvCert, srvKey, err := ca.Issue(pki.IssueRequest{
		Identity: pki.Identity{Kind: pki.KindServer, Name: "n1"},
		DNSNames: []string{pki.ServerName}, IPs: []net.IP{net.ParseIP("10.0.0.2")}, Server: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(FileCACert, ca.CertPEM)
	write(FileCAKey, caKey)
	write(FileServerCert, srvCert)
	write(FileServerKey, srvKey)
	write(FileAgent, []byte(`{"nodeId":"n1"}`))
	if err := secrets.GenerateKeyFile(filepath.Join(dir, FileMasterKey)); err != nil {
		t.Fatal(err)
	}
	keys, _ := secrets.LoadKeyFile(filepath.Join(dir, FileMasterKey))
	// The member keeps running: backups run next to a live server.
	m, err := etcd.Start(ctx, member(t, filepath.Join(dir, DirEtcd), "n1", ca))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	st, err := store.NewEtcd(ctx, m.Client(), etcdPrefix)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.UpsertServer(ctx, store.Server{Name: "n1", PrivateIP: "10.0.0.2", APIAddr: "10.0.0.2:7443"})
	_ = st.SetMeta(ctx, metaMasterKey, keys.ID())
	_ = st.SetMeta(ctx, "cluster", "test")
	return dir, m.Client()
}

// member describes an etcd member on free loopback ports.
func member(t *testing.T, dir, name string, ca *pki.CA) etcd.Config {
	t.Helper()
	ports, err := freePorts(2)
	if err != nil {
		t.Fatal(err)
	}
	return etcd.Config{Dir: dir, Name: name, Addr: loopback, ClientPort: ports[0], PeerPort: ports[1], CA: ca}
}

// backupOf returns a backup of a fresh data directory.
func backupOf(t *testing.T) []byte {
	t.Helper()
	dir, c := newDataDir(t)
	var buf bytes.Buffer
	if _, err := Create(context.Background(), dir, c, &buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func restore(t *testing.T, r io.Reader, dst string) (Manifest, error) {
	t.Helper()
	return Restore(context.Background(), r, dst, member(t, "", "", nil))
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src, c := newDataDir(t)
	var buf bytes.Buffer
	m, err := Create(ctx, src, c, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if m.Listen != "10.0.0.2:7443" || m.MasterKeyID == "" || m.Schema != store.SchemaVersion() {
		t.Errorf("manifest = %+v", m)
	}
	if _, ok := m.Files[FileNodeKey]; ok {
		t.Error("absent optional file listed")
	}

	dst := filepath.Join(t.TempDir(), "restored")
	cfg := member(t, "", "", nil)
	got, err := Restore(ctx, &buf, dst, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got.MasterKeyID != m.MasterKeyID {
		t.Error("manifest changed")
	}
	fi, err := os.Stat(dst)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("data dir: %v %v", fi, err)
	}
	for name := range m.Files {
		a, _ := os.ReadFile(filepath.Join(src, name))
		b, err := os.ReadFile(filepath.Join(dst, name))
		if name == FileState {
			if err == nil {
				t.Error("snapshot left in the data dir")
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs", name)
		}
		if fi, _ := os.Stat(filepath.Join(dst, name)); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %o", name, fi.Mode().Perm())
		}
	}
	// The restored member starts and still has the cluster's state.
	caPEM, _ := os.ReadFile(filepath.Join(dst, FileCACert))
	caKey, _ := os.ReadFile(filepath.Join(dst, FileCAKey))
	ca, err := pki.LoadCA(caPEM, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Dir, cfg.Name, cfg.CA = filepath.Join(dst, DirEtcd), "n1", ca
	em, err := etcd.Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer em.Close()
	st, err := store.NewEtcd(ctx, em.Client(), etcdPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := st.GetMeta(ctx, "cluster"); v != "test" {
		t.Errorf("cluster meta = %q", v)
	}
	// No temporary directories are left behind.
	entries, _ := os.ReadDir(filepath.Dir(dst))
	if len(entries) != 1 {
		t.Errorf("leftovers next to the data dir: %v", entries)
	}
}

func TestCreateRefuses(t *testing.T) {
	t.Parallel()
	dir, c := newDataDir(t)
	_ = os.Chmod(filepath.Join(dir, FileCAKey), 0o644)
	if _, err := Create(context.Background(), dir, c, io.Discard); err == nil {
		t.Error("backed up a world-readable key")
	}
	if _, err := Create(context.Background(), t.TempDir(), c, io.Discard); err == nil {
		t.Error("backed up a directory that is not a data dir")
	}
}

func TestRestoreNeverOverwrites(t *testing.T) {
	t.Parallel()
	archive := backupOf(t)
	dst := t.TempDir()
	_ = os.WriteFile(filepath.Join(dst, "keep"), []byte("live"), 0o600)
	if _, err := restore(t, bytes.NewReader(archive), dst); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("restore over existing data: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "keep")); string(b) != "live" {
		t.Error("existing data was touched")
	}
	// An empty directory is fine.
	empty := filepath.Join(t.TempDir(), "empty")
	_ = os.Mkdir(empty, 0o700)
	if _, err := restore(t, bytes.NewReader(archive), empty); err != nil {
		t.Errorf("restore into an empty dir: %v", err)
	}
}

// entry is one file of a hand-made archive.
type entry struct {
	name string
	data []byte
	typ  byte
	link string
}

// readArchive returns the entries of a real backup.
func readArchive(t *testing.T, archive []byte) []entry {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var out []entry
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out = append(out, entry{name: h.Name, data: b, typ: h.Typeflag})
	}
}

func writeArchive(t *testing.T, es []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range es {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0o600, Typeflag: typ, Linkname: e.link, ModTime: time.Now()}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.data))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			_, _ = tw.Write(e.data)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// withManifest rewrites the manifest so the given files are listed with
// their real checksums: the archive is consistent, only its content is bad.
func withManifest(t *testing.T, es []entry, mutate func(*Manifest)) []entry {
	t.Helper()
	var m Manifest
	if err := json.Unmarshal(es[0].data, &m); err != nil {
		t.Fatal(err)
	}
	m.Files = map[string]string{}
	for _, e := range es[1:] {
		if e.typ == 0 || e.typ == tar.TypeReg {
			sum := sha256.Sum256(e.data)
			m.Files[e.name] = hex.EncodeToString(sum[:])
		}
	}
	if mutate != nil {
		mutate(&m)
	}
	b, _ := json.Marshal(m)
	es[0].data = b
	return es
}

func TestRestoreRejectsBadArchives(t *testing.T) {
	t.Parallel()
	good := readArchive(t, backupOf(t))
	other := readArchive(t, backupOf(t))
	find := func(es []entry, name string) []byte {
		for _, e := range es {
			if e.name == name {
				return e.data
			}
		}
		t.Fatalf("no %s", name)
		return nil
	}
	replace := func(name string, data []byte) func([]entry) []entry {
		return func(es []entry) []entry {
			for i := range es {
				if es[i].name == name {
					es[i].data = data
				}
			}
			return withManifest(t, es, nil)
		}
	}
	add := func(e entry) func([]entry) []entry {
		return func(es []entry) []entry { return withManifest(t, append(es, e), nil) }
	}

	tests := map[string]struct {
		build func([]entry) []entry // nil: use raw bytes
		raw   []byte
		want  string
	}{
		"not gzip":   {raw: []byte("hello"), want: "not a backup"},
		"no entries": {build: func([]entry) []entry { return nil }, want: "no manifest"},
		"manifest not first": {build: func(es []entry) []entry {
			es[0], es[1] = es[1], es[0]
			return es
		}, want: "manifest must come first"},
		"tampered file": {build: func(es []entry) []entry {
			for i := range es {
				if es[i].name == FileCACert {
					es[i].data = append(es[i].data, '\n')
				}
			}
			return es
		}, want: "checksum"},
		"unlisted file": {build: func(es []entry) []entry {
			return append(es, entry{name: FileNodeKey, data: []byte("x")})
		}, want: "not listed"},
		"listed but missing": {build: func(es []entry) []entry {
			return withManifest(t, es, func(m *Manifest) { m.Files[FileNodeKey] = "00" })
		}, want: "missing"},
		"missing required": {build: func(es []entry) []entry {
			var out []entry
			for _, e := range es {
				if e.name != FileCAKey {
					out = append(out, e)
				}
			}
			return withManifest(t, out, nil)
		}, want: "no ca.key"},
		"path traversal":    {build: add(entry{name: "certs/../../etc/cron.d/x", data: []byte("x")}), want: "unexpected entry"},
		"absolute path":     {build: add(entry{name: "/etc/passwd", data: []byte("x")}), want: "unexpected entry"},
		"unknown top-level": {build: add(entry{name: "authorized_keys", data: []byte("x")}), want: "unexpected entry"},
		"dot segment":       {build: add(entry{name: "./" + FileNodeKey, data: []byte("x")}), want: "unexpected entry"},
		"ACME directory":    {build: add(entry{name: "certs/acme/x.key", data: []byte("x")}), want: "unexpected entry"},
		"symlink":           {build: add(entry{name: FileNodeKey, typ: tar.TypeSymlink, link: "/etc/shadow"}), want: "only regular files"},
		"hard link":         {build: add(entry{name: FileNodeCert, typ: tar.TypeLink, link: FileCAKey}), want: "only regular files"},
		"duplicate": {build: func(es []entry) []entry {
			return append(es, entry{name: FileCACert, data: find(es, FileCACert)})
		}, want: "duplicate"},
		"oversized key file": {build: replace(FileAgent, bytes.Repeat([]byte("x"), maxFileSize+1)), want: "too large"},
		"wrong format": {build: func(es []entry) []entry {
			return withManifest(t, es, func(m *Manifest) { m.Format = 99 })
		}, want: "format 99"},
		"master key of another cluster": {build: func(es []entry) []entry {
			return replace(FileMasterKey, find(other, FileMasterKey))(es)
		}, want: "does not belong"},
		"CA of another cluster": {build: func(es []entry) []entry {
			es = replace(FileCACert, find(other, FileCACert))(es)
			return replace(FileCAKey, find(other, FileCAKey))(es)
		}, want: "cluster CA does not match"},
		"server cert from another CA": {build: func(es []entry) []entry {
			es = replace(FileServerCert, find(other, FileServerCert))(es)
			return replace(FileServerKey, find(other, FileServerKey))(es)
		}, want: "not signed by the cluster CA"},
		"CA key does not match cert": {build: replace(FileCAKey, find(other, FileCAKey)), want: "cluster CA"},
		"corrupt snapshot":           {build: replace(FileState, bytes.Repeat([]byte("garbage!"), 1024)), want: "state snapshot"},
		"truncated snapshot": {build: func(es []entry) []entry {
			snap := find(es, FileState)
			return replace(FileState, snap[:len(snap)-100])(es)
		}, want: "state snapshot"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw := tt.raw
			if tt.build != nil {
				es := make([]entry, len(good))
				copy(es, good)
				for i := range es {
					es[i].data = bytes.Clone(es[i].data)
				}
				raw = writeArchive(t, tt.build(es))
			}
			parent := t.TempDir()
			dst := filepath.Join(parent, "armada")
			_, err := restore(t, bytes.NewReader(raw), dst)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
			// Nothing is left behind: no data dir, no temp dir.
			if entries, _ := os.ReadDir(parent); len(entries) != 0 {
				t.Errorf("left behind: %v", entries)
			}
			if _, err := os.Stat("/etc/cron.d/x"); err == nil && name == "path traversal" {
				t.Error("wrote outside the data dir")
			}
		})
	}
}

func TestCheckName(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{FileState, FileNodeKey, FileAgent, FileServerKey} {
		if err := checkName(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "certs", "certs/", "certs//x", "certs/a/../b", "../etcd.snapshot", "./etcd.snapshot", "etcd/member.key", "etcd/data/member/snap/db", "certs/acme/a.b/users/x@y.z/k.json", "haproxy/etc/haproxy.cfg", "ETCD.SNAPSHOT", "state.db", "certs/locks/x.lock"} {
		if checkName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
