package daemon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/backup"
	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/volbackup"
)

// The daemon parity harness's cases for the commands that need the
// cluster's state (ADR 0055, pull request 18b): backup, backup list,
// restore, user renew, and runtime-log. Go's armadad embeds etcd; the
// Rust one runs the pinned etcd and etcdutl of the runtime pack, which
// the harness hands it from ARMADA_ETCD_DIR (`make daemon-parity` fetches
// them into .cache/etcd with scripts/etcd-cache.sh): cases that need them
// are skipped without it when the Rust armadad runs. A server's running
// member is an etcd member the test starts on loopback ports for the
// case's data directory (both runs reach it the same way), and the
// control plane's bucket is a stand-in S3 endpoint Go reaches in process
// and the Rust armadad over HTTP (armada-node's test hook
// ARMADA_NODE_TEST_BUCKET_ADDR). An archive in the case directory or on
// standard output is compared by what it holds (realDescribeArchive), an
// etcd member's data by being one.

// The bucket's URL names a private address the Rust armadad's test hook
// sends to the stand-in, and its key.
const (
	stateBucketURL = "http://AK:SECRETKEY123@10.0.0.50:9000/backups/armada"
	stateBucketKey = "0123456789abcdef0123456789abcdef-key"
)

// stateFixtures are made once, so both runs of a case read the same bytes.
type stateFixtures struct {
	masterKey, otherKey []byte
	masterKeyID         string
	userCert, userKey   []byte
	// archive is a backup of server s1 with its record and the master
	// key's ID; bare is one of a state with neither.
	archive, bare []byte
	// objects are the bucket's: two backups of s1's control plane.
	objects map[string][]byte
	ids     []string
}

func newStateFixtures(t *testing.T, fx fixtures) stateFixtures {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	var sf stateFixtures
	keyFile := func(name string) ([]byte, string) {
		p := filepath.Join(dir, name)
		if err := secrets.GenerateKeyFile(p); err != nil {
			t.Fatal(err)
		}
		k, err := secrets.LoadKeyFile(p)
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return b, k.ID()
	}
	sf.masterKey, sf.masterKeyID = keyFile("master.key")
	sf.otherKey, _ = keyFile("other.key")
	ca, err := pki.LoadCA(fx.caCert, fx.caKey)
	if err != nil {
		t.Fatal(err)
	}
	key, csr, err := pki.NewCSR(pki.Identity{Kind: pki.KindUser, Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.SignUserCSR(csr, "alice")
	if err != nil {
		t.Fatal(err)
	}
	sf.userCert, sf.userKey = c.PEM, key

	state := func(name string, seed bool, fn func(data string, c *etcd.Member)) {
		data := filepath.Join(dir, name)
		writeServerFiles(t, data, fx, sf)
		m, err := etcd.Start(ctx, etcd.Config{Dir: filepath.Join(data, dirEtcd), Name: "s1", Addr: netip.MustParseAddr("127.0.0.1"),
			ClientPort: nextEtcdPort(), PeerPort: nextEtcdPort(), CA: ca, UnsafeNoFsync: true})
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		if seed {
			seedState(t, m, sf.masterKeyID)
		}
		fn(data, m)
	}
	archive := func(data string, m *etcd.Member) []byte {
		var buf bytes.Buffer
		if _, err := backup.Create(ctx, data, m.Client(), &buf); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	state("s1", true, func(data string, m *etcd.Member) {
		sf.archive = archive(data, m)
		mem := volbackup.NewMemory()
		target, err := volbackup.ParseTarget(stateBucketURL)
		if err != nil {
			t.Fatal(err)
		}
		for _, at := range []time.Time{time.Date(2026, 11, 22, 3, 0, 0, 0, time.UTC), time.Date(2026, 11, 23, 3, 0, 0, 0, time.UTC)} {
			if _, err := backup.Stage(ctx, data, m.Client(), func(staged string, _ backup.Manifest) error {
				repo, err := volbackup.Open(ctx, mem, volbackup.ControlPlaneRoot(target), []byte(stateBucketKey))
				if err != nil {
					return err
				}
				snap, _, err := repo.Backup(ctx, staged, "s1", at)
				sf.ids = append(sf.ids, snap.ID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		sf.objects = map[string][]byte{}
		for _, k := range mem.Keys() {
			b, err := mem.Get(ctx, k, 1<<30)
			if err != nil {
				t.Fatal(err)
			}
			sf.objects["armada/_control-plane/"+strings.TrimPrefix(k, volbackup.ControlPlaneRoot(target))] = b
		}
	})
	state("bare", false, func(data string, m *etcd.Member) { sf.bare = archive(data, m) })
	return sf
}

// seedState records server s1 and the master key's ID, as init does.
func seedState(t *testing.T, m *etcd.Member, keyID string) {
	t.Helper()
	ctx := context.Background()
	st, err := store.NewEtcd(ctx, m.Client(), etcdPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertServer(ctx, store.Server{Name: "s1", PrivateIP: "10.0.0.5", APIAddr: "10.0.0.5:7443"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMeta(ctx, "master_key_id", keyID); err != nil {
		t.Fatal(err)
	}
}

// writeServerFiles writes a control plane's data directory: the CA, the
// server's and the node's certificates, the master key, and agent.json.
func writeServerFiles(t *testing.T, data string, fx fixtures, sf stateFixtures) {
	t.Helper()
	for name, b := range map[string][]byte{
		fileCACert: fx.caCert, fileCAKey: fx.caKey, fileServerCert: fx.serverCert, fileServerKey: fx.serverKey,
		fileNodeCert: fx.nodeCert, fileNodeKey: fx.nodeKey, fileMasterKey: sf.masterKey,
		fileAgent: []byte(`{"nodeId": "s1", "privateIp": "10.0.0.5", "servers": ["10.0.0.5:7443"]}` + "\n"),
	} {
		fxWrite(t, filepath.Join(data, name), b, 0o600)
	}
	if err := os.Chmod(data, 0o700); err != nil {
		t.Fatal(err)
	}
}

// stateBucket is bucket "backups" as an S3 endpoint answers path-style
// requests (the Rust armadad's), and as Go's volbackup reaches it.
type stateBucket struct {
	mu   sync.Mutex
	objs map[string][]byte
	srv  *httptest.Server
}

func newStateBucket(t *testing.T) *stateBucket {
	t.Helper()
	b := &stateBucket{objs: map[string][]byte{}}
	b.srv = httptest.NewServer(b)
	t.Cleanup(b.srv.Close)
	return b
}

func (b *stateBucket) addr() string { return strings.TrimPrefix(b.srv.URL, "http://") }

// load replaces what the bucket holds.
func (b *stateBucket) load(objs map[string][]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objs = map[string][]byte{}
	for k, v := range objs {
		b.objs[k] = slices.Clone(v)
	}
}

var bucketModified = time.Date(2026, 11, 23, 3, 0, 0, 0, time.UTC)

func (b *stateBucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	b.mu.Lock()
	defer b.mu.Unlock()
	fail := func(code int, s3code string) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>`+s3code+`</Code><Message>no</Message></Error>`)
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if bucket != "backups" {
		fail(http.StatusNotFound, "NoSuchBucket")
		return
	}
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && key == "" && q.Has("location"):
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`)
	case r.Method == http.MethodPut && key != "":
		b.objs[key] = body
	case r.Method == http.MethodGet && key == "":
		var keys []string
		for k := range b.objs {
			if strings.HasPrefix(k, q.Get("prefix")) && k > q.Get("continuation-token") {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		truncated := len(keys) > 3
		if truncated {
			keys = keys[:3]
		}
		var res strings.Builder
		res.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>backups</Name>`)
		fmt.Fprintf(&res, "<KeyCount>%d</KeyCount><IsTruncated>%v</IsTruncated>", len(keys), truncated)
		if truncated {
			fmt.Fprintf(&res, "<NextContinuationToken>%s</NextContinuationToken>", keys[len(keys)-1])
		}
		for _, k := range keys {
			fmt.Fprintf(&res, "<Contents><Key>%s</Key><Size>%d</Size><LastModified>%s</LastModified></Contents>", k, len(b.objs[k]), bucketModified.Format("2006-01-02T15:04:05.000Z"))
		}
		res.WriteString("</ListBucketResult>")
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, res.String())
	case r.Method == http.MethodGet:
		o, ok := b.objs[key]
		if !ok {
			fail(http.StatusNotFound, "NoSuchKey")
			return
		}
		_, _ = w.Write(o)
	case r.Method == http.MethodDelete:
		delete(b.objs, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		fail(http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

// stateObjects is the same bucket as Go's volbackup reaches it: the keys
// below the URL's bucket.
type stateObjects struct{ b *stateBucket }

func (o stateObjects) Put(_ context.Context, key string, data []byte) error {
	o.b.mu.Lock()
	defer o.b.mu.Unlock()
	o.b.objs[key] = slices.Clone(data)
	return nil
}

func (o stateObjects) Get(_ context.Context, key string, maxSize int64) ([]byte, error) {
	o.b.mu.Lock()
	defer o.b.mu.Unlock()
	obj, ok := o.b.objs[key]
	if !ok {
		return nil, volbackup.ErrNotExist
	}
	if int64(len(obj)) > maxSize {
		return nil, fmt.Errorf("bucket: object larger than %d bytes", maxSize)
	}
	return slices.Clone(obj), nil
}

func (o stateObjects) List(_ context.Context, prefix string, fn func(volbackup.Object) error) error {
	o.b.mu.Lock()
	var out []volbackup.Object
	for k, obj := range o.b.objs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, volbackup.Object{Key: k, Size: int64(len(obj)), Modified: bucketModified})
		}
	}
	o.b.mu.Unlock()
	slices.SortFunc(out, func(a, b volbackup.Object) int { return strings.Compare(a.Key, b.Key) })
	for _, x := range out {
		if err := fn(x); err != nil {
			return err
		}
	}
	return nil
}

func (o stateObjects) Delete(_ context.Context, key string) error {
	o.b.mu.Lock()
	defer o.b.mu.Unlock()
	delete(o.b.objs, key)
	return nil
}

// stateCase is what a case of the state commands needs.
type stateCase struct {
	// member: a server's member runs for the case's data directory (the
	// test's, on loopback ports); loopback: the member the command starts
	// itself listens there.
	member, loopback bool
	// etcd: the Rust armadad needs the pinned etcd and etcdutl.
	etcd bool
	// bucket: the bucket holds the fixtures' backups; emptyBucket: none.
	bucket, emptyBucket bool
	// archiveOut: standard output is an archive.
	archiveOut bool
	// ports are the member's, set for the run.
	ports [2]int
}

// realRecordUser is recordUser as the package has it (TestMain replaces
// it with a stand-in).
func realRecordUser(ctx context.Context, dataDir, name string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	c, release, err := stateClient(ctx, dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = release() }()
	st, err := store.NewEtcd(ctx, c, etcdPrefix)
	if err != nil {
		return err
	}
	return st.KnowUser(ctx, name)
}

// realHostHasIP is hostHasIP as the package has it (tests replace it).
func realHostHasIP(ip netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if have, ok := netip.AddrFromSlice(n.IP); ok && have.Unmap() == ip {
				return true
			}
		}
	}
	return false
}

// stateEnv is the environment of a state case: the member's address and
// ports, etcd's programs, and the bucket, for the Rust armadad.
func (h *daemonHarness) stateEnv(env map[string]string, s *stateCase) {
	if s == nil {
		return
	}
	if s.member || s.loopback {
		env["ARMADA_DAEMON_TEST_ETCD_ADDR"] = "127.0.0.1"
		env["ARMADA_DAEMON_TEST_ETCD_PORTS"] = fmt.Sprintf("%d,%d", s.ports[0], s.ports[1])
	}
	if h.etcdDir != "" {
		env["ARMADA_DAEMON_TEST_ETCD_DIR"] = h.etcdDir
	}
	env["ARMADA_NODE_TEST_BUCKET_ADDR"] = h.bucket.addr()
}

// stateGo sets what Go's run of a state case replaces in the package,
// and returns what puts it back.
func (h *daemonHarness) stateGo(s *stateCase) func() {
	oldRecord, oldHost, oldBucket := recordUser, hostHasIP, openBucket
	oldAddr, oldPorts, oldFsync := etcdAddrOverride, etcdPorts, etcdNoFsync
	recordUser, hostHasIP = realRecordUser, realHostHasIP
	openBucket = func(volbackup.Target) (volbackup.Objects, error) { return stateObjects{h.bucket}, nil }
	if s != nil && (s.member || s.loopback) {
		etcdAddrOverride, etcdNoFsync = netip.MustParseAddr("127.0.0.1"), true
		ports := s.ports
		etcdPorts = func(string) (int, int) { return ports[0], ports[1] }
	}
	return func() {
		recordUser, hostHasIP, openBucket = oldRecord, oldHost, oldBucket
		etcdAddrOverride, etcdPorts, etcdNoFsync = oldAddr, oldPorts, oldFsync
	}
}

// stateRun prepares a run of a state case after its files are written:
// the bucket's objects and the server's member. The returned function
// stops the member; record writes what the member holds of users into
// the case directory before its files are compared.
func (h *daemonHarness) stateRun(t *testing.T, dir string, s *stateCase) (record func(), stop func()) {
	t.Helper()
	record, stop = func() {}, func() {}
	if s == nil {
		return
	}
	switch {
	case s.bucket:
		h.bucket.load(h.sf.objects)
	default:
		h.bucket.load(nil)
	}
	if !s.member {
		return
	}
	ca, err := pki.LoadCA(h.fx.caCert, h.fx.caKey)
	if err != nil {
		t.Fatal(err)
	}
	m, err := etcd.Start(context.Background(), etcd.Config{Dir: filepath.Join(dir, "data", dirEtcd), Name: "s1",
		Addr: netip.MustParseAddr("127.0.0.1"), ClientPort: s.ports[0], PeerPort: s.ports[1], CA: ca, UnsafeNoFsync: true})
	if err != nil {
		t.Fatal(err)
	}
	seedState(t, m, h.sf.masterKeyID)
	record = func() {
		ctx := context.Background()
		st, err := store.NewEtcd(ctx, m.Client(), etcdPrefix)
		if err != nil {
			t.Fatal(err)
		}
		users, err := st.ListPrincipals(ctx, store.KindUser)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, u := range users {
			lines = append(lines, fmt.Sprintf("user %s roles %v", u.Name, u.Roles))
		}
		fxWrite(t, filepath.Join(dir, "state-users.txt"), []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	}
	return record, func() { _ = m.Close() }
}

// summarizeEtcd describes a real etcd member's data directory by what it
// holds, not its bytes (each member writes its own), and reports whether
// it did.
func summarizeEtcd(p string) (string, bool) {
	fi, err := os.Stat(filepath.Join(p, "member", "snap", "db"))
	if err != nil || fi.Size() < 4096 {
		return "", false
	}
	wals, _ := filepath.Glob(filepath.Join(p, "member", "wal", "*.wal"))
	return fmt.Sprintf("an etcd member's data: a database, %d write-ahead log(s)", min(len(wals), 1)), true
}

// realDescribeArchive is a backup archive as compared: every entry's
// header, the manifest with its time and the snapshot's checksum checked
// and blanked, the snapshot by matching its manifest, other files by
// their checksums.
func realDescribeArchive(b []byte) string {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return "not a gzip stream: " + err.Error()
	}
	tr := tar.NewReader(gz)
	var out strings.Builder
	var m backup.Manifest
	sums := map[string]string{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fmt.Fprintf(&out, "read: %v\n", err)
			break
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			fmt.Fprintf(&out, "read %s: %v\n", hdr.Name, err)
			break
		}
		sum := sha256.Sum256(data)
		sums[hdr.Name] = hex.EncodeToString(sum[:])
		recent := time.Since(hdr.ModTime) < 10*time.Minute && hdr.ModTime.Equal(hdr.ModTime.Truncate(time.Second))
		size := fmt.Sprint(hdr.Size)
		if hdr.Name == backup.FileState {
			size = "SIZE"
		}
		fmt.Fprintf(&out, "%s mode %04o type %c uid %d gid %d user %q group %q format %v size %s recent %v pax %v\n",
			hdr.Name, hdr.Mode, hdr.Typeflag, hdr.Uid, hdr.Gid, hdr.Uname, hdr.Gname, hdr.Format, size, recent, hdr.PAXRecords)
		if hdr.Name == "manifest.json" {
			if err := json.Unmarshal(data, &m); err != nil {
				fmt.Fprintf(&out, "manifest: %v\n", err)
			}
		}
	}
	created := time.Since(m.Created) < 10*time.Minute && m.Created.Equal(m.Created.Truncate(time.Second)) && m.Created.Location() == time.UTC
	snapshotListed := m.Files[backup.FileState] == sums[backup.FileState]
	matches := true
	for name, sum := range m.Files {
		if sums[name] != sum {
			matches = false
		}
	}
	m.Created = time.Time{}
	if m.Files != nil {
		m.Files[backup.FileState] = "SNAPSHOT"
	}
	mb, _ := json.MarshalIndent(m, "", "  ")
	fmt.Fprintf(&out, "manifest (created now: %v, snapshot listed: %v, files match: %v):\n%s\n", created, snapshotListed, matches, mb)
	return out.String()
}

// stateTemp is the temporary names the commands make.
var stateTemp = regexp.MustCompile(`\.(backup|inspect|restore|etcd|etcd-start)-[0-9]+`)

// archiveEntry is one file of a hand-made archive.
type archiveEntry struct {
	name string
	data []byte
	flag byte
}

// readArchive is the entries of a backup archive.
func readArchive(t *testing.T, b []byte) []archiveEntry {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var out []archiveEntry
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, archiveEntry{name: hdr.Name, data: data, flag: hdr.Typeflag})
	}
}

// writeArchive packs entries; with manifest, the manifest's checksums are
// made to match the files first and mod changes it.
func writeArchive(t *testing.T, entries []archiveEntry, mod func(*backup.Manifest)) []byte {
	t.Helper()
	if mod != nil {
		for i, e := range entries {
			if e.name != "manifest.json" {
				continue
			}
			var m backup.Manifest
			if err := json.Unmarshal(e.data, &m); err != nil {
				t.Fatal(err)
			}
			for _, f := range entries {
				if _, ok := m.Files[f.name]; ok {
					sum := sha256.Sum256(f.data)
					m.Files[f.name] = hex.EncodeToString(sum[:])
				}
			}
			mod(&m)
			b, err := json.MarshalIndent(m, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			entries[i].data = b
		}
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		flag := e.flag
		if flag == 0 {
			flag = tar.TypeReg
		}
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.data)), Typeflag: flag, ModTime: time.Unix(1795000000, 0)}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// stateCases are the cases of the state commands.
func (h *daemonHarness) stateCases(t *testing.T) []daemonCase {
	t.Helper()
	sf := h.sf
	dd := []string{"--data-dir", "data"}
	with := func(args ...string) []string { return append(slices.Clone(args), dd...) }
	server := func(more ...func(*testing.T, string)) func(*testing.T, string) {
		return func(t *testing.T, dir string) {
			t.Helper()
			writeServerFiles(t, filepath.Join(dir, "data"), h.fx, sf)
			for _, m := range more {
				m(t, dir)
			}
		}
	}
	file := func(name string, b []byte, mode os.FileMode) func(*testing.T, string) {
		return func(t *testing.T, dir string) {
			t.Helper()
			fxWrite(t, filepath.Join(dir, name), b, mode)
		}
	}
	remove := func(name string) func(*testing.T, string) {
		return func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	chmod := func(name string, mode os.FileMode) func(*testing.T, string) {
		return func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Chmod(filepath.Join(dir, name), mode); err != nil {
				t.Fatal(err)
			}
		}
	}
	archive := func(b []byte) func(*testing.T, string) { return file("cp.tar", b, 0o600) }
	entries := func() []archiveEntry { return readArchive(t, sf.archive) }
	changed := func(mod func([]archiveEntry) []archiveEntry, man func(*backup.Manifest)) []byte {
		return writeArchive(t, mod(entries()), man)
	}
	bucketFiles := fxAll(file("url.txt", []byte(stateBucketURL+"\n"), 0o600), file("key.txt", []byte(stateBucketKey), 0o600))
	bucket := []string{"--backup-url", "url.txt", "--backup-key", "key.txt"}
	config := func(cert, key []byte) func(*testing.T, string) {
		b, err := json.MarshalIndent(map[string]any{"servers": []string{"10.0.0.5:7443"}, "ca": string(h.fx.caCert), "cert": string(cert), "key": string(key)}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return file("admin.config", append(b, '\n'), 0o600)
	}
	userConfig := config(sf.userCert, sf.userKey)
	renew := []string{"user", "renew", "--config", "admin.config", "--data-dir", "data"}
	st := func(s stateCase) *stateCase { return &s }
	member := st(stateCase{member: true, etcd: true})
	flip := func(b []byte) []byte {
		b = slices.Clone(b)
		b[len(b)/2] ^= 0xff
		return b
	}

	return []daemonCase{
		// backup.
		{name: "backup no output", args: with("backup")},
		{name: "backup output exists", args: with("backup", "-o", "cp.tar"), setup: fxAll(server(), file("cp.tar", []byte("an older backup"), 0o600))},
		{name: "backup not a server", args: with("backup", "-o", "cp.tar")},
		{name: "backup node certificate", args: with("backup", "-o", "cp.tar"), setup: h.serverDir(h.fx.nodeCert, h.fx.nodeKey, 0o600)},
		{name: "backup running member", args: with("backup", "-o", "cp.tar"), setup: server(), state: member},
		{name: "backup to stdout", args: with("backup", "-o", "-"), setup: server(), state: st(stateCase{member: true, etcd: true, archiveOut: true})},
		{name: "backup without optional files", args: with("backup", "-o", "cp.tar"), setup: server(remove("data/agent.json"), remove("data/node.crt"), remove("data/node.key")), state: member},
		{name: "backup member not running", args: with("backup", "-o", "cp.tar"), setup: server(), state: st(stateCase{loopback: true, etcd: true})},
		{name: "backup open data directory", args: with("backup", "-o", "cp.tar"), setup: server(chmod("data", 0o755)), state: st(stateCase{member: true})},
		{name: "backup no master key", args: with("backup", "-o", "cp.tar"), setup: server(remove("data/master.key")), state: st(stateCase{member: true})},
		{name: "backup open master key", args: with("backup", "-o", "cp.tar"), setup: server(chmod("data/master.key", 0o644)), state: member},

		// backup list.
		{name: "backup list", args: append([]string{"backup", "list"}, bucket...), setup: bucketFiles, state: st(stateCase{bucket: true})},
		{name: "backup list json", args: append([]string{"backup", "list", "-o", "json"}, bucket...), setup: bucketFiles, state: st(stateCase{bucket: true})},
		{name: "backup list yaml", args: append([]string{"backup", "list", "-o", "yaml"}, bucket...), setup: bucketFiles, state: st(stateCase{bucket: true})},
		{name: "backup list empty", args: append([]string{"backup", "list"}, bucket...), setup: bucketFiles, state: st(stateCase{emptyBucket: true})},
		{name: "backup list empty json", args: append([]string{"backup", "list", "-o", "json"}, bucket...), setup: bucketFiles, state: st(stateCase{emptyBucket: true})},
		{name: "backup list wrong key", args: append([]string{"backup", "list"}, bucket...), setup: fxAll(bucketFiles, file("key.txt", []byte("another key, long enough to be one: 0123456789"), 0o600)), state: st(stateCase{bucket: true})},
		{name: "backup list no key", args: []string{"backup", "list", "--backup-url", "url.txt"}, setup: bucketFiles},
		{name: "backup list both stdin", args: []string{"backup", "list", "--backup-url", "-", "--backup-key", "-"}},
		{name: "backup list url from stdin", args: []string{"backup", "list", "--backup-url", "-", "--backup-key", "key.txt"}, stdin: stateBucketURL + "\n", setup: bucketFiles, state: st(stateCase{bucket: true})},
		{name: "backup list open url file", args: append([]string{"backup", "list"}, bucket...), setup: fxAll(bucketFiles, chmod("url.txt", 0o644))},
		{name: "backup list missing url file", args: []string{"backup", "list", "--backup-url", "nope.txt", "--backup-key", "key.txt"}, setup: bucketFiles},
		{name: "backup list bad url", args: append([]string{"backup", "list"}, bucket...), setup: fxAll(bucketFiles, file("url.txt", []byte("ftp://AK:SK@10.0.0.50/backups"), 0o600))},
		{name: "backup list public http", args: append([]string{"backup", "list"}, bucket...), setup: fxAll(bucketFiles, file("url.txt", []byte("http://AK:SK@203.0.113.9/backups"), 0o600))},

		// restore from an archive.
		{name: "restore nothing", args: with("restore")},
		{name: "restore archive and bucket", args: append(with("restore", "cp.tar"), bucket...)},
		{name: "restore snapshot without bucket", args: with("restore", "cp.tar", "--snapshot", "latest")},
		{name: "restore archive", args: with("restore", "cp.tar"), setup: archive(sf.archive), state: st(stateCase{etcd: true})},
		{name: "restore stdin", args: with("restore", "-"), stdin: string(sf.archive), state: st(stateCase{etcd: true})},
		{name: "restore into an empty directory", args: with("restore", "cp.tar"), setup: fxAll(archive(sf.archive), func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "data"), 0o700); err != nil {
				t.Fatal(err)
			}
		}), state: st(stateCase{etcd: true})},
		{name: "restore not empty", args: with("restore", "cp.tar"), setup: fxAll(archive(sf.archive), file("data/x", []byte("x"), 0o600))},
		{name: "restore data is a file", args: with("restore", "cp.tar"), setup: fxAll(archive(sf.archive), file("data", []byte("x"), 0o600))},
		{name: "restore missing archive", args: with("restore", "nope.tar")},
		{name: "restore not gzip", args: with("restore", "cp.tar"), setup: archive([]byte("not an archive at all"))},
		{name: "restore empty file", args: with("restore", "cp.tar"), setup: archive(nil)},
		{name: "restore truncated", args: with("restore", "cp.tar"), setup: archive(sf.archive[:len(sf.archive)/2])},
		{name: "restore manifest not first", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry {
			return append(e[1:], e[0])
		}, nil))},
		{name: "restore tampered file", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry {
			for i := range e {
				if e[i].name == fileAgent {
					e[i].data = []byte(`{"nodeId": "evil"}`)
				}
			}
			return e
		}, nil))},
		{name: "restore unexpected entry", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry {
			return append(e, archiveEntry{name: "../escape", data: []byte("x")})
		}, nil))},
		{name: "restore directory entry", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry {
			return append(e[:1], append([]archiveEntry{{name: "etcd/", flag: tar.TypeDir}}, e[1:]...)...)
		}, nil))},
		{name: "restore duplicate entry", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry {
			return append(e, e[len(e)-1])
		}, nil))},
		{name: "restore missing listed file", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry {
			return slices.DeleteFunc(e, func(x archiveEntry) bool { return x.name == fileNodeKey })
		}, nil))},
		{name: "restore unlisted file", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry { return e }, func(m *backup.Manifest) {
			delete(m.Files, fileNodeKey)
		}))},
		{name: "restore no master key", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry {
			return slices.DeleteFunc(e, func(x archiveEntry) bool { return x.name == fileMasterKey })
		}, func(m *backup.Manifest) { delete(m.Files, fileMasterKey) }))},
		{name: "restore unknown manifest field", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry {
			e[0].data = append([]byte(`{"extra": 1, `), e[0].data[1:]...)
			return e
		}, nil))},
		{name: "restore broken manifest", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry {
			e[0].data = e[0].data[:len(e[0].data)/2]
			return e
		}, nil))},
		{name: "restore manifest of another type", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry {
			e[0].data = []byte(`{"format": "3"}`)
			return e
		}, nil))},
		{name: "restore older format", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry { return e }, func(m *backup.Manifest) { m.Format = 2 }))},
		{name: "restore newer schema", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry { return e }, func(m *backup.Manifest) { m.Schema = 99 }))},
		{name: "restore other CA", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry { return e }, func(m *backup.Manifest) { m.CAFingerprint = strings.Repeat("0", 64) }))},
		{name: "restore server key of another", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry {
			for i := range e {
				if e[i].name == fileServerKey {
					e[i].data = h.fx.publicKey
				}
			}
			return e
		}, func(*backup.Manifest) {}))},
		{name: "restore node certificate as server", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry {
			for i := range e {
				switch e[i].name {
				case fileServerCert:
					e[i].data = h.fx.nodeCert
				case fileServerKey:
					e[i].data = h.fx.nodeKey
				}
			}
			return e
		}, func(*backup.Manifest) {}))},
		{name: "restore no server record", args: with("restore", "cp.tar"), setup: archive(sf.bare), state: st(stateCase{etcd: true})},
		{name: "restore another master key", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry {
			for i := range e {
				if e[i].name == fileMasterKey {
					e[i].data = sf.otherKey
				}
			}
			return e
		}, func(*backup.Manifest) {})), state: st(stateCase{etcd: true})},
		{name: "restore corrupt snapshot", args: with("restore", "cp.tar"), setup: archive(changed(func(e []archiveEntry) []archiveEntry {
			for i := range e {
				if e[i].name == backup.FileState {
					e[i].data = flip(e[i].data)
				}
			}
			return e
		}, func(*backup.Manifest) {})), state: st(stateCase{etcd: true})},

		// restore from the bucket.
		{name: "restore latest from the bucket", args: append(with("restore"), bucket...), setup: bucketFiles, state: st(stateCase{bucket: true, etcd: true})},
		{name: "restore a backup from the bucket", args: append(with("restore", "--snapshot", sf.ids[0]), bucket...), setup: bucketFiles, state: st(stateCase{bucket: true, etcd: true})},
		{name: "restore unknown backup", args: append(with("restore", "--snapshot", "20261124T030000.000Z-00000000"), bucket...), setup: bucketFiles, state: st(stateCase{bucket: true})},
		{name: "restore invalid backup ID", args: append(with("restore", "--snapshot", "x"), bucket...), setup: bucketFiles, state: st(stateCase{bucket: true})},
		{name: "restore empty bucket", args: append(with("restore"), bucket...), setup: bucketFiles, state: st(stateCase{emptyBucket: true})},
		{name: "restore bucket not empty data", args: append(with("restore"), bucket...), setup: fxAll(bucketFiles, file("data/x", []byte("x"), 0o600)), state: st(stateCase{bucket: true})},

		// user renew.
		{name: "user renew no config", args: renew},
		{name: "user renew node certificate", args: renew, setup: config(h.fx.nodeCert, h.fx.nodeKey)},
		{name: "user renew no CA", args: renew, setup: userConfig},
		{name: "user renew not a server", args: renew, setup: fxAll(userConfig, file("data/ca.crt", h.fx.caCert, 0o600), file("data/ca.key", h.fx.caKey, 0o600))},
		{name: "user renew running member", args: renew, setup: fxAll(userConfig, server()), state: st(stateCase{member: true})},
		{name: "user renew member not running", args: renew, setup: fxAll(userConfig, server()), state: st(stateCase{loopback: true, etcd: true})},

		// runtime-log (its output is TestRuntimeLogMatchesGo's, in
		// internal/runtime/embedded).
		{name: "runtime-log relative", args: []string{"runtime-log", "logs"}},
		{name: "runtime-log not clean", args: []string{"runtime-log", "/var/../logs"}},
	}
}

// stdout is a run's standard output as compared: an archive by what it
// holds.
func (h *daemonHarness) stdout(c daemonCase, b []byte) string {
	if c.state != nil && c.state.archiveOut {
		return realDescribeArchive(b)
	}
	return string(b)
}

// describeClientConfig is a client config as compared, as written: its
// certificate by what it names, its key by being one.
func describeClientConfig(b []byte) string {
	var cc map[string]any
	if err := json.Unmarshal(b, &cc); err != nil {
		return string(b)
	}
	out := string(b)
	swap := func(v any, desc string) {
		s, ok := v.(string)
		if !ok {
			return
		}
		q, _ := json.Marshal(s)
		d, _ := json.Marshal(desc)
		out = strings.Replace(out, string(q), string(d), 1)
	}
	if cert, ok := cc["cert"].(string); ok {
		c, err := pki.ParseCertPEM([]byte(cert))
		if err != nil {
			swap(cert, "bad certificate: "+err.Error())
		} else {
			swap(cert, fmt.Sprintf("certificate %s, %d days, usages %v", c.Subject.CommonName, int(c.NotAfter.Sub(c.NotBefore).Hours()/24), c.ExtKeyUsage))
		}
	}
	if key, ok := cc["key"].(string); ok {
		swap(key, fmt.Sprintf("a key: %v", strings.Contains(key, "PRIVATE KEY")))
	}
	return out
}
