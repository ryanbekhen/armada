// Package backup creates and restores archives of a control plane: a
// snapshot of its etcd keyspace, the secrets master key, the cluster CA, the
// server certificate, ACME certificates, and the embedded agent's identity.
//
// An archive holds the cluster CA key and the master key in plaintext. It
// is written with mode 0600 and must be stored encrypted (for example by
// piping it through age or gpg). Restoring treats the archive as untrusted
// input: only known file names are extracted, sizes are capped, every file
// is checked against the manifest, and the result is verified before it
// replaces anything.
//
// The same files, staged as plain files (Stage), are what the leader backs
// up to a bucket (ADR 0051); RestoreSnapshot restores one with the checks
// of an archive (Restorer).
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/store"
	"github.com/ryanbekhen/armada/internal/version"
)

// Data directory layout covered by a backup. These names match the layout
// the CLI creates with `armadad init`.
const (
	FileState      = "etcd.snapshot"
	FileMasterKey  = "master.key"
	FileCACert     = "ca.crt"
	FileCAKey      = "ca.key"
	FileServerCert = "server.crt"
	FileServerKey  = "server.key"
	FileNodeCert   = "node.crt"
	FileNodeKey    = "node.key"
	FileAgent      = "agent.json"
	// DirEtcd holds the etcd member. It is not copied: its data is in
	// FileState and its certificate is issued again from the CA.
	DirEtcd = "etcd"
	// The embedded runtime's directories (runtime, containerd, containers,
	// logs) are not copied either: the bundle is extracted again, images
	// are pulled again, and containers are recreated by their agent.
	// Volumes (DirVolumes, ADR 0023) hold app data on whichever node runs
	// the app; `armada volume backup` copies them.
	DirVolumes = "volumes"
	// DirNFS holds the mount points of NFS volumes (ADR 0042); their data
	// is on the NFS server.
	DirNFS = "nfs"
	// FileNetworkKey is the node's own cluster network key (ADR 0025). It
	// is not copied: it belongs to the node, and a restored node makes a
	// new one, which its agent announces.
	FileNetworkKey = "network.key"
	// FileMeshCache is a mesh node's last peer list (ADR 0049). It is not
	// copied: the control plane sends it again, and until then the node
	// brings its tunnel up alone from FileAgent.
	FileMeshCache = "mesh.json"
	// etcdPrefix is where the control plane's records live in etcd.
	etcdPrefix = "/armada/"

	manifestName = "manifest.json"
	// format 3: ACME certificates live in etcd, so in FileState.
	format = 3

	metaMasterKey = "master_key_id"
)

// Required files must be present in every backup; Optional ones are copied
// when they exist.
var (
	Required = []string{FileState, FileMasterKey, FileCACert, FileCAKey, FileServerCert, FileServerKey}
	Optional = []string{FileNodeCert, FileNodeKey, FileAgent}
)

// Limits on what a restore accepts.
const (
	maxStateSize = 2 << 30 // 2 GiB
	maxFileSize  = 1 << 20 // 1 MiB for keys, certificates, ACME files
	maxEntries   = 10_000
	maxTotalSize = 4 << 30
)

// Manifest describes an archive. It is the first entry.
type Manifest struct {
	Format        int               `json:"format"`
	ArmadaVersion string            `json:"armadaVersion"`
	Created       time.Time         `json:"created"`
	Schema        int               `json:"schema"`
	Listen        string            `json:"listen"`
	MasterKeyID   string            `json:"masterKeyId"`
	CAFingerprint string            `json:"caFingerprint"`
	Files         map[string]string `json:"files"` // name → SHA-256 (hex)
}

// Create writes a backup of dataDir to w, with a snapshot of the state taken
// through c. The snapshot is consistent, so the server may keep running.
func Create(ctx context.Context, dataDir string, c *clientv3.Client, w io.Writer) (Manifest, error) {
	st, err := prepare(ctx, dataDir, c)
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(st.tmp)

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	mb, err := json.MarshalIndent(st.m, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	if err := writeEntry(tw, manifestName, int64(len(mb)), strings.NewReader(string(mb))); err != nil {
		return Manifest{}, err
	}
	for _, e := range st.files {
		if err := copyEntry(tw, e.name, e.src, st.m.Files[e.name]); err != nil {
			return Manifest{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return Manifest{}, err
	}
	return st.m, gz.Close()
}

// Stage writes the files a backup of dataDir holds into a directory of
// their own, as plain files: the manifest as manifest.json and every other
// file under its name, all owner-only. It calls fn with that directory and
// removes it afterwards. The control plane's scheduled backups (ADR 0051)
// copy the directory into a bucket; a Restorer takes the same files back.
func Stage(ctx context.Context, dataDir string, c *clientv3.Client, fn func(dir string, m Manifest) error) (Manifest, error) {
	st, err := prepare(ctx, dataDir, c)
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(st.tmp)
	dir := filepath.Join(st.tmp, "files")
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Manifest{}, err
	}
	mb, err := json.MarshalIndent(st.m, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, manifestName), mb, 0o600); err != nil {
		return Manifest{}, err
	}
	for _, e := range st.files {
		if err := copyFile(filepath.Join(dir, e.name), e.src, st.m.Files[e.name]); err != nil {
			return Manifest{}, err
		}
	}
	if err := fn(dir, st.m); err != nil {
		return Manifest{}, err
	}
	return st.m, nil
}

// staged is a backup before it is written out: its manifest, and where each
// file is read from. tmp holds the state snapshot; the caller removes it.
type staged struct {
	m     Manifest
	files []stagedFile
	tmp   string
}

type stagedFile struct{ name, src string }

// prepare takes a snapshot of the state into a temporary directory inside
// dataDir, checks it the way a restore does, and hashes every file.
func prepare(ctx context.Context, dataDir string, c *clientv3.Client) (_ *staged, err error) {
	if err := fsutil.CheckPrivate(dataDir); err != nil {
		return nil, err
	}
	for _, name := range Required[1:] {
		if _, err := os.Stat(filepath.Join(dataDir, name)); err != nil {
			return nil, fmt.Errorf("%s is not a control plane data directory: %w", dataDir, err)
		}
	}

	tmp, err := os.MkdirTemp(dataDir, ".backup-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(tmp)
		}
	}()
	snap := filepath.Join(tmp, FileState)
	if err := writeSnapshot(ctx, c, snap); err != nil {
		return nil, err
	}
	pem, err := readFiles(dataDir, FileCACert, FileCAKey, FileServerCert)
	if err != nil {
		return nil, err
	}
	ca, err := pki.LoadCA(pem[0], pem[1])
	if err != nil {
		return nil, err
	}
	name, err := serverName(pem[2])
	if err != nil {
		return nil, err
	}
	// The snapshot is checked the way a restore checks it, so a backup
	// that cannot be restored fails now rather than when it is needed.
	info, err := inspect(ctx, snap, ca, tmp, name)
	if err != nil {
		return nil, fmt.Errorf("verify snapshot: %w", err)
	}

	// Collect every file with its source path, then hash before writing so
	// the manifest can come first.
	files := []stagedFile{{FileState, snap}}
	for _, name := range append(slices.Clone(Required[1:]), Optional...) {
		src := filepath.Join(dataDir, name)
		if _, err := os.Lstat(src); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		files = append(files, stagedFile{name, src})
	}
	m := Manifest{
		Format:        format,
		ArmadaVersion: version.Get().Version,
		Created:       time.Now().UTC().Truncate(time.Second),
		Schema:        info.Schema,
		Listen:        info.Listen,
		MasterKeyID:   info.Meta[metaMasterKey],
		Files:         map[string]string{},
	}
	m.CAFingerprint = pki.Fingerprint(ca.Cert)
	for _, e := range files {
		sum, err := hashFile(e.src)
		if err != nil {
			return nil, err
		}
		m.Files[e.name] = sum
	}
	return &staged{m: m, files: files, tmp: tmp}, nil
}

func writeSnapshot(ctx context.Context, c *clientv3.Client, dst string) error {
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // inside a fresh temp dir
	if err != nil {
		return err
	}
	if err := etcd.Snapshot(ctx, c, f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func readFiles(dir string, names ...string) ([][]byte, error) {
	out := make([][]byte, 0, len(names))
	for _, n := range names {
		b, err := fsutil.ReadPrivateFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// stateInfo is what inspect learns from a snapshot.
type stateInfo struct {
	Schema int
	Meta   map[string]string
	// Listen is the API address recorded for the backed-up server.
	Listen string
}

// serverName returns the control plane node a server certificate is for.
func serverName(certPEM []byte) (string, error) {
	leaf, err := pki.ParseCertPEM(certPEM)
	if err != nil {
		return "", fmt.Errorf("server certificate: %w", err)
	}
	id, err := pki.IdentityFromCert(leaf)
	if err != nil || id.Kind != pki.KindServer {
		return "", errors.New("server certificate has no server identity")
	}
	return id.Name, nil
}

// inspect restores the snapshot into a scratch member below scratchDir,
// opens the state (which checks the schema version), and reads the cluster
// metadata. The scratch member is removed again.
func inspect(ctx context.Context, snapshotFile string, ca *pki.CA, scratchDir, server string) (stateInfo, error) {
	dir, err := os.MkdirTemp(scratchDir, ".inspect-")
	if err != nil {
		return stateInfo{}, err
	}
	defer os.RemoveAll(dir)
	ports, err := freePorts(2)
	if err != nil {
		return stateInfo{}, err
	}
	cfg := etcd.Config{Dir: filepath.Join(dir, "etcd"), Name: "inspect", Addr: loopback, ClientPort: ports[0], PeerPort: ports[1], CA: ca}
	if err := etcd.Restore(snapshotFile, cfg); err != nil {
		return stateInfo{}, err
	}
	m, err := etcd.Start(ctx, cfg)
	if err != nil {
		return stateInfo{}, err
	}
	defer m.Close()
	st, err := store.NewEtcd(ctx, m.Client(), etcdPrefix)
	if err != nil {
		return stateInfo{}, err
	}
	info := stateInfo{Schema: store.SchemaVersion(), Meta: map[string]string{}}
	for _, k := range []string{metaMasterKey} {
		v, err := st.GetMeta(ctx, k)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return stateInfo{}, err
		}
		info.Meta[k] = v
	}
	servers, err := st.ListServers(ctx)
	if err != nil {
		return stateInfo{}, err
	}
	for _, srv := range servers {
		if srv.Name == server {
			info.Listen = srv.APIAddr
		}
	}
	return info, nil
}

func hashFile(p string) (string, error) {
	if err := fsutil.CheckPrivate(p); err != nil {
		return "", err
	}
	f, err := os.Open(p) //nolint:gosec // path inside the operator's data directory
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyEntry streams a file into the archive and fails if it changed since
// it was hashed.
func copyEntry(tw *tar.Writer, name, src, sum string) error {
	f, err := os.Open(src) //nolint:gosec // path inside the operator's data directory
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	h := sha256.New()
	if err := writeEntry(tw, name, fi.Size(), io.TeeReader(f, h)); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != sum {
		return fmt.Errorf("%s changed while the backup was written; run it again", name)
	}
	return nil
}

// copyFile copies src to a new file dst (0600) and fails if it changed
// since it was hashed.
func copyFile(dst, src, sum string) error {
	in, err := os.Open(src) //nolint:gosec // path inside the operator's data directory
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // inside a fresh temp dir
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, h), in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != sum {
		return fmt.Errorf("%s changed while the backup was written; run it again", filepath.Base(dst))
	}
	return nil
}

func writeEntry(tw *tar.Writer, name string, size int64, r io.Reader) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o600, Size: size, Typeflag: tar.TypeReg,
		ModTime: time.Now().UTC().Truncate(time.Second), Format: tar.FormatPAX,
	}); err != nil {
		return err
	}
	_, err := io.CopyN(tw, r, size)
	return err
}

// Restore extracts a backup into dataDir, which must not exist or be
// empty, and turns the snapshot into the data of the etcd member described
// by member (its address and ports; the rest comes from the archive).
// Nothing is written to dataDir unless the whole archive verifies.
func Restore(ctx context.Context, r io.Reader, dataDir string, member etcd.Config) (Manifest, error) {
	rs, err := NewRestorer(dataDir)
	if err != nil {
		return Manifest{}, err
	}
	defer rs.Close()
	gz, err := gzip.NewReader(r)
	if err != nil {
		return Manifest{}, fmt.Errorf("not a backup archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for n := 0; ; n++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("read archive: %w", err)
		}
		if n == 0 && (hdr.Name != manifestName || hdr.Typeflag != tar.TypeReg || hdr.Size > maxFileSize) {
			return Manifest{}, errors.New("not an Armada backup: the manifest must come first")
		}
		if hdr.Typeflag != tar.TypeReg {
			return Manifest{}, fmt.Errorf("unexpected entry %q: only regular files are allowed", hdr.Name)
		}
		if err := rs.Add(hdr.Name, hdr.Size, tr); err != nil {
			return Manifest{}, err
		}
	}
	return rs.Finish(ctx, member)
}

// A Restorer restores a backup handed to it file by file, as Stage wrote
// it (the control plane's backups in a bucket, ADR 0051) or as an archive
// holds it: Add each file, then Finish. It checks what it is given exactly
// as Restore checks an archive, and nothing reaches the data directory
// unless all of it verifies. Close removes what Finish did not use.
type Restorer struct {
	dataDir, tmp string
	m            Manifest
	sums         map[string]string
	total        int64
	n            int
}

// NewRestorer prepares a restore into dataDir, which must not exist or be
// empty.
func NewRestorer(dataDir string) (*Restorer, error) {
	dataDir = filepath.Clean(dataDir)
	if entries, err := os.ReadDir(dataDir); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s is not empty; move it aside first (restore never overwrites a data directory)", dataDir)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	parent := filepath.Dir(dataDir)
	if err := os.MkdirAll(parent, 0o755); err != nil { //nolint:gosec // e.g. /var/lib; the data directory itself is 0700
		return nil, err
	}
	tmp, err := os.MkdirTemp(parent, "."+filepath.Base(dataDir)+".restore-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(tmp, 0o700); err != nil { //nolint:gosec // a directory: owner-only, needs the execute bit
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	return &Restorer{dataDir: dataDir, tmp: tmp, sums: map[string]string{}}, nil
}

// Close removes the files of a restore that did not finish.
func (rs *Restorer) Close() {
	if rs.tmp != "" {
		_ = os.RemoveAll(rs.tmp)
		rs.tmp = ""
	}
}

// Add takes one file of the backup: the manifest (manifest.json) or one of
// the known files, size bytes read from r.
func (rs *Restorer) Add(name string, size int64, r io.Reader) error {
	if rs.tmp == "" {
		return errors.New("the restore has ended")
	}
	if rs.n++; rs.n > maxEntries {
		return errors.New("archive has too many entries")
	}
	if name == manifestName {
		if rs.m.Format != 0 {
			return fmt.Errorf("duplicate entry %q", name)
		}
		if size < 0 || size > maxFileSize {
			return errors.New("not an Armada backup: the manifest is too large")
		}
		var m Manifest
		dec := json.NewDecoder(io.LimitReader(r, size))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&m); err != nil {
			return fmt.Errorf("manifest: %w", err)
		}
		if m.Format != format {
			return fmt.Errorf("backup format %d is not supported (want %d)", m.Format, format)
		}
		rs.m = m
		return nil
	}
	if err := checkName(name); err != nil {
		return err
	}
	if _, dup := rs.sums[name]; dup {
		return fmt.Errorf("duplicate entry %q", name)
	}
	limit := int64(maxFileSize)
	if name == FileState {
		limit = maxStateSize
	}
	if size < 0 || size > limit {
		return fmt.Errorf("%s is too large (%d bytes)", name, size)
	}
	if rs.total += size; rs.total > maxTotalSize {
		return errors.New("archive is too large")
	}
	sum, err := writeFile(rs.tmp, name, r, size)
	if err != nil {
		return err
	}
	rs.sums[name] = sum
	return nil
}

// Finish verifies the files, turns the snapshot into the data of the etcd
// member described by member (its address and ports; the rest comes from
// the backup), and moves everything into the data directory.
func (rs *Restorer) Finish(ctx context.Context, member etcd.Config) (Manifest, error) {
	if rs.tmp == "" {
		return Manifest{}, errors.New("the restore has ended")
	}
	defer rs.Close()
	if rs.m.Format == 0 {
		return Manifest{}, errors.New("not an Armada backup: no manifest")
	}
	tmp, m := rs.tmp, rs.m
	ca, err := verify(ctx, tmp, m, rs.sums)
	if err != nil {
		return Manifest{}, err
	}
	srv, err := fsutil.ReadPrivateFile(filepath.Join(tmp, FileServerCert))
	if err != nil {
		return Manifest{}, err
	}
	leaf, err := pki.ParseCertPEM(srv)
	if err != nil {
		return Manifest{}, err
	}
	id, err := pki.IdentityFromCert(leaf)
	if err != nil || id.Kind != pki.KindServer {
		return Manifest{}, errors.New("server certificate has no server identity")
	}
	member.Dir, member.Name, member.CA = filepath.Join(tmp, DirEtcd), id.Name, ca
	if !member.Addr.IsValid() {
		// The member listens on the server's private IP.
		for _, ip := range leaf.IPAddresses {
			if a, ok := netip.AddrFromSlice(ip); ok {
				member.Addr = a.Unmap()
				break
			}
		}
	}
	if err := etcd.Restore(filepath.Join(tmp, FileState), member); err != nil {
		return Manifest{}, err
	}
	if err := os.Remove(filepath.Join(tmp, FileState)); err != nil {
		return Manifest{}, err
	}

	if err := os.Remove(rs.dataDir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Manifest{}, err
	}
	if err := os.Rename(tmp, rs.dataDir); err != nil {
		return Manifest{}, err
	}
	rs.tmp = ""
	return m, nil
}

// checkName accepts only the known files.
func checkName(name string) error {
	if slices.Contains(Required, name) || slices.Contains(Optional, name) {
		return nil
	}
	return fmt.Errorf("unexpected entry %q in backup", name)
}

func writeFile(dir, name string, r io.Reader, size int64) (string, error) {
	dst := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // name validated by checkName, inside a fresh temp dir
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.CopyN(io.MultiWriter(f, h), r, size)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("extract %s: %w", name, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verify checks the extracted files against the manifest and each other,
// and returns the cluster CA.
func verify(ctx context.Context, dir string, m Manifest, sums map[string]string) (*pki.CA, error) {
	for name, want := range m.Files {
		got, ok := sums[name]
		if !ok {
			return nil, fmt.Errorf("%s is listed in the manifest but missing", name)
		}
		if got != want {
			return nil, fmt.Errorf("%s does not match its checksum; the archive is corrupt or was modified", name)
		}
	}
	for name := range sums {
		if _, ok := m.Files[name]; !ok {
			return nil, fmt.Errorf("%s is not listed in the manifest", name)
		}
	}
	for _, name := range Required {
		if _, ok := sums[name]; !ok {
			return nil, fmt.Errorf("backup has no %s", name)
		}
	}

	if m.Schema > store.SchemaVersion() {
		return nil, fmt.Errorf("the backup was made by a newer Armada (schema %d, this binary knows %d); restore it with that version", m.Schema, store.SchemaVersion())
	}
	read := func(name string) ([]byte, error) { return fsutil.ReadPrivateFile(filepath.Join(dir, name)) }
	caPEM, err := read(FileCACert)
	if err != nil {
		return nil, err
	}
	caKey, err := read(FileCAKey)
	if err != nil {
		return nil, err
	}
	ca, err := pki.LoadCA(caPEM, caKey)
	if err != nil {
		return nil, fmt.Errorf("cluster CA: %w", err)
	}
	if m.CAFingerprint != "" && pki.Fingerprint(ca.Cert) != m.CAFingerprint {
		return nil, errors.New("cluster CA does not match the manifest")
	}
	srvCert, err := read(FileServerCert)
	if err != nil {
		return nil, err
	}
	srvKey, err := read(FileServerKey)
	if err != nil {
		return nil, err
	}
	if _, err := pki.ServerTLS(caPEM, srvCert, srvKey); err != nil {
		return nil, fmt.Errorf("server certificate: %w", err)
	}
	leaf, err := pki.ParseCertPEM(srvCert)
	if err != nil {
		return nil, fmt.Errorf("server certificate: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("server certificate is not signed by the cluster CA: %w", err)
	}

	name, err := serverName(srvCert)
	if err != nil {
		return nil, err
	}
	info, err := inspect(ctx, filepath.Join(dir, FileState), ca, dir, name)
	if err != nil {
		return nil, fmt.Errorf("state snapshot: %w", err)
	}
	if info.Listen == "" {
		return nil, fmt.Errorf("the state has no control plane node %s; not a backup of this server", name)
	}
	keys, err := secrets.LoadKeyFile(filepath.Join(dir, FileMasterKey))
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}
	if rec := info.Meta[metaMasterKey]; rec != "" && rec != keys.ID() {
		return nil, fmt.Errorf("master key (id %s) does not belong to this state (id %s)", keys.ID(), rec)
	}
	return ca, nil
}

var loopback = netip.MustParseAddr("127.0.0.1")

// freePorts returns n currently unused loopback ports.
func freePorts(n int) ([]int, error) {
	out := make([]int, 0, n)
	for range n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		defer l.Close()
		out = append(out, l.Addr().(*net.TCPAddr).Port)
	}
	return out, nil
}
