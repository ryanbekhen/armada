package containerd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/platforms"
	"github.com/klauspost/compress/zstd"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/net/http/httpproxy"

	"github.com/ryanbekhen/armada/internal/runtime"
	"github.com/ryanbekhen/armada/internal/runtime/supervisor"
)

// The parity tests of armada-node runtime pull (node/src/runtime/image):
// Go's Driver.Pull on the supervisor store and armada-node pull the same
// references from registries in this process (TLS with a test CA that
// armada-node trusts only through --extra-ca, Go through
// testRegistryRoots) and must agree on what they record, the blobs they
// keep, and what they refuse. Gated on ARMADA_NODE_BIN.

// testPKI is a CA and a server certificate for 127.0.0.1, 127.0.0.2,
// localhost, and registry.test.
type testPKI struct {
	caFile string
	pool   *x509.CertPool
	cert   tls.Certificate
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test registry CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "registry.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"registry.test", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return testPKI{caFile: caFile, pool: pool, cert: tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}}
}

// testRegistry serves images and records who asked for what.
type testRegistry struct {
	mu        sync.Mutex
	srv       *httptest.Server
	host      string
	tags      map[string]digest.Digest // repo:tag
	blobs     map[digest.Digest][]byte
	types     map[digest.Digest]string
	private   map[string]bool
	auth      string // "", "basic", "bearer"
	user      string
	pass      string
	redirect  map[digest.Digest]string // blob -> Location
	tamper    map[digest.Digest][]byte
	seenAuth  map[string][]string // path -> Authorization headers
	tokenAuth []string            // Authorization headers the token service saw
}

func (p testPKI) serve(t *testing.T, addr string, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("listen on %s: %v", addr, err)
	}
	_ = srv.Listener.Close()
	srv.Listener = l
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{p.cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func newTestRegistry(t *testing.T, p testPKI) *testRegistry {
	r := &testRegistry{
		tags: map[string]digest.Digest{}, blobs: map[digest.Digest][]byte{}, types: map[digest.Digest]string{},
		private: map[string]bool{}, redirect: map[digest.Digest]string{}, tamper: map[digest.Digest][]byte{},
		seenAuth: map[string][]string{},
	}
	r.srv = p.serve(t, "127.0.0.1:0", http.HandlerFunc(r.serveHTTP))
	r.host = strings.TrimPrefix(r.srv.URL, "https://")
	return r
}

func (r *testRegistry) put(mt string, b []byte) ocispec.Descriptor {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := digest.FromBytes(b)
	r.blobs[d] = b
	r.types[d] = mt
	return ocispec.Descriptor{MediaType: mt, Digest: d, Size: int64(len(b))}
}

func (r *testRegistry) putJSON(t *testing.T, mt string, v any) ocispec.Descriptor {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return r.put(mt, b)
}

// with changes the registry under its lock.
func (r *testRegistry) with(f func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f()
}

func (r *testRegistry) blob(d digest.Digest) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.blobs[d]
}

func (r *testRegistry) tag(repo, tag string, d ocispec.Descriptor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tags[repo+":"+tag] = d.Digest
}

func (r *testRegistry) serveHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if req.URL.Path == "/token" {
		r.serveToken(w, req)
		return
	}
	p := strings.TrimPrefix(req.URL.Path, "/v2/")
	var repo, kind, ref string
	for _, k := range []string{"/manifests/", "/blobs/"} {
		if i := strings.LastIndex(p, k); i > 0 {
			repo, kind, ref = p[:i], strings.Trim(k, "/"), p[i+len(k):]
			break
		}
	}
	if repo == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	r.seenAuth[req.URL.Path] = append(r.seenAuth[req.URL.Path], req.Header.Get("Authorization"))
	if r.private[repo] && !r.authorized(req) {
		switch r.auth {
		case "basic":
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
		default:
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="test",scope="repository:%s:pull"`, r.srv.URL, repo))
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	d := digest.Digest(ref)
	if kind == "manifests" {
		if td, ok := r.tags[repo+":"+ref]; ok {
			d = td
		}
	} else if loc, ok := r.redirect[d]; ok {
		http.Redirect(w, req, loc, http.StatusFound)
		return
	}
	b, ok := r.blobs[d]
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown"}]}`)
		return
	}
	if tb, ok := r.tamper[d]; ok {
		b = tb
	}
	if kind == "manifests" {
		w.Header().Set("Content-Type", r.types[d])
		w.Header().Set("Docker-Content-Digest", d.String())
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(b)))
	if req.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(b)
}

func (r *testRegistry) authorized(req *http.Request) bool {
	h := req.Header.Get("Authorization")
	switch r.auth {
	case "basic":
		return h == "Basic "+base64.StdEncoding.EncodeToString([]byte(r.user+":"+r.pass))
	case "bearer":
		return h == "Bearer tok-"+r.user
	}
	return true
}

func (r *testRegistry) serveToken(w http.ResponseWriter, req *http.Request) {
	r.tokenAuth = append(r.tokenAuth, req.Header.Get("Authorization"))
	user, pass, _ := req.BasicAuth()
	if req.Method == http.MethodPost {
		_ = req.ParseForm()
		user, pass = req.PostForm.Get("username"), req.PostForm.Get("password")
	}
	w.Header().Set("Content-Type", "application/json")
	if user == r.user && pass == r.pass {
		_, _ = fmt.Fprintf(w, `{"token":"tok-%s","access_token":"tok-%s","expires_in":300}`, r.user, r.user)
		return
	}
	if user != "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	_, _ = io.WriteString(w, `{"token":"anonymous"}`)
}

// layer is a one-file tar the current user may unpack.
func layerTar(t *testing.T, name, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Uid: os.Getuid(), Gid: os.Getgid(), ModTime: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tw, body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zstdBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = enc.Close() }()
	return enc.EncodeAll(b, nil)
}

// singleImage adds one platform's manifest: a gzip layer and a zstd one
// (diffIDs overrides the config's diff IDs when set).
func (r *testRegistry) singleImage(t *testing.T, p ocispec.Platform, seed string, docker bool, diffIDs []digest.Digest) ocispec.Descriptor {
	t.Helper()
	l1 := layerTar(t, "a-"+seed, "first layer of "+seed)
	l2 := layerTar(t, "b-"+seed, "second layer of "+seed)
	layerType, configType, manifestType := ocispec.MediaTypeImageLayerGzip, ocispec.MediaTypeImageConfig, ocispec.MediaTypeImageManifest
	if docker {
		layerType, configType, manifestType = images.MediaTypeDockerSchema2LayerGzip, images.MediaTypeDockerSchema2Config, images.MediaTypeDockerSchema2Manifest
	}
	d1 := r.put(layerType, gzipBytes(t, l1))
	d2 := r.put(ocispec.MediaTypeImageLayerZstd, zstdBytes(t, l2))
	if diffIDs == nil {
		diffIDs = []digest.Digest{digest.FromBytes(l1), digest.FromBytes(l2)}
	}
	cfg := r.putJSON(t, configType, ocispec.Image{Platform: p, RootFS: ocispec.RootFS{Type: "layers", DiffIDs: diffIDs}})
	return r.putJSON(t, manifestType, ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: manifestType, Config: cfg, Layers: []ocispec.Descriptor{d1, d2}})
}

// indexImage adds an index of every platform plus an attestation.
func (r *testRegistry) indexImage(t *testing.T, seed string, ps ...ocispec.Platform) ocispec.Descriptor {
	t.Helper()
	var ms []ocispec.Descriptor
	for _, p := range ps {
		m := r.singleImage(t, p, seed+"-"+p.Architecture+p.Variant, false, nil)
		m.Platform = &p
		ms = append(ms, m)
	}
	att := r.putJSON(t, ocispec.MediaTypeImageManifest, ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest,
		Config: r.put("application/vnd.in-toto+json", []byte(`{"att":"`+seed+`"}`))})
	att.Platform = &ocispec.Platform{OS: "unknown", Architecture: "unknown"}
	ms = append(ms, att)
	return r.putJSON(t, ocispec.MediaTypeImageIndex, ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: ms})
}

// decompressApplier "applies" a layer by decompressing it, as the real
// applier checks its diff ID; mounting needs root.
type decompressApplier struct{ cs content.Store }

func (a decompressApplier) Apply(ctx context.Context, desc ocispec.Descriptor, _ []mount.Mount, _ ...diff.ApplyOpt) (ocispec.Descriptor, error) {
	ra, err := a.cs.ReaderAt(ctx, desc)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	defer func() { _ = ra.Close() }()
	r, err := compression.DecompressStream(content.NewReader(ra))
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	defer func() { _ = r.Close() }()
	dg := digest.Canonical.Digester()
	n, err := io.Copy(dg.Hash(), r)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: dg.Digest(), Size: n}, nil
}

type pullResult struct {
	ref       string
	platforms []string
	err       string
	platform  *runtime.PlatformError
}

func goPull(t *testing.T, dir, image string, auth *runtime.RegistryAuth) pullResult {
	t.Helper()
	imgs, err := supervisor.OpenImages(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = imgs.Close() }()
	imgs.UseApplier(decompressApplier{cs: (&supervisor.Store{Images: imgs}).ContentStore()})
	d := &Driver{ctr: &supervisor.Store{Images: imgs}}
	img, err := d.Pull(context.Background(), image, auth)
	if err != nil {
		res := pullResult{err: err.Error()}
		var pe *runtime.PlatformError
		if errors.As(err, &pe) {
			res.platform = pe
		}
		return res
	}
	return pullResult{ref: img.Ref, platforms: img.Platforms}
}

func rustPull(t *testing.T, bin, dir, ca, image string, auth *runtime.RegistryAuth, env ...string) pullResult {
	t.Helper()
	req := map[string]any{"image": image}
	if auth != nil {
		req["auth"] = map[string]string{"Username": auth.Username, "Password": auth.Password, "ServerAddress": auth.ServerAddress}
	}
	in, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "runtime", "pull", dir, "--extra-ca", ca)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "SSL_CERT_FILE=/nonexistent", "SSL_CERT_DIR=/nonexistent"}, env...)
	cmd.Stdin = bytes.NewReader(in)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("armada-node runtime pull: %v: %s", err, stderr.String())
	}
	var res struct {
		Ref       string   `json:"ref"`
		Platforms []string `json:"platforms"`
		Error     string   `json:"error"`
		Platform  *struct {
			Image string   `json:"image"`
			Want  string   `json:"want"`
			Have  []string `json:"have"`
		} `json:"platform"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("armada-node runtime pull: %v: %s", err, out)
	}
	r := pullResult{ref: res.Ref, platforms: res.Platforms, err: res.Error}
	if res.Platform != nil {
		r.platform = &runtime.PlatformError{Image: res.Platform.Image, Want: res.Platform.Want, Have: res.Platform.Have}
	}
	return r
}

// storeBlobs lists the blobs under a content directory.
func storeBlobs(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(filepath.Join(dir, "content", "blobs"), func(p string, e fs.DirEntry, err error) error {
		if err == nil && !e.IsDir() {
			out = append(out, filepath.Base(filepath.Dir(p))+":"+e.Name())
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// record is what both stores keep about an image name.
type record struct {
	Target    ocispec.Descriptor `json:"target"`
	Config    ocispec.Descriptor `json:"config"`
	ChainID   string             `json:"chainID"`
	Platforms []string           `json:"platforms"`
	Labels    map[string]string  `json:"labels"`
}

func goRecords(t *testing.T, dir string) map[string]record {
	t.Helper()
	out := map[string]record{}
	b, err := os.ReadFile(filepath.Join(dir, "images.json"))
	if os.IsNotExist(err) {
		return out
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func rustRecords(t *testing.T, bin, dir string) map[string]record {
	t.Helper()
	var recs []struct {
		Name string `json:"name"`
		record
	}
	if err := json.Unmarshal(runNode(t, bin, nil, "runtime", "images", dir), &recs); err != nil {
		t.Fatal(err)
	}
	out := map[string]record{}
	for _, r := range recs {
		out[r.Name] = r.record
	}
	return out
}

// pullEnv is a test registry with both stores.
type pullEnv struct {
	t       *testing.T
	bin     string
	pki     testPKI
	reg     *testRegistry
	goDir   string
	rustDir string
}

func newPullEnv(t *testing.T) *pullEnv {
	bin := nodeBin(t)
	p := newTestPKI(t)
	old := testRegistryRoots
	testRegistryRoots = p.pool
	t.Cleanup(func() { testRegistryRoots = old })
	return &pullEnv{t: t, bin: bin, pki: p, reg: newTestRegistry(t, p), goDir: t.TempDir(), rustDir: t.TempDir()}
}

// both pulls image into both stores and checks they agree.
func (e *pullEnv) both(image string, auth *runtime.RegistryAuth) (pullResult, pullResult) {
	e.t.Helper()
	g := goPull(e.t, e.goDir, image, auth)
	r := rustPull(e.t, e.bin, e.rustDir, e.pki.caFile, image, auth)
	if (g.err == "") != (r.err == "") {
		e.t.Fatalf("pull %s: Go %q, armada-node %q", image, g.err, r.err)
	}
	if g.ref != r.ref || !slices.Equal(g.platforms, r.platforms) {
		e.t.Errorf("pull %s: Go %s %v, armada-node %s %v", image, g.ref, g.platforms, r.ref, r.platforms)
	}
	if (g.platform == nil) != (r.platform == nil) || g.platform != nil &&
		(g.platform.Want != r.platform.Want || !slices.Equal(g.platform.Have, r.platform.Have) || g.platform.Error() != r.err) {
		e.t.Errorf("pull %s: platform errors Go %v, armada-node %v (%s)", image, g.platform, r.platform, r.err)
	}
	e.checkStores()
	return g, r
}

// checkStores compares the records and blobs of both stores.
func (e *pullEnv) checkStores() {
	e.t.Helper()
	gr, rr := goRecords(e.t, e.goDir), rustRecords(e.t, e.bin, e.rustDir)
	if len(gr) != len(rr) {
		e.t.Errorf("records: Go %v, armada-node %v", keys(gr), keys(rr))
	}
	for name, g := range gr {
		r, ok := rr[name]
		if !ok {
			e.t.Errorf("armada-node has no record of %s", name)
			continue
		}
		if g.Target.Digest != r.Target.Digest || g.Target.MediaType != r.Target.MediaType || g.Target.Size != r.Target.Size ||
			g.Config.Digest != r.Config.Digest || g.ChainID != r.ChainID || !slices.Equal(g.Platforms, r.Platforms) ||
			!equalLabels(g.Labels, r.Labels) {
			e.t.Errorf("%s: Go %+v\narmada-node %+v", name, g, r)
		}
	}
	// The blobs the records keep (a failed pull may leave others behind,
	// which Go cancels at a different point than armada-node).
	if g, r := keptBlobs(e.t, e.goDir, gr), keptBlobs(e.t, e.rustDir, rr); !slices.Equal(g, r) {
		e.t.Errorf("blobs: Go %v\narmada-node %v", g, r)
	}
}

// keptBlobs lists the blobs on disk that records reach: an index's
// manifests that are there, a manifest's config and layers.
func keptBlobs(t *testing.T, dir string, recs map[string]record) []string {
	t.Helper()
	seen := map[string]bool{}
	var walk func(d ocispec.Descriptor)
	walk = func(d ocispec.Descriptor) {
		b, err := os.ReadFile(filepath.Join(dir, "content", "blobs", d.Digest.Algorithm().String(), d.Digest.Encoded()))
		if err != nil || seen[d.Digest.String()] {
			return
		}
		seen[d.Digest.String()] = true
		var doc struct {
			Config    *ocispec.Descriptor  `json:"config"`
			Layers    []ocispec.Descriptor `json:"layers"`
			Manifests []ocispec.Descriptor `json:"manifests"`
		}
		if !images.IsManifestType(d.MediaType) && !images.IsIndexType(d.MediaType) {
			return
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Config != nil {
			walk(*doc.Config)
		}
		for _, c := range append(doc.Layers, doc.Manifests...) {
			walk(c)
		}
	}
	for _, r := range recs {
		walk(r.Target)
	}
	return keys(seen)
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equalLabels(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Public images, from an index and from a single manifest, by tag and by
// digest: both pull the node's platform, record the same, and keep the
// same blobs; a digest-pinned image on the node is used as it is.
func TestArmadaNodePullMatchesGo(t *testing.T) {
	e := newPullEnv(t)
	node := platforms.DefaultSpec()
	// 386 first: the node's own platform must win the sort.
	idx := e.reg.indexImage(t, "multi",
		ocispec.Platform{OS: "linux", Architecture: "386"},
		ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"},
		ocispec.Platform{OS: "linux", Architecture: node.Architecture, Variant: node.Variant},
	)
	e.reg.tag("apps/multi", "1", idx)
	single := e.reg.singleImage(t, ocispec.Platform{OS: "linux", Architecture: node.Architecture}, "single", true, nil)
	e.reg.tag("apps/single", "latest", single)

	g, _ := e.both(e.reg.host+"/apps/multi:1", nil)
	if !strings.HasSuffix(g.ref, "@"+idx.Digest.String()) || !slices.Contains(g.platforms, "linux/arm64") {
		t.Errorf("pulled %s %v", g.ref, g.platforms)
	}
	e.both(e.reg.host+"/apps/single", nil)
	// Again by digest: the image on the node is used, no fetch.
	e.both(e.reg.host+"/apps/multi@"+idx.Digest.String(), nil)
	e.both(e.reg.host+"/apps/multi@"+idx.Digest.String(), nil)
	// A tag that is not there.
	g, r := e.both(e.reg.host+"/apps/multi:2", nil)
	for _, msg := range []string{g.err, r.err} {
		if !strings.Contains(msg, "no such image or tag") {
			t.Errorf("missing tag: %s", msg)
		}
	}
}

// An image with no variant for the node is a PlatformError with the
// same platforms in both.
func TestArmadaNodePullPlatformErrorMatchesGo(t *testing.T) {
	e := newPullEnv(t)
	other := "s390x"
	idx := e.reg.indexImage(t, "foreign",
		ocispec.Platform{OS: "linux", Architecture: other},
		ocispec.Platform{OS: "windows", Architecture: "amd64"})
	e.reg.tag("apps/foreign", "1", idx)
	g, _ := e.both(e.reg.host+"/apps/foreign:1", nil)
	if g.platform == nil || !slices.Equal(g.platform.Have, []string{"linux/" + other, "windows/amd64"}) {
		t.Errorf("platform error %v (%s)", g.platform, g.err)
	}
	single := e.reg.singleImage(t, ocispec.Platform{OS: "linux", Architecture: other}, "s", false, nil)
	e.reg.tag("apps/foreign-single", "1", single)
	// A single manifest is not checked against the node's platform (the
	// Go driver pulls it, and reports its platform for placement).
	if g, _ := e.both(e.reg.host+"/apps/foreign-single:1", nil); g.err != "" || !slices.Equal(g.platforms, []string{"linux/" + other}) {
		t.Errorf("single manifest of another platform: %v %s", g.platforms, g.err)
	}
}

// Private images: credentials go only to the registry they were given
// for, never with a redirect to another host, and are refused or missing
// alike in both; basic and bearer.
func TestArmadaNodePullAuthMatchesGo(t *testing.T) {
	for _, scheme := range []string{"basic", "bearer"} {
		t.Run(scheme, func(t *testing.T) {
			e := newPullEnv(t)
			e.reg.with(func() { e.reg.auth, e.reg.user, e.reg.pass = scheme, "me", "secret" })
			e.reg.with(func() { e.reg.private["team/app"] = true })
			node := platforms.DefaultSpec()
			m := e.reg.singleImage(t, ocispec.Platform{OS: "linux", Architecture: node.Architecture}, "private-"+scheme, false, nil)
			e.reg.tag("team/app", "1", m)
			// One layer is served from another host.
			var cdnAuth []string
			var cdnMu sync.Mutex
			cdn := e.pki.serve(t, "127.0.0.2:0", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				cdnMu.Lock()
				cdnAuth = append(cdnAuth, req.Header.Get("Authorization"))
				cdnMu.Unlock()
				e.reg.mu.Lock()
				b := e.reg.blobs[digest.Digest(strings.TrimPrefix(req.URL.Path, "/cdn/"))]
				e.reg.mu.Unlock()
				_, _ = w.Write(b)
			}))
			var man ocispec.Manifest
			if err := json.Unmarshal(e.reg.blob(m.Digest), &man); err != nil {
				t.Fatal(err)
			}
			e.reg.with(func() { e.reg.redirect[man.Layers[0].Digest] = cdn.URL + "/cdn/" + man.Layers[0].Digest.String() })

			ref := e.reg.host + "/team/app:1"
			// No credentials, and credentials for another registry.
			for _, auth := range []*runtime.RegistryAuth{nil, {Username: "me", Password: "secret", ServerAddress: "other.test"}} {
				g, r := e.both(ref, auth)
				for _, msg := range []string{g.err, r.err} {
					if !strings.Contains(msg, "private") && !strings.Contains(msg, "refused") && !strings.Contains(msg, "credentials") {
						t.Errorf("auth %v: %s", auth, msg)
					}
				}
			}
			// Wrong password.
			if g, _ := e.both(ref, &runtime.RegistryAuth{Username: "me", Password: "wrong", ServerAddress: e.reg.host}); g.err == "" {
				t.Error("a wrong password pulled")
			}
			good := &runtime.RegistryAuth{Username: "me", Password: "secret", ServerAddress: "https://" + e.reg.host}
			if g, _ := e.both(ref, good); g.err != "" {
				t.Fatal(g.err)
			}
			cdnMu.Lock()
			defer cdnMu.Unlock()
			if len(cdnAuth) < 2 {
				t.Fatalf("the other host served %d requests", len(cdnAuth))
			}
			for _, h := range cdnAuth {
				if h != "" {
					t.Errorf("credentials sent to another host: %q", h)
				}
			}
			var tokenAuth []string
			e.reg.with(func() { tokenAuth = slices.Clone(e.reg.tokenAuth) })
			if scheme == "bearer" && len(tokenAuth) == 0 {
				t.Error("no token was asked for")
			}
			for _, h := range tokenAuth {
				if h != "" && h != "Basic "+base64.StdEncoding.EncodeToString([]byte("me:secret")) &&
					h != "Basic "+base64.StdEncoding.EncodeToString([]byte("me:wrong")) {
					t.Errorf("token service got %q", h)
				}
			}
		})
	}
}

// Content that is not what its digest or the config say is refused by
// both: a tampered layer, a config naming another layer's diff ID, and a
// pull that names another image's blobs it cannot fetch itself.
func TestArmadaNodePullRefusesMatchesGo(t *testing.T) {
	e := newPullEnv(t)
	node := platforms.DefaultSpec()
	p := ocispec.Platform{OS: "linux", Architecture: node.Architecture}

	tampered := e.reg.singleImage(t, p, "tampered", false, nil)
	var man ocispec.Manifest
	if err := json.Unmarshal(e.reg.blob(tampered.Digest), &man); err != nil {
		t.Fatal(err)
	}
	e.reg.with(func() { e.reg.tamper[man.Layers[1].Digest] = bytes.Repeat([]byte{'x'}, int(man.Layers[1].Size)) })
	e.reg.tag("apps/tampered", "1", tampered)
	if g, _ := e.both(e.reg.host+"/apps/tampered:1", nil); g.err == "" {
		t.Error("a tampered layer was accepted")
	}

	wrong := e.reg.singleImage(t, p, "wrong", false, []digest.Digest{digest.FromString("another"), digest.FromString("layer")})
	e.reg.tag("apps/wrong", "1", wrong)
	if g, _ := e.both(e.reg.host+"/apps/wrong:1", nil); g.err == "" {
		t.Error("layers that do not match their diff IDs were accepted")
	}

	// Space A pulls its private image with its credentials.
	e.reg.with(func() { e.reg.auth, e.reg.user, e.reg.pass = "basic", "a", "pw" })
	e.reg.with(func() { e.reg.private["a/private"] = true })
	private := e.reg.singleImage(t, p, "private", false, nil)
	e.reg.tag("a/private", "1", private)
	if g, _ := e.both(e.reg.host+"/a/private:1", &runtime.RegistryAuth{Username: "a", Password: "pw", ServerAddress: e.reg.host}); g.err != "" {
		t.Fatal(g.err)
	}
	// Another app names A's config and layers in a manifest of its own,
	// on a repository that serves none of them.
	var pm ocispec.Manifest
	if err := json.Unmarshal(e.reg.blob(private.Digest), &pm); err != nil {
		t.Fatal(err)
	}
	evil := e.reg.putJSON(t, ocispec.MediaTypeImageManifest, ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest, Config: pm.Config, Layers: pm.Layers, Annotations: map[string]string{"x": "y"}})
	e.reg.tag("b/evil", "1", evil)
	e.reg.with(func() { e.reg.private["b/evil"] = false })
	for _, d := range append([]ocispec.Descriptor{pm.Config}, pm.Layers...) {
		e.reg.with(func() {
			e.reg.redirect[d.Digest] = "https://" + e.reg.host + "/v2/a/private/blobs/" + d.Digest.String()
		})
	}
	g, r := e.both(e.reg.host+"/b/evil:1", nil)
	if g.err == "" {
		t.Error("another space's layers were taken by naming them")
	}
	for _, msg := range []string{g.err, r.err} {
		if !strings.Contains(msg, "did not serve it to these credentials") {
			t.Errorf("proof: %s", msg)
		}
	}
}

// A registry cannot steer a pull to plain HTTP or to a link-local
// address with a redirect; nothing reaches the plain target.
func TestArmadaNodePullRedirectsMatchGo(t *testing.T) {
	e := newPullEnv(t)
	var plainHits int
	var mu sync.Mutex
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		mu.Lock()
		plainHits++
		mu.Unlock()
	}))
	defer plain.Close()
	node := platforms.DefaultSpec()
	p := ocispec.Platform{OS: "linux", Architecture: node.Architecture}
	for name, target := range map[string]string{
		"plain":      plain.URL + "/blob",
		"link-local": "https://169.254.169.254/latest/meta-data",
		"v6-local":   "https://[fe80::1]:8443/x",
		"loop":       "", // redirects to itself
	} {
		m := e.reg.singleImage(t, p, "redirect-"+name, false, nil)
		var man ocispec.Manifest
		if err := json.Unmarshal(e.reg.blob(m.Digest), &man); err != nil {
			t.Fatal(err)
		}
		if target == "" {
			target = "https://" + e.reg.host + "/v2/apps/" + name + "/blobs/" + man.Layers[0].Digest.String()
		}
		e.reg.with(func() { e.reg.redirect[man.Layers[0].Digest] = target })
		e.reg.tag("apps/"+name, "1", m)
		g, r := e.both(e.reg.host+"/apps/"+name+":1", nil)
		if g.err == "" {
			t.Errorf("%s: pulled", name)
		}
		want := map[string]string{"plain": "registry requests must use https", "link-local": "refused", "v6-local": "refused", "loop": "redirects"}[name]
		for _, msg := range []string{g.err, r.err} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s: %s", name, msg)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if plainHits != 0 {
		t.Errorf("the plain-HTTP target got %d requests", plainHits)
	}
}

// Layer URLs a manifest names are ignored by both: the layers come from
// the registry, and neither the listed server nor the metadata address is
// asked.
func TestArmadaNodePullIgnoresLayerURLsMatchesGo(t *testing.T) {
	e := newPullEnv(t)
	var hits int
	var mu sync.Mutex
	foreign := e.pki.serve(t, "127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		http.Error(w, "nothing here", http.StatusNotFound)
	}))
	node := platforms.DefaultSpec()
	m := e.reg.singleImage(t, ocispec.Platform{OS: "linux", Architecture: node.Architecture}, "urls", false, nil)
	var man ocispec.Manifest
	if err := json.Unmarshal(e.reg.blob(m.Digest), &man); err != nil {
		t.Fatal(err)
	}
	for i := range man.Layers {
		man.Layers[i].URLs = []string{foreign.URL + "/layer", "http://169.254.169.254/latest/meta-data"}
	}
	withURLs := e.reg.putJSON(t, ocispec.MediaTypeImageManifest, man)
	e.reg.tag("apps/urls", "1", withURLs)
	g, _ := e.both(e.reg.host+"/apps/urls:1", nil)
	if g.err != "" {
		t.Fatalf("pull: %s", g.err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("the server a layer URL names got %d requests", hits)
	}
}

// Through the environment's HTTPS proxy, armada-node tunnels to the
// registry by name (the proxy resolves it), as Go's transport does; the
// proxy is chosen as golang.org/x/net/http/httpproxy chooses.
func TestArmadaNodeProxyMatchesGo(t *testing.T) {
	e := newPullEnv(t)
	node := platforms.DefaultSpec()
	m := e.reg.singleImage(t, ocispec.Platform{OS: "linux", Architecture: node.Architecture}, "proxied", false, nil)
	e.reg.tag("apps/proxied", "1", m)
	_, port, _ := net.SplitHostPort(e.reg.host)

	var connects []string
	var mu sync.Mutex
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		connects = append(connects, req.Host)
		mu.Unlock()
		host, p, _ := net.SplitHostPort(req.Host)
		if host != "registry.test" {
			http.Error(w, "unknown host", http.StatusBadGateway)
			return
		}
		upstream, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", p))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hj, _ := w.(http.Hijacker)
		conn, buf, err := hj.Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(upstream, buf); _ = upstream.Close() }()
		_, _ = io.Copy(conn, upstream)
		_ = conn.Close()
	}))
	defer proxy.Close()

	ref := "registry.test:" + port + "/apps/proxied:1"
	r := rustPull(t, e.bin, e.rustDir, e.pki.caFile, ref, nil, "HTTPS_PROXY="+proxy.URL)
	if r.err != "" || r.ref != "registry.test:"+port+"/apps/proxied@"+m.Digest.String() {
		t.Fatalf("through the proxy: %+v", r)
	}
	mu.Lock()
	if len(connects) == 0 || connects[0] != "registry.test:"+port {
		t.Errorf("CONNECTs: %v", connects)
	}
	mu.Unlock()

	// Which requests take the proxy.
	noProxy := "example.org, .sub.test, *.wild.test, 10.0.0.0/8, 192.168.1.1, [::1]:443, host.test:8443"
	for _, u := range []string{
		"https://localhost/v2/", "https://127.0.0.1/v2/", "https://[::1]/v2/", "https://example.org/v2/",
		"https://a.example.org/v2/", "https://badexample.org/v2/", "https://sub.test/v2/", "https://a.sub.test/v2/",
		"https://a.wild.test/v2/", "https://10.1.2.3/v2/", "https://11.1.2.3/v2/", "https://192.168.1.1/v2/",
		"https://host.test:8443/v2/", "https://host.test/v2/", "https://registry.test:5000/v2/",
	} {
		cfg := httpproxy.Config{HTTPSProxy: "proxy.test:3128", NoProxy: noProxy}
		pu, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		want, err := cfg.ProxyFunc()(pu)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(e.bin, "runtime", "proxy", u)
		cmd.Env = []string{"HTTPS_PROXY=proxy.test:3128", "NO_PROXY=" + noProxy}
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		var got struct{ Proxy string }
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatal(err)
		}
		wantHost := ""
		if want != nil {
			wantHost = want.Host
		}
		gotHost := ""
		if got.Proxy != "" {
			gu, err := url.Parse(got.Proxy)
			if err != nil {
				t.Fatal(err)
			}
			gotHost = gu.Host
		}
		if gotHost != wantHost {
			t.Errorf("%s: Go proxy %q, armada-node %q", u, wantHost, gotHost)
		}
	}
}

// References normalize, familiarize, and key credentials alike.
func TestArmadaNodeReferenceMatchesGo(t *testing.T) {
	bin := nodeBin(t)
	d := digest.FromString("x").String()
	type entry struct {
		Image string         `json:"image"`
		Auth  map[string]any `json:"auth,omitempty"`
	}
	auths := []*runtime.RegistryAuth{nil,
		{Username: "u", Password: "p", ServerAddress: "https://index.docker.io/v1/"},
		{Username: "u", Password: "p", ServerAddress: "ghcr.io"},
		{Username: "u", Password: "p", ServerAddress: "Registry.Example:5000"},
	}
	var in []entry
	var want []runtime.RegistryAuth
	var wantNil []bool
	for _, img := range []string{
		"nginx", "nginx:1.27", "library/nginx", "docker.io/library/nginx", "index.docker.io/nginx",
		"ghcr.io/a/b:v1", "localhost/x", "localhost:5000/x/y:z", "Registry.Example:5000/team/app",
		"[::1]:5000/x", "nginx@" + d, "nginx:1@" + d, "a/b/c/d", "a_b/c__d/e--f", "UPPER/x", "x/UPPER",
		"", "x:", "a//b", "-a", "x@sha256:abc", strings.Repeat("a", 64), "x:" + strings.Repeat("t", 129),
		"x/" + strings.Repeat("a", 260), "host:notaport/x", "a.b:5000",
	} {
		for _, a := range auths {
			en := entry{Image: img}
			if a != nil {
				en.Auth = map[string]any{"Username": a.Username, "Password": a.Password, "ServerAddress": a.ServerAddress}
				want = append(want, *a)
			} else {
				want = append(want, runtime.RegistryAuth{})
			}
			wantNil = append(wantNil, a == nil)
			in = append(in, en)
		}
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var got []struct {
		Ref      string `json:"ref"`
		Familiar string `json:"familiar"`
		Digested bool   `json:"digested"`
		PullKey  string `json:"pullKey"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(runNode(t, bin, b, "runtime", "reference"), &got); err != nil {
		t.Fatal(err)
	}
	for i, en := range in {
		ref, familiar, digested, err := normalize(en.Image)
		g := got[i]
		if (err != nil) != (g.Error != "") {
			t.Errorf("%q: Go %v, armada-node %q", en.Image, err, g.Error)
			continue
		}
		if err != nil {
			continue
		}
		var auth *runtime.RegistryAuth
		if !wantNil[i] {
			auth = &want[i]
		}
		if ref != g.Ref || familiar != g.Familiar || digested != g.Digested || pullKey(ref, auth) != g.PullKey {
			t.Errorf("%q: Go %s %s %v %s, armada-node %+v", en.Image, ref, familiar, digested, pullKey(ref, auth), g)
		}
	}
}

// Platform strings, which platforms the node runs, and the order it
// prefers them in agree with containerd's platforms package.
func TestArmadaNodePlatformsMatchGo(t *testing.T) {
	bin := nodeBin(t)
	ps := []ocispec.Platform{
		{OS: "linux", Architecture: "arm64", Variant: "v8"}, {OS: "linux", Architecture: "aarch64"},
		{OS: "linux", Architecture: "x86_64"}, {OS: "linux", Architecture: "arm", Variant: "v7"},
		{OS: "unknown", Architecture: "unknown"}, {OS: "", Architecture: "amd64"}, {OS: "linux", Architecture: "386"},
		{OS: "linux", Architecture: "amd64", Variant: "v2"}, {OS: "linux", Architecture: "amd64", Variant: "v1"},
		{OS: "Linux", Architecture: "AMD64"}, {OS: "linux", Architecture: "i386"}, {OS: "windows", Architecture: "amd64"},
		{OS: "linux", Architecture: "amd64", OSFeatures: []string{"x"}}, {OS: "linux", Architecture: "arm", Variant: "v6"},
		{OS: "linux", Architecture: "arm64", Variant: "v8.2"}, {OS: "linux", Architecture: "armhf"},
		{OS: "linux", Architecture: "ppc64le"}, {OS: "linux", Architecture: "amd64"},
	}
	b, err := json.Marshal(ps)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Strings []string `json:"strings"`
		Matches []bool   `json:"matches"`
		Order   []int    `json:"order"`
		Node    string   `json:"node"`
	}
	if err := json.Unmarshal(runNode(t, bin, b, "runtime", "platforms"), &got); err != nil {
		t.Fatal(err)
	}
	if want := platformStrings(ps); !slices.Equal(got.Strings, want) {
		t.Errorf("strings: Go %v, armada-node %v", want, got.Strings)
	}
	m := platforms.Default()
	for i, p := range ps {
		if m.Match(p) != got.Matches[i] {
			t.Errorf("%+v: Go matches %v", p, m.Match(p))
		}
	}
	order := make([]int, len(ps))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool { return m.Less(ps[order[i]], ps[order[j]]) })
	if !slices.Equal(order, got.Order) {
		t.Errorf("order: Go %v, armada-node %v", order, got.Order)
	}
	if got.Node != nodePlatform() {
		t.Errorf("node: Go %s, armada-node %s", nodePlatform(), got.Node)
	}
}

// Prune removes what nothing keeps and collects its blobs.
func TestArmadaNodePrune(t *testing.T) {
	e := newPullEnv(t)
	node := platforms.DefaultSpec()
	p := ocispec.Platform{OS: "linux", Architecture: node.Architecture}
	a := e.reg.singleImage(t, p, "keep", false, nil)
	b := e.reg.singleImage(t, p, "drop", false, nil)
	e.reg.tag("apps/keep", "1", a)
	e.reg.tag("apps/drop", "1", b)
	for _, ref := range []string{"apps/keep:1", "apps/drop:1"} {
		if r := rustPull(t, e.bin, e.rustDir, e.pki.caFile, e.reg.host+"/"+ref, nil); r.err != "" {
			t.Fatal(r.err)
		}
	}
	before := storeBlobs(t, e.rustDir)
	in := []byte(fmt.Sprintf(`{"keep":["%s/apps/keep@%s"],"graceSeconds":0}`, e.reg.host, a.Digest))
	var out struct {
		Removed []string `json:"removed"`
		Error   string   `json:"error"`
	}
	if err := json.Unmarshal(runNode(t, e.bin, in, "runtime", "prune", e.rustDir), &out); err != nil {
		t.Fatal(err)
	}
	if out.Error != "" || !slices.Equal(out.Removed, []string{e.reg.host + "/apps/drop:1"}) {
		t.Fatalf("prune: %+v", out)
	}
	after := storeBlobs(t, e.rustDir)
	if len(after) != len(before)-4 || !slices.Contains(after, "sha256:"+a.Digest.Encoded()) {
		t.Errorf("blobs before %d after %d", len(before), len(after))
	}
	if recs := rustRecords(t, e.bin, e.rustDir); len(recs) != 1 {
		t.Errorf("records left: %v", keys(recs))
	}
	// Within the grace nothing goes.
	in = []byte(`{"keep":[],"graceSeconds":3600}`)
	if err := json.Unmarshal(runNode(t, e.bin, in, "runtime", "prune", e.rustDir), &out); err != nil || len(out.Removed) != 0 {
		t.Errorf("prune within the grace: %+v %v", out, err)
	}
}
