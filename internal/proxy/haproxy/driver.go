package haproxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/proxy"
	"github.com/ryanbekhen/armada/internal/spec"
)

// Engine controls the HAProxy process.
type Engine interface {
	Running(ctx context.Context) (bool, error)
	// Start (re)creates the HAProxy container from the current config file.
	Start(ctx context.Context) error
	// Validate runs `haproxy -c` against a config file (container path).
	Validate(ctx context.Context, file string) error
	// Reload gracefully reloads the configuration (master-worker SIGUSR2).
	Reload(ctx context.Context) error
}

// Config configures a Driver.
type Config struct {
	// Dir is the host directory holding etc/ (config, certs) and run/
	// (Runtime API socket). It is created with mode 0700.
	Dir       string
	PrivateIP string
	// InternalIP is the container bridge gateway for the internal frontend;
	// empty disables internal ingress on this node.
	InternalIP string
	// Subnet is the node's container subnet in the cluster network, where
	// its replicas have their own addresses (ADR 0025); empty otherwise.
	Subnet string
	Engine Engine
	// API defaults to the Runtime API socket under Dir.
	API    API
	Logger *slog.Logger
}

// Driver is the HAProxy proxy.Driver.
type Driver struct {
	cfg Config
	log *slog.Logger

	mu       sync.Mutex
	sig      string
	layout   Layout
	applied  map[string]slot   // "backend/slot" -> what it serves; zero for a free slot
	certHash map[string]string // file name -> sha256 of PEM
	// clients is the content of the clients map HAProxy last loaded or
	// was given through the Runtime API.
	clients []byte
	// local is the content of the local map the same way.
	local []byte
	// Each HAProxy process counts requests from zero, so totals are carried
	// over from one process to the next (see Load).
	workerPID string
	totals    map[string]int64 // replica -> latest total
	carried   map[string]int64 // replica -> total before this process
}

var _ proxy.Driver = (*Driver)(nil)

// New prepares the directories and default certificate.
func New(cfg Config) (*Driver, error) {
	if cfg.Engine == nil {
		return nil, errors.New("haproxy: Engine is required")
	}
	if cfg.PrivateIP != "" {
		if _, err := netip.ParseAddr(cfg.PrivateIP); err != nil {
			return nil, fmt.Errorf("haproxy: invalid private IP %q", cfg.PrivateIP)
		}
	}
	if cfg.Subnet != "" {
		if p, err := netip.ParsePrefix(cfg.Subnet); err != nil || p.Masked() != p || !netutil.IsPrivate(p.Addr()) {
			return nil, fmt.Errorf("haproxy: subnet %q must be a private prefix", cfg.Subnet)
		}
	}
	if cfg.InternalIP != "" {
		ip, err := netip.ParseAddr(cfg.InternalIP)
		if err != nil || !netutil.IsPrivate(ip) {
			return nil, fmt.Errorf("haproxy: internal IP %q must be a private address", cfg.InternalIP)
		}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	for _, d := range []string{cfg.Dir, etcDir(cfg.Dir), filepath.Join(etcDir(cfg.Dir), certDir), runDir(cfg.Dir)} {
		if err := fsutil.MkdirPrivate(d); err != nil {
			return nil, err
		}
	}
	if cfg.API == nil {
		cfg.API = Socket{Path: filepath.Join(runDir(cfg.Dir), socketFile)}
	}
	// HAProxy reads its maps at start. Until the agent knows its containers
	// the clients map is empty, and no internal route matches anyone.
	for _, name := range []string{clientsFile, localFile} {
		if _, err := os.Stat(filepath.Join(etcDir(cfg.Dir), name)); errors.Is(err, os.ErrNotExist) {
			if err := fsutil.WriteFileAtomic(filepath.Join(etcDir(cfg.Dir), name), nil, 0o600); err != nil {
				return nil, err
			}
		}
	}
	def := filepath.Join(etcDir(cfg.Dir), defaultCertFile)
	if _, err := os.Stat(def); errors.Is(err, os.ErrNotExist) {
		b, err := selfSignedPEM()
		if err != nil {
			return nil, err
		}
		if err := fsutil.WriteFileAtomic(def, b, 0o600); err != nil {
			return nil, err
		}
	}
	return &Driver{
		cfg:      cfg,
		log:      cfg.Logger.With("component", "haproxy"),
		layout:   Layout{},
		applied:  map[string]slot{},
		certHash: map[string]string{},
	}, nil
}

func etcDir(dir string) string { return filepath.Join(dir, "etc") }
func runDir(dir string) string { return filepath.Join(dir, "run") }

// options are the node's parts of the configuration.
func (d *Driver) options() renderOptions {
	return renderOptions{PrivateIP: d.cfg.PrivateIP, InternalIP: d.cfg.InternalIP, Subnet: d.cfg.Subnet}
}

// Apply implements proxy.Driver.
func (d *Driver) Apply(ctx context.Context, cfg proxy.Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("refusing invalid proxy config: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	opts := d.options()
	// A proxy that outlives its agent keeps serving: take over what it runs
	// rather than reload it, if its configuration is still the right one.
	live, adopted := d.liveConfig(ctx, cfg, opts)
	layout := assignLayout(d.layout, cfg, opts.node())
	sig := signature(cfg, layout, opts)
	content := render(cfg, layout, opts)
	if content == nil {
		return errors.New("refusing proxy config: an interpolated value is not a single token")
	}

	adopted = adopted && sameStructure(live, content)
	changedCerts, err := d.writeCerts(cfg.Certificates)
	if err != nil {
		return err
	}
	if adopted {
		// A certificate may have been renewed while no agent ran.
		changedCerts = changedCerts[:0]
		for _, c := range cfg.Certificates {
			changedCerts = append(changedCerts, c.FileName())
		}
		d.sig = sig
		d.log.Info("kept the running haproxy")
	}
	routes := routeFiles(cfg, opts)
	for name, b := range routes {
		if err := fsutil.WriteFileAtomic(filepath.Join(etcDir(d.cfg.Dir), name), b, 0o600); err != nil {
			return err
		}
	}

	local := localMap(cfg, layout, opts.node())
	if !bytes.Equal(local, d.local) {
		if err := fsutil.WriteFileAtomic(filepath.Join(etcDir(d.cfg.Dir), localFile), local, 0o600); err != nil {
			return err
		}
	}

	running, err := d.cfg.Engine.Running(ctx)
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(etcDir(d.cfg.Dir), configFile)

	if !running {
		// Nothing is serving traffic yet, so there is no old config to keep.
		if err := fsutil.WriteFileAtomic(cfgPath, content, 0o600); err != nil {
			return err
		}
		if err := d.cfg.Engine.Start(ctx); err != nil {
			return fmt.Errorf("start haproxy: %w", err)
		}
		d.commit(sig, layout, cfg)
		d.local = local
		d.removeOldRoutes(routes)
		d.log.Info("haproxy started")
		return nil
	}

	if err := d.writeValidated(ctx, cfgPath, content); err != nil {
		return err
	}

	if sig != d.sig {
		// What the outgoing process counted since the last sample would
		// otherwise be lost with it.
		if _, err := d.load(ctx); err != nil {
			d.log.Debug("read proxy load before a reload", "err", err)
		}
		if err := d.cfg.Engine.Reload(ctx); err != nil {
			return fmt.Errorf("reload haproxy: %w", err)
		}
		d.commit(sig, layout, cfg)
		d.local = local
		d.removeOldRoutes(routes)
		d.log.Info("haproxy reloaded")
		return nil
	}

	// Same structure: update servers and certificates live. New servers are
	// enabled before old ones leave, so a backend never runs empty in
	// between (one replica being replaced by another).
	desired := desiredServers(cfg, layout, opts.node())
	for _, enable := range []bool{true, false} {
		for _, key := range sortedKeys(desired) {
			cur, want := d.applied[key], desired[key]
			if cur == want || (want.Addr == "" && cur.Addr == "") || (want.Addr != "") != enable {
				continue
			}
			if err := d.setServer(ctx, key, cur, want); err != nil {
				return err
			}
			if want.Addr == "" {
				want.Weight = cur.Weight // maintenance leaves the weight as it was
			}
			d.applied[key] = want
		}
	}
	// After the servers: a slot in the map that has gone falls through to
	// balancing, and one that has just arrived is already up to take a request.
	if !bytes.Equal(local, d.local) {
		if err := d.replaceMap(ctx, localFile, local); err != nil {
			return fmt.Errorf("update the local map: %w", err)
		}
		d.local = local
	}
	for _, name := range changedCerts {
		if err := d.updateCert(ctx, name, cfg); err != nil {
			// The file on disk is the new certificate: a reload loads it.
			// Otherwise the running proxy would keep the old one, and the
			// file no longer looks changed, until it expires.
			d.log.Warn("live certificate update failed; reloading", "cert", name, "err", err)
			if err := d.cfg.Engine.Reload(ctx); err != nil {
				return fmt.Errorf("reload haproxy for certificate %s: %w", name, err)
			}
			break
		}
	}
	d.layout = layout
	return nil
}

// removeOldRoutes deletes route maps the live configuration does not use.
func (d *Driver) removeOldRoutes(keep map[string][]byte) {
	entries, err := os.ReadDir(etcDir(d.cfg.Dir))
	if err != nil {
		return
	}
	for _, e := range entries {
		if _, ok := keep[e.Name()]; !ok && strings.HasPrefix(e.Name(), routeFilePrefix) {
			if err := os.Remove(filepath.Join(etcDir(d.cfg.Dir), e.Name())); err != nil {
				d.log.Debug("remove an old route map", "err", err)
			}
		}
	}
}

// writeValidated writes content next to the live config, validates it, and
// only then replaces the live file.
func (d *Driver) writeValidated(ctx context.Context, cfgPath string, content []byte) error {
	cur, err := os.ReadFile(cfgPath) //nolint:gosec // path under our data dir
	if err == nil && bytes.Equal(cur, content) {
		return nil
	}
	// The same structure with other server addresses, which the renderer has
	// already checked: running haproxy -c on it would only take time, on every
	// node, for every replica that comes or goes.
	if err == nil && sameStructure(cur, content) {
		return fsutil.WriteFileAtomic(cfgPath, content, 0o600)
	}
	next := cfgPath + ".new"
	if err := fsutil.WriteFileAtomic(next, content, 0o600); err != nil {
		return err
	}
	if err := d.cfg.Engine.Validate(ctx, containerConfDir+"/"+configFile+".new"); err != nil {
		_ = os.Remove(next)
		return fmt.Errorf("generated haproxy config is invalid, keeping the current one: %w", err)
	}
	return os.Rename(next, cfgPath)
}

func (d *Driver) commit(sig string, layout Layout, cfg proxy.Config) {
	d.sig = sig
	d.layout = layout
	d.applied = desiredServers(cfg, layout, d.options().node())
}

// slot is what a server slot serves: a replica's address and its weight
// (traffic splitting, ADR 0022).
type slot struct {
	Addr   string
	Weight int
}

func (d *Driver) setServer(ctx context.Context, key string, cur, want slot) error {
	if want.Addr == "" {
		_, err := d.cfg.API.Command(ctx, "set server "+key+" state maint")
		return err
	}
	if want.Weight != cur.Weight {
		if _, err := d.cfg.API.Command(ctx, fmt.Sprintf("set server %s weight %d", key, want.Weight)); err != nil {
			return err
		}
	}
	if want.Addr == cur.Addr {
		return nil // only the weight changed
	}
	ap, err := netip.ParseAddrPort(want.Addr)
	if err != nil {
		return err
	}
	if _, err := d.cfg.API.Command(ctx, fmt.Sprintf("set server %s addr %s port %d", key, ap.Addr(), ap.Port())); err != nil {
		return err
	}
	_, err = d.cfg.API.Command(ctx, "set server "+key+" state ready")
	return err
}

// writeCerts writes certificate files and removes stale ones. It returns the
// names whose content changed but which already existed (candidates for a
// live update); added or removed certificates change the signature and
// trigger a reload.
func (d *Driver) writeCerts(certs []proxy.Certificate) ([]string, error) {
	dir := filepath.Join(etcDir(d.cfg.Dir), certDir)
	want := map[string]bool{}
	var changed []string
	for _, c := range certs {
		name := c.FileName()
		want[name] = true
		sum := sha256.Sum256(c.PEM)
		h := hex.EncodeToString(sum[:])
		if d.certHash[name] == h {
			continue
		}
		if err := fsutil.WriteFileAtomic(filepath.Join(dir, name), c.PEM, 0o600); err != nil {
			return nil, err
		}
		if d.certHash[name] != "" {
			changed = append(changed, name)
		}
		d.certHash[name] = h
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !want[e.Name()] {
			_ = os.Remove(filepath.Join(dir, e.Name()))
			delete(d.certHash, e.Name())
		}
	}
	sort.Strings(changed)
	return changed, nil
}

func (d *Driver) updateCert(ctx context.Context, file string, cfg proxy.Config) error {
	var data []byte
	for _, c := range cfg.Certificates {
		if c.FileName() == file {
			data = c.PEM
		}
	}
	path := containerConfDir + "/" + certDir + "/" + file
	if _, err := d.cfg.API.Payload(ctx, "set ssl cert "+path, pemPayload(data)); err != nil {
		return err
	}
	_, err := d.cfg.API.Command(ctx, "commit ssl cert "+path)
	return err
}

var _ proxy.ClientSetter = (*Driver)(nil)

// maxClients bounds the clients map (a node subnet holds at most 253
// containers; this leaves room for anything).
const maxClients = 4096

// SetClients implements proxy.ClientSetter: it maps the addresses of this
// node's containers to their apps for the internal frontend's checks (ADR
// 0026). The map file is replaced for the next start or reload, and a
// running HAProxy gets the new map at once, atomically, through the
// Runtime API.
func (d *Driver) SetClients(ctx context.Context, clients map[netip.Addr]string) error {
	if d.cfg.Subnet == "" {
		return nil
	}
	content, err := clientsMap(clients, netip.MustParsePrefix(d.cfg.Subnet))
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.clients != nil && bytes.Equal(content, d.clients) {
		return nil
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(etcDir(d.cfg.Dir), clientsFile), content, 0o600); err != nil {
		return err
	}
	running, err := d.cfg.Engine.Running(ctx)
	if err != nil {
		return err
	}
	if running {
		if err := d.replaceMap(ctx, clientsFile, content); err != nil {
			return fmt.Errorf("update the clients map: %w", err)
		}
	}
	d.clients = content
	return nil
}

// clientsMap renders the clients map: one "<address> <project>:<app ID>"
// line per container of the node subnet, sorted. Every address and app is
// checked again, since they end up in the proxy.
func clientsMap(clients map[netip.Addr]string, subnet netip.Prefix) ([]byte, error) {
	if len(clients) > maxClients {
		return nil, fmt.Errorf("%d clients: at most %d", len(clients), maxClients)
	}
	addrs := make([]netip.Addr, 0, len(clients))
	for a, app := range clients {
		if !a.Is4() || !subnet.Contains(a) || !spec.ValidAppID(app) {
			return nil, fmt.Errorf("invalid client %s (%q)", a, app)
		}
		addrs = append(addrs, a)
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	var b bytes.Buffer
	for _, a := range addrs {
		project, _, _ := spec.SplitAppID(clients[a])
		fmt.Fprintf(&b, "%s %s:%s\n", a, project, clients[a])
	}
	return b.Bytes(), nil
}

// mapChunk bounds the lines sent in one command: HAProxy's Runtime API holds a
// payload in a buffer of 16 KiB by default.
const mapChunk = 8 << 10

// replaceMap swaps a map of the running HAProxy for content in one step: a new
// version is filled, then committed.
func (d *Driver) replaceMap(ctx context.Context, name string, content []byte) error {
	file := containerConfDir + "/" + name
	out, err := d.cfg.API.Command(ctx, "prepare map "+file)
	if err != nil {
		return err
	}
	ver, ok := strings.CutPrefix(strings.TrimSpace(out), "New version created:")
	ver = strings.TrimSpace(ver)
	if !ok || ver == "" || strings.Trim(ver, "0123456789") != "" {
		return fmt.Errorf("unexpected answer to prepare map: %q", out)
	}
	for _, chunk := range mapChunks(content, mapChunk) {
		if _, err := d.cfg.API.Payload(ctx, "add map @"+ver+" "+file, string(chunk)); err != nil {
			return err
		}
	}
	_, err = d.cfg.API.Command(ctx, "commit map @"+ver+" "+file)
	return err
}

// mapChunks splits content at line ends into pieces of about limit bytes.
func mapChunks(content []byte, limit int) [][]byte {
	var out [][]byte
	for len(content) > limit {
		cut := bytes.LastIndexByte(content[:limit], '\n') + 1
		if cut == 0 {
			cut = bytes.IndexByte(content, '\n') + 1
			if cut == 0 {
				break
			}
		}
		out = append(out, content[:cut])
		content = content[cut:]
	}
	if len(content) > 0 {
		out = append(out, content)
	}
	return out
}

// Health implements proxy.Driver.
func (d *Driver) Health(ctx context.Context) error {
	running, err := d.cfg.Engine.Running(ctx)
	if err != nil {
		return err
	}
	if !running {
		return errors.New("haproxy is not running")
	}
	_, err = d.cfg.API.Command(ctx, "show info")
	return err
}

// assignLayout keeps replicas in the slot they already occupy and puts new
// ones in the lowest free slot, for every slotted backend of a node.
func assignLayout(prev Layout, cfg proxy.Config, n node) Layout {
	next := Layout{}
	for _, p := range pools(cfg, n) {
		n := slotCount(len(p.servers))
		slots := make([]string, n)
		want := map[string]bool{}
		for _, s := range p.servers {
			want[s.Name] = true
		}
		for i, name := range prev[p.name] {
			if i < n && want[name] {
				slots[i] = name
				delete(want, name)
			}
		}
		for _, name := range sortedKeys(want) {
			for i := range slots {
				if slots[i] == "" {
					slots[i] = name
					break
				}
			}
		}
		next[p.name] = slots
	}
	return next
}

func desiredServers(cfg proxy.Config, layout Layout, n node) map[string]slot {
	out := map[string]slot{}
	for _, p := range pools(cfg, n) {
		slots := map[string]slot{}
		for _, s := range p.servers {
			slots[s.Name] = slot{Addr: s.Address, Weight: s.EffectiveWeight()}
		}
		for i, name := range layout[p.name] {
			// A free slot is rendered with the default weight.
			want, ok := slots[name]
			if !ok {
				want = slot{Weight: 1}
			}
			out[p.name+"/"+slotName(i)] = want
		}
	}
	return out
}

// signature captures everything that requires a reload: backends and their
// slot counts, health checks, routing rules, the certificate set, and
// node-specific settings. Server addresses are deliberately excluded.
func signature(cfg proxy.Config, layout Layout, opts renderOptions) string {
	type be struct {
		Name, Health string
		Slots        int
		Wake         bool
		LocalFirst   bool
		Timeout      int
		// Client address rules change what the backend lets through: a
		// change must reload, or the old rules would keep applying.
		IPAllow, IPDeny []string
	}
	s := struct {
		Opts     renderOptions
		ACME     string
		Trusted  []string
		Backends []be
		Rules    []proxy.Rule
		Certs    []string
	}{Opts: opts, ACME: cfg.ACMEAddress, Trusted: cfg.TrustedProxies}
	for _, b := range cfg.Backends {
		s.Backends = append(s.Backends, be{b.Name, b.HealthPath, len(layout[backendName(b.Name)]), b.Wake, b.LocalFirst, b.TimeoutSeconds, b.IPAllow, b.IPDeny})
	}
	slices.SortFunc(s.Backends, func(a, b be) int { return strings.Compare(a.Name, b.Name) })
	s.Rules = slices.Clone(cfg.Rules)
	slices.SortFunc(s.Rules, func(a, b proxy.Rule) int { return strings.Compare(a.Host+a.PathPrefix, b.Host+b.PathPrefix) })
	for _, c := range cfg.Certificates {
		s.Certs = append(s.Certs, c.Name)
	}
	slices.Sort(s.Certs)
	b, _ := json.Marshal(s)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// selfSignedPEM creates the fallback certificate served for unknown SNI
// names, so HAProxy can start before any real certificate exists.
func selfSignedPEM() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "armada-default"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...), nil
}
