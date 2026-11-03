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
	Engine     Engine
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

// Apply implements proxy.Driver.
func (d *Driver) Apply(ctx context.Context, cfg proxy.Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("refusing invalid proxy config: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	layout := assignLayout(d.layout, cfg)
	opts := renderOptions{PrivateIP: d.cfg.PrivateIP, InternalIP: d.cfg.InternalIP}
	sig := signature(cfg, layout, opts)
	content := render(cfg, layout, opts)
	if content == nil {
		return errors.New("refusing proxy config: an interpolated value is not a single token")
	}

	changedCerts, err := d.writeCerts(cfg.Certificates)
	if err != nil {
		return err
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
		d.log.Info("haproxy started")
		return nil
	}

	if err := d.writeValidated(ctx, cfgPath, content); err != nil {
		return err
	}

	if sig != d.sig {
		if err := d.cfg.Engine.Reload(ctx); err != nil {
			return fmt.Errorf("reload haproxy: %w", err)
		}
		d.commit(sig, layout, cfg)
		d.log.Info("haproxy reloaded")
		return nil
	}

	// Same structure: update servers and certificates live. New servers are
	// enabled before old ones leave, so a backend never runs empty in
	// between (one replica being replaced by another).
	desired := desiredServers(cfg, layout)
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
	for _, name := range changedCerts {
		if err := d.updateCert(ctx, name, cfg); err != nil {
			return err
		}
	}
	d.layout = layout
	return nil
}

// writeValidated writes content next to the live config, validates it, and
// only then replaces the live file.
func (d *Driver) writeValidated(ctx context.Context, cfgPath string, content []byte) error {
	if cur, err := os.ReadFile(cfgPath); err == nil && bytes.Equal(cur, content) { //nolint:gosec // path under our data dir
		return nil
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
	d.applied = desiredServers(cfg, layout)
}

// slot is what a server slot serves: a replica's address and its weight
// (traffic splitting, ADR 0024).
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
	if _, err := d.cfg.API.Payload(ctx, "set ssl cert "+path, string(data)); err != nil {
		return err
	}
	_, err := d.cfg.API.Command(ctx, "commit ssl cert "+path)
	return err
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
// ones in the lowest free slot.
func assignLayout(prev Layout, cfg proxy.Config) Layout {
	next := Layout{}
	for _, be := range cfg.Backends {
		n := slotCount(len(be.Servers))
		slots := make([]string, n)
		want := map[string]bool{}
		for _, s := range be.Servers {
			want[s.Name] = true
		}
		for i, name := range prev[be.Name] {
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
		next[be.Name] = slots
	}
	return next
}

func desiredServers(cfg proxy.Config, layout Layout) map[string]slot {
	out := map[string]slot{}
	for _, be := range cfg.Backends {
		slots := map[string]slot{}
		for _, s := range be.Servers {
			slots[s.Name] = slot{Addr: s.Address, Weight: s.EffectiveWeight()}
		}
		for i, name := range layout[be.Name] {
			// A free slot is rendered with the default weight.
			want, ok := slots[name]
			if !ok {
				want = slot{Weight: 1}
			}
			out[backendName(be.Name)+"/"+slotName(i)] = want
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
	}
	s := struct {
		Opts     renderOptions
		ACME     string
		Backends []be
		Rules    []proxy.Rule
		Certs    []string
	}{Opts: opts, ACME: cfg.ACMEAddress}
	for _, b := range cfg.Backends {
		s.Backends = append(s.Backends, be{b.Name, b.HealthPath, len(layout[b.Name]), b.Wake})
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
