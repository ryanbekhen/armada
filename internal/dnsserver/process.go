package dnsserver

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ryanbekhen/armada/internal/netutil"
)

// UnitPrefix names the systemd units armada-dns runs in (ADR 0053).
const UnitPrefix = "armada-dns-"

const (
	// controlTimeout bounds one request to armada-dns.
	controlTimeout = 5 * time.Second
	// readyTimeout is how long a new armada-dns has to open its control
	// socket.
	readyTimeout = 5 * time.Second
	// keepEvery is how often the agent checks armada-dns still runs, and
	// tells a process that restarted what it knows.
	keepEvery = 5 * time.Second
)

// Launcher starts and stops the units armada-dns runs in; tests replace
// systemd with plain processes.
type Launcher interface {
	// Start runs argv as unit, restarted by its manager when it exits.
	Start(ctx context.Context, unit string, argv []string) error
	// Stop stops unit; a unit that does not run is no error.
	Stop(ctx context.Context, unit string) error
	// Units lists the units whose name starts with UnitPrefix and run.
	Units(ctx context.Context) ([]string, error)
}

// ProcessConfig configures a Process.
type ProcessConfig struct {
	// Bin is the armada-dns program.
	Bin string
	// Addr, Port, Clients, Upstreams, UnknownWait, and StartWait mean what
	// they mean in Config.
	Addr        netip.Addr
	Port        uint16
	Clients     netip.Prefix
	Upstreams   []string
	UnknownWait time.Duration
	StartWait   time.Duration
	// Dir holds the control sockets (root-only).
	Dir string
	// Launcher defaults to systemd.
	Launcher Launcher
	Logger   *slog.Logger
}

// Process is the node-local resolver run by armada-dns (ADR 0053): a
// program of its own, in a systemd unit of its own, so it keeps answering
// while armadad restarts. It implements what the agent asks of Server.
type Process struct {
	cfg  ProcessConfig
	log  *slog.Logger
	unit string
	sock string
	argv []string

	mu sync.Mutex
	// names and clients are what the agent said last (nil: not yet);
	// epoch is the process that heard it.
	names   []string
	clients map[netip.Addr]string
	epoch   string
}

// StartProcess runs armada-dns, or finds it running from an earlier
// armadad. A unit of another program or other settings (an upgrade) hands
// what it knows to the new one, which reads it before it binds the port;
// both listen on the address (SO_REUSEPORT) until the old one is stopped,
// so no lookup goes unanswered.
func StartProcess(ctx context.Context, cfg ProcessConfig) (*Process, error) {
	if !cfg.Addr.IsValid() || !cfg.Addr.Is4() || !netutil.IsPrivate(cfg.Addr) {
		return nil, fmt.Errorf("dns: listen address %s must be a private IPv4 address", cfg.Addr)
	}
	if !cfg.Clients.IsValid() || !cfg.Clients.Addr().Is4() {
		return nil, errors.New("dns: an IPv4 client range is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 53
	}
	if cfg.Launcher == nil {
		cfg.Launcher = systemd{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	bin, err := os.ReadFile(cfg.Bin)
	if err != nil {
		return nil, fmt.Errorf("dns: %w", err)
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("dns: %w", err)
	}
	p := &Process{cfg: cfg, log: cfg.Logger.With("component", "dns")}
	h := sha256.New()
	h.Write(bin)
	args := []string{
		"--listen", netip.AddrPortFrom(cfg.Addr, cfg.Port).String(),
		"--clients", cfg.Clients.Masked().String(),
	}
	for _, u := range cfg.Upstreams {
		args = append(args, "--upstream", u)
	}
	if cfg.UnknownWait > 0 {
		args = append(args, "--unknown-wait-ms", strconv.FormatInt(cfg.UnknownWait.Milliseconds(), 10))
	}
	if cfg.StartWait > 0 {
		args = append(args, "--start-wait-ms", strconv.FormatInt(cfg.StartWait.Milliseconds(), 10))
	}
	for _, a := range args {
		h.Write([]byte{0})
		h.Write([]byte(a))
	}
	id := hex.EncodeToString(h.Sum(nil))[:16]
	p.unit = UnitPrefix + id
	p.sock = filepath.Join(cfg.Dir, id+".sock")
	p.argv = append([]string{cfg.Bin}, append(args, "--control", p.sock)...)
	if err := p.ensure(ctx); err != nil {
		return nil, err
	}
	p.handOver(ctx)
	return p, nil
}

// Address is where containers send their lookups.
func (p *Process) Address() string { return p.cfg.Addr.String() }

// Unit names the systemd unit armada-dns runs in.
func (p *Process) Unit() string { return p.unit }

// ensure makes the unit answer: as it is, or started (again).
func (p *Process) ensure(ctx context.Context) error {
	if _, err := p.call(ctx, "epoch"); err == nil {
		return nil
	}
	units, err := p.cfg.Launcher.Units(ctx)
	if err != nil {
		return fmt.Errorf("dns: %w", err)
	}
	if slices.Contains(units, p.unit) {
		// Starting, or stuck: give it the time a start has.
		if p.waitReady(ctx) == nil {
			return nil
		}
		if err := p.cfg.Launcher.Stop(ctx, p.unit); err != nil {
			return fmt.Errorf("dns: %w", err)
		}
	}
	argv := p.argv
	for _, u := range units {
		if u != p.unit && strings.HasPrefix(u, UnitPrefix) {
			// It answers until stopped: the new process starts with what
			// it knows, before it shares the port (handOver stops it).
			argv = append(slices.Clone(argv), "--take-over", p.oldSocket(u))
		}
	}
	if err := p.cfg.Launcher.Start(ctx, p.unit, argv); err != nil {
		return fmt.Errorf("dns: start %s: %w", p.unit, err)
	}
	if err := p.waitReady(ctx); err != nil {
		_ = p.cfg.Launcher.Stop(ctx, p.unit)
		return fmt.Errorf("dns: %s did not answer: %w", p.unit, err)
	}
	p.log.Info("internal DNS started", "unit", p.unit, "addr", p.cfg.Addr, "upstreams", p.cfg.Upstreams)
	return nil
}

func (p *Process) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(readyTimeout)
	for {
		_, err := p.call(ctx, "epoch")
		if err == nil || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// oldSocket is the control socket of another armada-dns unit.
func (p *Process) oldSocket(unit string) string {
	return filepath.Join(p.cfg.Dir, strings.TrimPrefix(unit, UnitPrefix)+".sock")
}

// handOver stops every other armada-dns unit: an older program or other
// settings, whose names and clients the new process took over.
func (p *Process) handOver(ctx context.Context) {
	units, err := p.cfg.Launcher.Units(ctx)
	if err != nil {
		p.log.Warn("cannot list internal DNS units", "err", err)
		return
	}
	for _, u := range units {
		if u == p.unit || !strings.HasPrefix(u, UnitPrefix) {
			continue
		}
		// The new process shares the port: the old one leaves it every new
		// lookup and answers those it holds before it stops.
		if _, err := control(ctx, p.oldSocket(u), "drain"); err != nil {
			p.log.Warn("old internal DNS did not drain", "unit", u, "err", err)
		}
		if err := p.cfg.Launcher.Stop(ctx, u); err != nil {
			p.log.Warn("cannot stop the old internal DNS", "unit", u, "err", err)
			continue
		}
		_ = os.Remove(p.oldSocket(u))
		_ = os.Remove(strings.TrimSuffix(p.oldSocket(u), ".sock") + ".state")
		p.log.Info("internal DNS handed over", "from", u, "to", p.unit)
	}
}

// SetNames replaces the names that resolve under .internal.
func (p *Process) SetNames(apps []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.names = append([]string{}, apps...)
	if p.names == nil {
		p.names = []string{}
	}
	p.push(namesLine(p.names))
}

// SetClients maps the node's container addresses to their app IDs.
func (p *Process) SetClients(clients map[netip.Addr]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients = make(map[netip.Addr]string, len(clients))
	for a, app := range clients {
		p.clients[a] = app
	}
	p.push(clientsLine(p.clients))
}

func namesLine(names []string) string { return strings.Join(append([]string{"names"}, names...), " ") }

func clientsLine(clients map[netip.Addr]string) string {
	words := make([]string, 0, len(clients)+1)
	words = append(words, "clients")
	for a, app := range clients {
		if a.Is4() {
			words = append(words, a.String()+"="+app)
		}
	}
	slices.Sort(words[1:])
	return strings.Join(words, " ")
}

// push sends one request with p.mu held. A process that has not heard
// everything yet (a new one, or after a failure) is told all of it; a
// failure is retried by Run.
func (p *Process) push(line string) {
	ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
	defer cancel()
	reply, err := p.call(ctx, line)
	if err != nil {
		p.log.Warn("internal DNS did not take the update; retrying", "err", err)
		p.epoch = ""
		return
	}
	if epoch := strings.TrimPrefix(reply, "ok "); epoch != p.epoch {
		p.epoch = ""
		for _, l := range p.lines() {
			if _, err := p.call(ctx, l); err != nil {
				p.log.Warn("internal DNS did not take the update; retrying", "err", err)
				return
			}
		}
		p.epoch = epoch
	}
}

// Run keeps armada-dns running and up to date until ctx ends: a process
// that restarted, or one that missed an update, hears everything again.
func (p *Process) Run(ctx context.Context) error {
	t := time.NewTicker(keepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		p.keep(ctx)
	}
}

func (p *Process) keep(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, readyTimeout+2*controlTimeout)
	defer cancel()
	if err := p.ensure(cctx); err != nil {
		p.log.Warn("internal DNS is not running", "err", err)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	reply, err := p.call(cctx, "epoch")
	if err != nil {
		return
	}
	epoch := strings.TrimPrefix(reply, "ok ")
	if epoch == p.epoch {
		return
	}
	for _, line := range p.lines() {
		if _, err := p.call(cctx, line); err != nil {
			p.log.Warn("internal DNS did not take the update; retrying", "err", err)
			return
		}
	}
	p.epoch = epoch
}

// lines is everything the agent said, as requests.
func (p *Process) lines() []string {
	var out []string
	if p.clients != nil {
		out = append(out, clientsLine(p.clients))
	}
	if p.names != nil {
		out = append(out, namesLine(p.names))
	}
	return out
}

func (p *Process) call(ctx context.Context, line string) (string, error) {
	return control(ctx, p.sock, line)
}

// control sends one request line to the armada-dns at sock and returns
// its answer without the trailing line break.
func control(ctx context.Context, sock, line string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
	if _, err := io.WriteString(c, line+"\n"); err != nil {
		return "", err
	}
	b, err := io.ReadAll(bufio.NewReader(io.LimitReader(c, 64<<20)))
	if err != nil {
		return "", err
	}
	reply := strings.TrimSuffix(string(b), "\n")
	if rest, ok := strings.CutPrefix(reply, "err "); ok {
		return "", fmt.Errorf("armada-dns: %s", rest)
	}
	if reply == "" {
		return "", errors.New("armada-dns: no answer")
	}
	return reply, nil
}

// systemd runs armada-dns as a transient service that restarts when it
// exits, outside armadad's cgroup so it outlives it.
type systemd struct{}

func (systemd) Start(ctx context.Context, unit string, argv []string) error {
	args := append([]string{
		"--unit=" + unit, "--collect", "--quiet",
		"--property=Restart=always",
		"--property=RestartSec=100ms",
		"--property=OOMScoreAdjust=-900",
		"--property=LimitNOFILE=65536",
		"--",
	}, argv...)
	out, err := exec.CommandContext(ctx, "systemd-run", args...).CombinedOutput() //nolint:gosec // argv names the pack's armada-dns and settings the agent built
	if err != nil {
		return fmt.Errorf("systemd-run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (systemd) Stop(ctx context.Context, unit string) error {
	out, err := exec.CommandContext(ctx, "systemctl", "stop", "--", unit).CombinedOutput() //nolint:gosec // the unit name is built from a hash
	if err != nil && !strings.Contains(string(out), "not loaded") {
		return fmt.Errorf("systemctl stop %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (systemd) Units(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "list-units", "--plain", "--no-legend", "--state=active,activating,reloading,deactivating", "--", UnitPrefix+"*").Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl list-units: %w", err)
	}
	var units []string
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			units = append(units, strings.TrimSuffix(f[0], ".service"))
		}
	}
	return units, nil
}

// StopUnits stops every armada-dns unit (armadad runtime reset).
func StopUnits(ctx context.Context) error {
	s := systemd{}
	units, err := s.Units(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, u := range units {
		errs = append(errs, s.Stop(ctx, u))
	}
	return errors.Join(errs...)
}
