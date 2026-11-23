//go:build linux

package clusternet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/encoding/protojson"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// The cluster network through armada-node (ADR 0054). With
// Config.Program, Apply, Up, UnreachablePeers, RotateKey, and the probe of
// a switch run `armada-node net ...`; Remove and Diagnose take the program
// as an argument (RemoveWith, DiagnoseWith). Net keeps what both
// implementations keep between passes in its own fields: armada-node gets
// it with every pass and gives it back, so either can do the next pass.
// The isolation policy is the exception: each side keeps the one it
// applied, and a pass after the other side's rebuilds the tables (they hold
// the same rules, but nothing is assumed).
//
// When armada-node fails, or the pass needs the userspace WireGuard
// device, which stays in Go, Go does the pass: Apply is a full,
// idempotent sync of the node, so whatever the failed pass left is set
// right. While the userspace device runs, every pass is Go's.

// programTimeout bounds one call of armada-node; Go does the pass when it
// takes longer.
var programTimeout = 2 * time.Minute

// programRun is what Net keeps about armada-node's passes. Net.mu guards
// it.
type programRun struct {
	// last is set while the last pass was armada-node's, and previous the
	// isolation policy it applied, as it wrote it.
	last     bool
	previous json.RawMessage
	// errs is the last error of each call (op), to log a failure once.
	errs map[string]string
	// noFallback makes armada-node's error the pass's (tests).
	noFallback bool
	// done is what armada-node's last pass changed (tests).
	done []string
}

// errUserspace: armada-node leaves the userspace WireGuard device to Go.
var errUserspace = errors.New("the pass needs the userspace WireGuard device, which the Go agent runs")

// programState is what armada-node reads and writes as State: Net's
// fields between passes.
type programState struct {
	Previous json.RawMessage
	Clean    struct{ Next, Site bool }
	Switch   programSwitch
	Since    []programSeen `json:",omitempty"`
	Last     string
}

type programSwitch struct {
	To, Step, Error        string
	Peers                  []string `json:",omitempty"`
	Reached                []string `json:",omitempty"`
	Probed, Probing, Moved bool
}

type programSeen struct {
	Key, Node string
	Since     int64
}

// programRequest is a request of net apply and net up.
type programRequest struct {
	Config    json.RawMessage
	Node      string
	PrivateIP string
	Endpoint  string
	MeshCache string
	UplinkMTU int
	Key       string
	Local     map[string]string
	Userspace bool
	State     programState
}

// programAnswer is what net apply and net up print.
type programAnswer struct {
	Error          string        `json:"error"`
	NeedsUserspace bool          `json:"needsUserspace"`
	State          *programState `json:"state"`
	Probe          *probeRequest `json:"probe"`
	Done           []string      `json:"done"`
	Log            []struct {
		Level string `json:"level"`
		Msg   string `json:"msg"`
	} `json:"log"`
}

// probeRequest is a probe armada-node's pass started: from this node's
// tunnel address to every peer's.
type probeRequest struct {
	From  string `json:"from"`
	Peers []struct {
		Node    string `json:"node"`
		Address string `json:"address"`
	} `json:"peers"`
}

// program returns the armada-node to run, "" for none.
func (n *Net) program() string {
	if n.cfg.Program == nil {
		return ""
	}
	return n.cfg.Program()
}

// runProgram runs bin with args and stdin, returning its output; the
// error carries the program's last words.
func runProgram(ctx context.Context, bin string, stdin []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, programTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // the runtime pack's armada-node
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			err = fmt.Errorf("%w: %s", err, msg)
		}
	}
	return out, err
}

// note logs what an armada-node call (op) ended in, once per distinct
// error. n.mu is held.
func (n *Net) note(op string, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if n.prog.errs == nil {
		n.prog.errs = map[string]string{}
	}
	prev, seen := n.prog.errs[op]
	n.prog.errs[op] = msg
	switch {
	case seen && prev == msg:
	case err == nil:
		if op == "apply" {
			n.log.Info("armada-node applies the cluster network")
		}
	case errors.Is(err, errUserspace):
		n.log.Info("the kernel has no WireGuard; Go applies the cluster network with its userspace device")
	case n.prog.noFallback:
		n.log.Warn("armada-node failed", "op", op, "err", err)
	default:
		n.log.Warn("armada-node failed; Go did it instead", "op", op, "err", err)
	}
}

// viaProgram runs Apply (op "apply") or Up ("up") through armada-node.
// done is false when Go must do the pass: no program, the userspace
// device, or a failure.
func (n *Net) viaProgram(ctx context.Context, op string, cfg *armadav1.NetworkConfig, local map[netip.Addr]string) (done bool, err error) {
	bin := n.program()
	if bin == "" {
		return false, nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.user != nil {
		return false, nil
	}
	err = n.pass(ctx, bin, op, cfg, local)
	n.note(op, err)
	if err == nil || n.prog.noFallback {
		return true, err
	}
	return false, nil
}

// pass runs one pass of armada-node and takes the state it gives back.
// n.mu is held.
func (n *Net) pass(ctx context.Context, bin, op string, cfg *armadav1.NetworkConfig, local map[netip.Addr]string) error {
	req := programRequest{Config: json.RawMessage("null"), Node: n.cfg.Node, PrivateIP: n.cfg.PrivateIP.String(),
		MeshCache: n.cfg.MeshCache, UplinkMTU: n.cfg.UplinkMTU, State: n.programState()}
	if cfg != nil {
		b, err := protojson.Marshal(cfg)
		if err != nil {
			return err
		}
		req.Config = b
	}
	if n.cfg.Endpoint.IsValid() {
		req.Endpoint = n.cfg.Endpoint.String()
	}
	if !n.cfg.Key.IsZero() {
		req.Key = n.cfg.Key.k.String()
	}
	if local != nil {
		req.Local = make(map[string]string, len(local))
		for a, app := range local {
			req.Local[a.String()] = app
		}
	}
	in, err := json.Marshal(req)
	if err != nil {
		return err
	}
	out, runErr := runProgram(ctx, bin, in, "net", op)
	var a programAnswer
	if err := json.Unmarshal(out, &a); err != nil || a.State == nil {
		// Nothing is known of what it did: the isolation tables are built
		// again, and the firewall rules of interfaces gone checked again.
		n.prog.last, n.prog.previous = true, nil
		n.nextClean, n.siteClean = false, false
		if runErr == nil {
			runErr = errors.New("unreadable answer")
		}
		return fmt.Errorf("armada-node net %s: %w", op, runErr)
	}
	n.takeProgramState(*a.State)
	n.prog.done = a.Done
	for _, l := range a.Log {
		if l.Level == "warn" {
			n.log.Warn(l.Msg)
		} else {
			n.log.Info(l.Msg)
		}
	}
	switch {
	case a.NeedsUserspace:
		return errUserspace
	case a.Error != "":
		return errors.New(a.Error)
	}
	if a.Probe != nil {
		probe, fallback := *a.Probe, !n.prog.noFallback
		n.startProbe(n.sw.to, n.sw.step, func() (map[string]bool, error) { return probeVia(bin, probe, fallback) })
	}
	return nil
}

// takeOver readies Net for a pass of Go's after one of armada-node's: Go
// builds the isolation tables again. n.mu is held.
func (n *Net) takeOver() {
	if n.prog.last {
		n.prog.last, n.prog.previous = false, nil
		n.isolated = nil
	}
}

// programState writes Net's fields as armada-node reads them. n.mu is
// held.
func (n *Net) programState() programState {
	st := programState{Previous: json.RawMessage("null"), Last: n.last}
	if n.prog.last && n.prog.previous != nil {
		// Only what armada-node applied itself; after a pass of Go's it
		// builds the tables again.
		st.Previous = n.prog.previous
	}
	st.Clean.Next, st.Clean.Site = n.nextClean, n.siteClean
	st.Switch = programSwitch{To: n.sw.to, Step: n.sw.step, Error: n.sw.err, Peers: slices.Clone(n.sw.peers),
		Probed: n.sw.probed, Probing: n.sw.probing, Moved: n.sw.moved}
	for _, name := range slices.Sorted(maps.Keys(n.sw.reached)) {
		if n.sw.reached[name] {
			st.Switch.Reached = append(st.Switch.Reached, name)
		}
	}
	st.Since = sinceOut(n.wgSince)
	return st
}

// sinceOut writes when each WireGuard peer was first configured, sorted by
// key, in Unix seconds.
func sinceOut(since map[wgtypes.Key]wgPeerSeen) []programSeen {
	out := make([]programSeen, 0, len(since))
	for k, s := range since {
		out = append(out, programSeen{Key: k.String(), Node: s.node, Since: s.since.Unix()})
	}
	slices.SortFunc(out, func(a, b programSeen) int { return strings.Compare(a.Key, b.Key) })
	return out
}

// takeProgramState sets Net's fields from what armada-node gave back.
// n.mu is held.
func (n *Net) takeProgramState(st programState) {
	n.prog.last, n.prog.previous = true, bytes.Clone(st.Previous)
	n.nextClean, n.siteClean = st.Clean.Next, st.Clean.Site
	sw := switchState{to: st.Switch.To, step: st.Switch.Step, err: st.Switch.Error, peers: st.Switch.Peers,
		probed: st.Switch.Probed, probing: st.Switch.Probing, moved: st.Switch.Moved}
	if st.Switch.Probed {
		sw.reached = map[string]bool{}
		for _, name := range st.Switch.Reached {
			sw.reached[name] = true
		}
	}
	n.sw = sw
	since := make(map[wgtypes.Key]wgPeerSeen, len(st.Since))
	for _, s := range st.Since {
		if k, err := wgtypes.ParseKey(s.Key); err == nil {
			since[k] = wgPeerSeen{node: s.Node, since: time.Unix(s.Since, 0)}
		}
	}
	if len(since) == 0 {
		since = nil
	}
	n.wgSince = since
	n.last = st.Last
}

// probeVia runs armada-node's probe, and with fallback Go's ping when the
// program does not answer. It runs on a thread in the node's network
// namespace (inNamespace), which the program inherits.
func probeVia(bin string, req probeRequest, fallback bool) (map[string]bool, error) {
	in, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	out, runErr := runProgram(context.Background(), bin, in, "net", "probe")
	var a struct {
		Reached []string `json:"reached"`
		Error   string   `json:"error"`
	}
	if err := json.Unmarshal(out, &a); err != nil || runErr != nil {
		if !fallback {
			return map[string]bool{}, fmt.Errorf("armada-node net probe: %w", errors.Join(runErr, err))
		}
		return goProbe(req)
	}
	reached := map[string]bool{}
	for _, name := range a.Reached {
		reached[name] = true
	}
	if a.Error != "" {
		return reached, errors.New(a.Error)
	}
	return reached, nil
}

// goProbe is Go's ping of what armada-node asked to probe.
func goProbe(req probeRequest) (map[string]bool, error) {
	from, err := netip.ParseAddr(req.From)
	if err != nil {
		return map[string]bool{}, err
	}
	var peers []peer
	for _, t := range req.Peers {
		a, err := netip.ParseAddr(t.Address)
		if err != nil {
			continue
		}
		peers = append(peers, peer{node: t.Node, subnet: netip.PrefixFrom(a, subnetBits)})
	}
	return ping(from, peers, probeWait)
}

// unreachableViaProgram is UnreachablePeers through armada-node, which
// reads the kernel's devices: done is false when Go must answer (no
// program, the userspace device, or a failure).
func (n *Net) unreachableViaProgram(since map[wgtypes.Key]wgPeerSeen, user bool) (peers []string, done bool) {
	bin := n.program()
	if bin == "" || user {
		return nil, false
	}
	in, err := json.Marshal(map[string]any{"Since": sinceOut(since)})
	if err != nil {
		return nil, false
	}
	out, err := runProgram(context.Background(), bin, in, "net", "unreachable")
	var a struct {
		Peers []string `json:"peers"`
	}
	if err == nil {
		err = json.Unmarshal(out, &a)
	}
	n.mu.Lock()
	n.note("unreachable", err)
	strict := n.prog.noFallback
	n.mu.Unlock()
	if err != nil {
		return nil, strict
	}
	if len(a.Peers) == 0 {
		return nil, true
	}
	return a.Peers, true
}

// rotateViaProgram is RotateKey through armada-node: it writes the new
// key, which Net then reads. n.mu is held.
func (n *Net) rotateViaProgram() (pub string, done bool, err error) {
	bin := n.program()
	if bin == "" {
		return "", false, nil
	}
	out, err := runProgram(context.Background(), bin, nil, "net", "key", "rotate", n.cfg.KeyPath)
	if err == nil {
		var k PrivateKey
		if k, err = LoadOrCreateKey(n.cfg.KeyPath); err == nil {
			if k.Public() == strings.TrimSpace(string(out)) {
				n.note("rotate-key", nil)
				n.cfg.Key = k
				n.log.Info("made a new network key")
				return k.Public(), true, nil
			}
			err = errors.New("the key file does not hold the key armada-node made")
		}
	}
	n.note("rotate-key", err)
	if n.prog.noFallback {
		return "", true, err
	}
	return "", false, nil
}

// RemoveWith is Remove through armada-node (bin, "" for Go), and Go's
// Remove when armada-node fails.
func RemoveWith(bin string) error {
	if bin == "" {
		return Remove()
	}
	if _, err := runProgram(context.Background(), bin, nil, "net", "remove"); err == nil {
		return nil
	}
	return Remove()
}

// DiagnoseWith is Diagnose through armada-node (bin, "" for Go), and Go's
// when armada-node fails or the node's WireGuard runs in userspace.
func DiagnoseWith(bin, mode string, ip, endpoint netip.Addr, sites Sites) []Check {
	if bin != "" {
		if out, ok := diagnoseVia(bin, mode, ip, endpoint, sites); ok {
			return out
		}
	}
	return Diagnose(mode, ip, endpoint, sites)
}

func diagnoseVia(bin, mode string, ip, endpoint netip.Addr, sites Sites) ([]Check, bool) {
	text := func(a netip.Addr) string {
		if a.IsValid() {
			return a.String()
		}
		return ""
	}
	in, err := json.Marshal(map[string]string{"Mode": mode, "PrivateIP": text(ip), "Endpoint": text(endpoint),
		"Cache": sites.Cache, "Node": sites.Node})
	if err != nil {
		return nil, false
	}
	out, err := runProgram(context.Background(), bin, in, "net", "diagnose")
	if err != nil {
		return nil, false
	}
	var a struct {
		Checks []struct {
			Name   string `json:"name"`
			Level  int    `json:"level"`
			Detail string `json:"detail"`
		} `json:"checks"`
		NeedsUserspace bool `json:"needsUserspace"`
	}
	if err := json.Unmarshal(out, &a); err != nil || a.NeedsUserspace || len(a.Checks) == 0 {
		return nil, false
	}
	checks := make([]Check, 0, len(a.Checks))
	for _, c := range a.Checks {
		checks = append(checks, Check{Name: c.Name, Level: c.Level, Detail: c.Detail})
	}
	return checks, true
}
