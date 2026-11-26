package agent

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// Recording the agent's scenarios for the Rust replay (ADR 0055, item
// 20). With -record-scenarios, runAgentParity runs each scenario against
// Go's agent only and writes agent/tests/testdata/scenarios/<test>/<name>.json:
// the scenario's options and every step it took (assignments, passes,
// waits for a probe's verdict, clock moves, usage samples, contact, fence,
// prune, rotations, moves, the sessions' requests, and every change to
// what the fakes answer: pfake's script, containers added or changed, the
// fake armada-node's script, the control plane's stream input, the log
// endpoint's status), each with the transcript lines Go's run wrote for
// it. agent/tests/scenarios.rs replays them against the Rust agent's
// parity program with the fakes ported to Rust and compares the lines.
// The spec hash and reconnect timing are recorded the same way
// (hash.json, reconnect.json).

var recordScenarios = flag.Bool("record-scenarios", false,
	"write agent/tests/testdata/scenarios (each scenario's steps and Go's transcript) for the Rust replay")

// agentFixtures is where the recordings go, from this package.
const agentFixtures = "../../agent/tests/testdata"

// agentRec records one scenario's steps.
type agentRec struct {
	p     *parityRun
	mu    sync.Mutex
	steps []map[string]any
	depth int
	// collecting holds the actions of an other or side step while its
	// function runs.
	collecting *[]map[string]any
	// export is the log endpoint's URL, written as $EXPORT.
	export string
}

func (r *agentRec) add(step map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, step)
}

// begin starts a step that writes transcript lines; the returned function
// ends it, keeping the lines written since.
func (r *agentRec) begin(step map[string]any) func() {
	if r == nil {
		return func() {}
	}
	start := len(r.p.out)
	r.depth++
	return func() {
		r.depth--
		step["expect"] = r.lines(r.p.out[start:])
		r.add(step)
	}
}

func (r *agentRec) lines(ls []string) []string {
	out := []string{}
	for _, l := range ls {
		if r.export != "" {
			l = strings.ReplaceAll(l, r.export, "$EXPORT")
		}
		out = append(out, l)
	}
	return out
}

// action is a call of the agent: a step of its own at the top level, part
// of the step whose function runs, or nothing inside the harness's steps.
func (r *agentRec) action(a map[string]any) {
	if r == nil {
		return
	}
	switch {
	case r.collecting != nil:
		*r.collecting = append(*r.collecting, a)
	case r.depth == 0:
		r.add(a)
	}
}

// note is called for every transcript line the scenario adds itself.
func (r *agentRec) note(kind string) {
	if r == nil {
		return
	}
	switch {
	case r.collecting != nil:
		if n := len(*r.collecting); n > 0 {
			(*r.collecting)[n-1]["note"] = kind
		}
	case r.depth == 0:
		r.mu.Lock()
		from := ""
		for i := len(r.steps) - 1; i >= 0; i-- {
			if op, _ := r.steps[i]["op"].(string); op == "hello" {
				from = op
				break
			}
		}
		r.mu.Unlock()
		r.add(map[string]any{"op": "note", "kind": kind, "from": from, "expect": r.lines(r.p.out[len(r.p.out)-1:])})
	}
}

// change records a change to what the fakes answer.
func (r *agentRec) change(op map[string]any) {
	if r != nil {
		r.add(op)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func b64s(bs [][]byte) []string {
	out := []string{}
	for _, b := range bs {
		out = append(out, b64(b))
	}
	return out
}

func wireRecords(rs []runtime.LogRecord) []map[string]any {
	out := []map[string]any{}
	for _, r := range rs {
		out = append(out, map[string]any{"timeNs": unixNs(r.Time), "stderr": r.Stream == runtime.Stderr, "data": b64(r.Data),
			"replica": r.Replica, "container": r.Container, "app": r.App, "revision": r.Revision})
	}
	return out
}

// script is everything a scenario may set on the fake, under its lock.
func (f *pfake) script() map[string]any {
	errs := map[string]any{}
	for k, e := range f.pullErr {
		errs[k] = wireError(e)
	}
	usage := map[string]any{}
	for k, u := range f.usage {
		usage[k] = map[string]any{"cpuNs": int64(u.CPU), "memoryBytes": u.MemoryBytes, "egressBytes": u.EgressBytes, "networkLost": u.NetworkLost, "oomKills": u.OOMKills}
	}
	load := map[string]any{}
	for k, l := range f.in.load {
		load[k] = map[string]int64{"inFlight": l.InFlight, "total": l.Total}
	}
	certs := map[string]string{}
	for k, c := range f.in.certs {
		certs[k] = b64(c)
	}
	frames := map[string]any{}
	for id, fs := range f.side.frames {
		var out []map[string]any
		for _, fr := range fs {
			out = append(out, map[string]any{"stderr": fr.Stream == runtime.Stderr, "data": b64(fr.Data), "timeNs": unixNs(fr.Time)})
		}
		frames[id] = out
	}
	var switching json.RawMessage
	if f.in.switching != nil {
		switching = json.RawMessage(compact(f.in.switching))
	}
	return map[string]any{
		"pullErr": errs, "runErr": maps.Clone(f.runErr), "digests": maps.Clone(f.digests), "platforms": maps.Clone(f.platforms),
		"initExits": maps.Clone(f.initExits), "holdStarts": f.holdStarts, "usage": usage,
		"agentStatus": map[string]any{"agent": f.agentStatus.Agent, "goImages": f.agentStatus.GoImages, "converted": f.agentStatus.Converted,
			"imagesToPull": f.agentStatus.ImagesToPull, "error": f.agentStatus.Error},
		"checks": maps.Clone(f.checks), "execCodes": maps.Clone(f.execCodes), "holdPulls": f.pullHold != nil,
		"in": map[string]any{"proxyErr": f.in.proxyErr, "healthErr": f.in.healthErr, "load": load, "loadErr": f.in.loadErr,
			"clientsErr": f.in.clientsErr, "netErr": f.in.netErr, "switching": switching, "peers": slices.Clone(f.in.peers),
			"userspace": f.in.userspace, "keyErr": f.in.keyErr, "certs": certs, "certErr": f.in.certErr, "moveErr": f.in.moveErr},
		"side": map[string]any{"frames": frames, "logsErr": f.side.logsErr, "search": wireRecords(f.side.search), "notice": f.side.notice,
			"tail": wireRecords(f.side.tail), "bodies": b64s(f.side.bodies), "size": f.side.size, "tailErr": f.side.tailErr,
			"queues": maps.Clone(f.side.queues), "qerr": maps.Clone(f.side.qerr), "boxes": maps.Clone(f.side.boxes)},
	}
}

// changed tells the recorder, if any, about a change to the fake.
func (f *pfake) changed(op map[string]any) {
	f.mu.Lock()
	rec := f.rec
	f.mu.Unlock()
	rec.change(op)
}

// recAgent is the agent under test as the recorder sees it: every call a
// scenario makes is recorded.
type recAgent struct {
	agentUnderTest
	r *agentRec
}

func (a recAgent) assign(as *armadav1.Assignment) {
	s := string(protoJSON(as))
	if a.r.export != "" {
		s = strings.ReplaceAll(s, a.r.export, "$EXPORT")
	}
	a.r.action(map[string]any{"op": "assign", "assignment": json.RawMessage(s)})
	a.agentUnderTest.assign(as)
}

func (a recAgent) contact(up bool) {
	a.r.action(map[string]any{"op": "contact", "up": up})
	a.agentUnderTest.contact(up)
}

func (a recAgent) fence() {
	a.r.action(map[string]any{"op": "fence"})
	a.agentUnderTest.fence()
}

func (a recAgent) prune() {
	a.r.action(map[string]any{"op": "prune"})
	a.agentUnderTest.prune()
}

func (a recAgent) rotate() {
	a.r.action(map[string]any{"op": "rotate"})
	a.agentUnderTest.rotate()
}

func (a recAgent) move(to string) {
	a.r.action(map[string]any{"op": "move", "to": to})
	a.agentUnderTest.move(to)
}

func (a recAgent) hello() *armadav1.Hello {
	a.r.action(map[string]any{"op": "hello"})
	return a.agentUnderTest.hello()
}

func (a recAgent) side() sideAgent { return a.agentUnderTest.(sideAgent) }

func (a recAgent) exec(req *armadav1.ExecRequest) {
	a.r.action(map[string]any{"op": "exec", "request": protoJSON(req)})
	a.side().exec(req)
}

func (a recAgent) logs(req *armadav1.LogRequest) {
	a.r.action(map[string]any{"op": "logs", "request": protoJSON(req)})
	a.side().logs(req)
}

func (a recAgent) volume(req *armadav1.VolumeRequest) {
	a.r.action(map[string]any{"op": "volume", "request": protoJSON(req)})
	a.side().volume(req)
}

func (a recAgent) pruneLogs() {
	a.r.action(map[string]any{"op": "pruneLogs"})
	a.side().pruneLogs()
}

func (a recAgent) queues() {
	a.r.action(map[string]any{"op": "queues"})
	a.side().queues()
}

func (a recAgent) sandboxes() {
	a.r.action(map[string]any{"op": "sandboxes"})
	a.side().sandboxes()
}

func (a recAgent) exportRound() time.Duration {
	a.r.action(map[string]any{"op": "export"})
	return a.side().exportRound()
}

func (a recAgent) cleanNFS() {
	a.r.action(map[string]any{"op": "cleanNfs"})
	a.side().cleanNFS()
}

// recordOpts is a scenario's options as the replay reads them.
func recordOpts(o parityOpts) map[string]any {
	return map[string]any{
		"members": o.members, "volumes": o.volumes, "exec": o.exec, "stats": o.stats, "noSecretsDir": o.noSecretsDir,
		"volumesDir": o.volumesDir, "unpublished": o.unpublished, "dns": o.dns, "bridge": o.bridge,
		"crashBaseNs": int64(o.crashBase), "bootNs": o.boot.UnixNano(), "proxy": o.proxy, "network": o.network, "move": o.move,
		"networkKey": o.networkKey, "side": o.side, "sandbox": o.sandbox, "encodes": o.encodes,
	}
}

// fixtureName is a test's file under agentFixtures.
func fixtureName(t *testing.T) string {
	parts := strings.SplitN(t.Name(), "/", 2)
	if len(parts) == 1 {
		return filepath.Join(agentFixtures, "scenarios", parts[0]+".json")
	}
	return filepath.Join(agentFixtures, "scenarios", parts[0], parts[1]+".json")
}

// writeFixture writes v as indented JSON.
func writeFixture(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// recordAgentScenario runs body against Go's agent with a recorder and
// writes the scenario's fixture.
func recordAgentScenario(t *testing.T, opts parityOpts, body func(p *parityRun)) {
	t.Helper()
	p := newParityRun(t, opts, false)
	defer p.a.stop()
	r := &agentRec{p: p}
	if p.sh != nil {
		r.export = p.sh.export.srv.URL
	}
	p.rec = r
	p.a = recAgent{agentUnderTest: p.a, r: r}
	p.f.mu.Lock()
	p.f.rec = r
	p.f.recording = true
	p.f.mu.Unlock()
	body(p)
	writeFixture(t, fixtureName(t), map[string]any{"name": t.Name(), "opts": recordOpts(opts), "steps": r.steps})
}

// nodeScriptJSON is the fake armada-node's script as the replay reads it:
// an archive of one repeated byte written by its length.
func nodeScriptJSON(sc nodeScript) map[string]any {
	m := map[string]any{"archiveAnswer": sc.ArchiveAnswer, "restoreAnswer": sc.RestoreAnswer, "answers": sc.Answers, "readySnapshot": sc.ReadySnapshot}
	if a := sc.Archive; a != "" {
		if strings.Count(a, a[:1]) == len(a) {
			m["archiveRepeat"] = map[string]any{"byte": a[:1], "n": len(a)}
		} else {
			m["archive"] = a
		}
	}
	return m
}
