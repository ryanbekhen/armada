package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// Recording the scenarios for the Rust replay (ADR 0055, item 20). With
// -record-scenarios, runParity runs each scenario against Go's server
// only and writes server/tests/testdata/scenarios/<test>.json: every step the
// scenario took at the server's boundaries (calls of the API and their
// streams, fake agents' sessions, the store's methods the harness
// called, clock moves, passes, the fake etcd membership) with Go's
// answer to each, normalized as the transcripts are. Go's notes are
// written between them, for people to read. server/tests/scenarios.rs
// replays the steps against the Rust server and compares every answer,
// so the scenarios keep checking the Rust control plane once Go is gone.
//
// Answers are compared whole, which is stricter than the notes (they
// record what a scenario picked from them); a value a later step sends
// that came from an answer (a join token, a certificate) is written as a
// reference to that answer ({"@ref": id, "path": [...]}) and the replay
// takes it from the Rust server's own answer. A scenario that reaches
// what the replay does not do yet (stand-ins of buckets, alert
// channels, DNS, certificate storage, volume, log, and exec sessions)
// is written with only its name and why, and the replay lists it as
// skipped.

var recordScenarios = flag.Bool("record-scenarios", false,
	"write server/tests/testdata/scenarios/*.json (each scenario's steps and Go's answers) for the Rust replay")

// scenarioFixtures is where the recordings go, from this package.
const scenarioFixtures = "../../server/tests/testdata/scenarios"

// recordRandomKeys are fields the recording names as random besides the
// transcripts' (parityRandomKeys): the scenarios alias join tokens only
// after the answer that holds them, and the replay's CA is its own.
var recordRandomKeys = map[string]bool{"token": true, "cahash": true}

// recorder writes one scenario's steps.
type recorder struct {
	sc   *scenario
	norm *scenario
	cfg  parityConfig

	mu          sync.Mutex
	steps       []map[string]any
	polling     bool
	poll        []map[string]any
	pending     map[string]recRef
	refs        map[string]recRef
	ids         int
	conns       int
	streams     int
	agents      int
	quiet       int
	unsupported []string
	// lastConnect is the connection the last agent session was opened on.
	lastConnect int
	// buckets name the scenario's volume buckets.
	buckets map[*volumeBucket]int
}

// recRef is where a value came from: an answer's leaf (a step and a
// path in its JSON), or an address of the server under test.
type recRef struct {
	step map[string]any
	path []any
	// part takes the part before or after the first "." (a join token's
	// ID and secret); enc "unb64" decodes a base64 leaf (a PEM a later
	// dial uses).
	part, enc string
	addr      string
}

func newRecorder(sc *scenario, cfg parityConfig) *recorder {
	r := &recorder{sc: sc, cfg: cfg, refs: map[string]recRef{}}
	r.norm = &scenario{t: sc.t, fx: sc.fx, seen: map[string]map[string]string{}, extraRandom: recordRandomKeys}
	switch {
	case cfg.certs || cfg.wildcard:
		r.skip("a certificate manager over certmagic's storage")
	case cfg.metrics:
		r.skip("the metrics endpoint")
	case cfg.alerts:
		r.skip("stand-ins of alert channels")
	case cfg.cpBackups:
		r.skip("control plane backups to a stand-in bucket")
	case cfg.meshJoin || cfg.siteJoin:
		r.skip("public join listeners")
	}
	return r
}

// skip marks the scenario as one the replay does not run yet.
func (r *recorder) skip(why string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unsupported = append(r.unsupported, why)
}

// addrs names the server's addresses, which the replay takes from its own.
func (r *recorder) addrs(sut serverUnderTest) {
	for name, a := range map[string]string{"api": sut.api(), "join": sut.join(), "siteJoin": sut.siteJoin()} {
		if a != "" {
			r.refs[a] = recRef{addr: name}
		}
	}
	r.norm.alias(sut.api(), "<api>")
	r.norm.alias(r.sc.fx.acmeAddr, "<acme>")
	r.norm.alias(sut.join(), "<join>")
	r.norm.alias(sut.siteJoin(), "<site-join>")
}

// add appends a step (to the poll being recorded, while one is).
func (r *recorder) add(step map[string]any) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.polling {
		r.poll = append(r.poll, step)
	} else {
		r.steps = append(r.steps, step)
	}
	return step
}

// expect records Go's answer to step, normalized, and remembers its
// leaves for later references. v is what the transcripts encode (a
// message, an error, a store answer); raw its JSON before normalizing.
func (r *recorder) expect(step map[string]any, key string, v any) {
	r.mu.Lock()
	step[key] = json.RawMessage(r.norm.encode(v))
	r.mu.Unlock()
	if err, ok := v.(error); ok && err != nil {
		return
	}
	r.register(step, toTree(r.sc.t, v), nil, "")
}

// register remembers the leaves of an answer a later step may send.
func (r *recorder) register(step map[string]any, v any, path []any, key string) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			r.register(step, e, append(append([]any(nil), path...), k), k)
		}
	case []any:
		for i, e := range x {
			r.register(step, e, append(append([]any(nil), path...), i), key)
		}
	case string:
		if len(x) < 8 || strings.HasPrefix(x, "{") {
			return
		}
		r.mu.Lock()
		norm := r.norm.normalize(x, key)
		r.mu.Unlock()
		// Times come from the test clock (a later step sends them as they
		// are); other values the normalizer names differ from run to run.
		if s, ok := norm.(string); ok && (s == x || s == "<time>") {
			return
		}
		r.remember(x, recRef{step: step, path: path})
		if b, err := base64.StdEncoding.DecodeString(x); err == nil && bytes.HasPrefix(b, []byte("-----BEGIN")) {
			r.remember(string(b), recRef{step: step, path: path, enc: "unb64"})
		}
		if a, b, ok := strings.Cut(x, "."); ok && len(a) >= 8 && len(b) >= 8 {
			r.remember(a, recRef{step: step, path: path, part: "before"})
			r.remember(b, recRef{step: step, path: path, part: "after"})
		}
	}
}

func (r *recorder) remember(v string, ref recRef) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.polling {
		if r.pending == nil {
			r.pending = map[string]recRef{}
		}
		r.pending[v] = ref
		return
	}
	if old, ok := r.refs[v]; ok && old.addr != "" {
		return
	}
	r.refs[v] = ref
}

// template is v (a JSON tree of something a step sends) with every value
// that came from an answer or the server's addresses replaced by a
// reference.
func (r *recorder) template(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = r.template(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = r.template(e)
		}
		return out
	case string:
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.templateString(x)
	}
	return v
}

// templateString is s as a reference, or as {"@concat": parts} when it
// holds a value that came from an answer among other text (a token with
// spaces around it), or s itself.
func (r *recorder) templateString(s string) any {
	if ref, ok := r.refs[s]; ok {
		return r.refOf(ref)
	}
	best := ""
	for v := range r.refs {
		if len(v) >= 16 && len(v) > len(best) && strings.Contains(s, v) {
			best = v
		}
	}
	if best == "" {
		return s
	}
	before, after, _ := strings.Cut(s, best)
	var parts []any
	if before != "" {
		parts = append(parts, r.templateString(before))
	}
	parts = append(parts, r.refOf(r.refs[best]))
	if after != "" {
		parts = append(parts, r.templateString(after))
	}
	return map[string]any{"@concat": parts}
}

func (r *recorder) refOf(ref recRef) map[string]any {
	if ref.addr != "" {
		return map[string]any{"@addr": ref.addr}
	}
	id, ok := ref.step["id"].(int)
	if !ok {
		r.ids++
		id = r.ids
		ref.step["id"] = id
	}
	out := map[string]any{"@ref": id, "path": ref.path}
	if ref.part != "" {
		out["part"] = ref.part
	}
	if ref.enc != "" {
		out["enc"] = ref.enc
	}
	return out
}

// input is v (a message or a value) as a JSON tree with references.
func (r *recorder) input(v any) any {
	return r.template(toTree(r.sc.t, v))
}

// toTree is v's JSON as a tree: protojson for messages, encoding/json
// otherwise, numbers kept as written.
func toTree(t *testing.T, v any) any {
	var b []byte
	var err error
	switch x := v.(type) {
	case nil:
		return nil
	case proto.Message:
		b, err = protojson.Marshal(x)
	default:
		b, err = json.Marshal(x)
	}
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var tree any
	if err := d.Decode(&tree); err != nil {
		t.Fatal(err)
	}
	return tree
}

// note writes Go's note between the steps, for people to read.
func (r *recorder) note(label, value string) {
	r.mu.Lock()
	polling := r.polling
	r.mu.Unlock()
	if polling {
		return
	}
	r.add(map[string]any{"op": "note", "label": label, "value": json.RawMessage(value)})
}

// startPoll begins a poll: the reads of one try of a condition.
func (r *recorder) startPoll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.polling, r.poll, r.pending = true, nil, nil
}

// endPoll ends a try; a try that met its condition becomes a step whose
// reads the replay repeats until it gets Go's answers.
func (r *recorder) endPoll(what string, met bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !met {
		r.poll, r.pending = nil, nil
		return
	}
	r.polling = false
	for k, v := range r.pending {
		if old, ok := r.refs[k]; !ok || old.addr == "" {
			r.refs[k] = v
		}
	}
	if len(r.poll) > 0 {
		r.steps = append(r.steps, map[string]any{"op": "poll", "what": what, "steps": r.poll})
	}
	r.poll, r.pending = nil, nil
}

// muted runs f without recording the calls it makes at the boundaries.
func (r *recorder) muted(f func()) {
	if r == nil {
		f()
		return
	}
	r.mu.Lock()
	r.quiet++
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.quiet--
		r.mu.Unlock()
	}()
	f()
}

func (r *recorder) isQuiet() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.quiet > 0
}

func (r *recorder) nextConn() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conns++
	return r.conns
}

// dialOptions are the interceptors that record conn's calls.
func (r *recorder) dialOptions(conn int) []grpc.DialOption {
	if r == nil {
		return nil
	}
	return []grpc.DialOption{grpc.WithUnaryInterceptor(r.unary(conn)), grpc.WithStreamInterceptor(r.stream(conn))}
}

func (r *recorder) unary(conn int) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if r.isQuiet() {
			return invoker(ctx, method, req, reply, cc, opts...)
		}
		var header *metadata.MD
		for _, o := range opts {
			if h, ok := o.(grpc.HeaderCallOption); ok {
				header = h.HeaderAddr
			}
		}
		step := map[string]any{"op": "call", "conn": conn, "method": method, "req": r.input(req)}
		err := invoker(ctx, method, req, reply, cc, opts...)
		r.add(step)
		if err != nil {
			r.expect(step, "expect", err)
		} else {
			r.expect(step, "expect", reply)
		}
		if header != nil {
			r.expect(step, "header", header.Get("armada-servers"))
		}
		return err
	}
}

// connectMethod is the agents' session, which connectAgent records.
const (
	connectMethod       = "/armada.v1.AgentService/Connect"
	volumeSessionMethod = "/armada.v1.AgentService/VolumeSession"
)

func (r *recorder) stream(conn int) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		if method == connectMethod {
			r.mu.Lock()
			r.lastConnect = conn
			r.mu.Unlock()
			return streamer(ctx, desc, cc, method, opts...)
		}
		// Fake agents' volume sessions: the replay's own fake agents
		// answer the requests that open them.
		if r.isQuiet() || method == volumeSessionMethod {
			return streamer(ctx, desc, cc, method, opts...)
		}
		r.mu.Lock()
		r.streams++
		id := r.streams
		r.mu.Unlock()
		step := r.add(map[string]any{"op": "open", "conn": conn, "stream": id, "method": method})
		cs, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			r.expect(step, "expect", err)
			return nil, err
		}
		return &recStream{ClientStream: cs, r: r, id: id}, nil
	}
}

// recStream records a stream's messages as the scenario sends and reads
// them.
type recStream struct {
	grpc.ClientStream
	r  *recorder
	id int
}

func (s *recStream) SendMsg(m any) error {
	s.r.add(map[string]any{"op": "send", "stream": s.id, "msg": s.r.input(m)})
	return s.ClientStream.SendMsg(m)
}

func (s *recStream) CloseSend() error {
	s.r.add(map[string]any{"op": "closeSend", "stream": s.id})
	return s.ClientStream.CloseSend()
}

func (s *recStream) RecvMsg(m any) error {
	err := s.ClientStream.RecvMsg(m)
	step := s.r.add(map[string]any{"op": "recv", "stream": s.id})
	if err != nil {
		s.r.expect(step, "expect", err)
	} else {
		s.r.expect(step, "expect", m)
	}
	return err
}

// dial records a connection with a certificate of the CA for id.
func (r *recorder) dial(conn int, id pki.Identity, recorded bool) {
	r.add(map[string]any{"op": "dial", "conn": conn, "kind": id.Kind, "name": id.Name, "record": recorded})
}

// dialPEM records a connection with a certificate and key: one the CA
// issued here is dialled as its identity (the replay's CA is its own),
// any other comes from an answer.
func (r *recorder) dialPEM(conn int, certPEM, keyPEM []byte) {
	if cert, err := pki.ParseCertPEM(certPEM); err == nil {
		if _, from := r.refs[string(certPEM)]; !from && cert.CheckSignatureFrom(r.sc.fx.ca.Cert) == nil {
			id, _ := pki.IdentityFromCert(cert)
			r.dial(conn, id, false)
			return
		}
	}
	r.add(map[string]any{"op": "dialPEM", "conn": conn, "cert": r.template(string(certPEM)), "key": r.template(string(keyPEM))})
}

// recSut records what a scenario asks of the server under test.
type recSut struct {
	serverUnderTest
	r *recorder
}

func (s *recSut) server(req map[string]any) {
	req["op"] = "server"
	s.r.add(req)
}

func (s *recSut) reconcile(t *testing.T) {
	s.server(map[string]any{"do": "reconcile"})
	s.serverUnderTest.reconcile(t)
}

func (s *recSut) autoscale(t *testing.T) {
	s.server(map[string]any{"do": "autoscale"})
	s.serverUnderTest.autoscale(t)
}

func (s *recSut) backups(t *testing.T) {
	s.server(map[string]any{"do": "backups"})
	s.serverUnderTest.backups(t)
}

func (s *recSut) cpBackups(t *testing.T) {
	s.server(map[string]any{"do": "cpBackups"})
	s.serverUnderTest.cpBackups(t)
}

func (s *recSut) prunePlacements(t *testing.T) {
	s.server(map[string]any{"do": "prunePlacements"})
	s.serverUnderTest.prunePlacements(t)
}

func (s *recSut) cpStage(content, fail string) {
	s.server(map[string]any{"do": "cpStage", "content": content, "fail": fail})
	s.serverUnderTest.cpStage(content, fail)
}

func (s *recSut) certEvent(name, msg string) {
	s.server(map[string]any{"do": "certEvent", "name": name, "message": msg})
	s.serverUnderTest.certEvent(name, msg)
}

func (s *recSut) settingsChanged() int {
	n := s.serverUnderTest.settingsChanged()
	step := s.r.add(map[string]any{"op": "settingsChanged"})
	s.r.expect(step, "expect", n)
	return n
}

func (s *recSut) managed() map[string]any {
	s.r.skip("the certificate manager's names")
	return s.serverUnderTest.managed()
}

// write writes the recording.
func (r *recorder) write(t *testing.T) {
	name, _, _ := strings.Cut(t.Name(), "/")
	doc := map[string]any{"name": name}
	if len(r.unsupported) > 0 {
		doc["skip"] = strings.Join(slices.Compact(slices.Sorted(slices.Values(r.unsupported))), "; ")
	} else {
		doc["config"] = map[string]any{
			"join": r.cfg.join, "joinBurst": r.cfg.joinBurst, "masterKey": r.cfg.masterKey, "cluster": r.cfg.cluster,
			"nodeLostSeconds": int64(r.cfg.nodeLost / time.Second), "nodeCertValiditySeconds": int64(r.cfg.nodeCertValidity / time.Second),
			"drainTimeoutMs": r.cfg.drain.Milliseconds(), "warmupMs": r.cfg.warmup.Milliseconds(),
			"progressDeadlineMs": r.cfg.progress.Milliseconds(), "plainHttp": r.cfg.plainHTTP,
			"startMs": r.sc.fx.start.UnixMilli(),
		}
	}
	var b bytes.Buffer
	head, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	b.Write(head[:len(head)-1])
	if len(r.unsupported) == 0 {
		// One step a line, so a change reads as a diff of steps.
		b.WriteString(`,"steps":[`)
		for i, s := range r.steps {
			line, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString("\n")
			b.Write(line)
		}
		b.WriteString("\n]")
	}
	b.WriteString("}\n")
	if err := os.MkdirAll(scenarioFixtures, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scenarioFixtures, name+".json"), b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// recStore is the store a scenario writes and reads besides the server:
// each method it calls is recorded with its arguments as the store's
// parity program takes them (armada_store::parity_call), and its answer.
type recStore struct {
	st *store.Etcd
	r  *recorder
}

func (s *recStore) call(method string, args map[string]any, f func() (any, error)) (any, error) {
	v, err := f()
	if s.r == nil || s.r.isQuiet() {
		return v, err
	}
	step := s.r.add(map[string]any{"op": "store", "method": method, "args": s.r.input(args)})
	if err != nil {
		s.r.expect(step, "expect", err)
		return v, err
	}
	rv := v
	if evs, ok := v.([]store.Event); ok {
		// An event's key ends in random hex (the replay blanks it too).
		c := make([]store.Event, len(evs))
		copy(c, evs)
		for i := range c {
			c[i].Key = ""
		}
		// Events of one instant come in their keys' random order: the
		// recording keeps them sorted, and the replay compares them
		// unordered.
		slices.SortStableFunc(c, func(a, b store.Event) int {
			x, _ := json.Marshal(a)
			y, _ := json.Marshal(b)
			return bytes.Compare(x, y)
		})
		rv = c
	}
	s.r.expect(step, "expect", rv)
	return v, err
}

func (s *recStore) ListReplicas(ctx context.Context, f store.ReplicaFilter) ([]store.Replica, error) {
	v, err := s.call("ListReplicas", map[string]any{"filter": f}, func() (any, error) { return s.st.ListReplicas(ctx, f) })
	rs, _ := v.([]store.Replica)
	return rs, err
}

func (s *recStore) SetNodeStatus(ctx context.Context, id string, st store.NodeStatus) error {
	_, err := s.call("SetNodeStatus", map[string]any{"id": id, "status": st}, func() (any, error) { return nil, s.st.SetNodeStatus(ctx, id, st) })
	return err
}

func (s *recStore) UpsertNode(ctx context.Context, n store.Node) error {
	_, err := s.call("UpsertNode", map[string]any{"node": n}, func() (any, error) { return nil, s.st.UpsertNode(ctx, n) })
	return err
}

func (s *recStore) CreateUser(ctx context.Context, p store.Principal, actor string) (store.Principal, error) {
	v, err := s.call("CreateUser", map[string]any{"principal": p, "actor": actor}, func() (any, error) { return s.st.CreateUser(ctx, p, actor) })
	out, _ := v.(store.Principal)
	return out, err
}

func (s *recStore) CreateSpace(ctx context.Context, name, actor string, by *store.Principal) (store.Space, error) {
	v, err := s.call("CreateSpace", map[string]any{"name": name, "actor": actor, "by": by}, func() (any, error) { return s.st.CreateSpace(ctx, name, actor, by) })
	out, _ := v.(store.Space)
	return out, err
}

func (s *recStore) GetNode(ctx context.Context, id string) (store.Node, error) {
	v, err := s.call("GetNode", map[string]any{"id": id}, func() (any, error) { return s.st.GetNode(ctx, id) })
	out, _ := v.(store.Node)
	return out, err
}

func (s *recStore) GetApp(ctx context.Context, name string) (store.App, error) {
	v, err := s.call("GetApp", map[string]any{"name": name}, func() (any, error) { return s.st.GetApp(ctx, name) })
	out, _ := v.(store.App)
	return out, err
}

func (s *recStore) DeleteReplica(ctx context.Context, id string) error {
	_, err := s.call("DeleteReplica", map[string]any{"id": id}, func() (any, error) { return nil, s.st.DeleteReplica(ctx, id) })
	return err
}

func (s *recStore) CreateReplica(ctx context.Context, rep store.Replica) error {
	_, err := s.call("CreateReplica", map[string]any{"replica": rep}, func() (any, error) { return nil, s.st.CreateReplica(ctx, rep) })
	return err
}

func (s *recStore) UpdateReplicaStatus(ctx context.Context, node string, st store.ReplicaStatus) error {
	_, err := s.call("UpdateReplicaStatus", map[string]any{"node": node, "status": st}, func() (any, error) { return nil, s.st.UpdateReplicaStatus(ctx, node, st) })
	return err
}

func (s *recStore) ListJobRuns(ctx context.Context, job string) ([]store.JobRun, error) {
	v, err := s.call("ListJobRuns", map[string]any{"job": job}, func() (any, error) { return s.st.ListJobRuns(ctx, job) })
	out, _ := v.([]store.JobRun)
	return out, err
}

func (s *recStore) Assign(ctx context.Context, kind, name string, g store.Grant, actor string) (store.Principal, error) {
	v, err := s.call("Assign", map[string]any{"kind": kind, "name": name, "grant": g, "actor": actor}, func() (any, error) { return s.st.Assign(ctx, kind, name, g, actor) })
	out, _ := v.(store.Principal)
	return out, err
}

func (s *recStore) SetNodeLabels(ctx context.Context, id string, set map[string]string, remove []string, actor string) (map[string]string, error) {
	v, err := s.call("SetNodeLabels", map[string]any{"id": id, "set": set, "remove": remove, "actor": actor}, func() (any, error) {
		return s.st.SetNodeLabels(ctx, id, set, remove, actor)
	})
	out, _ := v.(map[string]string)
	return out, err
}

func (s *recStore) InitNetwork(ctx context.Context, n store.Network) error {
	args := map[string]any{"Mode": n.Mode, "ClusterCIDR": n.ClusterCIDR, "IsolateDefault": n.IsolateDefault, "MeshCIDR": n.MeshCIDR}
	_, err := s.call("InitNetwork", args, func() (any, error) { return nil, s.st.InitNetwork(ctx, n) })
	return err
}

func (s *recStore) SetNodeCordoned(ctx context.Context, id string, on bool, actor string) error {
	_, err := s.call("SetNodeCordoned", map[string]any{"id": id, "on": on, "actor": actor}, func() (any, error) { return nil, s.st.SetNodeCordoned(ctx, id, on, actor) })
	return err
}

func (s *recStore) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.call("SetMeta", map[string]any{"key": key, "value": value}, func() (any, error) { return nil, s.st.SetMeta(ctx, key, value) })
	return err
}

func (s *recStore) GetMeta(ctx context.Context, key string) (string, error) {
	v, err := s.call("GetMeta", map[string]any{"key": key}, func() (any, error) { return s.st.GetMeta(ctx, key) })
	out, _ := v.(string)
	return out, err
}

func (s *recStore) Deploy(ctx context.Context, sp *spec.App, actor string) (store.Revision, bool, error) {
	var rev store.Revision
	var created bool
	_, err := s.call("Deploy", map[string]any{"spec": sp, "actor": actor, "opts": map[string]any{}}, func() (any, error) {
		var err error
		rev, created, err = s.st.Deploy(ctx, sp, actor)
		return map[string]any{"Rev": rev, "Created": created}, err
	})
	return rev, created, err
}

func (s *recStore) BindVolume(ctx context.Context, app, name, node, actor string) error {
	_, err := s.call("BindVolume", map[string]any{"app": app, "name": name, "node": node, "actor": actor}, func() (any, error) {
		return nil, s.st.BindVolume(ctx, app, name, node, actor)
	})
	return err
}

func (s *recStore) UpsertServer(ctx context.Context, srv store.Server) error {
	_, err := s.call("UpsertServer", map[string]any{"server": srv}, func() (any, error) { return nil, s.st.UpsertServer(ctx, srv) })
	return err
}

func (s *recStore) UpdateJobRun(ctx context.Context, run store.JobRun) error {
	_, err := s.call("UpdateJobRun", map[string]any{"run": run}, func() (any, error) { return nil, s.st.UpdateJobRun(ctx, run) })
	return err
}

// SetSecretValue sets a secret's key to value, sealed with the master
// key (the replay seals with its own copy of the same key).
func (s *recStore) SetSecretValue(ctx context.Context, keys *secrets.Keyring, secret, key, value string, rollout bool, actor string) (int, []string, error) {
	seal := func(v int) (secrets.Sealed, error) {
		return keys.Seal(secret, key, v, secrets.NewValue([]byte(value)))
	}
	var version int
	var revs []string
	v, err := func() (any, error) {
		var err error
		version, revs, err = s.st.SetSecret(ctx, secret, key, seal, rollout, actor)
		return map[string]any{"Version": version, "Revisions": revs}, err
	}()
	if s.r != nil && !s.r.isQuiet() {
		step := s.r.add(map[string]any{"op": "setSecret", "secret": secret, "key": key, "value": value, "rollout": rollout, "actor": actor})
		if err != nil {
			s.r.expect(step, "expect", err)
		} else {
			s.r.expect(step, "expect", v)
		}
	}
	return version, revs, err
}

func (s *recStore) SetRevisionPlatforms(ctx context.Context, revision string, platforms []string) error {
	_, err := s.call("SetRevisionPlatforms", map[string]any{"revision": revision, "platforms": platforms}, func() (any, error) {
		return nil, s.st.SetRevisionPlatforms(ctx, revision, platforms)
	})
	return err
}

func (s *recStore) SetNodeRestricted(ctx context.Context, id string, on bool, actor string) error {
	_, err := s.call("SetNodeRestricted", map[string]any{"id": id, "on": on, "actor": actor}, func() (any, error) {
		return nil, s.st.SetNodeRestricted(ctx, id, on, actor)
	})
	return err
}

func (s *recStore) SetDomainVerification(ctx context.Context, name string, verified bool, message string) error {
	_, err := s.call("SetDomainVerification", map[string]any{"name": name, "verified": verified, "message": message}, func() (any, error) {
		return nil, s.st.SetDomainVerification(ctx, name, verified, message)
	})
	return err
}

func (s *recStore) ListVolumes(ctx context.Context, app string) ([]store.Volume, error) {
	v, err := s.call("ListVolumes", map[string]any{"app": app}, func() (any, error) { return s.st.ListVolumes(ctx, app) })
	out, _ := v.([]store.Volume)
	return out, err
}

func (s *recStore) ListEvents(ctx context.Context, since time.Time) ([]store.Event, error) {
	v, err := s.call("ListEvents", map[string]any{"since": since}, func() (any, error) { return s.st.ListEvents(ctx, since) })
	out, _ := v.([]store.Event)
	return out, err
}

func (s *recStore) ListApps(ctx context.Context) ([]store.App, error) {
	v, err := s.call("ListApps", map[string]any{}, func() (any, error) { return s.st.ListApps(ctx) })
	out, _ := v.([]store.App)
	return out, err
}

func (s *recStore) GetRevision(ctx context.Context, name string) (store.Revision, error) {
	v, err := s.call("GetRevision", map[string]any{"name": name}, func() (any, error) { return s.st.GetRevision(ctx, name) })
	out, _ := v.(store.Revision)
	return out, err
}

func (s *recStore) GetDomain(ctx context.Context, name string) (store.Domain, error) {
	v, err := s.call("GetDomain", map[string]any{"name": name}, func() (any, error) { return s.st.GetDomain(ctx, name) })
	out, _ := v.(store.Domain)
	return out, err
}

func (s *recStore) DeletePrincipal(ctx context.Context, kind, name, actor string) error {
	_, err := s.call("DeletePrincipal", map[string]any{"kind": kind, "name": name, "actor": actor}, func() (any, error) {
		return nil, s.st.DeletePrincipal(ctx, kind, name, actor)
	})
	return err
}

func (s *recStore) CreateJobRun(ctx context.Context, job, trigger string, at time.Time, actor string) (store.JobRun, error) {
	v, err := s.call("CreateJobRun", map[string]any{"job": job, "trigger": trigger, "at": at, "actor": actor}, func() (any, error) {
		return s.st.CreateJobRun(ctx, job, trigger, at, actor)
	})
	out, _ := v.(store.JobRun)
	return out, err
}

// recordJoinDial records a connection to the join listener (no client
// certificate, the CA pinned).
func (sc *scenario) recordJoinDial(addr string) []grpc.DialOption {
	if sc.rec == nil {
		return nil
	}
	conn := sc.rec.nextConn()
	sc.rec.add(map[string]any{"op": "dialJoin", "conn": conn, "addr": sc.rec.template(addr)})
	return sc.rec.dialOptions(conn)
}

// sleep waits d on the wall clock (a stream the server holds open).
func (sc *scenario) sleep(d time.Duration) {
	if sc.rec != nil {
		sc.rec.add(map[string]any{"op": "sleep", "ms": d.Milliseconds()})
	}
	time.Sleep(d)
}

// connsSince are the IDs of the last n connections dialled.
func (r *recorder) connsSince(n int) []int {
	if r == nil {
		return make([]int, n)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]int, n)
	for i := range out {
		out[i] = r.conns - n + 1 + i
	}
	return out
}

// recordProbe records a call of method with an empty message, as any
// client could make it, and what came of it: the refusal, or whether a
// handler answered (TestParityMethodAccess). ported says the transcript
// tells an error of the handler from an answer.
func (sc *scenario) recordProbe(conn int, m protoreflect.MethodDescriptor, ported bool, outcome any) {
	if sc.rec == nil {
		return
	}
	full := "/" + string(m.Parent().FullName()) + "/" + string(m.Name())
	step := sc.rec.add(map[string]any{"op": "probe", "conn": conn, "method": full, "ported": ported})
	sc.rec.expect(step, "expect", outcome)
}

// members is the fake etcd membership (a copy); with see, a recording
// records it as a read.
func (sc *scenario) members(see bool) []etcd.MemberInfo {
	ms, _ := sc.fc.Members(sc.ctx)
	if see && sc.rec != nil {
		step := sc.rec.add(map[string]any{"op": "members"})
		sc.rec.expect(step, "expect", ms)
	}
	return ms
}

// setMembers replaces the fake etcd membership and what AddLearner fails
// with.
func (sc *scenario) setMembers(ms []etcd.MemberInfo, addErr error) {
	if sc.rec != nil {
		step := map[string]any{"op": "setMembers", "members": ms}
		if addErr != nil {
			step["addErr"] = addErr.Error()
		}
		sc.rec.add(step)
	}
	sc.fc.mu.Lock()
	sc.fc.members, sc.fc.addErr = ms, addErr
	sc.fc.mu.Unlock()
}

// othersSeen are the messages besides assignments the agent got so far.
func (a *parityAgent) othersSeen() []*armadav1.ServerMessage {
	if r := a.sc.rec; r != nil && a.rid != "" {
		step := r.add(map[string]any{"op": "others", "agent": a.rid})
		// As protobuf JSON, which the replay reads them as.
		list := make([]any, 0, len(a.others))
		for _, m := range a.others {
			b, err := protojson.Marshal(m)
			if err != nil {
				a.sc.t.Fatal(err)
			}
			var tree any
			if err := json.Unmarshal(b, &tree); err != nil {
				a.sc.t.Fatal(err)
			}
			list = append(list, tree)
		}
		r.expect(step, "expect", rawJSON{list})
	}
	return a.others
}

// clearOthers forgets them.
func (a *parityAgent) clearOthers() {
	if r := a.sc.rec; r != nil && a.rid != "" {
		r.add(map[string]any{"op": "clearOthers", "agent": a.rid})
	}
	a.others = nil
}

// bucketID names a volume bucket the scenario's fake agents share.
func (r *recorder) bucketID(b *volumeBucket) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.buckets == nil {
		r.buckets = map[*volumeBucket]int{}
	}
	id, ok := r.buckets[b]
	if !ok {
		id = len(r.buckets) + 1
		r.buckets[b] = id
	}
	return id
}
