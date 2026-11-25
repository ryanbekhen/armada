package agent

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/conntrack"
	"github.com/ryanbekhen/armada/internal/nodeprog"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/queuelen"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// The sessions' part of the agent parity harness (ADR 0055 item 16, third
// part): exec, log, and volume sessions against a control plane in the
// test (sideServer, over mTLS, which records what each stream carries and
// sends what the scenario scripts), queue readings and sandboxes through
// the fake runtime, the log export to an endpoint in the test, and
// volumes, NFS, and connection tracking through a fake armada-node: this
// test binary run again (TestMain), which records each call with its
// request and answers what the scenario's script says. Go's agent runs it
// as its VolumeProgram, Node, and Conntrack program, the Rust agent as its
// volume, NFS, and conntrack seams' program, so both talk the same
// protocol to the same answers.

// TestMain runs the fake armada-node when the harness starts this binary
// as one.
func TestMain(m *testing.M) {
	if root := os.Getenv(fakeNodeRoot); root != "" {
		os.Exit(fakeNode(root, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeNodeRoot names the run's directory for the fake armada-node: its
// script (script.json) and the log of its calls (node.log) are there.
const fakeNodeRoot = "ARMADA_FAKE_NODE_ROOT"

// nodeScript is what the fake armada-node answers, by call.
type nodeScript struct {
	Archive       string            `json:"archive"`       // stdout of volume archive
	ArchiveAnswer json.RawMessage   `json:"archiveAnswer"` // descriptor 3
	RestoreAnswer json.RawMessage   `json:"restoreAnswer"` // descriptor 3 after ready
	Answers       map[string]string `json:"answers"`       // other calls by "group op"
	ReadySnapshot string            `json:"readySnapshot"` // restore-snapshot: "ready ID", "" answers at once
}

func fakeNode(root string, args []string) int {
	b, _ := os.ReadFile(filepath.Join(root, "script.json"))
	var sc nodeScript
	_ = json.Unmarshal(b, &sc)
	logf, err := os.OpenFile(filepath.Join(root, "node.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 2
	}
	defer logf.Close()
	norm := func(s string) string { return strings.ReplaceAll(s, root, "$ROOT") }
	rec := func(format string, a ...any) { _, _ = logf.WriteString(norm(fmt.Sprintf(format, a...)) + "\n") }
	// request reads stdin's first line as JSON, leaving out what changes
	// between runs (times, deadlines) and summing up the zone table.
	in := bufio.NewReader(os.Stdin)
	request := func() string {
		line, _ := in.ReadString('\n')
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			return strings.TrimSpace(line)
		}
		delete(m, "now")
		delete(m, "timeoutMs")
		if z, ok := m["zone"].([]any); ok {
			m["zone"] = len(z)
		}
		out, _ := json.Marshal(m)
		return string(out)
	}
	answer := func(key, def string) string {
		if a, ok := sc.Answers[key]; ok {
			return a
		}
		return def
	}
	if len(args) < 2 {
		return 2
	}
	switch op := args[0] + " " + args[1]; op {
	case "volume archive":
		rec("volume archive %s", args[2])
		_, _ = os.Stdout.WriteString(sc.Archive)
		fd3 := os.NewFile(3, "answer")
		_, _ = fd3.Write(sc.ArchiveAnswer)
	case "volume restore":
		fd3 := os.NewFile(3, "answer")
		_, _ = fd3.WriteString("ready\n")
		data, _ := io.ReadAll(in)
		fd4, _ := io.ReadAll(os.NewFile(4, "session"))
		rec("volume restore %s stdin=%q session=%s", args[2], data, fd4)
		_, _ = fd3.Write(sc.RestoreAnswer)
	case "volume size":
		var sizes []int
		for _, d := range args[2:] {
			sizes = append(sizes, 100*len(filepath.Base(d)))
		}
		rec("volume size %s", strings.Join(args[2:], " "))
		out, _ := json.Marshal(map[string]any{"sizes": sizes})
		fmt.Println(string(out))
	case "volume snapshot", "volume prune", "volume snapshots":
		rec("%s %s", op, request())
		fmt.Println("touched")
		fmt.Println(answer(op, "{}"))
	case "volume restore-snapshot":
		rec("%s %s", op, request())
		if sc.ReadySnapshot == "" {
			fmt.Println(answer(op, "{}"))
			return 0
		}
		fmt.Println("ready " + sc.ReadySnapshot)
		goLine, _ := in.ReadString('\n')
		rec("restore-snapshot then %q", goLine)
		fmt.Println("touched")
		fmt.Println(answer(op, "{}"))
	case "nfs source", "nfs unmount", "nfs mount", "conntrack read", "conntrack raise":
		rec("%s %s", op, request())
		fmt.Println(answer(op, "{}"))
	default:
		rec("unknown %q", args)
		return 2
	}
	return 0
}

// sideServer is the control plane's side of exec, log, and volume
// sessions: it records what each stream carries and sends what the
// scenario scripts.
type sideServer struct {
	armadav1.UnimplementedAgentServiceServer
	mu     sync.Mutex
	log    []string
	execIn []*armadav1.ExecInput
	volIn  []*armadav1.VolumeData
}

func (s *sideServer) note(format string, a ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log = append(s.log, fmt.Sprintf(format, a...))
}

func (s *sideServer) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.log
	s.log = nil
	return out
}

// short is a message's data shown by its length past 64 bytes.
func short(b []byte) string {
	if len(b) > 64 {
		return fmt.Sprintf("%d bytes %q...", len(b), b[:16])
	}
	return strconv.Quote(string(b))
}

func execText(m *armadav1.ExecSessionOutput) string {
	switch o := m.GetOutput().(type) {
	case *armadav1.ExecSessionOutput_Stdout:
		return "stdout " + short(o.Stdout)
	case *armadav1.ExecSessionOutput_Stderr:
		return "stderr " + short(o.Stderr)
	case *armadav1.ExecSessionOutput_ExitCode:
		return "exit " + strconv.Itoa(int(o.ExitCode))
	case *armadav1.ExecSessionOutput_Error:
		return "error " + strconv.Quote(o.Error)
	}
	return "attach " + m.GetRequestId()
}

func (s *sideServer) ExecSession(stream grpc.BidiStreamingServer[armadav1.ExecSessionOutput, armadav1.ExecInput]) error {
	s.mu.Lock()
	in := s.execIn
	s.mu.Unlock()
	sent := false
	for {
		m, err := stream.Recv()
		if err != nil {
			return nil
		}
		s.note("exec %s", execText(m))
		switch m.GetOutput().(type) {
		case *armadav1.ExecSessionOutput_ExitCode, *armadav1.ExecSessionOutput_Error:
			return nil
		case nil:
			if !sent {
				sent = true
				for _, x := range in {
					if err := stream.Send(x); err != nil {
						return nil
					}
				}
			}
		}
	}
}

func (s *sideServer) PushLogs(stream grpc.ClientStreamingServer[armadav1.LogPush, armadav1.PushLogsResponse]) error {
	for {
		m, err := stream.Recv()
		if err != nil {
			return stream.SendAndClose(&armadav1.PushLogsResponse{})
		}
		t := ""
		if m.GetTime() != nil {
			t = " at " + m.GetTime().AsTime().UTC().Format(time.RFC3339Nano)
		}
		s.note("logs %s stream=%d data=%s error=%q replica=%q%s", m.GetRequestId(), m.GetStream(), short(m.GetData()), m.GetError(), m.GetReplica(), t)
	}
}

func (s *sideServer) VolumeSession(stream grpc.BidiStreamingServer[armadav1.VolumeData, armadav1.VolumeData]) error {
	s.mu.Lock()
	in := s.volIn
	s.mu.Unlock()
	sent := false
	// Archive data is noted as its total and first bytes: how a pipe's
	// reads cut it into messages differs from one run to the next.
	var data []byte
	for {
		m, err := stream.Recv()
		if err != nil {
			return nil
		}
		if len(m.GetData()) > VolumeChunk {
			s.note("volume chunk of %d bytes", len(m.GetData()))
		}
		d := armadav1.VolumeData{RequestId: m.GetRequestId(), Done: m.GetDone(), Error: m.GetError(), Snapshot: m.GetSnapshot(), Snapshots: m.GetSnapshots()}
		data = append(data, m.GetData()...)
		if len(m.GetData()) > 0 && d.RequestId == "" && !d.Done && d.Error == "" && d.Snapshot == nil && d.Snapshots == nil {
			continue
		}
		if len(data) > 0 {
			s.note("volume data=%s", short(data))
			data = nil
		}
		s.note("volume %s", compact(&d))
		if m.GetDone() || m.GetError() != "" {
			return nil
		}
		if !sent {
			sent = true
			for _, x := range in {
				if err := stream.Send(x); err != nil {
					return nil
				}
			}
		}
	}
}

// exportCall is one request the log endpoint got.
type exportServer struct {
	mu     sync.Mutex
	log    []string
	status int
	srv    *httptest.Server
}

var observed = regexp.MustCompile(`"observedTimeUnixNano":"\d+"`)

func (e *exportServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body := "(not gzip)"
	if zr, err := gzip.NewReader(r.Body); err == nil {
		b, _ := io.ReadAll(zr)
		body = observed.ReplaceAllString(string(b), `"observedTimeUnixNano":"NOW"`)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.log = append(e.log, fmt.Sprintf("%s %s type=%s encoding=%s agent=%s auth=%q tenant=%q %s", r.Method, r.URL.Path,
		r.Header.Get("Content-Type"), r.Header.Get("Content-Encoding"), r.Header.Get("User-Agent"),
		r.Header.Get("Authorization"), r.Header.Get("X-Scope-OrgID"), body))
	if e.status != 0 {
		w.WriteHeader(e.status)
		_, _ = w.Write([]byte("too many\nrequests secret-token"))
	}
}

func (e *exportServer) take() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.log
	e.log = nil
	return out
}

// sideHarness is one run's control plane, fake armada-node, and log
// endpoint.
type sideHarness struct {
	t      *testing.T
	f      *pfake
	root   string
	bin    string
	creds  string
	addr   string
	srv    *sideServer
	export *exportServer
	agent  *Agent
}

func newSideHarness(t *testing.T, f *pfake) *sideHarness {
	t.Helper()
	root := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The fake armada-node: this binary, told where its run's directory is.
	bin := filepath.Join(root, "armada-node")
	script := fmt.Sprintf("#!/bin/sh\n%s=%s exec %s \"$@\"\n", fakeNodeRoot, root, self)
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"volumes", "nfs", "conntrack"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	ca, err := pki.NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindServer, Name: "s1"}, DNSNames: []string{pki.ServerName}, Server: true})
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := pki.ServerTLS(ca.CertPEM, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	ss := &sideServer{}
	armadav1.RegisterAgentServiceServer(gs, ss)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	ex := &exportServer{}
	ex.srv = httptest.NewServer(ex)
	t.Cleanup(ex.srv.Close)
	h := &sideHarness{t: t, f: f, root: root, bin: bin, creds: writeCreds(t, ca, "n1"), addr: lis.Addr().String(), srv: ss, export: ex}
	h.script(nodeScript{})
	return h
}

// script sets what the fake armada-node answers.
func (h *sideHarness) script(sc nodeScript) {
	b, _ := json.Marshal(sc)
	if err := os.WriteFile(filepath.Join(h.root, "script.json"), b, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// nodeCalls returns the fake armada-node's calls since the last time.
func (h *sideHarness) nodeCalls() []string {
	p := filepath.Join(h.root, "node.log")
	b, _ := os.ReadFile(p)
	_ = os.Remove(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

func (h *sideHarness) rustConfig() map[string]any {
	return map[string]any{
		"nodeBin": h.bin, "nfsDir": filepath.Join(h.root, "nfs"), "conntrackDir": filepath.Join(h.root, "conntrack"),
		"conntrackMemory": 1 << 30, "queueMs": 15_000, "sandboxMs": 3_600_000,
	}
}

func (h *sideHarness) connect() map[string]any {
	return map[string]any{"dataDir": h.creds, "node": "n1", "servers": []string{h.addr}}
}

func (h *sideHarness) goConfig(t *testing.T, cfg *Config) {
	creds, err := LoadCredentials(h.creds, "n1")
	if err != nil {
		t.Fatal(err)
	}
	cc, err := creds.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(h.addr, grpc.WithTransportCredentials(credentials.NewTLS(cc)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	cfg.Client = armadav1.NewAgentServiceClient(conn)
	cfg.VolumeProgram = func() string { return h.bin }
	cfg.Node = nodeprog.New(h.bin)
	cfg.NFSDir = filepath.Join(h.root, "nfs")
	// The kernel's NFS client is not asked: mounts go through the fake
	// armada-node, as the agent's own mountNFS sends them.
	cfg.MountNFS = func(ctx context.Context, server, export, target string, readOnly bool) error {
		return h.agent.mountNFS(ctx, server, export, target, readOnly)
	}
	cfg.Conntrack = conntrack.At(filepath.Join(h.root, "conntrack"), 1<<30).WithProgram(nodeprog.New(h.bin))
	cfg.SandboxInterval = time.Hour
}

// pfakeEncoding is pfake with a runtime that renders its tails itself.
type pfakeEncoding struct{ *pfake }

func (e pfakeEncoding) TailLogsEncoded(_ context.Context, target string, maxBytes int64, enc runtime.LogEncoding) (runtime.LogTail, error) {
	f := e.pfake
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("tailLogsEncoded", map[string]any{"target": target != "", "maxBytes": maxBytes, "format": enc.Format, "node": enc.Node,
		"batchRecords": enc.BatchRecords, "batchBytes": enc.BatchBytes})
	if f.side.tailErr != "" {
		return runtime.LogTail{}, errors.New(f.side.tailErr)
	}
	return runtime.LogTail{Bodies: slices.Clone(f.side.bodies), Size: f.side.size, Commit: f.commit(target)}, nil
}

// side is what the fake runtime answers for the sessions and loops.
type side struct {
	frames  map[string][]runtime.LogFrame
	logsErr string
	search  []runtime.LogRecord
	notice  string
	tail    []runtime.LogRecord
	bodies  [][]byte
	size    int64
	tailErr string
	queues  map[string]int64
	qerr    map[string]string
	boxes   map[string]string
}

func (f *pfake) commit(target string) func() error {
	return func() error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.record("commitLogs", map[string]any{"target": target != ""})
		return nil
	}
}

// execSession answers an exec with streams by the command's first word:
// echo prints its arguments and its input, big prints 70,000 bytes, fail
// writes to stderr and exits 3, num prints its argument, missing does not
// start.
func (f *pfake) execSession(id string, opts runtime.ExecOptions) (int, error) {
	var stdin any
	if opts.Stdin != nil {
		b, _ := io.ReadAll(opts.Stdin)
		stdin = string(b)
	}
	f.mu.Lock()
	f.record("execSession", map[string]any{"id": id, "cmd": opts.Cmd, "tty": opts.TTY, "rows": opts.Size.Rows, "cols": opts.Size.Cols, "stdin": stdin})
	f.mu.Unlock()
	stdout, stderr, code := execAnswer(opts.Cmd, stdin)
	if code < 0 {
		return 0, errors.New("exec: no such file")
	}
	if stdout != "" {
		_, _ = opts.Stdout.Write([]byte(stdout))
	}
	if stderr != "" && opts.Stderr != nil {
		_, _ = opts.Stderr.Write([]byte(stderr))
	}
	return code, nil
}

func execAnswer(cmd []string, stdin any) (string, string, int) {
	in, _ := stdin.(string)
	switch cmd[0] {
	case "echo":
		return strings.Join(cmd[1:], " ") + "\n" + in, "", 0
	case "big":
		return strings.Repeat("x", 70_000), "", 0
	case "fail":
		return "", "oops\n", 3
	case "num":
		return strings.Join(cmd[1:], " "), "", 0
	case "missing":
		return "", "", -1
	}
	return "", "", 0
}

type frameStream struct{ frames []runtime.LogFrame }

func (s *frameStream) Next() (runtime.LogFrame, error) {
	if len(s.frames) == 0 {
		return runtime.LogFrame{}, io.EOF
	}
	f := s.frames[0]
	s.frames = s.frames[1:]
	return f, nil
}

func (s *frameStream) Close() error { return nil }

func (f *pfake) logs(id string, o runtime.LogOptions) (runtime.LogStream, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("logs", map[string]any{"id": id, "follow": o.Follow, "tail": o.Tail, "grep": o.Grep})
	if f.side.logsErr != "" {
		return nil, errors.New(f.side.logsErr)
	}
	return &frameStream{frames: slices.Clone(f.side.frames[id])}, nil
}

func (f *pfake) SearchLogs(_ context.Context, q runtime.LogQuery) ([]runtime.LogRecord, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("searchLogs", map[string]any{"app": q.App, "replica": q.Replica, "container": q.Container, "sinceNs": unixNs(q.Since),
		"untilNs": unixNs(q.Until), "grep": q.Grep, "limit": q.Limit, "maxBytes": q.MaxBytes})
	return slices.Clone(f.side.search), f.side.notice, nil
}

func (f *pfake) PruneLogs(_ context.Context, retention time.Duration, maxBytes int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("pruneLogs", map[string]any{"retentionMs": retention.Milliseconds(), "maxBytes": maxBytes})
	return nil
}

func (f *pfake) TailLogs(_ context.Context, target string, maxBytes int64) (runtime.LogTail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("tailLogs", map[string]any{"target": target != "", "maxBytes": maxBytes})
	if f.side.tailErr != "" {
		return runtime.LogTail{}, errors.New(f.side.tailErr)
	}
	return runtime.LogTail{Records: slices.Clone(f.side.tail), Commit: f.commit(target)}, nil
}

func (f *pfake) readQueue(method, id string, q runtime.QueueRead) (int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(method, map[string]any{"id": id, "type": q.Type, "name": q.Name, "url": q.URL, "addresses": len(q.Addresses)})
	if e := f.side.qerr[q.Name]; e != "" {
		return 0, true, queuelen.FromText(e)
	}
	return f.side.queues[q.Name], true, nil
}

func (f *pfake) ReadQueue(_ context.Context, container string, q runtime.QueueRead) (int64, bool, error) {
	return f.readQueue("readQueue", container, q)
}

func (f *pfake) ReadSandboxQueue(_ context.Context, id string, q runtime.QueueRead) (int64, bool, error) {
	return f.readQueue("readSandboxQueue", id, q)
}

func (f *pfake) CanSandbox() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sandbox
}

func (f *pfake) EnsureSandbox(_ context.Context, id string) (runtime.Sandbox, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ensureSandbox", map[string]any{"id": id})
	if f.side.boxes == nil {
		f.side.boxes = map[string]string{}
	}
	ip := "10.120.0." + strconv.Itoa(100+nameHash(id)%100)
	f.side.boxes[id] = ip
	return runtime.Sandbox{ID: id, IP: ip}, nil
}

func (f *pfake) RemoveSandbox(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("removeSandbox", map[string]any{"id": id})
	delete(f.side.boxes, id)
	return nil
}

func (f *pfake) ListSandboxes(context.Context) ([]runtime.Sandbox, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("listSandboxes", map[string]any{})
	var out []runtime.Sandbox
	for id, ip := range f.side.boxes {
		out = append(out, runtime.Sandbox{ID: id, IP: ip})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *pfake) DialSandbox(context.Context, string, string, string) (net.Conn, error) {
	return nil, errors.New("no dials in the parity tests")
}

// answerSide answers the Rust program's calls of the sessions' part.
func (f *pfake) answerSide(method string, raw []byte) (any, bool, error) {
	var c struct {
		ID         string   `json:"id"`
		Cmd        []string `json:"cmd"`
		TTY        bool     `json:"tty"`
		Rows, Cols uint16
		Stdin      *string `json:"stdin"`
		Follow     bool    `json:"follow"`
		Tail       int     `json:"tail"`
		Grep       string  `json:"grep"`
		App        string  `json:"app"`
		Replica    string  `json:"replica"`
		Container  string  `json:"container"`
		SinceNs    int64   `json:"sinceNs"`
		UntilNs    int64   `json:"untilNs"`
		Limit      int     `json:"limit"`
		MaxBytes   int64   `json:"maxBytes"`
		Retention  int64   `json:"retentionMs"`
		Target     string  `json:"target"`
		Format     string  `json:"format"`
		Node       string  `json:"node"`
		BatchRecs  int     `json:"batchRecords"`
		BatchBytes int     `json:"batchBytes"`
		Type       string  `json:"type"`
		Name       string  `json:"name"`
		URL        string  `json:"url"`
		Addresses  []string
	}
	_ = json.Unmarshal(raw, &c)
	ctx := context.Background()
	at := func(n int64) time.Time {
		if n == 0 {
			return time.Time{}
		}
		return time.Unix(0, n)
	}
	wireRec := func(r runtime.LogRecord) map[string]any {
		return map[string]any{"timeNs": unixNs(r.Time), "stderr": r.Stream == runtime.Stderr, "data": string(r.Data),
			"replica": r.Replica, "container": r.Container, "app": r.App, "revision": r.Revision}
	}
	switch method {
	case "execSession":
		opts := runtime.ExecOptions{Cmd: c.Cmd, TTY: c.TTY, Size: runtime.TermSize{Rows: c.Rows, Cols: c.Cols}}
		if c.Stdin != nil {
			opts.Stdin = strings.NewReader(*c.Stdin)
		}
		var out, errOut bytes.Buffer
		opts.Stdout, opts.Stderr = &out, &errOut
		code, err := f.execSession(c.ID, opts)
		return map[string]any{"stdout": out.String(), "stderr": errOut.String(), "code": code}, true, err
	case "logs":
		ls, err := f.logs(c.ID, runtime.LogOptions{Follow: c.Follow, Tail: c.Tail, Grep: c.Grep})
		if err != nil {
			return nil, true, err
		}
		out := []map[string]any{}
		for {
			fr, err := ls.Next()
			if err != nil {
				break
			}
			out = append(out, map[string]any{"stderr": fr.Stream == runtime.Stderr, "data": string(fr.Data), "timeNs": unixNs(fr.Time)})
		}
		return out, true, nil
	case "searchLogs":
		recs, notice, err := f.SearchLogs(ctx, runtime.LogQuery{App: c.App, Replica: c.Replica, Container: c.Container,
			Since: at(c.SinceNs), Until: at(c.UntilNs), Grep: c.Grep, Limit: c.Limit, MaxBytes: c.MaxBytes})
		out := []map[string]any{}
		for _, r := range recs {
			out = append(out, wireRec(r))
		}
		return map[string]any{"records": out, "notice": notice}, true, err
	case "pruneLogs":
		return nil, true, f.PruneLogs(ctx, time.Duration(c.Retention)*time.Millisecond, c.MaxBytes)
	case "tailLogs":
		tail, err := f.TailLogs(ctx, c.Target, c.MaxBytes)
		out := []map[string]any{}
		for _, r := range tail.Records {
			out = append(out, wireRec(r))
		}
		return map[string]any{"records": out}, true, err
	case "tailLogsEncoded":
		tail, err := pfakeEncoding{f}.TailLogsEncoded(ctx, c.Target, c.MaxBytes, runtime.LogEncoding{Format: c.Format, Node: c.Node,
			BatchRecords: c.BatchRecs, BatchBytes: c.BatchBytes})
		bodies := []string{}
		for _, b := range tail.Bodies {
			bodies = append(bodies, string(b))
		}
		return map[string]any{"bodies": bodies, "size": tail.Size}, true, err
	case "commitLogs":
		return nil, true, f.commit(c.Target)()
	case "readQueue", "readSandboxQueue":
		n, _, err := f.readQueue(method, c.ID, runtime.QueueRead{Type: c.Type, Name: c.Name, URL: c.URL})
		return n, true, err
	case "ensureSandbox":
		s, err := f.EnsureSandbox(ctx, c.ID)
		return map[string]any{"id": s.ID, "ip": s.IP}, true, err
	case "removeSandbox":
		return nil, true, f.RemoveSandbox(ctx, c.ID)
	case "listSandboxes":
		list, err := f.ListSandboxes(ctx)
		out := []map[string]any{}
		for _, s := range list {
			out = append(out, map[string]any{"id": s.ID, "ip": s.IP})
		}
		return out, true, err
	}
	return nil, false, nil
}

// sideAgent is what both agents do beside the reconcile pass.
type sideAgent interface {
	exec(*armadav1.ExecRequest)
	logs(*armadav1.LogRequest)
	volume(*armadav1.VolumeRequest)
	pruneLogs()
	queues()
	sandboxes()
	exportRound() time.Duration
	cleanNFS()
}

func (g *goAgent) exec(r *armadav1.ExecRequest)     { g.a.serveExec(g.ctx, r) }
func (g *goAgent) logs(r *armadav1.LogRequest)      { g.a.serveLogs(g.ctx, r) }
func (g *goAgent) volume(r *armadav1.VolumeRequest) { g.a.serveVolume(g.ctx, r) }
func (g *goAgent) pruneLogs()                       { g.a.pruneLogs(g.ctx) }
func (g *goAgent) queues()                          { g.a.measureQueues(g.ctx) }
func (g *goAgent) sandboxes() {
	g.a.syncSandboxes(g.ctx)
	g.a.sb.reads.Wait()
}

func (g *goAgent) exportRound() time.Duration {
	lt, _ := g.a.cfg.Driver.(runtime.LogTailer)
	w, _ := g.a.exportRound(g.ctx, lt, &g.export)
	return w
}

func (g *goAgent) cleanNFS() {
	g.a.mu.Lock()
	d := g.a.desired
	g.a.mu.Unlock()
	g.a.cleanNFS(d)
}

func (r *rustAgent) exec(req *armadav1.ExecRequest) {
	r.request("exec", map[string]any{"request": protoJSON(req)})
}

func (r *rustAgent) logs(req *armadav1.LogRequest) {
	r.request("logs", map[string]any{"request": protoJSON(req)})
}

func (r *rustAgent) volume(req *armadav1.VolumeRequest) {
	r.request("volume", map[string]any{"request": protoJSON(req)})
}
func (r *rustAgent) pruneLogs() { r.request("pruneLogs", nil) }
func (r *rustAgent) queues()    { r.request("queues", nil) }
func (r *rustAgent) sandboxes() { r.request("sandboxes", nil) }
func (r *rustAgent) cleanNFS()  { r.request("cleanNfs", nil) }
func (r *rustAgent) exportRound() time.Duration {
	var ms int64
	_ = json.Unmarshal(r.request("export", nil)["waitMs"], &ms)
	return time.Duration(ms) * time.Millisecond
}

// side runs fn on the agent and records what everything outside it saw:
// the runtime's calls, the sessions' streams, the fake armada-node's
// calls, and the log endpoint's requests.
func (p *parityRun) side(name string, fn func(a sideAgent)) {
	fn(p.a.(sideAgent))
	p.note("side", name)
	p.note("calls", strings.Join(p.f.takeCalls(), "\n"))
	p.note("server", p.normalize(strings.Join(p.sh.srv.take(), "\n")))
	p.note("node", strings.Join(p.sh.nodeCalls(), "\n"))
	ex := strings.ReplaceAll(strings.Join(p.sh.export.take(), "\n"), p.sh.export.srv.URL, "$EXPORT")
	p.note("export", ex)
}

// sampleSide records a usage sample, the ages of sandbox readings left out.
func (p *parityRun) sampleSide(name string) {
	u := p.a.sample()
	for _, s := range u.GetSandboxes() {
		s.AgeMillis = 0
	}
	p.note("usage "+name, p.normalize(compact(u)))
	p.note("calls", strings.Join(p.f.takeCalls(), "\n"))
	p.note("node", strings.Join(p.sh.nodeCalls(), "\n"))
}

func sideOpts(o *parityOpts) { o.side = true }

func TestAgentParitySide(t *testing.T) {
	t.Parallel()
	running := func(p *parityRun, specs ...*armadav1.ReplicaSpec) {
		p.assign(specs...)
		p.until("running", func(r *armadav1.ReplicaReport) bool {
			for _, s := range specs {
				if !report(r, s.GetId()).GetReady() {
					return false
				}
			}
			return true
		})
	}
	scenarios := []struct {
		name string
		opts func(*parityOpts)
		body func(p *parityRun)
	}{
		{"exec", sideOpts, func(p *parityRun) {
			s := noProbe(pr("web-r1-a", "nginx:1", 0))
			s.Sidecars = []*armadav1.ContainerSpec{{Name: "proxy", Image: "envoy:1"}}
			running(p, s)
			p.sh.srv.execIn = []*armadav1.ExecInput{
				{Input: &armadav1.ExecInput_Resize{Resize: &armadav1.TermSize{Rows: 40, Cols: 100}}},
				{Input: &armadav1.ExecInput_Stdin{Stdin: []byte("hello\n")}},
				{Input: &armadav1.ExecInput_CloseStdin{CloseStdin: true}},
			}
			p.side("echo with input", func(a sideAgent) {
				a.exec(&armadav1.ExecRequest{RequestId: "e1", ReplicaId: "web-r1-a", Cmd: []string{"echo", "hi", "there"}, Stdin: true,
					Tty: true, Size: &armadav1.TermSize{Rows: 24, Cols: 80}})
			})
			p.sh.srv.execIn = nil
			p.side("big output", func(a sideAgent) {
				a.exec(&armadav1.ExecRequest{RequestId: "e2", ReplicaId: "web-r1-a", Cmd: []string{"big"}})
			})
			p.side("exit code", func(a sideAgent) {
				a.exec(&armadav1.ExecRequest{RequestId: "e3", ReplicaId: "web-r1-a", Cmd: []string{"fail", "x"}, Container: "app"})
			})
			p.side("sidecar", func(a sideAgent) {
				a.exec(&armadav1.ExecRequest{RequestId: "e4", ReplicaId: "web-r1-a", Cmd: []string{"fail"}, Container: "proxy"})
			})
			p.side("no such sidecar", func(a sideAgent) {
				a.exec(&armadav1.ExecRequest{RequestId: "e5", ReplicaId: "web-r1-a", Cmd: []string{"sh"}, Container: "nope"})
			})
			p.side("not assigned", func(a sideAgent) {
				a.exec(&armadav1.ExecRequest{RequestId: "e6", ReplicaId: "other-r1-a", Cmd: []string{"sh"}})
			})
			p.side("bad command", func(a sideAgent) {
				a.exec(&armadav1.ExecRequest{RequestId: "e7", ReplicaId: "web-r1-a", Cmd: []string{"sh", "a\x00b"}})
			})
			p.side("does not start", func(a sideAgent) {
				a.exec(&armadav1.ExecRequest{RequestId: "e8", ReplicaId: "web-r1-a", Cmd: []string{"missing"}})
			})
		}},
		{"logs", sideOpts, func(p *parityRun) {
			s := noProbe(pr("web-r1-a", "nginx:1", 0))
			s.Sidecars = []*armadav1.ContainerSpec{{Name: "proxy", Image: "envoy:1"}}
			running(p, s)
			t1 := parityT0.Add(time.Second)
			p.f.set(func(f *pfake) {
				f.side.frames = map[string][]runtime.LogFrame{
					"armada-web-r1-a-1": {{Stream: runtime.Stdout, Data: []byte("GET /ok\n"), Time: t1}, {Stream: runtime.Stderr, Data: []byte("Error: boom\n")},
						{Stream: runtime.Stdout, Data: []byte("GET /err\n"), Time: t1}},
					"armada-web-r1-a-1-proxy": {{Stream: runtime.Stdout, Data: []byte("proxy up\n")}},
				}
			})
			p.side("tail", func(a sideAgent) {
				a.logs(&armadav1.LogRequest{RequestId: "l1", ReplicaId: "web-r1-a", Tail: 10})
			})
			p.side("follow with grep", func(a sideAgent) {
				a.logs(&armadav1.LogRequest{RequestId: "l2", ReplicaId: "web-r1-a", Follow: true, Grep: "ERR"})
			})
			p.side("sidecar", func(a sideAgent) {
				a.logs(&armadav1.LogRequest{RequestId: "l3", ReplicaId: "web-r1-a", Container: "proxy"})
			})
			p.side("no such container", func(a sideAgent) {
				a.logs(&armadav1.LogRequest{RequestId: "l4", ReplicaId: "web-r1-a", Container: "nope"})
			})
			p.side("no replica", func(a sideAgent) {
				a.logs(&armadav1.LogRequest{RequestId: "l5", ReplicaId: "gone-r1-a"})
			})
			p.f.set(func(f *pfake) { f.side.logsErr = "log file gone" })
			p.side("runtime error", func(a sideAgent) {
				a.logs(&armadav1.LogRequest{RequestId: "l6", ReplicaId: "web-r1-a"})
			})
			p.f.set(func(f *pfake) {
				f.side.search = []runtime.LogRecord{{Time: t1, Stream: runtime.Stderr, Data: []byte("old\n"), Replica: "web-r1-z"}}
				f.side.notice = "stopped after 1 GiB"
			})
			p.side("search", func(a sideAgent) {
				a.logs(&armadav1.LogRequest{RequestId: "l7", ReplicaId: "web", Query: &armadav1.LogQuery{App: "web", Replica: "web-r1-z",
					Since: timestamppb.New(parityT0), Until: timestamppb.New(t1), Grep: "Old", Limit: 99999}})
			})
			p.side("search without bounds", func(a sideAgent) {
				a.logs(&armadav1.LogRequest{RequestId: "l8", Query: &armadav1.LogQuery{App: "web"}})
			})
			p.side("prune before settings", func(a sideAgent) { a.pruneLogs() })
			p.a.assign(&armadav1.Assignment{Replicas: []*armadav1.ReplicaSpec{s}, Logs: &armadav1.LogSettings{RetentionSeconds: 86400, MaxBytes: 1 << 30}})
			p.side("prune", func(a sideAgent) { a.pruneLogs() })
		}},
		{"volumes", sideOpts, func(p *parityRun) {
			s := noProbe(pr("web-r1-a", "nginx:1", 0))
			s.Volumes = []*armadav1.VolumeSpec{{Name: "data", Path: "/data"}}
			running(p, s)
			p.sh.script(nodeScript{Archive: strings.Repeat("A", 70_000), ArchiveAnswer: json.RawMessage(`{}`), RestoreAnswer: json.RawMessage(`{}`)})
			p.side("archive, stopped", func(a sideAgent) {
				a.volume(&armadav1.VolumeRequest{RequestId: "v1", Op: armadav1.VolumeRequest_OP_BACKUP, App: "web", Volume: "data", Stop: true})
			})
			p.reconcile("resumed")
			p.side("archive missing", func(a sideAgent) {
				a.volume(&armadav1.VolumeRequest{RequestId: "v2", Op: armadav1.VolumeRequest_OP_BACKUP, App: "web", Volume: "none"})
			})
			p.sh.script(nodeScript{ArchiveAnswer: json.RawMessage(`{"error":"archive volume: walk: \"x\" changed","changed":true}`)})
			p.side("archive changed", func(a sideAgent) {
				a.volume(&armadav1.VolumeRequest{RequestId: "v3", Op: armadav1.VolumeRequest_OP_BACKUP, App: "web", Volume: "data"})
			})
			p.sh.srv.volIn = []*armadav1.VolumeData{{Data: []byte("tar-1")}, {Data: []byte("tar-2"), Done: true}}
			p.sh.script(nodeScript{RestoreAnswer: json.RawMessage(`{}`)})
			p.side("restore", func(a sideAgent) {
				a.volume(&armadav1.VolumeRequest{RequestId: "v4", Op: armadav1.VolumeRequest_OP_RESTORE, App: "web", Volume: "data"})
			})
			p.reconcile("restarted after the restore")
			p.sh.srv.volIn = []*armadav1.VolumeData{{Data: []byte("tar-1")}, {Error: "the client went away"}}
			p.sh.script(nodeScript{RestoreAnswer: json.RawMessage(`{"error":"read archive: the client went away"}`)})
			p.side("restore cut", func(a sideAgent) {
				a.volume(&armadav1.VolumeRequest{RequestId: "v5", Op: armadav1.VolumeRequest_OP_RESTORE, App: "web", Volume: "data"})
			})
			p.reconcile("restarted after the cut restore")
			p.sh.srv.volIn = nil
			p.side("remove while used", func(a sideAgent) {
				a.volume(&armadav1.VolumeRequest{RequestId: "v6", Op: armadav1.VolumeRequest_OP_REMOVE, App: "web", Volume: "data"})
			})
			p.side("bad name", func(a sideAgent) {
				a.volume(&armadav1.VolumeRequest{RequestId: "v7", Op: armadav1.VolumeRequest_OP_BACKUP, App: "web", Volume: "../x"})
			})
			p.side("unknown operation", func(a sideAgent) {
				a.volume(&armadav1.VolumeRequest{RequestId: "v8", App: "web", Volume: "data"})
			})
			p.sampleSide("sizes")
			bucket := &armadav1.BackupTarget{Url: "https://k:s@s3.example.com/b", Key: []byte("0123456789abcdef0123456789abcdef"),
				Keep: &armadav1.BackupKeep{Last: 3, Daily: 7}, TimeZone: "Europe/Amsterdam"}
			p.sh.script(nodeScript{Answers: map[string]string{
				"volume snapshot":  `{"snapshot":{"id":"20260101T000000-ab","time":"2026-01-01T00:00:00.5Z","files":3,"bytes":1024,"node":"n1"},"newBytes":512,"uploaded":2}`,
				"volume prune":     `{"snapshots":2,"stored":4096,"deletedSnapshots":1,"deletedChunks":4}`,
				"volume snapshots": `{"snapshots":[{"id":"a","time":"2026-01-01T00:00:00Z","files":1,"bytes":2,"node":"n1"},{"id":"b","time":"2026-01-02T00:00:00+01:00","files":1,"bytes":2,"node":"n2"}]}`,
			}})
			p.side("snapshot", func(a sideAgent) {
				a.volume(&armadav1.VolumeRequest{RequestId: "v9", Op: armadav1.VolumeRequest_OP_SNAPSHOT, App: "web", Volume: "data", Backup: bucket, Stop: true})
			})
			p.reconcile("resumed after the snapshot")
			p.side("snapshots", func(a sideAgent) {
				a.volume(&armadav1.VolumeRequest{RequestId: "v10", Op: armadav1.VolumeRequest_OP_SNAPSHOTS, App: "web", Volume: "data", Backup: bucket})
			})
			p.side("no bucket", func(a sideAgent) {
				a.volume(&armadav1.VolumeRequest{RequestId: "v11", Op: armadav1.VolumeRequest_OP_SNAPSHOTS, App: "web", Volume: "data"})
			})
			p.sh.script(nodeScript{Answers: map[string]string{
				"volume snapshot": `{"snapshot":{"id":"s2","time":"2026-01-01T00:00:00Z","files":3,"bytes":1024,"node":"n1"},"newBytes":0,"uploaded":0}`,
				"volume prune":    `{"snapshots":5,"stored":10,"deletedSnapshots":0,"deletedChunks":0,"error":"bucket: DeleteObject: AccessDenied (HTTP 403)"}`,
			}})
			p.side("snapshot whose prune failed", func(a sideAgent) {
				a.volume(&armadav1.VolumeRequest{RequestId: "v12", Op: armadav1.VolumeRequest_OP_SNAPSHOT, App: "web", Volume: "data", Backup: bucket})
			})
			p.sh.script(nodeScript{ReadySnapshot: "s2", Answers: map[string]string{
				"volume restore-snapshot": `{"snapshot":{"id":"s2","time":"2026-01-01T00:00:00Z","files":3,"bytes":1024,"node":"n1"}}`,
			}})
			p.side("restore a snapshot", func(a sideAgent) {
				a.volume(&armadav1.VolumeRequest{RequestId: "v13", Op: armadav1.VolumeRequest_OP_RESTORE_SNAPSHOT, App: "web", Volume: "data", Backup: bucket, Snapshot: "latest"})
			})
			p.reconcile("restarted after the snapshot's restore")
			p.sh.script(nodeScript{Answers: map[string]string{"volume restore-snapshot": `{"error":"no backup of web/data in the bucket"}`}})
			p.side("no snapshot to restore", func(a sideAgent) {
				a.volume(&armadav1.VolumeRequest{RequestId: "v14", Op: armadav1.VolumeRequest_OP_RESTORE_SNAPSHOT, App: "web", Volume: "data", Backup: bucket, Snapshot: "latest"})
			})
			p.assign()
			p.reconcile("replica gone")
			p.side("remove", func(a sideAgent) {
				a.volume(&armadav1.VolumeRequest{RequestId: "v15", Op: armadav1.VolumeRequest_OP_REMOVE, App: "web", Volume: "data"})
			})
		}},
		{"queues", sideOpts, func(p *parityRun) {
			s := pr("web-r1-a", "nginx:1", 8080)
			s.Readiness = &armadav1.Probe{Path: "/r"}
			s.Queues = []*armadav1.QueueProbe{{Type: "queue", Command: []string{"num", "42"}}, {Type: "redis", Url: "redis://:pw@10.0.0.9:6379/0", Name: "jobs"},
				{Type: "rabbitmq", Url: "amqp://u:p@10.0.0.9/v", Name: "work"}}
			w := pr("worker-r1-a", "busybox", 8081)
			w.App, w.Readiness = "worker", &armadav1.Probe{Path: "/r"}
			w.Queues = []*armadav1.QueueProbe{{Type: "queue", Command: []string{"num", "lots"}}}
			p.f.set(func(f *pfake) {
				f.side.queues = map[string]int64{"jobs": 7}
				f.side.qerr = map[string]string{"work": queuelen.ErrUnreachable.Error()}
			})
			running(p, s, w)
			p.side("read", func(a sideAgent) { a.queues() })
			p.sampleSide("lengths")
			s.Queues[0].Command = []string{"big"}
			p.assign(s, w)
			p.reconcile("new command")
			p.side("read again", func(a sideAgent) { a.queues() })
		}},
		{"sandboxes", func(o *parityOpts) {
			o.side, o.sandbox, o.unpublished, o.network, o.bridge = true, true, true, true, "10.120.0."
		}, func(p *parityRun) {
			probe := func(name string) *armadav1.QueueProbe {
				return &armadav1.QueueProbe{Type: "redis", Url: "redis://10.0.0.9", UrlRef: "u/1", Name: name}
			}
			p.f.set(func(f *pfake) {
				f.side.queues = map[string]int64{"a": 3}
				f.side.qerr = map[string]string{"b": "the broker refused the URL's credentials"}
				f.side.boxes = map[string]string{"stale.ops": "10.120.0.250"}
			})
			p.a.assign(&armadav1.Assignment{Network: &armadav1.NetworkConfig{Mode: "plain", ClusterCidr: "10.120.0.0/16"}, QueueSandboxes: []*armadav1.QueueSandbox{
				{Job: "nightly", Probe: probe("a"), IntervalSeconds: 30}, {Job: "import.ops", Probe: probe("b")},
				{Job: "Bad", Probe: probe("a")}, {Job: "cmd", Probe: &armadav1.QueueProbe{Type: "queue"}},
			}})
			p.side("sync", func(a sideAgent) { a.sandboxes() })
			p.sampleSide("readings")
			p.reconcile("local addresses")
			p.side("sync again: nothing due", func(a sideAgent) { a.sandboxes() })
			var many []*armadav1.QueueSandbox
			for i := range 70 {
				many = append(many, &armadav1.QueueSandbox{Job: fmt.Sprintf("j%02d.s%d", i, i%3), Probe: probe("a")})
			}
			p.a.assign(&armadav1.Assignment{Network: &armadav1.NetworkConfig{Mode: "plain", ClusterCidr: "10.120.0.0/16"}, QueueSandboxes: many})
			p.sampleSide("dropped")
		}},
		{"nfs", sideOpts, func(p *parityRun) {
			s := noProbe(pr("web-r1-a", "nginx:1", 0))
			s.Volumes = []*armadav1.VolumeSpec{{Name: "shared", Path: "/shared", Nfs: &armadav1.NfsSource{Server: "10.0.0.7", Path: "/exports/web", ReadOnly: true}}}
			running(p, s)
			p.side("mounted", func(sideAgent) {})
			p.sh.script(nodeScript{Answers: map[string]string{"nfs source": `{"source":"10.0.0.7:/exports/old","mounted":true}`}})
			s.Env = append(s.Env, &armadav1.EnvVar{Name: "B", Value: "2"})
			p.assign(s)
			p.until("recreated on a moved export", func(r *armadav1.ReplicaReport) bool {
				return report(r, s.Id).GetReady() && report(r, s.Id).GetContainerId() == "armada-web-r1-a-2"
			})
			p.side("remounted", func(sideAgent) {})
			p.sh.script(nodeScript{Answers: map[string]string{"nfs mount": `{"error":"mount NFS export: connection timed out"}`}})
			bad := noProbe(pr("api-r1-a", "nginx:1", 0))
			bad.App = "api"
			bad.Volumes = []*armadav1.VolumeSpec{{Name: "x", Path: "/x", Nfs: &armadav1.NfsSource{Server: "10.0.0.8", Path: "/e"}}}
			p.assign(s, bad)
			p.reconcile("a mount that fails")
			p.side("failed mount", func(sideAgent) {})
			p.sh.script(nodeScript{Answers: map[string]string{"nfs source": `{"source":"10.0.0.7:/exports/web","mounted":true}`}})
			p.assign()
			p.reconcile("replicas gone: unmounted")
			p.side("cleaned", func(a sideAgent) { a.cleanNFS() })
		}},
		{"connection tracking", sideOpts, func(p *parityRun) {
			p.sh.script(nodeScript{Answers: map[string]string{
				"conntrack raise": `{"previous":65536}`, "conntrack read": `{"entries":120,"limit":262144,"ok":true}`,
			}})
			p.sampleSide("raised")
			p.sh.script(nodeScript{Answers: map[string]string{
				"conntrack raise": `{"error":"raise the connection tracking limit: open x: permission denied"}`, "conntrack read": `{"ok":false}`,
			}})
			p.sampleSide("not raised")
			p.sampleSide("not raised again")
		}},
		{"log export", sideOpts, exportScenario},
		{"log export encoded", func(o *parityOpts) { o.side, o.encodes = true, true }, exportScenario},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			opts := defaultOpts()
			if sc.opts != nil {
				sc.opts(&opts)
			}
			runAgentParity(t, opts, sc.body)
		})
	}
}

func exportScenario(p *parityRun) {
	t1 := time.Date(2026, 1, 1, 0, 0, 1, 5, time.UTC)
	p.f.set(func(f *pfake) {
		f.side.tail = []runtime.LogRecord{
			{Time: t1, Data: []byte("hello <world> & more\n"), App: "web", Revision: "web--r1", Replica: "web-r1-a"},
			{Time: t1, Stream: runtime.Stderr, Data: []byte("bad \xff byte"), App: "api.ops", Replica: "api.ops-r1-a", Container: "side"},
			{Time: t1, Data: []byte("not an app"), App: "-x-"},
		}
		f.side.bodies = [][]byte{[]byte(`{"streams":[]}`), []byte(`{"streams":[{"stream":{}}]}`)}
		f.side.size = 100
	})
	p.side("off", func(a sideAgent) { p.note("wait", a.exportRound().String()) })
	export := func(e *armadav1.LogExport) {
		p.a.assign(&armadav1.Assignment{Logs: &armadav1.LogSettings{Export: e}})
	}
	export(&armadav1.LogExport{Format: "loki", Endpoint: p.sh.export.srv.URL + "/loki/api/v1/push", User: "u1", Token: []byte("secret-token"), Tenant: "t1", SetAt: 5})
	p.side("loki", func(a sideAgent) { p.note("wait", a.exportRound().String()) })
	p.sampleSide("sending")
	export(&armadav1.LogExport{Format: "otlp", Endpoint: p.sh.export.srv.URL + "/v1/logs", Token: []byte("secret-token"), SetAt: 6})
	p.side("otlp", func(a sideAgent) { p.note("wait", a.exportRound().String()) })
	p.sh.export.mu.Lock()
	p.sh.export.status = http.StatusTooManyRequests
	p.sh.export.mu.Unlock()
	p.side("refused", func(a sideAgent) { p.note("wait", a.exportRound().String()) })
	p.side("refused again", func(a sideAgent) { p.note("wait", a.exportRound().String()) })
	p.sampleSide("failing")
	export(&armadav1.LogExport{Format: "loki", Endpoint: "http://203.0.113.5/push", SetAt: 7})
	p.side("public http", func(a sideAgent) { p.note("wait", a.exportRound().String()) })
	p.sampleSide("bad endpoint")
	export(nil)
	p.side("off again", func(a sideAgent) { p.note("wait", a.exportRound().String()) })
	p.sampleSide("off")
}
