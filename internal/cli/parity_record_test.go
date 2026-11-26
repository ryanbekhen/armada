package cli

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Recording the client's parity cases for the Rust replay (ADR 0055, item
// 20). With -record-fixtures, TestClientParity runs every case against Go's
// armada only and writes client/tests/testdata/parity.jsonl.gz: one line
// per case with what the case gives the client (arguments, its own
// environment, standard input, the files and the client config it starts
// with, the time Go's run started) and what the fake AdminService answers
// (protobuf JSON per method, in order), then Go's outcome: exit code,
// standard output and error, the requests the fake received (normalized
// as the harness compares them), the client config left, and every file
// left with its mode. client/tests/parity.rs replays each line against
// the Rust armada (built with its test-hooks feature, so its clock starts
// at the recorded time) and a stand-in AdminService of its own, and
// compares as compareResults does.
//
// What differs from run to run is written as a placeholder: the case's
// directory {DIR}, the fake's address {ADDR}, the CA certificate {CA}, the
// user certificate {CERT}, and its key {KEY}, as written and inside
// JSON strings ({CA_JSON}, {CERT_JSON}, {KEY_JSON}: the lines joined by
// \n); the replay puts its own in their place.

var recordFixtures = flag.Bool("record-fixtures", false,
	"write client/tests/testdata/parity.jsonl.gz (each case and Go's outcome) for the Rust replay")

// clientFixtures is where the recording goes, from this package.
const clientFixtures = "../../client/tests/testdata/parity.jsonl.gz"

// recordedConfig is the client config a case starts with.
type recordedConfig struct {
	Mode os.FileMode `json:"mode"`
	Text string      `json:"text"`
}

type clientRecorder struct {
	h     *harness
	lines [][]byte
}

func newClientRecorder(h *harness) *clientRecorder {
	if !*recordFixtures {
		return nil
	}
	return &clientRecorder{h: h}
}

// before notes the config a case starts with and the time Go's run starts.
func (h *harness) before(dir string) {
	h.startConfig = nil
	if fi, err := os.Stat(h.configPath(dir)); err == nil {
		b, _ := os.ReadFile(h.configPath(dir))
		h.startConfig = &recordedConfig{Mode: fi.Mode().Perm(), Text: string(b)}
	}
	h.dir = dir
	h.started = time.Now()
}

func answerJSON(m proto.Message) json.RawMessage {
	if m == nil {
		return json.RawMessage("null")
	}
	b, err := protojson.MarshalOptions{}.Marshal(m)
	if err != nil {
		panic(err)
	}
	return json.RawMessage(compactJSON(b))
}

func (r *clientRecorder) add(t *testing.T, h *harness, c parityCase, res parityResult) {
	t.Helper()
	answers := map[string]any{}
	for method, as := range c.answers {
		var list []map[string]any
		for _, a := range as {
			e := map[string]any{}
			if a.msg != nil {
				e["msg"] = answerJSON(a.msg)
			}
			if a.code != codes.OK {
				e["code"] = int(a.code)
				e["text"] = a.text
			}
			if a.servers != "" {
				e["servers"] = a.servers
			}
			if a.stream != nil {
				var st []json.RawMessage
				for _, m := range a.stream {
					st = append(st, answerJSON(m))
				}
				e["stream"] = st
			}
			list = append(list, e)
		}
		answers[method] = list
	}
	var calls []map[string]any
	for _, cl := range res.Calls {
		e := map[string]any{"method": cl.Method}
		switch cl.Method {
		case "RestoreVolume":
			e["start"] = cl.start
			e["data"] = base64.StdEncoding.EncodeToString(cl.data)
		case "ExecInput":
			e["data"] = base64.StdEncoding.EncodeToString(cl.data)
			e["rest"] = cl.rest
		default:
			e["request"] = cl.Request
		}
		calls = append(calls, e)
	}
	line := map[string]any{
		"name":    c.name,
		"args":    c.args,
		"env":     c.env,
		"stdin":   c.stdin,
		"files":   c.files,
		"config":  h.startConfig,
		"now":     h.started.UnixNano(),
		"answers": answers,
		"go": map[string]any{
			"code":   res.Code,
			"stdout": res.Stdout,
			"stderr": res.Stderr,
			"calls":  calls,
			"config": res.Config,
			"files":  res.Files,
		},
	}
	b, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	v = r.placeholders(v, h.dir)
	if b, err = json.Marshal(v); err != nil {
		t.Fatal(err)
	}
	r.lines = append(r.lines, b)
}

// placeholders replaces in every string what differs from run to run.
func (r *clientRecorder) placeholders(v any, dir string) any {
	type pair struct{ from, to string }
	var pairs []pair
	for _, p := range []pair{{r.h.cfg.CA, "{CA}"}, {r.h.cfg.Cert, "{CERT}"}, {r.h.cfg.Key, "{KEY}"}} {
		pairs = append(pairs, p, pair{strings.ReplaceAll(p.from, "\n", `\n`), strings.TrimSuffix(p.to, "}") + "_JSON}"})
	}
	pairs = append(pairs, pair{dir, "{DIR}"}, pair{r.h.addr, "{ADDR}"})
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case string:
			for _, p := range pairs {
				x = strings.ReplaceAll(x, p.from, p.to)
			}
			return x
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
		case map[string]any:
			for k := range x {
				x[k] = walk(x[k])
			}
		}
		return v
	}
	return walk(v)
}

func (r *clientRecorder) write(t *testing.T) {
	t.Helper()
	if t.Failed() {
		return
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	for _, l := range r.lines {
		_, _ = zw.Write(l)
		_, _ = zw.Write([]byte("\n"))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientFixtures, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("recorded %d cases into %s (%d bytes)", len(r.lines), clientFixtures, buf.Len())
}
