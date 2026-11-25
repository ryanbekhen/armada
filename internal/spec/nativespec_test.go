package spec

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The parity tests of the spec crate (spec/, ADR 0055): every input runs
// through this package and through armada-spec-check, the crate's test
// program, and the answers must be the same, error texts included. They
// run only with ARMADA_SPEC_BIN naming the program:
//
//	cargo build --locked -p armada-spec --bin armada-spec-check
//	ARMADA_SPEC_BIN=$PWD/target/debug/armada-spec-check go test -run TestArmadaSpec ./internal/spec/
//
// ARMADA_SPEC_MUTATIONS sets how many mutated specs run (default 20000).

type specProgram struct {
	t   *testing.T
	in  *bufio.Writer
	out *bufio.Reader
	cmd *exec.Cmd
}

func startSpecProgram(t *testing.T) *specProgram {
	t.Helper()
	bin := os.Getenv("ARMADA_SPEC_BIN")
	if bin == "" {
		t.Skip("ARMADA_SPEC_BIN is not set")
	}
	cmd := exec.Command(bin)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &specProgram{t: t, in: bufio.NewWriter(stdin), out: bufio.NewReaderSize(stdout, 1<<20), cmd: cmd}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	return p
}

// ask sends one request and decodes the answer into v.
func (p *specProgram) ask(req any, v any) {
	p.t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		p.t.Fatal(err)
	}
	if _, err := p.in.Write(append(b, '\n')); err != nil {
		p.t.Fatal(err)
	}
	if err := p.in.Flush(); err != nil {
		p.t.Fatal(err)
	}
	line, err := p.out.ReadBytes('\n')
	if err != nil {
		p.t.Fatalf("armada-spec-check: %v", err)
	}
	if err := json.Unmarshal(line, v); err != nil {
		p.t.Fatalf("armada-spec-check answered %q: %v", line, err)
	}
}

// lossy is a Go string as encoding/json writes it: each byte of invalid
// UTF-8 becomes U+FFFD.
func lossy(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteRune(utf8.RuneError)
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// randomOrder reports whether Go's error text depends on map iteration:
// the job-only fields of an app, CORS header lists, and placement.require
// are checked in no fixed order, which Go does not promise.
func randomOrder(goErr string) bool {
	return strings.Count(goErr, "is only valid for kind: job") > 1 ||
		(strings.Contains(goErr, "ingress.cors.allowHeaders") && strings.Contains(goErr, "ingress.cors.exposeHeaders")) ||
		strings.Count(goErr, "placement.require") > 1
}

func sameError(goErr, rustErr string) bool {
	goErr = lossy(goErr)
	if goErr == rustErr {
		return true
	}
	if !randomOrder(goErr) {
		return false
	}
	a, b := strings.Split(goErr, "\n"), strings.Split(rustErr, "\n")
	sort.Strings(a)
	sort.Strings(b)
	return slices.Equal(a, b)
}

// sameJSON compares two JSON documents as values.
func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

var parityKeys = map[string][]string{
	"":       {"database-url", "API_KEY", "port", "armada-x", "Bad-Key"},
	"shared": {"token", "redis-url"},
	"db":     {"password", "url"},
}

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// nonNil writes a nil list as an empty one, as the Rust summary does.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// specSummary is what armada-spec-check's summary holds: the values of
// App's methods.
func specSummary(a *App) map[string]any {
	lo, hi := a.ScaleBounds()
	with := map[string]any{}
	if c, err := a.WithSecretEnv(parityKeys); err != nil {
		with["error"] = err.Error()
	} else {
		b, _ := json.Marshal(c)
		with["env"] = string(b)
	}
	backups := []any{}
	for _, v := range a.Volumes {
		if v.Backup == nil {
			continue
		}
		backups = append(backups, map[string]any{
			"next":     v.Backup.Next(mustTime("2026-03-29T00:30:00Z")).Format(time.RFC3339Nano),
			"location": v.Backup.Location().String(),
		})
	}
	windows := []any{}
	if a.Scale != nil {
		for _, r := range a.Scale.Rules {
			open, until := r.Window(mustTime("2026-11-25T08:59:30Z"))
			windows = append(windows, map[string]any{"open": open, "until": until.Format(time.RFC3339Nano)})
		}
	}
	var jobNext any
	if s, ok := a.JobSchedule(); ok {
		t := mustTime("2026-03-28T22:15:00Z")
		var out []string
		for range 5 {
			t = s.Next(t)
			out = append(out, t.Format(time.RFC3339Nano))
		}
		jobNext = out
	}
	var ipAllow, ipDeny, cors any
	tcp := false
	if a.Ingress != nil {
		ipAllow, ipDeny = IPRanges(a.Ingress.IPAllow), IPRanges(a.Ingress.IPDeny)
		if a.Ingress.CORS != nil {
			cors = a.Ingress.CORS.CORSMethods()
		}
		tcp = a.Ingress.TCP()
	}
	var runs any
	if a.Trigger != nil {
		var r []int
		for _, n := range []int64{0, 1, 7, 100, 1_000_000_000_000} {
			r = append(r, a.Trigger.RunsWanted(n))
		}
		runs = r
	}
	var queueName any
	if q := a.QueueTrigger(); q != nil {
		queueName = q.Name()
	}
	return map[string]any{
		"id":                  a.ID(),
		"autoscaled":          a.Autoscaled(),
		"bounds":              []int{lo, hi},
		"scalesToZero":        a.ScalesToZero(),
		"idleAfter":           int64(a.IdleAfter()),
		"replicas":            a.Replicas(),
		"memoryBytes":         a.MemoryBytes(),
		"nanoCPUs":            a.NanoCPUs(),
		"cpuMillis":           a.CPUMillis(),
		"multipleRevisions":   a.MultipleRevisions(),
		"queueRules":          len(a.QueueRules()),
		"hasContainers":       a.HasContainers(),
		"containerNames":      nonNil(a.ContainerNames()),
		"reservedCPUMillis":   a.ReservedCPUMillis(),
		"reservedMemoryBytes": a.ReservedMemoryBytes(),
		"failsOver":           a.FailsOver(),
		"hasVolumes":          a.HasVolumes(),
		"hasLocalVolumes":     a.HasLocalVolumes(),
		"hasNFSVolumes":       a.HasNFSVolumes(),
		"jobTimeout":          int64(a.JobTimeout()),
		"jobHistory":          a.JobHistory(),
		"jobTasks":            a.JobTasks(),
		"jobParallelism":      a.JobParallelism(),
		"jobConcurrency":      a.JobConcurrency(),
		"jobNext":             jobNext,
		"secretRefs":          nonNil(a.SecretRefs()),
		"backupSecretRefs":    nonNil(a.BackupSecretRefs()),
		"usesSpaceSecrets":    a.UsesSpaceSecrets(),
		"placement":           a.Placement.String(),
		"spreadKey":           a.Placement.SpreadKey(),
		"ipAllow":             ipAllow,
		"ipDeny":              ipDeny,
		"corsMethods":         cors,
		"tcp":                 tcp,
		"searchDomain":        InternalSearchDomain(a.ID()),
		"pollEvery":           int64(a.Trigger.PollEvery()),
		"maxRuns":             a.Trigger.MaxRuns(),
		"runsWanted":          runs,
		"queueName":           queueName,
		"withSecretEnv":       with,
		"backups":             backups,
		"windows":             windows,
	}
}

type parseAnswer struct {
	Error   *string         `json:"error"`
	JSON    string          `json:"json"`
	Export  json.RawMessage `json:"export"`
	Summary json.RawMessage `json:"summary"`
}

type specParity struct {
	p      *specProgram
	t      *testing.T
	failed int
	counts map[string]int
}

func (s *specParity) fail(format string, args ...any) {
	s.t.Helper()
	s.failed++
	if s.failed <= 25 {
		s.t.Errorf(format, args...)
	}
	if s.failed == 25 {
		s.t.Error("more differences follow; only the first 25 are shown")
	}
}

// parse runs one spec through ParseIn and armada-spec-check.
func (s *specParity) parse(data []byte, space string) {
	s.t.Helper()
	s.counts["parse"]++
	var got parseAnswer
	s.p.ask(map[string]any{"op": "parse", "data": base64.StdEncoding.EncodeToString(data), "space": space}, &got)
	app, err := ParseIn(data, space)
	if err != nil {
		s.counts["parse error"]++
		if got.Error == nil {
			s.fail("spec %q (space %q): Go: %v; Rust parsed it", data, space, err)
		} else if !sameError(err.Error(), *got.Error) {
			s.fail("spec %q (space %q):\nGo:   %q\nRust: %q", data, space, err.Error(), *got.Error)
		}
		return
	}
	if got.Error != nil {
		s.fail("spec %q (space %q): Go parsed it; Rust: %s", data, space, *got.Error)
		return
	}
	goJSON, err := json.Marshal(app)
	if err != nil {
		s.t.Fatal(err)
	}
	if string(goJSON) != got.JSON {
		s.fail("spec %q: JSON\nGo:   %s\nRust: %s", data, goJSON, got.JSON)
	}
	var export any
	if b, err := app.Export(); err != nil {
		export = map[string]any{"error": err.Error()}
	} else {
		export = lossy(string(b))
	}
	goExport, _ := json.Marshal(export)
	if !sameJSON(goExport, got.Export) {
		s.fail("spec %q: export\nGo:   %s\nRust: %s", data, goExport, got.Export)
	}
	goSummary, _ := json.Marshal(specSummary(app))
	if !sameJSON(goSummary, got.Summary) {
		s.fail("spec %q: summary\nGo:   %s\nRust: %s", data, goSummary, got.Summary)
	}
	s.json(goJSON)
}

// json reads a stored spec on both sides and compares what each writes
// back, its export, and its validation.
func (s *specParity) json(data []byte) {
	s.t.Helper()
	s.counts["json"]++
	var got struct {
		Error    *string         `json:"error"`
		JSON     string          `json:"json"`
		Export   json.RawMessage `json:"export"`
		Validate *string         `json:"validate"`
	}
	s.p.ask(map[string]any{"op": "json", "json": string(data)}, &got)
	var app App
	if err := json.Unmarshal(data, &app); err != nil {
		if got.Error == nil {
			s.fail("JSON %s: Go: %v; Rust read it", data, err)
		} else if lossy(err.Error()) != *got.Error {
			s.fail("JSON %s:\nGo:   %q\nRust: %q", data, err.Error(), *got.Error)
		}
		return
	}
	if got.Error != nil {
		s.fail("JSON %s: Go read it; Rust: %s", data, *got.Error)
		return
	}
	goJSON, _ := json.Marshal(&app)
	if string(goJSON) != got.JSON {
		s.fail("JSON %s:\nGo:   %s\nRust: %s", data, goJSON, got.JSON)
	}
	var export any
	if b, err := app.Export(); err != nil {
		export = map[string]any{"error": err.Error()}
	} else {
		export = lossy(string(b))
	}
	goExport, _ := json.Marshal(export)
	if !sameJSON(goExport, got.Export) {
		s.fail("JSON %s: export\nGo:   %s\nRust: %s", data, goExport, got.Export)
	}
	err := app.Validate()
	switch {
	case err == nil && got.Validate != nil:
		s.fail("JSON %s: Go: valid; Rust: %s", data, *got.Validate)
	case err != nil && got.Validate == nil:
		s.fail("JSON %s: Go: %v; Rust: valid", data, err)
	case err != nil && !sameError(err.Error(), *got.Validate):
		s.fail("JSON %s: validate\nGo:   %q\nRust: %q", data, err.Error(), *got.Validate)
	}
}

// nonceRe matches Substitute's placeholders, which reach the output only
// where the spec hides a variable from the parser (in an escape sequence
// or a tag), and differ on every call.
var nonceRe = regexp.MustCompile(`av[0-9a-f]{16}n`)

// substitute runs Substitute on both sides.
func (s *specParity) substitute(data []byte, vars map[string]string) {
	s.t.Helper()
	s.counts["substitute"]++
	var got struct {
		Error *string `json:"error"`
		Out   string  `json:"out"`
	}
	s.p.ask(map[string]any{"op": "substitute", "data": base64.StdEncoding.EncodeToString(data), "vars": vars}, &got)
	out, err := Substitute(data, vars)
	if got.Error != nil {
		*got.Error = nonceRe.ReplaceAllString(*got.Error, "avNONCEn")
	}
	got.Out = nonceRe.ReplaceAllString(got.Out, "avNONCEn")
	out = nonceRe.ReplaceAll(out, []byte("avNONCEn"))
	if err != nil {
		err = errors.New(nonceRe.ReplaceAllString(err.Error(), "avNONCEn"))
	}
	switch {
	case err != nil && got.Error == nil:
		s.fail("substitute %q: Go: %v; Rust: %q", data, err, got.Out)
	case err != nil && lossy(err.Error()) != *got.Error:
		s.fail("substitute %q:\nGo:   %q\nRust: %q", data, err.Error(), *got.Error)
	case err == nil && got.Error != nil:
		s.fail("substitute %q: Go: %q; Rust: %s", data, out, *got.Error)
	case err == nil && lossy(string(out)) != got.Out:
		s.fail("substitute %q:\nGo:   %q\nRust: %q", data, out, got.Out)
	}
}

// specCorpus is every spec-like text of the repository: YAML files, YAML
// blocks of the documents, here-documents of the shell scripts, and every
// string literal of this package's tests.
func specCorpus(t *testing.T) [][]byte {
	t.Helper()
	root := filepath.Join("..", "..")
	var out [][]byte
	block := regexp.MustCompile("(?s)```ya?ml\n(.*?)```")
	heredoc := regexp.MustCompile(`(?s)<<-?'?([A-Z]+)'?\n(.*?)\n[\t ]*([A-Z]+)\n`)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "target", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".yaml", ".yml":
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out = append(out, b)
		case ".md":
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range block.FindAllSubmatch(b, -1) {
				out = append(out, m[1])
			}
		case ".sh":
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range heredoc.FindAllSubmatch(b, -1) {
				out = append(out, m[2])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, trickySpecs...)
	return append(out, testLiterals(t)...)
}

// trickySpecs reach the corners of the YAML decoder: anchors, aliases,
// merge keys, tags, duplicate keys, the UnmarshalYAML methods (which
// encode their node again, comments included, so their errors count
// lines from that text), and documents.
var trickySpecs = func() [][]byte {
	var out [][]byte
	for _, s := range []string{
		"",
		"# only a comment\n",
		"---\n",
		"---\n...\n",
		"name: web\nimage: nginx\n---\nname: other\n",
		"name: web\nimage: nginx\n---\n: bad\n",
		"name: web\nimage: nginx\n...\n# after\n",
		"- name: web\n",
		"hello\n",
		"~\n",
		"name: web\nimage: nginx\nname: again\n",
		"name: web\nimage: nginx\n\"name\": again\n",
		"base: &b {name: web}\n",
		"name: &n web\nimage: nginx\nenv:\n  - name: A\n    value: *n\n",
		"name: web\nimage: nginx\n<<: {kind: job}\n",
		"x: &m {name: web, image: nginx}\n",
		"name: web\n<<: &m {image: nginx, kind: job}\n",
		"name: web\nimage: nginx\n<<: [{retries: 1}, {retries: 2}]\n",
		"name: web\nimage: nginx\n<<: 5\n",
		"name: web\nimage: nginx\n<<: [5]\n",
		"name: web\nimage: nginx\nprobes:\n  readiness: &p\n    path: /a\n  liveness: *p\ningress: {type: external, port: 80}\n",
		"name: web\nimage: nginx\nprobes:\n  readiness:\n    # a comment\n    path: /a\n    unknown: 1\ningress: {type: external, port: 80}\n",
		"name: web\nimage: nginx\nprobes:\n  readiness:\n    path: /a  # trailing\n    port: x\n    period: 1x\n",
		"name: web\nimage: nginx\nprobes:\n  readiness: [a, b]\n",
		"name: web\nimage: nginx\nprobes:\n  readiness: {path: /a, period: {x: 1}}\n",
		"name: web\nimage: nginx\ningress:\n  type: external\n  port: 80\n  ipAllow:\n    - 10.0.0.0/8\n    - range: 192.168.0.0/16\n      name: lan\n    - {range: 1.2.3.4, bogus: 1}\n",
		"name: web\nimage: nginx\nenvFrom: secrets\n",
		"name: web\nimage: nginx\nenvFrom: other\n",
		"name: web\nimage: nginx\nenvFrom:\n  - secret: db\n  - secret: db\n  - {secret: x, extra: 1}\n",
		"name: web\nimage: nginx\nenvFrom: {secret: db}\n",
		"name: web\nimage: nginx\nenvFrom: []\n",
		"name: web\nimage: nginx\nenvFrom: ~\n",
		"name: web\nimage: nginx\nvolumes:\n  - name: d\n    path: /d\n    backup: {every: 1h, keep: 3, urlSecretRef: u, keySecretRef: k}\n",
		"name: web\nimage: nginx\nvolumes:\n  - name: d\n    path: /d\n    backup: {every: 1h, keep: {last: 1, daily: 7}, urlSecretRef: u, keySecretRef: k}\n",
		"name: web\nimage: nginx\nvolumes:\n  - name: d\n    path: /d\n    backup: {every: 1h, keep: x, urlSecretRef: u, keySecretRef: k}\n",
		"name: web\nimage: nginx\nvolumes:\n  - name: d\n    path: /d\n    backup: {every: 1h, keep: {last: x, yearly: 1}, urlSecretRef: u, keySecretRef: k}\n",
		"name: web\nimage: nginx\nvolumes:\n  - name: d\n    path: /d\n    backup: {every: 1h, keep: 1.9, urlSecretRef: u, keySecretRef: k}\n",
		"name: web\nimage: nginx\nplacement:\n  require:\n    zone: a\n    rack: [r1, r2]\n    kind: {x: 1}\n",
		"name: web\nimage: nginx\nplacement:\n  require:\n    zone: ~\n",
		"name: web\nimage: nginx\nplacement:\n  require: {<<: {zone: a}, rack: b}\n",
		"name: web\nimage: nginx\nplacement:\n  require: [a]\n",
		"name: !!str web\nimage: !!binary bmdpbng=\n",
		"name: web\nimage: !!binary bad!\n",
		"name: web\nimage: nginx\nretries: !!int x\n",
		"name: web\nimage: nginx\nkind: job\nretries: 0x2\nhistory: 1e1\ntasks: 2.9\n",
		"name: web\nimage: nginx\nkind: job\nretries: 9223372036854775808\n",
		"name: web\nimage: nginx\nkind: job\nretries: .nan\n",
		"name: web\nimage: nginx\nkind: job\nretries: -.inf\n",
		"name: web\nimage: nginx\nkind: job\nretries: true\n",
		"name: web\nimage: nginx\nkind: job\nretries: 2001-01-01\n",
		"name: web\nimage: nginx\ningress: {type: external, port: 80, sticky: yes}\n",
		"name: web\nimage: nginx\ningress: {type: external, port: 80, sticky: \"off\"}\n",
		"name: web\nimage: nginx\ningress: {type: external, port: 80, sticky: maybe}\n",
		"name: 1\nimage: 2\n",
		"name: web\nimage: nginx\nspace: shop\n",
		"name: web\nimage: nginx\nenvFromAdded: [A]\n",
		"name: web\nimage: nginx\ndrain: 10\n",
		"name: web\nimage: nginx\ndrain: [1s]\n",
		"name: web\nimage: nginx\ndrain: \"1h30m\"\n",
		"name: web\nimage: nginx\ncommand: run\n",
		"name: web\nimage: nginx\ncommand: [a, [b], c]\n",
		"name: web\nimage: nginx\nenv: [{name: A, value: [1]}]\n",
		"? name\n: web\nimage: nginx\n",
		"name: web\nimage: nginx\n? [a]\n: b\n",
		"&a name: web\n*a : x\nimage: nginx\n",
		"name: web\nimage: nginx\nscale: {min: 0, max: 3, rules: [{type: http, concurrent: 10}]}\ningress: {type: internal, port: 80}\n",
		"name: web\nimage: nginx\nscale: &s {min: 1}\nresources: *s\n",
		"a: &a [*a]\nname: web\nimage: nginx\nenv: *a\n",
		"name: \"w\\x65b\"\nimage: 'ngi''nx'\n",
		"name: >-\n  web\nimage: |\n  nginx\n",
		"\xef\xbb\xbfname: web\nimage: nginx\n",
		"name: web\r\nimage: nginx\r\n",
		"name:\tweb\nimage: nginx\n",
		"name: web\nimage: nginx\nargs: [\"a\\u0000b\"]\n",
		"%YAML 1.1\n---\nname: web\nimage: nginx\n",
		"%TAG !e! tag:example.com,2000:\n---\nname: !e!x web\nimage: nginx\n",
		"name: web\nimage: nginx\nprobes: {readiness: /health, liveness: {command: [sh, -c, true], port: 8}}\ningress: {type: external, port: 80}\n",
	} {
		out = append(out, []byte(s))
	}
	return out
}()

// testLiterals returns every string literal of this package's tests.
func testLiterals(t *testing.T) [][]byte {
	t.Helper()
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fset := token.NewFileSet()
	for _, f := range files {
		if f == "nativespec_test.go" {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					out = append(out, []byte(s))
				}
			}
			return true
		})
	}
	return out
}

// interesting are values mutations put into specs.
var interesting = []string{
	"", "~", "null", "0", "1", "-1", "2", "8080", "65536", "1e3", "0x50", "0o17", "0b101", "1_000", "1.5", "-0",
	".inf", ".nan", "9223372036854775807", "9223372036854775808", "18446744073709551616", "yes", "no", "on", "Off",
	"true", "False", "10s", "1h", "0s", "-1s", "1.5m", "90s", "25h", "1d", "abc", "web", "web-api", "Web", "a--b",
	"\"quoted\"", "'single'", "a b", "ÿ", "\"\\u00e9\"", "[]", "[a, b]", "{}", "{a: 1}", "!!str 1", "!!int x",
	"!!binary aGk=", "!!float 1", "!!bool yes", "!foo bar", "*", "&a x", "*a", "|\n  text", ">\n  folded",
	"2001-01-01", "2001-01-01T00:00:00Z", "external", "internal", "none", "tcp", "http", "job", "app",
	"secrets", "multiple", "single", "redis", "rabbitmq", "schedule", "cpu", "memory", "queue", "restore",
	"0 2 * * *", "*/5 * * * *", "61 * * * *", "@daily", "Europe/Berlin", "America/New_York", "Mars/Olympus",
	"10.0.0.1", "10.0.0.0/8", "::1", "::ffff:1.2.3.4", "0.0.0.0/0", "fe80::1%eth0", "/data", "/proc/x", "/",
	"/a/../b", "999:999", "-1:0", "256Mi", "1Gi", "0.5", "500m", "64.001", "https://app.example.com",
	"http://localhost:3000", "*", "X-Token", "db/url", "a/b/c", "DATABASE_URL", "ghcr.io/org/app:1",
	"nginx@sha256:" + strings.Repeat("a", 64), "localhost:5000/x", strings.Repeat("x", 300),
}

var specKeys = []string{
	"apiVersion", "kind", "name", "image", "command", "args", "env", "envFrom", "secretFiles", "registry",
	"ingress", "type", "protocol", "port", "domains", "routes", "path", "stripPrefix", "allow", "ipAllow",
	"ipDeny", "range", "sticky", "cors", "allowOrigins", "timeout", "dns", "provider", "tokenSecretRef",
	"revisions", "mode", "traffic", "revision", "weight", "label", "probes", "startup", "readiness",
	"liveness", "period", "failureThreshold", "scale", "min", "max", "rules", "concurrent", "utilization",
	"length", "duration", "replicas", "idleAfter", "resources", "cpu", "memory", "placement", "require",
	"spreadBy", "volumes", "owner", "backup", "every", "keep", "last", "daily", "urlSecretRef",
	"keySecretRef", "failover", "nfs", "server", "initContainers", "sidecars", "drain", "schedule",
	"timeZone", "retries", "concurrency", "history", "tasks", "parallelism", "trigger", "perRun",
	"pollingInterval", "list", "secretRef", "value", "space", "unknown", "<<",
}

var yamlBytes = []byte(" \n\t:-?,[]{}#&*!|>'\"%@`~0aZ\r\xff\xc3")

// mutate changes a spec at random: a value, a key, a line, or a byte.
func mutate(r *rand.Rand, data []byte) []byte {
	lines := strings.Split(string(data), "\n")
	switch r.IntN(10) {
	case 0, 1, 2:
		// A value after a colon.
		i := r.IntN(len(lines))
		if c := strings.Index(lines[i], ": "); c >= 0 {
			lines[i] = lines[i][:c+2] + interesting[r.IntN(len(interesting))]
		} else if d := strings.Index(lines[i], "- "); d >= 0 {
			lines[i] = lines[i][:d+2] + interesting[r.IntN(len(interesting))]
		}
	case 3:
		// A key.
		i := r.IntN(len(lines))
		indent := len(lines[i]) - len(strings.TrimLeft(lines[i], " -"))
		lines[i] = lines[i][:indent] + specKeys[r.IntN(len(specKeys))] + ": " + interesting[r.IntN(len(interesting))]
	case 4:
		// A line dropped or repeated.
		i := r.IntN(len(lines))
		if r.IntN(2) == 0 {
			lines = slices.Delete(lines, i, i+1)
		} else {
			lines = slices.Insert(lines, i, lines[i])
		}
	case 5:
		// A line indented differently.
		i := r.IntN(len(lines))
		if r.IntN(2) == 0 {
			lines[i] = "  " + lines[i]
		} else {
			lines[i] = strings.TrimPrefix(lines[i], "  ")
		}
	case 6:
		// A new nested key.
		i := r.IntN(len(lines))
		indent := len(lines[i]) - len(strings.TrimLeft(lines[i], " "))
		lines = slices.Insert(lines, i+1, strings.Repeat(" ", indent+2*r.IntN(2))+specKeys[r.IntN(len(specKeys))]+": "+interesting[r.IntN(len(interesting))])
	default:
		// Bytes.
		b := []byte(strings.Join(lines, "\n"))
		for range 1 + r.IntN(3) {
			if len(b) == 0 {
				break
			}
			i := r.IntN(len(b))
			switch r.IntN(3) {
			case 0:
				b[i] = yamlBytes[r.IntN(len(yamlBytes))]
			case 1:
				b = slices.Delete(b, i, i+1)
			default:
				b = slices.Insert(b, i, yamlBytes[r.IntN(len(yamlBytes))])
			}
		}
		return b
	}
	return []byte(strings.Join(lines, "\n"))
}

// TestArmadaSpecParseMatchesGo parses the corpus, the specs this package's
// tests build, and mutations of them with both, and compares the errors,
// the JSON, the export, and what App's methods answer.
func TestArmadaSpecParseMatchesGo(t *testing.T) {
	p := startSpecProgram(t)
	s := &specParity{p: p, t: t, counts: map[string]int{}}
	corpus := specCorpus(t)
	for _, c := range corpus {
		s.parse(c, "")
		s.parse(c, "shop")
	}
	n := 20000
	if v := os.Getenv("ARMADA_SPEC_MUTATIONS"); v != "" {
		var err error
		if n, err = strconv.Atoi(v); err != nil {
			t.Fatal(err)
		}
	}
	// Mutate the specs that parse, so most mutations stay near valid.
	var valid [][]byte
	for _, c := range corpus {
		if _, err := Parse(c); err == nil {
			valid = append(valid, c)
		}
	}
	if len(valid) == 0 {
		t.Fatal("no valid spec in the corpus")
	}
	r := rand.New(rand.NewPCG(1, 2))
	for range n {
		data := valid[r.IntN(len(valid))]
		for range 1 + r.IntN(3) {
			data = mutate(r, data)
		}
		s.parse(data, "")
	}
	t.Logf("compared %v", s.counts)
}

// TestArmadaSpecSubstituteMatchesGo sets variables in the corpus and in
// mutations with ${NAME} placed in values, keys, and odd places.
func TestArmadaSpecSubstituteMatchesGo(t *testing.T) {
	p := startSpecProgram(t)
	s := &specParity{p: p, t: t, counts: map[string]int{}}
	vars := map[string]string{
		"IMAGE": "ghcr.io/org/app:1", "PORT": "8080", "MAX": "10", "EMPTY": "", "SPACE": "a b",
		"COLON": "a: b", "LIST": "[1, 2]", "QUOTE": "it's \"x\"", "LINES": "a\nb\n", "BOOL": "true",
		"NULL": "~", "UNI": "é\u2028x", "HASH": "# not a comment", "API_DOMAIN": "app.example.com", "DOMAIN": "x.example.com",
	}
	names := []string{"IMAGE", "PORT", "MAX", "EMPTY", "SPACE", "COLON", "LIST", "QUOTE", "LINES", "BOOL", "NULL", "UNI", "HASH", "MISSING", "OTHER"}
	corpus := specCorpus(t)
	for _, c := range corpus {
		s.substitute(c, vars)
	}
	r := rand.New(rand.NewPCG(3, 4))
	for range 5000 {
		data := []byte(string(corpus[r.IntN(len(corpus))]))
		for range 1 + r.IntN(3) {
			v := "${" + names[r.IntN(len(names))] + "}"
			switch r.IntN(6) {
			case 0:
				v = "$" + v
			case 1:
				v = "$${"
			}
			if len(data) == 0 {
				data = []byte(v)
				continue
			}
			i := r.IntN(len(data) + 1)
			data = slices.Insert(data, i, []byte(v)...)
		}
		if r.IntN(4) == 0 {
			data = mutate(r, data)
		}
		s.substitute(data, vars)
	}
	t.Logf("compared %v", s.counts)
}

// TestArmadaSpecJSONMatchesGo reads stored specs whose JSON was changed:
// field names in another case, nulls, unknown fields, wrong types.
func TestArmadaSpecJSONMatchesGo(t *testing.T) {
	p := startSpecProgram(t)
	s := &specParity{p: p, t: t, counts: map[string]int{}}
	var stored [][]byte
	for _, c := range specCorpus(t) {
		if a, err := Parse(c); err == nil {
			b, _ := json.Marshal(a)
			stored = append(stored, b)
			s.json(b)
		}
	}
	r := rand.New(rand.NewPCG(5, 6))
	edits := []func(m map[string]any){
		func(m map[string]any) { m["NAME"] = "other" },
		func(m map[string]any) { m["unknownField"] = 1 },
		func(m map[string]any) { m["ingress"] = nil },
		func(m map[string]any) { m["drain"] = "90s" },
		func(m map[string]any) { m["envFrom"] = "secrets" },
		func(m map[string]any) { m["envFrom"] = []any{map[string]any{"secret": "db"}} },
		func(m map[string]any) { m["envFromAdded"] = []any{"X"} },
		func(m map[string]any) { m["space"] = "shop" },
		func(m map[string]any) { m["history"] = 3 },
		func(m map[string]any) {
			m["placement"] = map[string]any{"require": map[string]any{"zone": nil, "rack": []any{"a"}}}
		},
		func(m map[string]any) {
			m["ingress"] = map[string]any{"type": "external", "port": 80, "cors": map[string]any{"allowOrigins": nil}}
		},
		func(m map[string]any) { m["Image"] = "nginx" },
		func(m map[string]any) { m["name"] = 5 },
		func(m map[string]any) { m["command"] = []any{"a", 1} },
		func(m map[string]any) { m["placement"] = map[string]any{"require": map[string]any{"zone": []any{1}}} },
		func(m map[string]any) { m["placement"] = map[string]any{"require": map[string]any{"zone": "a"}} },
		func(m map[string]any) {
			m["sidecars"] = []any{map[string]any{"name": "s", "env": []any{map[string]any{"value": true}}}}
		},
		func(m map[string]any) { m["retries"] = "3" },
		func(m map[string]any) { m["history"] = 1.5 },
		func(m map[string]any) { m["drain"] = 5 },
		func(m map[string]any) { m["drain"] = "5x" },
		func(m map[string]any) { m["command"] = "run" },
		func(m map[string]any) { m["env"] = []any{map[string]any{"name": 1}} },
		func(m map[string]any) { m["ingress"] = map[string]any{"type": "external", "port": "80"} },
		func(m map[string]any) { m["scale"] = "big" },
		func(m map[string]any) { m["envFrom"] = "all" },
		func(m map[string]any) {
			m["volumes"] = []any{map[string]any{"name": "d", "path": "/d", "backup": map[string]any{"keep": "x"}}}
		},
	}
	for range 2000 {
		var m map[string]any
		if err := json.Unmarshal(stored[r.IntN(len(stored))], &m); err != nil {
			t.Fatal(err)
		}
		edits[r.IntN(len(edits))](m)
		b, _ := json.Marshal(m)
		s.json(b)
	}
	t.Logf("compared %v", s.counts)
}

// goCall is what armada-spec-check's call answers for f.
func goCall(f string, args []any) any {
	str := func(i int) string { s, _ := args[i].(string); return s }
	er := func(err error) any {
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		return map[string]any{"ok": true}
	}
	switch f {
	case "ValidName":
		return ValidName(str(0))
	case "ValidSpace":
		return ValidSpace(str(0))
	case "ValidAppID":
		return ValidAppID(str(0))
	case "SplitAppID":
		sp, n, ok := SplitAppID(str(0))
		return []any{sp, n, ok}
	case "AppID":
		return AppID(str(0), str(1))
	case "InternalSearchDomain":
		return InternalSearchDomain(str(0))
	case "ValidSearchDomain":
		return ValidSearchDomain(str(0))
	case "ValidHostName":
		return ValidHostName(str(0))
	case "LabelHost":
		return LabelHost(str(0), str(1))
	case "InternalHost":
		return InternalHost(str(0))
	case "ValidRevisionName":
		return ValidRevisionName(str(0), str(1))
	case "ValidateDomain":
		return er(ValidateDomain(str(0)))
	case "ValidateRoutePath":
		return er(ValidateRoutePath(str(0)))
	case "ValidateProbePath":
		return er(ValidateProbePath(str(0)))
	case "ValidateName":
		return er(ValidateName(str(0)))
	case "ParseIPRange":
		p, err := ParseIPRange(str(0))
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		return map[string]any{"ok": p.String()}
	case "CheckNFSServer":
		return er(CheckNFSServer(str(0)))
	case "CheckNFSPath":
		return er(CheckNFSPath(str(0)))
	case "ParseOwner":
		u, g, err := ParseOwner(str(0))
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		return map[string]any{"ok": []int{u, g}}
	case "ParseMemory":
		n, err := ParseMemory(str(0))
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		return map[string]any{"ok": n}
	case "ParseCPU":
		n, err := ParseCPU(str(0))
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		return map[string]any{"ok": n}
	case "ValidateSecretName":
		return er(ValidateSecretName(str(0)))
	case "ValidateSecretKey":
		return er(ValidateSecretKey(str(0)))
	case "ValidateSecretRef":
		return er(ValidateSecretRef(str(0)))
	case "SplitSecretRef":
		a, b := SplitSecretRef(str(0))
		return []any{a, b}
	case "SecretSource":
		a, b := SecretSource(str(0), str(1))
		return []any{a, b}
	case "RegistryHost":
		return RegistryHost(str(0))
	case "SecretEnvName":
		return SecretEnvName(str(0))
	case "ValidCORSOrigin":
		return ValidCORSOrigin(str(0))
	case "ValidCORSHeader":
		return ValidCORSHeader(str(0))
	case "CheckLabelKey":
		return er(CheckLabelKey(str(0)))
	case "CheckLabelValue":
		return er(CheckLabelValue(str(0)))
	case "CheckAdminLabel":
		return er(CheckAdminLabel(str(0), str(1)))
	case "ValidateVolumePath":
		return er(ValidateVolumePath(str(0)))
	case "VarNameRe":
		return VarNameRe.MatchString(str(0))
	case "ParseDuration":
		d, err := time.ParseDuration(str(0))
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		return map[string]any{"ok": int64(d), "string": d.String()}
	}
	panic("unknown function " + f)
}

var oneStringFuncs = []string{
	"ValidName", "ValidSpace", "ValidAppID", "SplitAppID", "InternalSearchDomain", "ValidSearchDomain",
	"ValidHostName", "InternalHost", "ValidateDomain", "ValidateRoutePath", "ValidateProbePath", "ValidateName",
	"ParseIPRange", "CheckNFSServer", "CheckNFSPath", "ParseOwner", "ParseMemory", "ParseCPU",
	"ValidateSecretName", "ValidateSecretKey", "ValidateSecretRef", "SplitSecretRef", "RegistryHost",
	"SecretEnvName", "ValidCORSOrigin", "ValidCORSHeader", "CheckLabelKey", "CheckLabelValue",
	"ValidateVolumePath", "VarNameRe", "ParseDuration",
}

var twoStringFuncs = []string{"AppID", "LabelHost", "ValidRevisionName", "SecretSource", "CheckAdminLabel"}

// TestArmadaSpecValidatorsMatchGo calls every exported check of the
// package with the string literals of its tests, the values mutations
// use, and mutations of them.
func TestArmadaSpecValidatorsMatchGo(t *testing.T) {
	p := startSpecProgram(t)
	inputs := map[string]bool{}
	for _, l := range testLiterals(t) {
		if len(l) < 300 && utf8.Valid(l) {
			inputs[string(l)] = true
		}
	}
	for _, v := range interesting {
		inputs[v] = true
	}
	r := rand.New(rand.NewPCG(7, 8))
	base := slices.Sorted(func(yield func(string) bool) {
		for k := range inputs {
			if !yield(k) {
				return
			}
		}
	})
	chars := []rune("aZ09-._/:@%~ \t\n\u00e9\u2028\x00\x7f[]{}*?=&+")
	for range 3000 {
		s := []rune(base[r.IntN(len(base))])
		for range 1 + r.IntN(2) {
			i := r.IntN(len(s) + 1)
			switch r.IntN(3) {
			case 0:
				s = slices.Insert(s, i, chars[r.IntN(len(chars))])
			case 1:
				if i < len(s) {
					s = slices.Delete(s, i, i+1)
				}
			default:
				if i < len(s) {
					s[i] = chars[r.IntN(len(chars))]
				}
			}
		}
		inputs[string(s)] = true
	}
	list := slices.Sorted(func(yield func(string) bool) {
		for k := range inputs {
			if !yield(k) {
				return
			}
		}
	})
	compared := 0
	failed := 0
	check := func(f string, args []any) {
		t.Helper()
		var got json.RawMessage
		p.ask(map[string]any{"op": "call", "fn": f, "args": args}, &got)
		want, _ := json.Marshal(goCall(f, args))
		compared++
		if !sameJSON(want, got) {
			failed++
			if failed <= 25 {
				t.Errorf("%s(%q):\nGo:   %s\nRust: %s", f, args, want, got)
			}
		}
	}
	for _, s := range list {
		for _, f := range oneStringFuncs {
			check(f, []any{s})
		}
	}
	for i := range 4000 {
		a, b := list[r.IntN(len(list))], list[r.IntN(len(list))]
		check(twoStringFuncs[i%len(twoStringFuncs)], []any{a, b})
	}
	for _, port := range []int{-1, 0, 1, 22, 53, 79, 80, 443, 2379, 8404, 51820, 65535, 65536} {
		var got json.RawMessage
		p.ask(map[string]any{"op": "call", "fn": "CheckTCPPort", "args": []any{port}}, &got)
		want := map[string]any{"ok": true}
		if err := CheckTCPPort(port); err != nil {
			want = map[string]any{"error": err.Error()}
		}
		w, _ := json.Marshal(want)
		compared++
		if !sameJSON(w, got) {
			t.Errorf("CheckTCPPort(%d): Go %s, Rust %s", port, w, got)
		}
	}
	// FairOrder over random IDs.
	ids := []string{"a", "b", "c.shop", "d.shop", "e.blog", "f", "g.blog", "h.shop", "Bad.x", "i.default"}
	for range 500 {
		n := r.IntN(len(ids) + 1)
		pick := make([]string, n)
		for i := range pick {
			pick[i] = ids[r.IntN(len(ids))]
		}
		var got json.RawMessage
		p.ask(map[string]any{"op": "call", "fn": "FairOrder", "args": []any{pick}}, &got)
		w, _ := json.Marshal(FairOrder(pick))
		compared++
		if !sameJSON(w, got) {
			t.Errorf("FairOrder(%q): Go %s, Rust %s", pick, w, got)
		}
	}
	// CheckTraffic.
	revs := []string{"latest", "web--r1", "web--r2", "web--r0", "web--r1234567890", "api--r1", "", "web.shop--r1"}
	labels := []string{"", "canary", "blue", "Bad", strings.Repeat("l", 60), "canary"}
	for range 2000 {
		app := []string{"web", "web.shop", "api"}[r.IntN(3)]
		n := r.IntN(12)
		var tt []TrafficTarget
		var js []any
		for range n {
			x := TrafficTarget{Revision: revs[r.IntN(len(revs))], Weight: []int{0, 10, 50, 90, 100, 101, -1}[r.IntN(7)], Label: labels[r.IntN(len(labels))]}
			tt = append(tt, x)
			js = append(js, map[string]any{"revision": x.Revision, "weight": x.Weight, "label": x.Label})
		}
		latest := r.IntN(2) == 0
		var got json.RawMessage
		p.ask(map[string]any{"op": "call", "fn": "CheckTraffic", "args": []any{app, js, latest}}, &got)
		want := []string{}
		for _, e := range CheckTraffic(app, tt, latest) {
			want = append(want, e.Error())
		}
		w, _ := json.Marshal(want)
		compared++
		if !sameJSON(w, got) {
			t.Errorf("CheckTraffic(%q, %v, %v): Go %s, Rust %s", app, tt, latest, w, got)
		}
	}
	// CheckBackupPlan.
	for range 2000 {
		b := map[string]any{
			"every":    []int64{0, int64(time.Minute), int64(5 * time.Minute), int64(time.Hour), int64(200 * time.Hour)}[r.IntN(5)],
			"schedule": []string{"", "0 2 * * *", "bad", "@daily", "*/15 * * * mon-fri"}[r.IntN(5)],
			"timeZone": []string{"", "Europe/Berlin", "Nowhere/Land", "Local", "UTC", strings.Repeat("x", 70)}[r.IntN(6)],
			"last":     []int{0, 1, 7, 1001, -1}[r.IntN(5)],
			"daily":    []int{0, 3}[r.IntN(2)],
		}
		plan := &VolumeBackup{
			Every: Duration(b["every"].(int64)), Schedule: b["schedule"].(string), TimeZone: b["timeZone"].(string),
			Keep: BackupKeep{Last: b["last"].(int), Daily: b["daily"].(int)},
		}
		var got json.RawMessage
		p.ask(map[string]any{"op": "call", "fn": "CheckBackupPlan", "args": []any{b}}, &got)
		want := map[string]any{"ok": true}
		if err := CheckBackupPlan(plan); err != nil {
			want = map[string]any{"error": err.Error()}
		}
		w, _ := json.Marshal(want)
		compared++
		if !sameJSON(w, got) {
			t.Errorf("CheckBackupPlan(%v): Go %s, Rust %s", b, w, got)
		}
	}
	t.Logf("compared %d calls", compared)
}

// TestArmadaSpecSchedulesMatchGo compares cron fires across daylight
// saving changes in several zones, and schedule rule windows.
func TestArmadaSpecSchedulesMatchGo(t *testing.T) {
	p := startSpecProgram(t)
	schedules := []string{
		"0 2 * * *", "30 2 * * *", "*/15 * * * *", "0 0 1 * *", "0 0 * * 0", "0 0 31 * *", "0 0 29 2 *",
		"0 9-17 * * mon-fri", "5,10 3 * * *", "0 1 * * sun", "59 23 31 12 *", "0 0 1 1 *", "0 */6 * * *",
		"30 1 * * *", "0 3 * * *", "15 2 1-7 * 1", "0 0 * * 7", "bad", "* * *", "0 0 32 * *", "@hourly",
		"TZ=UTC 0 * * * *", "0 0 * jan,jul *", "0 12 * * MON", "*/0 * * * *", "1-5/2 * * * *", "0 0 ? * *",
	}
	zones := []string{"", "UTC", "Europe/Berlin", "America/New_York", "Australia/Lord_Howe", "Asia/Kolkata", "Pacific/Chatham", "Local", "Nowhere/Land", "america/new_york"}
	starts := []string{
		"2026-03-08T06:59:00Z", "2026-03-29T00:30:00Z", "2026-10-25T00:30:00Z", "2026-11-01T05:30:00Z",
		"2026-04-05T15:00:00Z", "2026-12-31T23:59:59Z", "2028-02-28T12:00:00Z", "2026-11-25T08:00:00.5Z",
	}
	compared, failed := 0, 0
	for _, s := range schedules {
		for _, z := range zones {
			for _, st := range starts {
				var got json.RawMessage
				p.ask(map[string]any{"op": "call", "fn": "Schedule", "args": []any{s, z, map[string]any{"t": st, "zone": z}, 8}}, &got)
				var want any
				if _, _, err := parseSchedule(s, z); err != nil {
					want = map[string]any{"error": err.Error()}
				} else {
					sch, _ := (&App{Schedule: s, TimeZone: z}).JobSchedule()
					loc, err := time.LoadLocation(z)
					if err != nil {
						loc = time.UTC
					}
					tm, _ := time.Parse(time.RFC3339Nano, st)
					tm = tm.In(loc)
					var out []string
					for range 8 {
						tm = sch.Next(tm)
						out = append(out, tm.Format(time.RFC3339Nano))
					}
					want = map[string]any{"ok": out}
				}
				w, _ := json.Marshal(want)
				compared++
				if !sameJSON(w, got) {
					failed++
					if failed <= 25 {
						t.Errorf("schedule %q in %q from %s:\nGo:   %s\nRust: %s", s, z, st, w, got)
					}
				}
			}
		}
	}
	for _, s := range schedules[:17] {
		for _, z := range zones[:7] {
			for _, d := range []time.Duration{time.Minute, 30 * time.Minute, 2 * time.Hour, 25 * time.Hour, 7 * 24 * time.Hour} {
				for _, now := range starts {
					rule := ScaleRule{Type: ScaleSchedule, Schedule: s, TimeZone: z, Duration: Duration(d)}
					var got json.RawMessage
					p.ask(map[string]any{"op": "call", "fn": "Window", "args": []any{
						map[string]any{"type": rule.Type, "schedule": s, "timeZone": z, "duration": int64(d)},
						map[string]any{"t": now},
					}}, &got)
					open, until := rule.Window(mustTime(strings.Replace(now, ".5Z", "Z", 1)).Add(map[bool]time.Duration{true: 500 * time.Millisecond}[strings.HasSuffix(now, ".5Z")]))
					w, _ := json.Marshal([]any{open, until.Format(time.RFC3339Nano)})
					compared++
					if !sameJSON(w, got) {
						failed++
						if failed <= 25 {
							t.Errorf("window %q in %q for %s at %s:\nGo:   %s\nRust: %s", s, z, d, now, w, got)
						}
					}
				}
			}
		}
	}
	t.Logf("compared %d schedules and windows", compared)
}

// TestArmadaSpecProgramRuns makes sure the comparison is not vacuous: a
// spec that parses, and one that does not, give answers.
func TestArmadaSpecProgramRuns(t *testing.T) {
	p := startSpecProgram(t)
	var got parseAnswer
	p.ask(map[string]any{"op": "parse", "data": base64.StdEncoding.EncodeToString([]byte("name: web\nimage: nginx\n"))}, &got)
	if got.Error != nil || !strings.Contains(got.JSON, `"name":"web"`) {
		t.Fatalf("armada-spec-check did not parse a spec: %+v", got)
	}
	var bad parseAnswer
	p.ask(map[string]any{"op": "parse", "data": base64.StdEncoding.EncodeToString([]byte("name: web\n"))}, &bad)
	if bad.Error == nil || *bad.Error != "image: is required" {
		t.Fatalf("armada-spec-check accepted a spec without an image: %+v", bad)
	}
}
