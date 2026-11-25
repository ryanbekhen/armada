package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/clientconfig/sshtest"
	"github.com/ryanbekhen/armada/internal/pki"
)

// The client parity harness (ADR 0055, pull request 17): every case runs
// Go's armada in process (Run) and the Rust one (ARMADA_CLIENT_BIN, a
// build of client/) with the same arguments, environment, standard input,
// working directory, and client config, against one AdminService in the
// test (mTLS with test certificates) that records each request and gives
// scripted answers. Standard output, standard error, the exit code, the
// requests sent, and the client config left behind must match. Without
// ARMADA_CLIENT_BIN only Go's runs, which keeps the cases themselves
// checked.
//
// The cases are the ones below, every example line of every command the
// Rust client has (examples.go and each command's Example), and every such
// command's help.

// parityNouns are the nouns the Rust client has (ADR 0055, pull request
// 17a); the verbs of laterVerbs come with the other nouns in 17b.
var (
	parityNouns = []string{"app", "revision", "replica", "job", "run", "secret", "space", "version", "completion", "help"}
	laterVerbs  = []string{"armada app logs", "armada app exec", "armada app top", "armada app events", "armada job logs"}
)

// answer is a scripted reply to one call.
type answer struct {
	msg     proto.Message
	code    codes.Code
	text    string
	servers string // the armada-servers header
}

func okAnswer(m proto.Message) []answer { return []answer{{msg: m}} }

func failAnswer(c codes.Code, text string) []answer { return []answer{{code: c, text: text}} }

type call struct{ Method, Request string }

// scriptedAdmin answers every AdminService method from a script: a list of
// answers per method, the last one repeated.
type scriptedAdmin struct {
	mu     sync.Mutex
	script map[string][]answer
	calls  []call
}

func (f *scriptedAdmin) reset(script map[string][]answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.script = maps.Clone(script)
	f.calls = nil
}

func (f *scriptedAdmin) unary(ctx context.Context, req any, info *grpc.UnaryServerInfo, _ grpc.UnaryHandler) (any, error) {
	method := path.Base(info.FullMethod)
	b, _ := protojson.MarshalOptions{}.Marshal(req.(proto.Message))
	f.mu.Lock()
	f.calls = append(f.calls, call{method, string(b)})
	as := f.script[method]
	if len(as) == 0 {
		f.mu.Unlock()
		return nil, status.Errorf(codes.Unimplemented, "no answer scripted for %s", method)
	}
	a := as[0]
	if len(as) > 1 {
		f.script[method] = as[1:]
	}
	f.mu.Unlock()
	if a.code != codes.OK {
		return nil, status.Error(a.code, a.text)
	}
	if a.servers != "" {
		_ = grpc.SetHeader(ctx, metadata.Pairs(clientconfig.ServersHeader, a.servers))
	}
	return a.msg, nil
}

// parityCase is one command line run by both clients.
type parityCase struct {
	name    string
	args    []string
	env     map[string]string
	stdin   string
	files   map[string]string // relative to the case's directory
	answers map[string][]answer
	// config changes the client config the case starts with; noConfig
	// leaves none, mode is its mode (default 0600).
	config   func(*clientconfig.Config)
	noConfig bool
	mode     os.FileMode
}

type parityResult struct {
	Code           int
	Stdout, Stderr string
	Calls          []call
	Config         string
}

type harness struct {
	addr   string
	fake   *scriptedAdmin
	cfg    clientconfig.Config
	bin    string
	sshDir string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ca, err := pki.NewCA("parity")
	if err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, err := ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindServer, Name: "s1"}, DNSNames: []string{pki.ServerName}, Server: true})
	if err != nil {
		t.Fatal(err)
	}
	userCert, userKey, err := ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindUser, Name: "ada"}, Client: true})
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := pki.ServerTLS(ca.CertPEM, srvCert, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &scriptedAdmin{}
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)), grpc.UnaryInterceptor(f.unary))
	armadav1.RegisterAdminServiceServer(s, armadav1.UnimplementedAdminServiceServer{})
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)

	// ssh(1) is this test binary (TestMain runs sshtest.Main), first in
	// PATH for both clients.
	sshDir := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(self, filepath.Join(sshDir, "ssh")); err != nil {
		t.Fatal(err)
	}
	bin := os.Getenv("ARMADA_CLIENT_BIN")
	if bin != "" {
		if bin, err = filepath.Abs(bin); err != nil {
			t.Fatal(err)
		}
	}
	return &harness{
		addr:   lis.Addr().String(),
		fake:   f,
		bin:    bin,
		sshDir: sshDir,
		cfg: clientconfig.Config{
			Servers: []string{lis.Addr().String()},
			CA:      string(ca.CertPEM),
			Cert:    string(userCert),
			Key:     string(userKey),
		},
	}
}

func (h *harness) env(dir string, c parityCase) map[string]string {
	env := map[string]string{
		"HOME":                   filepath.Join(dir, "home"),
		"PATH":                   h.sshDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"XDG_CACHE_HOME":         filepath.Join(dir, "cache"),
		"TZ":                     "UTC",
		"ARMADA_NO_UPDATE_CHECK": "1",
		"ARMADA_CONFIG":          "",
		"ARMADA_SPACE":           "",
		"CI":                     "",
	}
	maps.Copy(env, c.env)
	return env
}

func (h *harness) configPath(dir string) string {
	return filepath.Join(dir, "home", ".armada", "config")
}

// prepare writes the case's files and config afresh.
func (h *harness) prepare(t *testing.T, dir string, c parityCase) {
	t.Helper()
	_ = os.RemoveAll(filepath.Join(dir, "home"))
	if err := os.MkdirAll(filepath.Join(dir, "home", ".armada"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range c.files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if c.noConfig {
		return
	}
	cc := h.cfg
	cc.Servers = slices.Clone(cc.Servers)
	if c.config != nil {
		c.config(&cc)
	}
	if err := cc.SaveFile(h.configPath(dir)); err != nil {
		t.Fatal(err)
	}
	if c.mode != 0 {
		if err := os.Chmod(h.configPath(dir), c.mode); err != nil {
			t.Fatal(err)
		}
	}
}

func (h *harness) collect(dir string, r *parityResult) {
	h.fake.mu.Lock()
	r.Calls = slices.Clone(h.fake.calls)
	h.fake.mu.Unlock()
	if b, err := os.ReadFile(h.configPath(dir)); err == nil {
		fi, _ := os.Stat(h.configPath(dir))
		r.Config = fmt.Sprintf("%04o\n%s", fi.Mode().Perm(), b)
	}
}

func (h *harness) runGo(t *testing.T, dir string, c parityCase) parityResult {
	t.Helper()
	h.prepare(t, dir, c)
	h.fake.reset(c.answers)
	for k, v := range h.env(dir, c) {
		t.Setenv(k, v)
	}
	// cobra writes completion errors to os.Stderr itself, before the
	// command's own lines: a program's one stderr.
	r0, w0, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	direct := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r0)
		direct <- b
	}()
	stderr := os.Stderr
	os.Stderr = w0
	var out, errb bytes.Buffer
	code := Run(context.Background(), NewRootCommand(), c.args, strings.NewReader(c.stdin), &out, &errb)
	os.Stderr = stderr
	_ = w0.Close()
	r := parityResult{Code: code, Stdout: out.String(), Stderr: string(<-direct) + errb.String()}
	h.collect(dir, &r)
	return r
}

func (h *harness) runRust(t *testing.T, dir string, c parityCase) parityResult {
	t.Helper()
	h.prepare(t, dir, c)
	h.fake.reset(c.answers)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.bin, c.args...)
	cmd.Dir = dir
	for k, v := range h.env(dir, c) {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdin = strings.NewReader(c.stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %s: %v", h.bin, err)
	}
	r := parityResult{Code: code, Stdout: out.String(), Stderr: errb.String()}
	h.collect(dir, &r)
	return r
}

// toolchain is the compiler named in version's output.
var toolchain = regexp.MustCompile(`\b(go[0-9][0-9.a-z]*|rust[0-9][0-9.a-z-]*)\b`)

// sinceTime is a duration since a time of the answers, which the two clients
// work out a moment apart, so a second may tick between them.
var sinceTime = regexp.MustCompile(`\b([0-9]+[hms])+ ago\b`)

// normalize makes outputs comparable: the compiler's name in version's
// output, durations since a time, and JSON compared as values (protojson
// adds spaces at random).
func normalize(s string) any {
	s = toolchain.ReplaceAllString(s, "TOOLCHAIN")
	s = sinceTime.ReplaceAllString(s, "DURATION ago")
	var v any
	if d := json.NewDecoder(strings.NewReader(s)); d.Decode(&v) == nil && !d.More() {
		return v
	}
	return s
}

func compareResults(t *testing.T, goRes, rust parityResult) {
	t.Helper()
	if goRes.Code != rust.Code {
		t.Errorf("exit code: Go %d, Rust %d", goRes.Code, rust.Code)
	}
	if !reflect.DeepEqual(normalize(goRes.Stdout), normalize(rust.Stdout)) {
		t.Errorf("stdout differs:\n--- Go\n%s--- Rust\n%s", goRes.Stdout, rust.Stdout)
	}
	if !reflect.DeepEqual(normalize(goRes.Stderr), normalize(rust.Stderr)) {
		t.Errorf("stderr differs:\n--- Go\n%s--- Rust\n%s", goRes.Stderr, rust.Stderr)
	}
	if !reflect.DeepEqual(goRes.Calls, rust.Calls) {
		t.Errorf("requests differ:\n--- Go\n%v\n--- Rust\n%v", goRes.Calls, rust.Calls)
	}
	if goRes.Config != rust.Config {
		t.Errorf("client config differs:\n--- Go\n%s\n--- Rust\n%s", goRes.Config, rust.Config)
	}
}

func TestClientParity(t *testing.T) {
	h := newHarness(t)
	old := time.Local
	time.Local = time.UTC
	t.Cleanup(func() { time.Local = old })
	cases := parityCases(h)
	cases = append(cases, exampleCases(t)...)
	cases = append(cases, helpCases()...)
	names := map[string]bool{}
	for _, c := range cases {
		if names[c.name] {
			t.Fatalf("two cases named %q", c.name)
		}
		names[c.name] = true
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			goRes := h.runGo(t, dir, c)
			if h.bin == "" {
				return
			}
			compareResults(t, goRes, h.runRust(t, dir, c))
		})
	}
	t.Logf("%d cases", len(cases))
}

// sshtestHost keeps the import used: the stand-in reaches only this host.
const sshtestHost = sshtest.Host

func ts(ago time.Duration) *timestamppb.Timestamp {
	return timestamppb.New(time.Now().Add(-ago))
}

// webSpec is the spec GetAppSpec answers with in update cases.
const webSpec = `apiVersion: armada.dev/v1alpha1
kind: app
name: web
image: ghcr.io/acme/web:1.4.2
env:
  - name: DEBUG
    value: "1"
  - name: DATABASE_URL
    secretRef: db/url
ingress:
  type: external
  port: 8080
probes:
  readiness:
    path: /healthz
    port: 8080
scale:
  min: 2
`

const jobSpec = `apiVersion: armada.dev/v1alpha1
kind: job
name: migrate
image: ghcr.io/acme/api:1.4
command:
  - ./migrate
`

// files every case directory holds, for examples that name them.
var exampleFiles = map[string]string{
	"web.yaml":     "apiVersion: armada.dev/v1alpha1\nkind: app\nname: web\nimage: ghcr.io/acme/web:${TAG}\ningress:\n  type: external\n  port: 8080\n",
	"migrate.yaml": jobSpec,
	"db.env":       "# the database\nDATABASE_URL=postgres://db/x\nPASSWORD=s3cret\n",
	"key.pem":      "-----BEGIN KEY-----\nAAAA\n-----END KEY-----\n",
	"vars.env":     "# tags\nTAG=1.4.2\n\nREGION=eu\n",
}

func appStatus(name string) *armadav1.AppStatus {
	return &armadav1.AppStatus{
		Name: name, Image: "ghcr.io/acme/web:1.4.3", ActiveRevision: "web--r2", DesiredReplicas: 2,
		Ingress: "external", Urls: []string{"https://web.apps.example.com", "https://www.example.com"},
		IpAllow: []*armadav1.IPRule{{Range: "203.0.113.0/24", Name: "office", Description: "the VPN"}, {Range: "198.51.100.7/32"}},
		Autoscale: &armadav1.Autoscale{Min: 2, Max: 10, Message: "steady\x1b[31m", Rules: []*armadav1.AutoscaleRule{
			{Type: "http", Target: 50, Current: 34, Measured: true},
			{Type: "cpu", Target: 70},
			{Type: "redis", Target: 100, Current: 12, Measured: true},
		}},
		Replicas: []*armadav1.ReplicaStatus{
			{Id: "web-r2-k3p9x", Revision: "web--r2", NodeId: "node1", State: "running", Ready: true, Address: "10.120.0.5:8080",
				CreatedAt: ts(330 * time.Second), Restarts: 2, LastRestartAt: ts(125 * time.Second), Containers: []string{"app", "log-ship"}, InitContainers: []string{"migrate"}},
			{Id: "web-r2-a8b2c", Revision: "web--r2", NodeId: "node2", State: "running", Ready: true, Address: "10.120.1.5:8080",
				CreatedAt: ts(50 * time.Hour), Message: "line one\nline two", Containers: []string{"app"}},
			{Id: "web-r1-zz9yy", Revision: "web--r1", NodeId: "node2", State: "running", Draining: true, CreatedAt: ts(72 * time.Hour)},
		},
	}
}

func revisions() *armadav1.ListRevisionsResponse {
	return &armadav1.ListRevisionsResponse{Revisions: []*armadav1.RevisionInfo{
		{Name: "web--r2", Image: "ghcr.io/acme/web:1.4.3", ImageDigest: "sha256:abc", CreatedAt: timestamppb.New(time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)), Active: true, Target: true, Platforms: []string{"linux/amd64", "linux/arm64"}},
		{Name: "web--r1", Image: "ghcr.io/acme/web:1.4.2", CreatedAt: timestamppb.New(time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC))},
		{Name: "api--r12", Image: "ghcr.io/acme/api:2", ImageDigest: "sha256:def", CreatedAt: timestamppb.New(time.Date(2026, 11, 18, 7, 0, 0, 0, time.UTC)), Target: true},
	}}
}

func jobRuns() *armadav1.ListJobRunsResponse {
	return &armadav1.ListJobRunsResponse{Runs: []*armadav1.JobRunInfo{
		{Job: "migrate", Run: 12, State: "succeeded", Trigger: "manual", Attempts: 1, Node: "node1", StartedAt: ts(10 * time.Minute), FinishedAt: ts(9 * time.Minute),
			Tasks: []*armadav1.JobTaskInfo{{Index: 0, State: "succeeded", Attempts: 1, Node: "node1"}, {Index: 1, State: "failed", Attempts: 3, ExitCode: 2, Message: "boom"}}},
		{Job: "migrate", Run: 11, State: "failed", Trigger: "schedule", Attempts: 2, ExitCode: 1, Message: "exit\x07", StartedAt: ts(3 * time.Hour), FinishedAt: ts(170 * time.Minute)},
		{Job: "migrate", Run: 10, State: "running", Trigger: "queue", StartedAt: ts(90 * time.Second)},
	}}
}

func jobs() *armadav1.ListJobsResponse {
	return &armadav1.ListJobsResponse{Jobs: []*armadav1.JobInfo{
		{Name: "migrate", Revision: "migrate--r1", Image: "ghcr.io/acme/api:1.4", Schedule: "0 3 * * *", TimeZone: "Asia/Jakarta", NextRun: timestamppb.New(time.Now().Add(5*time.Hour + 30*time.Second)),
			LastRun: &armadav1.JobRunInfo{Run: 12, State: "succeeded", FinishedAt: ts(9*time.Minute + 30*time.Second)}, Active: 0},
		{Name: "report.shop", Image: "ghcr.io/acme/report:2", Trigger: &armadav1.JobTrigger{Type: "redis", Name: "reports", PerRun: 10, Parallelism: 4, PollingIntervalSeconds: 30, Node: "node1", Measured: true, Length: 42, MeasuredAt: ts(20 * time.Second)}},
		{Name: "sweep", Image: "busybox", Trigger: &armadav1.JobTrigger{Type: "rabbitmq", Name: "q", PerRun: 1, Parallelism: 1, PollingIntervalSeconds: 60}},
	}}
}

func spaces() *armadav1.ListSpacesResponse {
	return &armadav1.ListSpacesResponse{Spaces: []*armadav1.SpaceInfo{
		{Name: "default", Apps: 3, CreatedAt: ts(400 * time.Hour)},
		{Name: "shop", Apps: 1, NetworkIsolation: true, CreatedAt: ts(2 * time.Hour), CreatedBy: "ada"},
	}}
}

// defaultAnswers lets every command of the examples run to its end.
func defaultAnswers() map[string][]answer {
	return map[string][]answer{
		"ListApps": okAnswer(&armadav1.ListAppsResponse{Apps: []*armadav1.AppSummary{
			{Name: "web", Image: "ghcr.io/acme/web:1.4.2", Revision: "web--r1", Ready: 0, Desired: 2, State: "progressing", TargetRevision: "web--r2", TargetImage: "ghcr.io/acme/web:1.4.3", Url: "https://web.apps.example.com"},
			{Name: "api.shop", Image: "ghcr.io/acme/api:2", Revision: "api--r3", Ready: 2, Desired: 2, State: "ready"},
		}}),
		"Status":           okAnswer(&armadav1.StatusResponse{Apps: []*armadav1.AppStatus{appStatus("web")}}),
		"GetAppSpec":       failAnswer(codes.NotFound, "app not found"),
		"Deploy":           okAnswer(&armadav1.DeployResponse{App: "web", Revision: "web--r2"}),
		"Rollback":         okAnswer(&armadav1.RollbackResponse{Revision: "web--r2"}),
		"RestartApp":       okAnswer(&armadav1.RestartAppResponse{Revision: "web--r2"}),
		"SetTraffic":       okAnswer(&armadav1.SetTrafficResponse{Traffic: []*armadav1.TrafficTarget{{Revision: "web--r3", Weight: 90}, {Revision: "web--r4", Weight: 10, Label: "canary"}}}),
		"RemoveApp":        okAnswer(&armadav1.RemoveAppResponse{}),
		"ListRevisions":    okAnswer(revisions()),
		"ListJobs":         okAnswer(jobs()),
		"ListJobRuns":      okAnswer(jobRuns()),
		"RunJob":           okAnswer(&armadav1.RunJobResponse{Run: 12}),
		"CancelJob":        okAnswer(&armadav1.CancelJobResponse{Runs: []int64{3, 4}}),
		"DeleteJob":        okAnswer(&armadav1.DeleteJobResponse{}),
		"SetSecret":        okAnswer(&armadav1.SetSecretResponse{Version: 2}),
		"ListSecrets":      okAnswer(&armadav1.ListSecretsResponse{}),
		"DeleteSecret":     okAnswer(&armadav1.DeleteSecretResponse{}),
		"CreateSpace":      okAnswer(&armadav1.SpaceInfo{Name: "shop"}),
		"UpdateSpace":      okAnswer(&armadav1.SpaceInfo{Name: "default", NetworkIsolation: true}),
		"DeleteSpace":      okAnswer(&armadav1.DeleteSpaceResponse{}),
		"ListSpaces":       okAnswer(spaces()),
		"ListServers":      okAnswer(&armadav1.ListServersResponse{Servers: []*armadav1.ServerInfo{{Name: "s1", Version: "v0.1.0-alpha.41"}, {Name: "s2"}, {Name: "s3", Version: "v0.1.0-alpha.41"}}}),
		"ListSpaceSecrets": okAnswer(&armadav1.ListSpaceSecretsResponse{Secrets: []*armadav1.SpaceSecretInfo{{Name: "db", Keys: 2, UpdatedAt: timestamppb.New(time.Date(2026, 11, 20, 1, 2, 3, 0, time.UTC)), UpdatedBy: "ada", UsedBy: []string{"web", "worker"}}, {Name: "api", Keys: 1}}}),
	}
}

// with returns the default answers with some replaced.
func with(over map[string][]answer) map[string][]answer {
	a := defaultAnswers()
	maps.Copy(a, over)
	return a
}

// rustCommand reports whether the Rust client has the command at path.
func rustCommand(path string) bool {
	words := strings.Fields(path)
	if len(words) < 2 || !slices.Contains(parityNouns, words[1]) {
		return false
	}
	for _, l := range laterVerbs {
		if path == l || strings.HasPrefix(path, l+" ") {
			return false
		}
	}
	return true
}

// exampleCases runs every example line of every command the Rust client
// has, against the default answers.
func exampleCases(t *testing.T) []parityCase {
	t.Helper()
	var out []parityCase
	seen := map[string]bool{}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		for _, line := range strings.Split(strings.ReplaceAll(c.Example, "\\\n", " "), "\n") {
			if i := strings.Index(line, "#"); i >= 0 {
				line = line[:i]
			}
			for _, part := range strings.FieldsFunc(strings.ReplaceAll(line, "&&", ";"), func(r rune) bool { return r == ';' || r == '|' }) {
				words := shellWords(part)
				if len(words) < 2 || words[0] != "armada" {
					continue
				}
				root := NewRootCommand()
				found, _, err := root.Find(words[1:])
				if err != nil || !rustCommand(found.CommandPath()) {
					continue
				}
				key := strings.Join(words, " ")
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, parityCase{name: "example " + key, args: words[1:], files: exampleFiles, answers: defaultAnswers(),
					stdin: "from-stdin\n"})
			}
		}
	}
	root := NewRootCommand()
	addExamples(root)
	walk(root)
	if len(out) == 0 {
		t.Fatal("no example lines")
	}
	return out
}

// helpCases asks every command the Rust client has for its help.
func helpCases() []parityCase {
	var out []parityCase
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		p := c.CommandPath()
		if c.Hidden || (c.Parent() != nil && !rustCommand(p)) {
			return
		}
		args := append(strings.Fields(p)[1:], "--help")
		out = append(out, parityCase{name: "help " + p, args: args})
	}
	walk(NewRootCommand())
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		out = append(out, parityCase{name: "help completion " + shell, args: []string{"completion", shell, "--help"}})
	}
	return out
}

// parityCases are the cases written for the harness: what the examples
// do not reach.
func parityCases(h *harness) []parityCase {
	shared := func(c *clientconfig.Config) { c.Space = "shop" }
	cases := []parityCase{
		// The framework.
		{name: "root", args: nil},
		{name: "root help flag", args: []string{"--help"}},
		{name: "unknown noun", args: []string{"ap"}},
		{name: "unknown noun far", args: []string{"zzz"}},
		{name: "unknown verb", args: []string{"app", "deplyo"}},
		{name: "verb prefix", args: []string{"app", "delet"}},
		{name: "verb hint", args: []string{"app", "scale", "web"}},
		{name: "verb hint secret", args: []string{"secret", "get", "db"}},
		{name: "alias plural", args: []string{"apps", "ls"}, answers: defaultAnswers()},
		{name: "missing argument", args: []string{"app", "show"}},
		{name: "too many arguments", args: []string{"app", "show", "a", "b"}},
		{name: "no arguments taken", args: []string{"app", "list", "x"}},
		{name: "variadic", args: []string{"app", "traffic", "web"}},
		{name: "run show missing argument", args: []string{"run", "show", "migrate"}},
		{name: "unknown flag", args: []string{"app", "list", "--nope"}},
		{name: "unknown shorthand", args: []string{"app", "list", "-x"}},
		{name: "flag needs value", args: []string{"app", "list", "-o"}},
		{name: "bad int", args: []string{"app", "deploy", "web", "--min", "two"}},
		{name: "bad bool", args: []string{"app", "delete", "web", "--yes=maybe"}},
		{name: "bad duration", args: []string{"app", "rollback", "web", "--timeout", "soon"}},
		{name: "help command", args: []string{"help", "app", "deploy"}},
		{name: "help unknown topic", args: []string{"help", "nope", "x"}},
		{name: "help flag before verb", args: []string{"app", "--help", "deploy"}},
		{name: "exclusive flags", args: []string{"app", "deploy", "web", "--ip-allow", "10.0.0.0/8", "--no-ip-rules"}},
		{name: "required flag", args: []string{"secret", "create", "db"}},
		{name: "invalid space", args: []string{"app", "list"}, env: map[string]string{"ARMADA_SPACE": "Bad_Space"}},
		{name: "space flag default", args: []string{"app", "list", "--help"}, env: map[string]string{"ARMADA_SPACE": "shop"}},
		{name: "output format", args: []string{"app", "list", "-o", "yaml"}},
		{name: "output format show", args: []string{"app", "show", "web", "-o", "xml"}},
		{name: "name of another space", args: []string{"app", "show", "web.prod", "--space", "shop"}},
		{name: "bad id", args: []string{"app", "show", "a..b"}},

		// The client config.
		{name: "no config", args: []string{"app", "list"}, noConfig: true},
		{name: "loose config", args: []string{"app", "list"}, mode: 0o644},
		{name: "incomplete config", args: []string{"app", "list"}, config: func(c *clientconfig.Config) { c.Key = "" }},
		{name: "bad ssh in config", args: []string{"app", "list"}, config: func(c *clientconfig.Config) { c.SSH = "-oProxyCommand=x" }},
		{name: "config space", args: []string{"app", "list"}, config: shared, answers: defaultAnswers()},
		{name: "config path flag", args: []string{"--config", "other/config", "app", "list"}},
		{name: "config env", args: []string{"app", "list"}, env: map[string]string{"ARMADA_CONFIG": "nowhere"}},
		{name: "unreachable server", args: []string{"app", "list"}, config: func(c *clientconfig.Config) { c.Servers = []string{"127.0.0.1:1"} }},
		{name: "bad ca", args: []string{"app", "list"}, config: func(c *clientconfig.Config) { c.CA = "nope" }},
		{name: "bad key", args: []string{"app", "list"}, config: func(c *clientconfig.Config) { c.Key = "nope" }},
		{name: "ssh unknown host", args: []string{"app", "list"}, config: func(c *clientconfig.Config) { c.SSH = "elsewhere.test" }},
		{name: "ssh first server down", args: []string{"app", "list"}, answers: defaultAnswers(), config: func(c *clientconfig.Config) {
			c.SSH = sshtestHost
			c.Servers = append([]string{"127.0.0.1:1"}, c.Servers...)
		}},
		{name: "first server down", args: []string{"app", "list"}, answers: defaultAnswers(), config: func(c *clientconfig.Config) {
			c.Servers = append([]string{"127.0.0.1:1"}, c.Servers...)
		}},
		{name: "arguments after dashes", args: []string{"app", "show", "--", "web"}, answers: defaultAnswers()},
		{name: "grouped shorthands", args: []string{"app", "list", "-Aojson"}, answers: defaultAnswers()},
		{name: "shorthand equals", args: []string{"app", "list", "-o=json", "-A=false"}, answers: defaultAnswers()},
		{name: "through ssh", args: []string{"app", "list"}, config: func(c *clientconfig.Config) { c.SSH = "ops@" + sshtestHost }, answers: defaultAnswers()},
		{name: "server sync", args: []string{"space", "list"}, answers: with(map[string][]answer{"ListSpaces": {{msg: spaces(), servers: h.addr + ",10.0.0.9:7443"}}})},
		{name: "server sync tunnel kept", args: []string{"space", "list"}, answers: with(map[string][]answer{"ListSpaces": {{msg: spaces(), servers: "10.0.0.9:7443"}}})},
		{name: "server sync public refused", args: []string{"space", "list"}, answers: with(map[string][]answer{"ListSpaces": {{msg: spaces(), servers: "8.8.8.8:7443"}}})},
		{name: "rpc error printable", args: []string{"app", "show", "web"}, answers: with(map[string][]answer{"Status": failAnswer(codes.FailedPrecondition, "first\x1b[2J problem\nsecond\tline")})},
		{name: "rpc error unavailable", args: []string{"space", "list"}, answers: with(map[string][]answer{"ListSpaces": failAnswer(codes.Unavailable, "not the leader")})},

		// app.
		{name: "app list", args: []string{"app", "list"}, answers: defaultAnswers()},
		{name: "app list all", args: []string{"app", "list", "-A"}, answers: defaultAnswers()},
		{name: "app list pages", args: []string{"app", "list", "--space", "shop"}, answers: with(map[string][]answer{"ListApps": {
			{msg: &armadav1.ListAppsResponse{Apps: []*armadav1.AppSummary{{Name: "a.shop", Image: "x", Ready: 1, Desired: 1}}, NextPageToken: "p2"}},
			{msg: &armadav1.ListAppsResponse{Apps: []*armadav1.AppSummary{{Name: "b.shop", Image: "y"}}}},
		}})},
		{name: "app list json", args: []string{"app", "list", "-o", "json"}, answers: defaultAnswers()},
		{name: "app show", args: []string{"app", "show", "web"}, answers: defaultAnswers()},
		{name: "app show json", args: []string{"app", "show", "web", "-o", "json"}, answers: defaultAnswers()},
		{name: "app show yaml", args: []string{"app", "show", "web", "-o", "yaml"}, answers: with(map[string][]answer{"GetAppSpec": okAnswer(&armadav1.GetAppSpecResponse{Spec: []byte(webSpec), Revision: "web--r2"})})},
		{name: "app show yaml of a job", args: []string{"app", "show", "migrate", "-o", "yaml"}, answers: with(map[string][]answer{"GetAppSpec": okAnswer(&armadav1.GetAppSpecResponse{Spec: []byte(jobSpec)})})},
		{name: "app show not found", args: []string{"app", "show", "web"}, answers: with(map[string][]answer{"Status": okAnswer(&armadav1.StatusResponse{})})},
		{name: "app show rollout failed", args: []string{"app", "show", "web"}, answers: with(map[string][]answer{"Status": okAnswer(&armadav1.StatusResponse{Apps: []*armadav1.AppStatus{{
			Name: "web", Image: "x", ActiveRevision: "web--r1", TargetRevision: "web--r1", DesiredReplicas: 3, RolloutState: "failed", RolloutMessage: "web--r2: crash\x1b",
			PlacementMessage: "no node fits", IpDeny: []*armadav1.IPRule{{Range: "192.0.2.0/24", Description: "bots"}},
			Traffic:   []*armadav1.TrafficTarget{{Revision: "web--r1", Weight: 100, Urls: []string{"https://r1--web.example.com"}}},
			Autoscale: &armadav1.Autoscale{Min: 1, Max: 4, LastScaledAt: ts(3 * time.Hour), Rules: []*armadav1.AutoscaleRule{{Type: "schedule", Target: 3}, {Type: "queue", Target: 5}, {Type: "memory", Target: 80, Current: 81, Measured: true}}},
		}, {Name: "x"}}})})},
		{name: "app show rolling", args: []string{"app", "show", "web"}, answers: with(map[string][]answer{"Status": okAnswer(&armadav1.StatusResponse{Apps: []*armadav1.AppStatus{{
			Name: "web", ActiveRevision: "web--r1", TargetRevision: "web--r2", RolloutState: "progressing"}}})})},
		{name: "app delete unconfirmed", args: []string{"app", "delete", "web"}},
		{name: "app delete", args: []string{"app", "rm", "web", "--yes"}, answers: defaultAnswers()},
		{name: "app restart", args: []string{"app", "restart", "web.shop"}, answers: defaultAnswers()},
		{name: "app rollback to", args: []string{"app", "rollback", "web", "--to", "r1"}, answers: defaultAnswers()},
		{name: "app rollback full name", args: []string{"app", "rollback", "web", "--to", "web--r1"}, answers: defaultAnswers()},
		{name: "app traffic", args: []string{"app", "traffic", "web", "r3=90", "web--r4=10"}, answers: defaultAnswers()},
		{name: "app traffic bad weight", args: []string{"app", "traffic", "web", "r3=101"}},
		{name: "app traffic no weight", args: []string{"app", "traffic", "web", "r3"}},

		// Rollouts waited for.
		{name: "wait live", args: []string{"app", "restart", "web", "--wait"}, answers: with(map[string][]answer{"Status": {
			{msg: &armadav1.StatusResponse{Apps: []*armadav1.AppStatus{{Name: "web", ActiveRevision: "web--r1", TargetRevision: "web--r2", RolloutState: "progressing", DesiredReplicas: 2,
				Replicas: []*armadav1.ReplicaStatus{{Revision: "web--r2", Ready: true}}}}}},
			{msg: &armadav1.StatusResponse{Apps: []*armadav1.AppStatus{appStatus("web")}}},
		}})},
		{name: "wait failed", args: []string{"app", "rollback", "web", "--wait"}, answers: with(map[string][]answer{"Status": okAnswer(&armadav1.StatusResponse{Apps: []*armadav1.AppStatus{{
			Name: "web", ActiveRevision: "web--r1", TargetRevision: "web--r1", RolloutState: "failed", RolloutMessage: "crashed"}}})})},
		{name: "wait replaced", args: []string{"app", "restart", "web", "--wait"}, answers: with(map[string][]answer{"Status": okAnswer(&armadav1.StatusResponse{Apps: []*armadav1.AppStatus{{
			Name: "web", ActiveRevision: "web--r1", TargetRevision: "web--r3"}}})})},
		{name: "wait traffic", args: []string{"app", "restart", "web", "--wait"}, answers: with(map[string][]answer{"Status": okAnswer(&armadav1.StatusResponse{Apps: []*armadav1.AppStatus{{
			Name: "web", ActiveRevision: "web--r2", TargetRevision: "web--r2", Traffic: []*armadav1.TrafficTarget{{Revision: "web--r1", Weight: 100}}}}})})},
		{name: "wait timeout", args: []string{"app", "restart", "web", "--wait", "--timeout", "1500ms"}, answers: with(map[string][]answer{"Status": okAnswer(&armadav1.StatusResponse{Apps: []*armadav1.AppStatus{{
			Name: "web", ActiveRevision: "web--r1", TargetRevision: "web--r2", RolloutState: "progressing", DesiredReplicas: 1}}})})},

		// app deploy and job deploy.
		{name: "deploy new from flags", args: []string{"app", "deploy", "hello", "--image", "traefik/whoami:v1.10", "--port", "80", "--ingress", "external", "--min", "2",
			"--env", "A=1", "--env", "B=x=y", "--secret-env", "DB=db/url", "--domain", "www.example.com", "--cpu", "250m", "--memory", "256Mi", "--health-path", "/ready",
			"--ip-allow", "10.0.0.0/8,name=office,description=VPN, main", "--cors-origin", "https://a.example.com", "--sticky", "--registry-user", "bot", "--registry-secret", "reg"},
			answers: defaultAnswers()},
		{name: "deploy update from flags", args: []string{"app", "deploy", "web", "--image", "ghcr.io/acme/web:1.5", "--remove-env", "DEBUG", "--port", "9090", "--scale-cpu", "70", "--max", "5"},
			answers: with(map[string][]answer{"GetAppSpec": okAnswer(&armadav1.GetAppSpecResponse{Spec: []byte(webSpec), Revision: "web--r2"}), "Deploy": okAnswer(&armadav1.DeployResponse{App: "web", Revision: "web--r3"})})},
		{name: "deploy unchanged", args: []string{"app", "deploy", "web", "--min", "2"},
			answers: with(map[string][]answer{"GetAppSpec": okAnswer(&armadav1.GetAppSpecResponse{Spec: []byte(webSpec), Revision: "web--r2"})})},
		{name: "deploy diff from flags", args: []string{"app", "deploy", "web", "--env", "LOG=debug", "--no-autoscale", "--health-path", "", "--diff"},
			answers: with(map[string][]answer{"GetAppSpec": okAnswer(&armadav1.GetAppSpecResponse{Spec: []byte(webSpec), Revision: "web--r2"})})},
		{name: "deploy diff no change", args: []string{"app", "deploy", "web", "--min", "2", "--diff"},
			answers: with(map[string][]answer{"GetAppSpec": okAnswer(&armadav1.GetAppSpecResponse{Spec: []byte(webSpec), Revision: "web--r2"})})},
		{name: "deploy file vars", args: []string{"app", "deploy", "--file", "web.yaml", "--vars", "vars.env", "--var", "TAG=2.0"}, files: exampleFiles, answers: defaultAnswers()},
		{name: "deploy file stdin diff", args: []string{"app", "deploy", "-f", "-", "--diff"}, stdin: webSpec,
			answers: with(map[string][]answer{"GetAppSpec": okAnswer(&armadav1.GetAppSpecResponse{Spec: []byte(strings.Replace(webSpec, "min: 2", "min: 3", 1)), Revision: "web--r2"})})},
		{name: "deploy file missing var", args: []string{"app", "deploy", "--file", "web.yaml"}, files: exampleFiles},
		{name: "deploy file missing", args: []string{"app", "deploy", "--file", "nope.yaml"}},
		{name: "deploy file name mismatch", args: []string{"app", "deploy", "api", "--file", "-"}, stdin: webSpec},
		{name: "deploy file and flags", args: []string{"app", "deploy", "--file", "web.yaml", "--image", "x"}, files: exampleFiles},
		{name: "deploy vars without file", args: []string{"app", "deploy", "web", "--var", "A=1"}},
		{name: "deploy bad var", args: []string{"app", "deploy", "--file", "web.yaml", "--var", "1A=x"}, files: exampleFiles},
		{name: "deploy bad vars file", args: []string{"app", "deploy", "--file", "web.yaml", "--vars", "bad.env"}, files: map[string]string{"web.yaml": exampleFiles["web.yaml"], "bad.env": "TAG=1\nTAG=2\n"}},
		{name: "deploy nothing", args: []string{"app", "deploy", "web"}},
		{name: "deploy no name", args: []string{"app", "deploy", "--image", "x"}},
		{name: "deploy new without image", args: []string{"app", "deploy", "web", "--new", "--port", "80"}},
		{name: "deploy new", args: []string{"app", "deploy", "web", "--new", "--image", "nginx", "--wait"}, answers: defaultAnswers()},
		{name: "deploy new and diff", args: []string{"app", "deploy", "web", "--new", "--diff", "--image", "x"}},
		{name: "deploy invalid spec", args: []string{"app", "deploy", "web", "--image", "x", "--ingress", "public", "--min", "500"}, answers: defaultAnswers()},
		{name: "deploy max without rule", args: []string{"app", "deploy", "web", "--image", "x", "--max", "3"}, answers: defaultAnswers()},
		{name: "deploy two rules", args: []string{"app", "deploy", "web", "--image", "x", "--scale-cpu", "50", "--scale-http", "10"}, answers: defaultAnswers()},
		{name: "deploy bad env", args: []string{"app", "deploy", "web", "--image", "x", "--env", "=1"}, answers: defaultAnswers()},
		{name: "deploy bad ip rule", args: []string{"app", "deploy", "web", "--image", "x", "--ip-deny", "1.2.3.4,who=x"}, answers: defaultAnswers()},
		{name: "deploy deleted meanwhile", args: []string{"app", "deploy", "web", "--min", "3"},
			answers: with(map[string][]answer{"GetAppSpec": okAnswer(&armadav1.GetAppSpecResponse{Spec: []byte(webSpec), Revision: "web--r2"}), "Deploy": failAnswer(codes.NotFound, "gone")})},
		{name: "deploy job as app", args: []string{"app", "deploy", "migrate", "--image", "x"},
			answers: with(map[string][]answer{"GetAppSpec": okAnswer(&armadav1.GetAppSpecResponse{Spec: []byte(jobSpec)})})},
		{name: "job deploy flags", args: []string{"job", "deploy", "report", "--image", "ghcr.io/acme/report:2", "--schedule", "0 3 * * *", "--time-zone", "Asia/Jakarta",
			"--timeout", "30m", "--retries", "2", "--concurrency", "forbid", "--tasks", "1", "--env-from", "db"}, answers: defaultAnswers()},
		{name: "job deploy update", args: []string{"job", "deploy", "migrate", "--command", "", "--args", "--all", "--env-from-secrets", "--diff"},
			answers: with(map[string][]answer{"GetAppSpec": okAnswer(&armadav1.GetAppSpecResponse{Spec: []byte(jobSpec), Revision: "migrate--r1"})})},
		{name: "job deploy app file", args: []string{"job", "deploy", "--file", "-"}, stdin: webSpec},

		// revision and replica.
		{name: "revision list", args: []string{"revision", "list", "web"}, answers: defaultAnswers()},
		{name: "revision show", args: []string{"revision", "show", "web--r2"}, answers: defaultAnswers()},
		{name: "revision show missing", args: []string{"revision", "show", "web--r9"}, answers: defaultAnswers()},
		{name: "revision show bad", args: []string{"revision", "show", "r2"}},
		{name: "replica list all apps", args: []string{"replica", "list", "-A"}, answers: with(map[string][]answer{"Status": okAnswer(&armadav1.StatusResponse{Apps: []*armadav1.AppStatus{appStatus("web"), appStatus("api.shop")}})})},
		{name: "replica list space", args: []string{"replica", "ls"}, answers: with(map[string][]answer{"Status": okAnswer(&armadav1.StatusResponse{Apps: []*armadav1.AppStatus{appStatus("web"), appStatus("api.shop")}})})},
		{name: "replica list json", args: []string{"replica", "list", "web", "-o", "json"}, answers: defaultAnswers()},

		// job and run.
		{name: "job list", args: []string{"job", "list"}, answers: defaultAnswers()},
		{name: "job list all", args: []string{"job", "ls", "-A"}, answers: defaultAnswers()},
		{name: "job show", args: []string{"job", "show", "migrate"}, answers: defaultAnswers()},
		{name: "job show trigger", args: []string{"job", "show", "report.shop"}, answers: defaultAnswers()},
		{name: "job show unread", args: []string{"job", "show", "sweep"}, answers: defaultAnswers()},
		{name: "job show json", args: []string{"job", "show", "migrate", "-o", "json"}, answers: defaultAnswers()},
		{name: "job show missing", args: []string{"job", "show", "nope"}, answers: defaultAnswers()},
		{name: "job start wait failed", args: []string{"job", "start", "migrate", "--wait"}, answers: with(map[string][]answer{"RunJob": okAnswer(&armadav1.RunJobResponse{Run: 11})})},
		{name: "job start wait gone", args: []string{"job", "start", "migrate", "--wait"}, answers: with(map[string][]answer{"RunJob": okAnswer(&armadav1.RunJobResponse{Run: 99})})},
		{name: "job cancel none", args: []string{"job", "cancel", "migrate"}, answers: with(map[string][]answer{"CancelJob": okAnswer(&armadav1.CancelJobResponse{})})},
		{name: "run show", args: []string{"run", "show", "migrate", "12"}, answers: defaultAnswers()},
		{name: "run show no tasks", args: []string{"run", "show", "migrate", "11"}, answers: defaultAnswers()},
		{name: "run show bad", args: []string{"run", "show", "migrate", "x"}},
		{name: "run show missing", args: []string{"run", "show", "migrate", "7"}, answers: defaultAnswers()},
		{name: "run list json", args: []string{"run", "list", "migrate", "-o", "json"}, answers: defaultAnswers()},

		// secret.
		{name: "secret set stdin", args: []string{"secret", "set", "db", "PASSWORD"}, stdin: "hunter2\r\n", answers: with(map[string][]answer{"SetSecret": okAnswer(&armadav1.SetSecretResponse{Version: 3, Revisions: []string{"web--r3", "worker--r8"}})})},
		{name: "secret set wait", args: []string{"secret", "set", "db", "PASSWORD", "--wait"}, stdin: "x", answers: with(map[string][]answer{"SetSecret": okAnswer(&armadav1.SetSecretResponse{Version: 3, Revision: "web--r2"})})},
		{name: "secret set empty", args: []string{"secret", "set", "db", "PASSWORD"}, stdin: "\n"},
		{name: "secret set allow empty", args: []string{"secret", "set", "db", "PASSWORD", "--allow-empty", "--no-rollout"}, answers: defaultAnswers()},
		{name: "secret set file", args: []string{"secret", "set", "tls", "key", "--from-file", "key.pem"}, files: exampleFiles, answers: defaultAnswers()},
		{name: "secret set bad key", args: []string{"secret", "set", "db", "Bad-Key"}},
		{name: "secret set bad name", args: []string{"secret", "set", "DB", "key"}},
		{name: "secret set env file", args: []string{"secret", "set", "db", "--from-env-file", "-"}, stdin: "A=1\n# c\nb-c=2=3\n", answers: defaultAnswers()},
		{name: "secret set env file args", args: []string{"secret", "set", "db", "KEY", "--from-env-file", "db.env"}},
		{name: "secret set env file both", args: []string{"secret", "set", "db", "--from-env-file", "db.env", "--from-file", "x"}},
		{name: "secret set env file fails", args: []string{"secret", "set", "db", "--from-env-file", "db.env"}, files: exampleFiles,
			answers: with(map[string][]answer{"SetSecret": {{msg: &armadav1.SetSecretResponse{Version: 1}}, {code: codes.PermissionDenied, text: "not yours"}}})},
		{name: "secret create exists", args: []string{"secret", "create", "db", "--from-env-file", "db.env"}, files: exampleFiles,
			answers: with(map[string][]answer{"ListSecrets": okAnswer(&armadav1.ListSecretsResponse{Secrets: []*armadav1.SecretInfo{{Name: "A"}}})})},
		{name: "secret create bad line", args: []string{"secret", "create", "db", "--from-env-file", "-"}, stdin: "A=1\nnot a line\n"},
		{name: "secret create duplicate", args: []string{"secret", "create", "db", "--from-env-file", "-"}, stdin: "A=1\nA=2\n"},
		{name: "secret create empty file", args: []string{"secret", "create", "db", "--from-env-file", "-"}, stdin: "# nothing\n"},
		{name: "secret list all", args: []string{"secret", "list", "-A"}, answers: defaultAnswers()},
		{name: "secret list json", args: []string{"secret", "list", "-o", "json"}, answers: defaultAnswers()},
		{name: "secret show", args: []string{"secret", "show", "web"}, answers: with(map[string][]answer{"ListSecrets": okAnswer(&armadav1.ListSecretsResponse{Secrets: []*armadav1.SecretInfo{
			{Name: "url", Version: 4, UpdatedAt: timestamppb.New(time.Date(2026, 11, 21, 4, 5, 6, 0, time.UTC)), UpdatedBy: "ada", UsedBy: []string{"web--r20", "web--r19", "web--r18", "web--r12", "worker--r3", "worker--r4"}},
			{Name: "token"},
		}})})},
		{name: "secret show missing", args: []string{"secret", "show", "nope"}, answers: defaultAnswers()},
		{name: "secret show missing none", args: []string{"secret", "show", "nope"}, answers: with(map[string][]answer{"ListSpaceSecrets": okAnswer(&armadav1.ListSpaceSecretsResponse{})})},
		{name: "secret unset", args: []string{"secret", "unset", "db", "OLD"}, answers: defaultAnswers()},
		{name: "secret delete unconfirmed", args: []string{"secret", "delete", "db"}},

		// space.
		{name: "space use", args: []string{"space", "use", "shop"}, answers: defaultAnswers()},
		{name: "space use default", args: []string{"space", "use", "default"}, config: shared},
		{name: "space use missing", args: []string{"space", "use", "nope"}, answers: defaultAnswers()},
		{name: "space use invalid", args: []string{"space", "use", "No"}},
		{name: "space show", args: []string{"space", "show", "shop"}, answers: defaultAnswers()},
		{name: "space show missing", args: []string{"space", "show", "nope"}, answers: defaultAnswers()},
		{name: "space update nothing", args: []string{"space", "update", "default"}},
		{name: "space update off", args: []string{"space", "update", "default", "--network-isolation=false"}, answers: defaultAnswers()},
		{name: "space list json", args: []string{"space", "list", "-o", "json"}, answers: defaultAnswers()},

		// version.
		{name: "version", args: []string{"version"}, answers: defaultAnswers()},
		{name: "version no config", args: []string{"version"}, noConfig: true},
		{name: "version server error", args: []string{"version"}, answers: with(map[string][]answer{"ListServers": failAnswer(codes.PermissionDenied, "denied")})},
		{name: "version latest cached", args: []string{"version"}, env: map[string]string{"ARMADA_NO_UPDATE_CHECK": ""}, answers: defaultAnswers(),
			files: map[string]string{"cache/armada/latest.json": fmt.Sprintf(`{"tag":"v0.1.0-alpha.41","checked":%d}`, time.Now().Unix())}},
		{name: "version yaml", args: []string{"version", "-o", "yaml"}},

		// completion.
		{name: "complete nouns", args: []string{"__complete", ""}},
		{name: "complete nouns no descriptions", args: []string{"__completeNoDesc", "s"}},
		{name: "complete verbs", args: []string{"__complete", "app", ""}},
		{name: "complete flags", args: []string{"__complete", "app", "deploy", "--"}},
		{name: "complete exclusive flags", args: []string{"__complete", "app", "deploy", "--ip-allow", "x", "--"}},
		{name: "complete required flag", args: []string{"__complete", "secret", "create", "db", ""}},
		{name: "complete apps", args: []string{"__complete", "app", "show", ""}, answers: defaultAnswers()},
		{name: "complete apps prefix", args: []string{"__complete", "app", "show", "w"}, answers: defaultAnswers()},
		{name: "complete apps of a space", args: []string{"__complete", "--space", "shop", "app", "show", ""}, answers: with(map[string][]answer{
			"ListApps": okAnswer(&armadav1.ListAppsResponse{Apps: []*armadav1.AppSummary{{Name: "api.shop", Space: "shop"}}}),
		})},
		{name: "complete jobs", args: []string{"__complete", "job", "start", ""}, answers: defaultAnswers()},
		{name: "complete runs", args: []string{"__complete", "run", "show", "migrate", ""}, answers: defaultAnswers()},
		{name: "complete secrets", args: []string{"__complete", "secret", "show", ""}, answers: defaultAnswers()},
		{name: "complete keys", args: []string{"__complete", "secret", "unset", "web", ""}, answers: with(map[string][]answer{"ListSecrets": okAnswer(&armadav1.ListSecretsResponse{Secrets: []*armadav1.SecretInfo{{Name: "url"}, {Name: "token"}}})})},
		{name: "complete weights", args: []string{"__complete", "app", "traffic", "web", ""}, answers: defaultAnswers()},
		{name: "complete revision ids", args: []string{"__complete", "revision", "show", ""}, answers: defaultAnswers()},
		{name: "complete to", args: []string{"__complete", "app", "rollback", "web", "--to", ""}, answers: defaultAnswers()},
		{name: "complete spaces", args: []string{"__complete", "space", "use", ""}, answers: defaultAnswers()},
		{name: "complete past the arguments", args: []string{"__complete", "app", "show", "web", ""}},
		{name: "complete help", args: []string{"__complete", "help", "app", ""}},
		{name: "complete unknown", args: []string{"__complete", "nope", "x", ""}},
		{name: "complete bad flag", args: []string{"__complete", "app", "list", "--nope", ""}},
		{name: "complete after help", args: []string{"__complete", "app", "list", "-h", ""}},
		{name: "complete descriptions off", args: []string{"__complete", "app", ""}, env: map[string]string{"ARMADA_COMPLETION_DESCRIPTIONS": "false"}},
		{name: "completion bash", args: []string{"completion", "bash"}},
		{name: "completion zsh no descriptions", args: []string{"completion", "zsh", "--no-descriptions"}},
		{name: "completion fish", args: []string{"completion", "fish"}},
		{name: "completion powershell", args: []string{"completion", "powershell", "--no-descriptions"}},
		{name: "completion noun", args: []string{"completion"}},
		{name: "completion extra", args: []string{"completion", "bash", "x"}},
	}
	return cases
}
