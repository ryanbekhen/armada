package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/spec"
)

// fakeAdmin answers the RPCs the app commands use, keeping specs the way
// the server does: one revision per change, exported as GetAppSpec does.
type fakeAdmin struct {
	armadav1.AdminServiceClient
	specs    map[string]string
	revs     map[string]int
	deploys  []*armadav1.DeployRequest
	scales   []*armadav1.ScaleRequest
	projects []string
	apps     []*armadav1.AppSummary
	pageSize int
	// beforeDeploy runs before a deploy is applied, as another change
	// landing in between would.
	beforeDeploy func()
}

func newFakeAdmin() *fakeAdmin {
	return &fakeAdmin{specs: map[string]string{}, revs: map[string]int{}, projects: []string{"default"}}
}

func (f *fakeAdmin) rev(id string) string { return id + "--r" + strconv.Itoa(f.revs[id]) }

func (f *fakeAdmin) GetAppSpec(_ context.Context, req *armadav1.GetAppSpecRequest, _ ...grpc.CallOption) (*armadav1.GetAppSpecResponse, error) {
	s, ok := f.specs[req.App]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "app %s: not found", req.App)
	}
	return &armadav1.GetAppSpecResponse{Spec: []byte(s), Revision: f.rev(req.App)}, nil
}

func (f *fakeAdmin) Deploy(_ context.Context, req *armadav1.DeployRequest, _ ...grpc.CallOption) (*armadav1.DeployResponse, error) {
	f.deploys = append(f.deploys, req)
	if f.beforeDeploy != nil {
		f.beforeDeploy()
	}
	sp, err := spec.ParseIn(req.Spec, req.Project)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	id := sp.ID()
	_, exists := f.specs[id]
	switch {
	case req.MustCreate && exists:
		return nil, status.Errorf(codes.AlreadyExists, "%s exists; change it with update", id)
	case req.MustExist && !exists:
		return nil, status.Errorf(codes.NotFound, "app %s: not found", id)
	case req.BaseRevision != "" && exists && req.BaseRevision != f.rev(id):
		return nil, status.Errorf(codes.FailedPrecondition, "%s changed since %s (now %s); run the command again", id, req.BaseRevision, f.rev(id))
	}
	out, err := sp.Export()
	if err != nil {
		return nil, err
	}
	if string(out) != f.specs[id] {
		f.specs[id] = string(out)
		f.revs[id]++
	}
	return &armadav1.DeployResponse{App: id, Revision: f.rev(id)}, nil
}

func (f *fakeAdmin) Scale(_ context.Context, req *armadav1.ScaleRequest, _ ...grpc.CallOption) (*armadav1.ScaleResponse, error) {
	f.scales = append(f.scales, req)
	return &armadav1.ScaleResponse{}, nil
}

func (f *fakeAdmin) ListProjects(context.Context, *armadav1.ListProjectsRequest, ...grpc.CallOption) (*armadav1.ListProjectsResponse, error) {
	resp := &armadav1.ListProjectsResponse{}
	for _, p := range f.projects {
		resp.Projects = append(resp.Projects, &armadav1.ProjectInfo{Name: p})
	}
	return resp, nil
}

// ListApps pages f.apps like the server: sorted, after the token.
func (f *fakeAdmin) ListApps(_ context.Context, req *armadav1.ListAppsRequest, _ ...grpc.CallOption) (*armadav1.ListAppsResponse, error) {
	start := 0
	if req.PageToken != "" {
		for start < len(f.apps) && f.apps[start].Name <= req.PageToken {
			start++
		}
	}
	end := min(start+f.pageSize, len(f.apps))
	resp := &armadav1.ListAppsResponse{Apps: f.apps[start:end]}
	if end < len(f.apps) {
		resp.NextPageToken = f.apps[end-1].Name
	}
	return resp, nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// withFake makes the commands talk to f and returns a client config path.
func withFake(t *testing.T, f *fakeAdmin) string {
	t.Helper()
	orig := dialAdmin
	dialAdmin = func(*globals) (armadav1.AdminServiceClient, io.Closer, error) { return f, nopCloser{}, nil }
	t.Cleanup(func() { dialAdmin = orig })
	t.Setenv("ARMADA_PROJECT", "")
	path := filepath.Join(t.TempDir(), "config")
	cc := &clientconfig.Config{Servers: []string{"10.0.0.1:7443"}, CA: "ca", Cert: "cert", Key: "key"}
	if err := cc.SaveFile(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAppCreateAndUpdateFromFlags(t *testing.T) {
	f := newFakeAdmin()
	cfg := withFake(t, f)
	cli := func(args ...string) (int, string, string) { return run(t, append(args, "--config", cfg)...) }

	code, out, stderr := cli("app", "create", "hello", "--image", "traefik/whoami:v1.10", "--port", "80", "--ingress", "external",
		"--replicas", "2", "--env", "A=1", "--secret-env", "DB=db-url", "--health-path", "/healthz", "--memory", "128Mi")
	if code != 0 || out != "Created hello (revision hello--r1).\n" {
		t.Fatalf("create: %d %q %q", code, out, stderr)
	}
	if d := f.deploys[0]; !d.MustCreate || d.MustExist || d.BaseRevision != "" {
		t.Errorf("create sent %+v", d)
	}
	if code, _, stderr := cli("app", "create", "hello", "--image", "nginx:1"); code == 0 || !strings.Contains(stderr, "hello exists") {
		t.Errorf("create twice: %d %q", code, stderr)
	}

	// One flag changes one field; the rest stays.
	code, out, stderr = cli("app", "update", "hello", "--image", "traefik/whoami:v1.11", "--port", "8080")
	if code != 0 || out != "Updated hello (revision hello--r2).\n" {
		t.Fatalf("update: %d %q %q", code, out, stderr)
	}
	d := f.deploys[len(f.deploys)-1]
	if !d.MustExist || d.MustCreate || d.BaseRevision != "hello--r1" {
		t.Errorf("update sent must_exist=%v must_create=%v base=%q", d.MustExist, d.MustCreate, d.BaseRevision)
	}
	sp, err := spec.Parse([]byte(f.specs["hello"]))
	if err != nil {
		t.Fatal(err)
	}
	if sp.Image != "traefik/whoami:v1.11" || sp.Ingress.Type != "external" || sp.Ingress.Port != 8080 || sp.Replicas() != 2 ||
		len(sp.Env) != 2 || sp.Env[0] != (spec.EnvVar{Name: "A", Value: "1"}) || sp.Env[1] != (spec.EnvVar{Name: "DB", SecretRef: "db-url"}) ||
		sp.Probes.Readiness.Path != "/healthz" || sp.Probes.Readiness.Port != 8080 || sp.Resources.Memory != "128Mi" {
		t.Errorf("after update:\n%s", f.specs["hello"])
	}
	if code, out, _ := cli("app", "update", "hello", "--image", "traefik/whoami:v1.11"); code != 0 || out != "hello is unchanged (revision hello--r2).\n" {
		t.Errorf("no-op update: %d %q", code, out)
	}
	// Each --args is one argument, kept as written: commas stay.
	if code, _, stderr := cli("app", "update", "hello", "--args", "--hosts=a,b", "--args", "two words"); code != 0 {
		t.Fatalf("update args: %s", stderr)
	}
	if sp, _ := spec.Parse([]byte(f.specs["hello"])); len(sp.Args) != 2 || sp.Args[0] != "--hosts=a,b" || sp.Args[1] != "two words" {
		t.Errorf("args: %q", sp.Args)
	}
	if code, _, _ := cli("app", "update", "hello", "--args", ""); code != 0 {
		t.Fatal("clearing args failed")
	}
	if sp, _ := spec.Parse([]byte(f.specs["hello"])); len(sp.Args) != 0 {
		t.Errorf("args not cleared: %q", sp.Args)
	}
	if code, _, _ := cli("app", "update", "hello", "--remove-env", "A", "--env", "C=3", "--min", "1", "--max", "4", "--scale-cpu", "70"); code != 0 {
		t.Fatal("update env and scale failed")
	}
	sp, _ = spec.Parse([]byte(f.specs["hello"]))
	if len(sp.Env) != 2 || sp.Env[0].Name != "DB" || sp.Env[1].Name != "C" || !sp.Autoscaled() || *sp.Scale.Min != 1 || *sp.Scale.Max != 4 || sp.Scale.Rules[0].Utilization != 70 {
		t.Errorf("after env and scale update:\n%s", f.specs["hello"])
	}

	// Another change landing in between is not lost.
	f.beforeDeploy = func() { f.revs["hello"]++ }
	if code, _, stderr := cli("app", "update", "hello", "--image", "nginx:1"); code == 0 || !strings.Contains(stderr, "changed since hello--r") {
		t.Errorf("stale update: %d %q", code, stderr)
	}
	f.beforeDeploy = nil

	for args, want := range map[string]string{
		"app update ghost --image nginx:1":                               "does not exist",
		"app update hello":                                               "nothing to change",
		"app update hello --replicas 2 --min 1":                          "--replicas sets a fixed count",
		"app update hello --min 1 --max 3 --scale-cpu 50 --scale-http 9": "give one of",
		"app create hi --image nginx:1 --var A=1":                        "--vars and --var",
		"app create hi --image nginx:1 --file x.yaml":                    "either --file or flags",
		"app create hi --port 80":                                        "--image is required",
		"app update hello --env NOEQUALS":                                "--env: want NAME=VALUE",
		"app update hello --remove-env NOPE":                             "no such variable",
		"job update hello --retries 2":                                   "hello is an app, not a job",
	} {
		if code, _, stderr := cli(strings.Fields(args)...); code == 0 || !strings.Contains(stderr, want) {
			t.Errorf("%s: %d %q, want %q", args, code, stderr, want)
		}
	}
	if code, _, stderr := cli("app", "update", "hello", "--env", "TOKEN=s3cret-value", "--port", "0"); code == 0 || strings.Contains(stderr, "s3cret-value") {
		t.Errorf("invalid update: %d %q", code, stderr)
	}
}

func TestAppUpdateFileDiffAndCreateIfMissing(t *testing.T) {
	f := newFakeAdmin()
	cfg := withFake(t, f)
	cli := func(args ...string) (int, string, string) { return run(t, append(args, "--config", cfg)...) }
	if code, _, stderr := cli("app", "create", "web", "--image", "nginx:1.27", "--port", "80", "--ingress", "internal", "--env", "A=1"); code != 0 {
		t.Fatal(stderr)
	}
	file := filepath.Join(t.TempDir(), "web.yaml")
	if err := os.WriteFile(file, []byte("name: web\nimage: nginx:1.28\ningress:\n  type: internal\n  port: 80\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// --diff prints the change and deploys nothing.
	before := len(f.deploys)
	code, out, stderr := cli("app", "update", "web", "--file", file, "--diff")
	if code != 0 || !strings.Contains(out, "- image: nginx:1.27\n") || !strings.Contains(out, "+ image: nginx:1.28\n") || !strings.Contains(out, "-   - name: A\n") || len(f.deploys) != before {
		t.Errorf("--diff: %d %q %q", code, out, stderr)
	}
	if _, out, _ := cli("app", "update", "web", "--image", "nginx:1.27", "--diff"); out != "No changes.\n" {
		t.Errorf("--diff without changes = %q", out)
	}

	// --file replaces the whole spec: A is gone.
	if code, out, stderr := cli("app", "update", "web", "--file", file); code != 0 || out != "Updated web (revision web--r2).\n" {
		t.Fatalf("update --file: %d %q %q", code, out, stderr)
	}
	if d := f.deploys[len(f.deploys)-1]; !d.MustExist || d.BaseRevision != "" {
		t.Errorf("update --file sent %+v", d)
	}
	if strings.Contains(f.specs["web"], "name: A") || !strings.Contains(f.specs["web"], "nginx:1.28") {
		t.Errorf("after update --file:\n%s", f.specs["web"])
	}
	if code, _, stderr := cli("app", "update", "other", "--file", file); code == 0 || !strings.Contains(stderr, "names web, not other") {
		t.Errorf("update --file with another name: %d %q", code, stderr)
	}

	// --create-if-missing creates, from flags or a file.
	if code, _, stderr := cli("app", "update", "api", "--image", "nginx:1"); code == 0 || !strings.Contains(stderr, "does not exist") {
		t.Errorf("update of a missing app: %d %q", code, stderr)
	}
	if code, out, stderr := cli("app", "update", "api", "--image", "nginx:1", "--create-if-missing"); code != 0 || out != "Created api (revision api--r1).\n" {
		t.Errorf("update --create-if-missing: %d %q %q", code, out, stderr)
	}
	if d := f.deploys[len(f.deploys)-1]; !d.MustCreate {
		t.Errorf("--create-if-missing sent %+v", d)
	}
	other := filepath.Join(t.TempDir(), "worker.yaml")
	if err := os.WriteFile(other, []byte("name: worker\nimage: busybox:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, stderr := cli("app", "update", "--file", other, "--create-if-missing"); code != 0 || out != "Created worker (revision worker--r1).\n" {
		t.Errorf("update --file --create-if-missing: %d %q %q", code, out, stderr)
	}

	// A job spec is refused by app create, and the other way round.
	job := filepath.Join(t.TempDir(), "job.yaml")
	if err := os.WriteFile(job, []byte("kind: job\nname: report\nimage: busybox:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := cli("app", "create", "--file", job); code == 0 || !strings.Contains(stderr, "use armada job create") {
		t.Errorf("app create with a job: %d %q", code, stderr)
	}
	if code, _, stderr := cli("job", "create", "--file", file); code == 0 || !strings.Contains(stderr, "use armada app create") {
		t.Errorf("job create with an app: %d %q", code, stderr)
	}
	if code, out, stderr := cli("job", "create", "nightly", "--image", "busybox:1", "--schedule", "0 3 * * *", "--retries", "1"); code != 0 || out != "Created nightly (revision nightly--r1).\n" {
		t.Errorf("job create from flags: %d %q %q", code, out, stderr)
	}
	if !strings.Contains(f.specs["nightly"], "kind: job") || !strings.Contains(f.specs["nightly"], "schedule: 0 3 * * *") {
		t.Errorf("job spec:\n%s", f.specs["nightly"])
	}
}

func TestListAppsPages(t *testing.T) {
	f := newFakeAdmin()
	f.pageSize = 2
	for _, n := range []string{"a", "b", "c", "d", "e.staging"} {
		f.apps = append(f.apps, &armadav1.AppSummary{Name: n, Ready: 1, Desired: 1, State: "ready", Image: "nginx:1"})
	}
	apps, err := listApps(context.Background(), f, &armadav1.ListAppsRequest{AllProjects: true})
	if err != nil || len(apps) != 5 || apps[4].Name != "e.staging" {
		t.Fatalf("listApps = %v, %v", apps, err)
	}
	cfg := withFake(t, f)
	code, out, _ := run(t, "app", "list", "-A", "--config", cfg)
	if code != 0 || !strings.HasPrefix(out, "PROJECT  NAME  READY") || !strings.Contains(out, "staging  e     1/1") || strings.Count(out, "\n") != 6 {
		t.Errorf("app list -A =\n%s", out)
	}
	code, out, _ = run(t, "app", "list", "-o", "json", "--config", cfg)
	var resp struct {
		Apps []struct{ Name string } `json:"apps"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &resp) != nil || len(resp.Apps) != 5 {
		t.Errorf("app list -o json = %s", out)
	}
}

func TestProjectUse(t *testing.T) {
	f := newFakeAdmin()
	f.projects = append(f.projects, "staging")
	cfg := withFake(t, f)
	cli := func(args ...string) (int, string, string) { return run(t, append(args, "--config", cfg)...) }
	scaled := func() string { return f.scales[len(f.scales)-1].App }

	if code, out, stderr := cli("project", "use", "staging"); code != 0 || out != "Using project staging.\n" {
		t.Fatalf("project use: %d %q %q", code, out, stderr)
	}
	cc, err := clientconfig.Load(cfg)
	if err != nil || cc.Project != "staging" {
		t.Fatalf("config project = %v, %v", cc, err)
	}
	if fi, _ := os.Stat(cfg); fi.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %v", fi.Mode())
	}
	cli("app", "scale", "web", "--replicas", "2")
	if scaled() != "web.staging" {
		t.Errorf("scale in the used project named %s", scaled())
	}
	cli("app", "scale", "web", "--replicas", "2", "--project", "default")
	if scaled() != "web" {
		t.Errorf("--project default named %s", scaled())
	}
	t.Setenv("ARMADA_PROJECT", "prod")
	cli("app", "scale", "web", "--replicas", "2")
	if scaled() != "web.prod" {
		t.Errorf("ARMADA_PROJECT named %s", scaled())
	}
	t.Setenv("ARMADA_PROJECT", "")
	if code, _, stderr := cli("project", "use", "ghost"); code == 0 || !strings.Contains(stderr, "project ghost not found") {
		t.Errorf("use of a missing project: %d %q", code, stderr)
	}
	if code, _, _ := cli("project", "use", "default"); code != 0 {
		t.Fatal("project use default failed")
	}
	cli("app", "scale", "web", "--replicas", "2")
	if scaled() != "web" {
		t.Errorf("after use default: %s", scaled())
	}
	if cc, _ := clientconfig.Load(cfg); cc.Project != "" {
		t.Errorf("config project after use default = %q", cc.Project)
	}
}

func TestLineDiff(t *testing.T) {
	var b strings.Builder
	if err := printDiff(&b, []byte("a\nb\nc\n"), []byte("a\nx\nc\nd\n")); err != nil {
		t.Fatal(err)
	}
	if want := "  a\n- b\n+ x\n  c\n+ d\n"; b.String() != want {
		t.Errorf("diff = %q, want %q", b.String(), want)
	}
	long := func(n int, mark string) []byte {
		var s strings.Builder
		for i := range n {
			if i == n/2 {
				s.WriteString(mark + "\n")
				continue
			}
			fmt.Fprintf(&s, "line %d\n", i)
		}
		return []byte(s.String())
	}
	b.Reset()
	_ = printDiff(&b, long(40, "old"), long(40, "new"))
	if lines := strings.Count(b.String(), "\n"); lines != 8 || !strings.Contains(b.String(), "- old\n+ new\n") {
		t.Errorf("diff keeps 3 lines of context:\n%s", b.String())
	}
}

// --ip-allow and --ip-deny replace who may reach the app from outside;
// --no-ip-rules lets everyone again (ADR 0035).
func TestAppIPRuleFlags(t *testing.T) {
	f := newFakeAdmin()
	cfg := withFake(t, f)
	cli := func(args ...string) (int, string, string) { return run(t, append(args, "--config", cfg)...) }
	if code, _, stderr := cli("app", "create", "admin", "--image", "nginx:1", "--port", "80", "--ingress", "external",
		"--ip-allow", "203.0.113.0/24,name=office,description=the VPN, for admins", "--ip-allow", "2001:db8::/32,name=v6"); code != 0 {
		t.Fatal(stderr)
	}
	ingress := func() *spec.Ingress {
		sp, err := spec.Parse([]byte(f.specs["admin"]))
		if err != nil {
			t.Fatal(err)
		}
		return sp.Ingress
	}
	if in := ingress(); !slices.Equal(in.IPAllow, []spec.IPRule{{Name: "office", Range: "203.0.113.0/24", Description: "the VPN, for admins"}, {Range: "2001:db8::/32", Name: "v6"}}) || in.IPDeny != nil {
		t.Errorf("after create: %+v", in)
	}
	if code, _, stderr := cli("app", "update", "admin", "--ip-deny", "198.51.100.7"); code != 0 {
		t.Fatal(stderr)
	}
	if in := ingress(); in.IPAllow != nil || !slices.Equal(in.IPDeny, []spec.IPRule{{Range: "198.51.100.7"}}) {
		t.Errorf("after --ip-deny: %+v", in)
	}
	// Other ingress changes keep the rules.
	if code, _, stderr := cli("app", "update", "admin", "--domain", "admin.example.org"); code != 0 {
		t.Fatal(stderr)
	}
	if in := ingress(); !slices.Equal(in.IPDeny, []spec.IPRule{{Range: "198.51.100.7"}}) {
		t.Errorf("a domain change dropped the rules: %+v", in)
	}
	if code, _, stderr := cli("app", "update", "admin", "--no-ip-rules"); code != 0 {
		t.Fatal(stderr)
	}
	if in := ingress(); in.IPAllow != nil || in.IPDeny != nil {
		t.Errorf("after --no-ip-rules: %+v", in)
	}
	for args, want := range map[string]string{
		"app update admin --ip-allow 203.0.113.0/24 --ip-deny 198.51.100.7": "none of the others can be",
		"app update admin --ip-allow 0.0.0.0/0":                             "matches every address",
		"app update admin --ip-allow example.org":                           "not an IP address",
		"app update admin --ip-allow 203.0.113.0/24,owner=me":               "want RANGE[,name=NAME][,description=TEXT]",
		"app update admin --ip-allow 203.0.113.0/24,name=a,name=b":          "want RANGE[,name=NAME][,description=TEXT]",
	} {
		if code, _, stderr := cli(strings.Fields(args)...); code == 0 || !strings.Contains(stderr, want) {
			t.Errorf("%s: %d %q, want %q", args, code, stderr, want)
		}
	}
}

func TestAppCORSFlags(t *testing.T) {
	f := newFakeAdmin()
	cfg := withFake(t, f)
	cli := func(args ...string) (int, string, string) { return run(t, append(args, "--config", cfg)...) }
	if code, _, stderr := cli("app", "create", "api", "--image", "nginx:1", "--port", "80", "--ingress", "external",
		"--cors-origin", "https://app.example.org", "--cors-origin", "http://localhost:3000"); code != 0 {
		t.Fatal(stderr)
	}
	cors := func() *spec.CORS {
		sp, err := spec.Parse([]byte(f.specs["api"]))
		if err != nil {
			t.Fatal(err)
		}
		return sp.Ingress.CORS
	}
	if c := cors(); c == nil || !slices.Equal(c.AllowOrigins, []string{"https://app.example.org", "http://localhost:3000"}) {
		t.Errorf("after create: %+v", c)
	}
	if code, _, stderr := cli("app", "update", "api", "--cors-origin", "*"); code != 0 || !slices.Equal(cors().AllowOrigins, []string{"*"}) {
		t.Errorf("--cors-origin *: %s", stderr)
	}
	if code, _, stderr := cli("app", "update", "api", "--no-cors"); code != 0 || cors() != nil {
		t.Errorf("--no-cors: %s", stderr)
	}
	if code, _, stderr := cli("app", "update", "api", "--cors-origin", "https://a.example.org/path"); code == 0 || !strings.Contains(stderr, "is not an origin") {
		t.Errorf("bad origin: %d %q", code, stderr)
	}
}
