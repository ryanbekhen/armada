package cli

import (
	"context"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// fakeNames answers the calls replica list, restart, secret show, and
// completion make.
type fakeNames struct {
	*fakeAdmin
	restarted []string
	statusFor []string
}

func (f *fakeNames) Status(_ context.Context, req *armadav1.StatusRequest, _ ...grpc.CallOption) (*armadav1.StatusResponse, error) {
	f.statusFor = append(f.statusFor, req.App)
	api := &armadav1.AppStatus{Name: "api", Replicas: []*armadav1.ReplicaStatus{
		{Id: "api-r12-k3p9x", Revision: "api--r12", NodeId: "app-01", State: "running", Ready: true, Containers: []string{"app", "log-ship"}, InitContainers: []string{"migrate"}},
		{Id: "api-r12-x7q2a", Revision: "api--r12", NodeId: "app-02", State: "running", Ready: true, Containers: []string{"app", "log-ship"}},
	}}
	other := &armadav1.AppStatus{Name: "web.staging", Replicas: []*armadav1.ReplicaStatus{{Id: "web.staging-r1-aaaaa", Revision: "web.staging--r1", State: "running"}}}
	resp := &armadav1.StatusResponse{Nodes: []*armadav1.NodeStatus{{Id: "app-01"}, {Id: "app-02"}}}
	switch {
	case req.NodesOnly:
	case req.App == "api":
		resp.Apps = []*armadav1.AppStatus{api}
	case req.App == "":
		resp.Apps = []*armadav1.AppStatus{api, other}
	}
	return resp, nil
}

func (f *fakeNames) RestartApp(_ context.Context, req *armadav1.RestartAppRequest, _ ...grpc.CallOption) (*armadav1.RestartAppResponse, error) {
	f.restarted = append(f.restarted, req.App)
	return &armadav1.RestartAppResponse{Revision: req.App + "--r13"}, nil
}

func (f *fakeNames) ListSpaceSecrets(context.Context, *armadav1.ListSpaceSecretsRequest, ...grpc.CallOption) (*armadav1.ListSpaceSecretsResponse, error) {
	return &armadav1.ListSpaceSecretsResponse{Secrets: []*armadav1.SpaceSecretInfo{{Name: "mail"}, {Name: "db"}, {Name: "api"}}}, nil
}

func (f *fakeNames) ListSecrets(_ context.Context, req *armadav1.ListSecretsRequest, _ ...grpc.CallOption) (*armadav1.ListSecretsResponse, error) {
	if req.App != "db" {
		return &armadav1.ListSecretsResponse{}, nil
	}
	return &armadav1.ListSecretsResponse{Secrets: []*armadav1.SecretInfo{{Name: "url"}, {Name: "password"}}}, nil
}

func (f *fakeNames) ListRevisions(_ context.Context, req *armadav1.ListRevisionsRequest, _ ...grpc.CallOption) (*armadav1.ListRevisionsResponse, error) {
	return &armadav1.ListRevisionsResponse{Revisions: []*armadav1.RevisionInfo{{Name: req.App + "--r11"}, {Name: req.App + "--r12"}}}, nil
}

func namesCLI(t *testing.T) (*fakeNames, func(args ...string) (int, string, string)) {
	f, cfg := namesFake(t)
	return f, func(args ...string) (int, string, string) { return run(t, append(args, "--config", cfg)...) }
}

func namesFake(t *testing.T) (*fakeNames, string) {
	f := &fakeNames{fakeAdmin: newFakeAdmin()}
	f.apps, f.pageSize = []*armadav1.AppSummary{{Name: "api", Space: "default"}, {Name: "worker", Space: "default"}}, 1
	cfg := withFake(t, f.fakeAdmin)
	orig := dialAdmin
	dialAdmin = func(*globals) (armadav1.AdminServiceClient, io.Closer, error) { return f, nopCloser{}, nil }
	t.Cleanup(func() { dialAdmin = orig })
	return f, cfg
}

func TestReplicaList(t *testing.T) {
	_, cli := namesCLI(t)
	code, out, stderr := cli("replica", "list", "api")
	want := "REPLICA  NODE    STATE    REVISION  CONTAINERS                     RESTARTS  AGE\n" +
		"k3p9x    app-01  running  r12       app, log-ship (init: migrate)  0         -\n" +
		"x7q2a    app-02  running  r12       app, log-ship                  0         -\n"
	if code != 0 || out != want {
		t.Errorf("replica list api: %d %q %q\nwant %q", code, out, stderr, want)
	}
	// Every app of the space, with its name; other spaces' apps left out.
	code, out, _ = cli("replica", "ls")
	if code != 0 || !strings.HasPrefix(out, "APP  REPLICA") || !strings.Contains(out, "api  k3p9x") || strings.Contains(out, "web") {
		t.Errorf("replica list: %d %q", code, out)
	}
	if code, out, _ = cli("replica", "list", "api", "-o", "json"); code != 0 || !strings.Contains(out, `"initContainers"`) {
		t.Errorf("json: %d %q", code, out)
	}
}

func TestAppRestart(t *testing.T) {
	f, cli := namesCLI(t)
	code, out, stderr := cli("app", "restart", "api")
	if code != 0 || out != "Restarting api as api--r13.\n" || len(f.restarted) != 1 || f.restarted[0] != "api" {
		t.Errorf("restart: %d %q %q %v", code, out, stderr, f.restarted)
	}
	if code, _, _ := cli("app", "restart", "api", "--space", "staging"); code != 0 || f.restarted[1] != "api.staging" {
		t.Errorf("restart in a space: %v", f.restarted)
	}
}

func TestSecretShowNamesTheSpaceSecrets(t *testing.T) {
	_, cli := namesCLI(t)
	code, _, stderr := cli("secret", "show", "dbb")
	if code == 0 || !strings.Contains(stderr, `space default has no secret "dbb"; its secrets: api, db, mail`) {
		t.Errorf("unknown secret: %d %q", code, stderr)
	}
}

func TestVerbHints(t *testing.T) {
	_, cli := namesCLI(t)
	code, _, stderr := cli("app", "scale", "api", "3")
	if code == 0 || !strings.Contains(stderr, `unknown command "scale"`) || !strings.Contains(stderr, "armada app deploy APP --min N") || strings.Contains(stderr, " 3") {
		t.Errorf("app scale: %d %q", code, stderr)
	}
}

func TestExecArgs(t *testing.T) {
	_, cli := namesCLI(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"app", "exec"}, "missing APP"},
		{[]string{"app", "exec", "api", "env", "SECRET=x"}, "put -- before the command"},
		{[]string{"app", "exec", "api", "web", "--", "env"}, "give one app before --"},
	} {
		code, _, stderr := cli(tc.args...)
		if code == 0 || !strings.Contains(stderr, tc.want) || strings.Contains(stderr, "SECRET=x") {
			t.Errorf("%v: %d %q", tc.args, code, stderr)
		}
	}
}

// complete runs cobra's completion request for args and returns the names.
func complete(t *testing.T, cfg string, args ...string) []string {
	t.Helper()
	code, out, stderr := run(t, append([]string{"__complete", "--config", cfg}, args...)...)
	if code != 0 {
		t.Fatalf("__complete %v: %d %q", args, code, stderr)
	}
	var names []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l != "" && !strings.HasPrefix(l, ":") {
			names = append(names, l)
		}
	}
	return names
}

func TestCompletion(t *testing.T) {
	_, cfg := namesFake(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"app", "show", ""}, "api worker"},
		{[]string{"app", "show", "w"}, "worker"},
		{[]string{"app", "exec", "api", "--replica", ""}, "k3p9x x7q2a"},
		{[]string{"app", "exec", "api", "--container", ""}, "app log-ship migrate"},
		{[]string{"app", "logs", "api", "--replica", "k"}, "k3p9x"},
		{[]string{"app", "rollback", "api", "--to", ""}, "r11 r12"},
		{[]string{"app", "traffic", "api", ""}, "r11= r12="},
		{[]string{"secret", "show", ""}, "api db mail"},
		{[]string{"secret", "unset", "db", ""}, "password url"},
		{[]string{"replica", "list", ""}, "api worker"},
		{[]string{"node", "drain", ""}, "app-01 app-02"},
		{[]string{"space", "use", ""}, "default"},
		{[]string{"app", "show", "api", ""}, ""},
		{[]string{"app", "exec", "api", "--", ""}, ""},
	} {
		if got := strings.Join(complete(t, cfg, tc.args...), " "); got != tc.want {
			t.Errorf("complete %v = %q, want %q", tc.args, got, tc.want)
		}
	}
}
