package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/version"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Execute(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVersionText(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := run(t, "version")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	if want := version.Get().String() + "\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
}

func TestVersionJSON(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"version", "--output", "json"},
		{"version", "-o", "json"},
	} {
		code, stdout, stderr := run(t, args...)
		if code != 0 {
			t.Fatalf("%v: exit code = %d, stderr = %q", args, code, stderr)
		}

		var got version.Info
		dec := json.NewDecoder(strings.NewReader(stdout))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("%v: invalid JSON %q: %v", args, stdout, err)
		}
		if want := version.Get(); got != want {
			t.Errorf("%v: decoded = %+v, want %+v", args, got, want)
		}
	}
}

func TestVersionRejectsBadInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"unknown output format", []string{"version", "-o", "yaml"}, `unsupported output format "yaml"`},
		{"positional argument", []string{"version", "extra"}, `unknown command "extra"`},
		{"unknown flag", []string{"version", "--nope"}, "unknown flag: --nope"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code, stdout, stderr := run(t, tt.args...)
			if code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantErr)
			}
		})
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Parallel()

	code, _, stderr := run(t, "deploy-everything")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, `unknown command "deploy-everything"`) {
		t.Errorf("stderr = %q, want unknown command error", stderr)
	}
}

func TestHelp(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := run(t, "--help")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	for _, want := range []string{version.Name, "version", "Print build information"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("help output missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "completion ") {
		t.Errorf("completion command should be hidden from help:\n%s", stdout)
	}
}

func TestFlagStateDoesNotLeak(t *testing.T) {
	t.Parallel()

	// Each Execute builds a fresh tree, so a flag set in one invocation must
	// not affect the next one.
	if code, _, stderr := run(t, "version", "-o", "json"); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	_, stdout, _ := run(t, "version")
	if strings.HasPrefix(strings.TrimSpace(stdout), "{") {
		t.Errorf("second invocation reused json output: %q", stdout)
	}
}

func TestExecUsage(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"exec", "web"},
		{"exec", "web", "sh"},            // no --
		{"exec", "--", "sh"},             // no app
		{"exec", "web", "x", "--", "sh"}, // two args before --
		{"exec", "web", "--", "a\x00b"},  // NUL byte
	} {
		code, _, stderr := run(t, args...)
		if code != 1 || stderr == "" || strings.Contains(stderr, "a\x00b") {
			t.Errorf("%q: code=%d stderr=%q", args, code, stderr)
		}
	}
}

func TestVolumeUsage(t *testing.T) {
	t.Parallel()
	for args, want := range map[string]string{
		"volume rm web data":      "--yes",
		"volume backup web data":  "-o FILE",
		"volume restore web data": "accepts 3 arg",
		"volume ls a b":           "accepts at most 1 arg",
		"volume rm web":           "accepts 2 arg",
	} {
		code, _, stderr := run(t, strings.Fields(args)...)
		if code != 1 || !strings.Contains(stderr, want) {
			t.Errorf("%q: code=%d stderr=%q", args, code, stderr)
		}
	}
}

func TestDiskBytes(t *testing.T) {
	t.Parallel()
	for b, want := range map[int64]string{0: "0B", 13: "13B", 1024: "1.0Ki", 1536: "1.5Ki", 5 << 20: "5.0Mi", 3 << 30: "3.0Gi", 2 << 40: "2.0Ti"} {
		if got := diskBytes(b); got != want {
			t.Errorf("diskBytes(%d) = %q, want %q", b, got, want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	t.Parallel()

	for in, want := range map[int64]string{0: "-", 512 << 20: "512Mi", 2 << 30: "2.0Gi"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q", in, got)
		}
	}
}

// TestClientDependencies keeps the client free of what only a machine needs
// (ADR 0027): it must stay small and build for every system it supports.
func TestClientDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/ryanbekhen/armada/cmd/armada").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, banned := range []string{
			"github.com/ryanbekhen/armada/internal/daemon",
			"github.com/ryanbekhen/armada/internal/agent",
			"github.com/ryanbekhen/armada/internal/server",
			"github.com/ryanbekhen/armada/internal/store",
			"github.com/ryanbekhen/armada/internal/etcd",
			"github.com/ryanbekhen/armada/internal/clusternet",
			"github.com/ryanbekhen/armada/internal/runtime/",
			"github.com/ryanbekhen/armada/internal/proxy",
			"go.etcd.io/etcd/server",
			"github.com/containerd/",
		} {
			if strings.HasPrefix(dep, banned) {
				t.Errorf("the armada client depends on %s", dep)
			}
		}
	}
}

func TestInstallCommand(t *testing.T) {
	pinned := installCommand("v0.1.0-alpha.2")
	if want := "curl -fsSL " + InstallURL + " | sudo ARMADA_VERSION=v0.1.0-alpha.2 sh"; pinned != want {
		t.Fatalf("got %q, want %q", pinned, want)
	}
	for _, v := range []string{"", "dev", "v0.1.0-3-gabc;id", "(devel)"} {
		if got := installCommand(v); strings.Contains(got, "ARMADA_VERSION") {
			t.Errorf("version %q pinned: %q", v, got)
		}
	}
}
