package cli

import (
	"bytes"
	"context"
	"encoding/json"
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
