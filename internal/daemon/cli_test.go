package daemon

import (
	"bytes"
	"context"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/cli"
)

// daemonCommands are the top-level commands of armadad; tests send every
// other command to the armada client.
var daemonCommands = []string{"version", "init", "agent", "join", "doctor", "backup", "restore", "runtime", "runtime-log", "upgrade"}

// isDaemon reports whether args name an armadad command: one of
// daemonCommands, `server` but for its list and remove, and `admin renew`
// with --data-dir.
func isDaemon(args []string) bool {
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--config" || a == "--project" {
			i++
			continue
		}
		if !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
		}
	}
	if len(pos) == 0 {
		return true
	}
	switch pos[0] {
	case "server", "servers":
		return len(pos) == 1 || !slices.Contains([]string{"list", "ls", "remove", "rm", "delete"}, pos[1])
	case "admin":
		return slices.Contains(args, "--data-dir")
	}
	return slices.Contains(daemonCommands, pos[0])
}

// execute runs args through armadad or armada, whichever has the command; a
// nil stdin means os.Stdin.
func execute(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if isDaemon(args) {
		return cli.Run(ctx, NewRootCommand(), args, stdin, stdout, stderr)
	}
	return cli.Run(ctx, cli.NewRootCommand(), args, stdin, stdout, stderr)
}

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = execute(context.Background(), args, nil, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestIsDaemon(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want bool
	}{
		{[]string{"server", "--data-dir", "d"}, true},
		{[]string{"server", "join", "a"}, true},
		{[]string{"server", "list", "--config", "c"}, false},
		{[]string{"--config", "c", "admin", "renew", "--data-dir", "d"}, true},
		{[]string{"admin", "renew", "--config", "c"}, false},
		{[]string{"deploy", "-f", "x", "--config", "c"}, false},
		{[]string{"runtime", "reset"}, true},
	} {
		if got := isDaemon(tt.args); got != tt.want {
			t.Errorf("isDaemon(%q) = %v, want %v", tt.args, got, tt.want)
		}
	}
}
