package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestSecretValueFromTerminal(t *testing.T) {
	orig := readTerminalSecret
	t.Cleanup(func() { readTerminalSecret = orig })
	readTerminalSecret = func(*cobra.Command) ([]byte, error) { return []byte("typed\n"), nil }
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("piped"))
	b, err := ReadSecretValue(cmd, "")
	// Hidden prompt input is kept as typed (ReadPassword strips the Enter).
	if err != nil || string(b) != "typed\n" {
		t.Errorf("terminal value = %q, %v", b, err)
	}
	readTerminalSecret = func(*cobra.Command) ([]byte, error) { return nil, errNotTerminal }
	cmd.SetIn(strings.NewReader("piped\r\n"))
	if b, err := ReadSecretValue(cmd, ""); err != nil || string(b) != "piped" {
		t.Errorf("piped value = %q, %v", b, err)
	}
}

func TestRevisionRuns(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		app  string
		in   []string
		want string
	}{
		{"api", nil, "-"},
		{"api", []string{"api--r20", "api--r19", "api--r18", "api--r17", "api--r11", "api--r12", "api--r13", "api--r14", "api--r15", "api--r16"}, "r11-r20"},
		{"api", []string{"api--r3"}, "r3"},
		{"api", []string{"api--r3", "api--r4", "api--r7", "api--r9", "api--r10", "api--r11"}, "r3,r4,r7,r9-r11"},
		{"web.shop", []string{"web.shop--r2", "web.shop--r1"}, "r1,r2"},
		{"api", []string{"api--r2", "other--r1"}, "api--r2,other--r1"},
		{"api", []string{"api--rx"}, "api--rx"},
	} {
		if got := revisionRuns(c.app, c.in); got != c.want {
			t.Errorf("revisionRuns(%q, %q) = %q, want %q", c.app, c.in, got, c.want)
		}
	}
}
