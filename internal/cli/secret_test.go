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
