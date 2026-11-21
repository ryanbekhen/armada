package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// moved says on stderr, never stdout, that a command a script may still run
// has a new form (ADR 0052). The old form keeps its arguments, output, and
// exit code until 1.0.
func moved(cmd *cobra.Command, old, now string) {
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "note: %q is now %q\n", old, now)
}
