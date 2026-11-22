package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

// Every command opens its help with examples that run (ADR 0052).
func TestEveryCommandHasExamples(t *testing.T) {
	for _, p := range ExampleProblems(NewRootCommand) {
		t.Error(p)
	}
}

func TestExampleProblemsCatchesMistakes(t *testing.T) {
	root := func() *cobra.Command {
		r := &cobra.Command{Use: "armada"}
		r.AddCommand(&cobra.Command{Use: "show APP", Args: cobra.ExactArgs(1), Run: func(*cobra.Command, []string) {},
			Example: "  armada show api --nope\n  armada show\n  armada gone x\n  armada show api   # fine"})
		return r
	}
	got := ExampleProblems(root)
	if len(got) != 3 {
		t.Errorf("problems = %q", got)
	}
}
