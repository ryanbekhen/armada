package daemon

import (
	"testing"

	"github.com/ryanbekhen/armada/internal/cli"
)

// Every armadad command opens its help with examples that run (ADR 0052).
func TestEveryCommandHasExamples(t *testing.T) {
	for _, p := range cli.ExampleProblems(NewRootCommand) {
		t.Error(p)
	}
}
