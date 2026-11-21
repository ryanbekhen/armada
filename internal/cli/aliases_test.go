package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Every list command answers to ls and every delete command to rm, no two
// sibling commands share a name or alias, and no command keeps an old verb
// (ADR 0032).
func TestCommandAliases(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		seen := map[string]string{}
		for _, sub := range c.Commands() {
			for _, n := range append([]string{sub.Name()}, sub.Aliases...) {
				if other, ok := seen[n]; ok {
					t.Errorf("%s: %q is used by both %s and %s", c.CommandPath(), n, other, sub.Name())
				}
				seen[n] = sub.Name()
			}
			switch sub.Name() {
			case "list":
				if !slices.Contains(sub.Aliases, "ls") {
					t.Errorf("%s has no ls alias", sub.CommandPath())
				}
			case "delete":
				if !slices.Contains(sub.Aliases, "rm") {
					t.Errorf("%s has no rm alias", sub.CommandPath())
				}
			case "remove", "add", "cordon", "uncordon", "open", "runs":
				t.Errorf("%s: old verb %s", sub.CommandPath(), sub.Name())
			}
			walk(sub)
		}
	}
	walk(NewRootCommand())

	for _, args := range [][]string{{"nodes", "ls"}, {"servers", "ls"}, {"domains", "ls"}, {"secrets", "ls"}, {"node", "rm"}, {"server", "delete"},
		{"apps", "ls"}, {"revision", "ls"}, {"run", "ls"}, {"node", "join-token"}} {
		c, _, err := NewRootCommand().Find(args)
		if err != nil || c.Name() == "armada" {
			t.Errorf("armada %v does not resolve: %v", args, err)
		}
	}
	// No noun holds nouns (ADR 0052): every command is NOUN VERB.
	for _, noun := range NewRootCommand().Commands() {
		for _, verb := range noun.Commands() {
			if verb.HasSubCommands() {
				t.Errorf("armada %s %s holds commands of its own", noun.Name(), verb.Name())
			}
		}
	}
	// The words before ADR 0052 are gone and fail, so a script notices.
	for _, args := range []string{"app create web", "app update web", "app revision list web", "job create j", "job update j",
		"job run j", "rbac user list", "alert channel list", "cluster set", "space set default", "volume snapshot list a v",
		"secret import api f"} {
		if code, _, stderr := run(t, strings.Fields(args)...); code != 1 || !strings.Contains(stderr, "unknown command") {
			t.Errorf("armada %s: code=%d stderr=%q", args, code, stderr)
		}
	}
	// The root holds only nouns and version.
	for _, c := range NewRootCommand().Commands() {
		if !c.HasSubCommands() && c.Name() != "version" && c.Name() != "help" && c.Name() != "completion" {
			t.Errorf("armada %s is not a noun", c.Name())
		}
	}
}
