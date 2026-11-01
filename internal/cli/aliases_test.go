package cli

import (
	"slices"
	"testing"

	"github.com/spf13/cobra"
)

// Every list command answers to ls and every remove command to rm and
// delete, and no two sibling commands share a name or alias.
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
			case "remove", "rm":
				for _, want := range []string{"rm", "remove", "delete"} {
					if want != sub.Name() && !slices.Contains(sub.Aliases, want) {
						t.Errorf("%s has no %s alias", sub.CommandPath(), want)
					}
				}
			}
			walk(sub)
		}
	}
	walk(NewRootCommand())

	for _, args := range [][]string{{"nodes", "ls"}, {"servers", "ls"}, {"domains", "ls"}, {"secrets", "ls"}, {"node", "rm"}, {"server", "delete"}, {"tokens", "create"}} {
		c, _, err := NewRootCommand().Find(args)
		if err != nil || c.Name() == "armada" {
			t.Errorf("armada %v does not resolve: %v", args, err)
		}
	}
}
