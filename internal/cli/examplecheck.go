package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// ExampleProblems checks the command tree newRoot builds (ADR 0052): every
// runnable command has two to four examples, and every example line that
// runs the tree's program names a command, flags, and arguments that exist
// on a fresh tree. Lines that only run other programs (systemctl) and
// comment lines are allowed. Tests of both binaries call it.
func ExampleProblems(newRoot func() *cobra.Command) []string {
	var out []string
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		if !c.Runnable() || c.HasSubCommands() || c.Hidden || c.Name() == "help" || c.Root() == c {
			return
		}
		path := c.CommandPath()
		if strings.TrimSpace(c.Example) == "" {
			out = append(out, path+" has no examples")
			return
		}
		var cmds []string
		for _, line := range strings.Split(strings.ReplaceAll(c.Example, "\\\n", " "), "\n") {
			if !strings.HasPrefix(line, "  ") {
				out = append(out, fmt.Sprintf("%s: example %q is not indented by two spaces", path, line))
			}
			if !strings.HasPrefix(strings.TrimSpace(line), "#") {
				cmds = append(cmds, line)
			}
		}
		if len(cmds) > 4 {
			out = append(out, fmt.Sprintf("%s has %d examples; keep two to four", path, len(cmds)))
		}
		for _, line := range cmds {
			out = append(out, exampleProblems(newRoot, path, line)...)
		}
	}
	walk(newRoot())
	return out
}

// exampleProblems checks each part of an example line (split at &&, |,
// and ;) that runs the program, sudo and env assignments skipped.
func exampleProblems(newRoot func() *cobra.Command, path, line string) []string {
	var out []string
	name := newRoot().Name()
	if i := strings.Index(line, "#"); i >= 0 {
		line = line[:i]
	}
	for _, part := range strings.FieldsFunc(strings.ReplaceAll(line, "&&", ";"), func(r rune) bool { return r == ';' || r == '|' }) {
		words := shellWords(part)
		for len(words) > 0 && (words[0] == "sudo" || words[0] == "env" || strings.Contains(words[0], "=")) {
			words = words[1:]
		}
		if len(words) == 0 || words[0] != name {
			continue
		}
		root := newRoot()
		c, rest, err := root.Find(words[1:])
		switch {
		case err != nil:
			out = append(out, fmt.Sprintf("%s: example %q: %v", path, line, err))
		case c == root:
			out = append(out, fmt.Sprintf("%s: example %q runs no command", path, line))
		default:
			if err := c.ParseFlags(rest); err != nil {
				out = append(out, fmt.Sprintf("%s: example %q: %v", path, line, err))
			} else if err := c.ValidateArgs(c.Flags().Args()); err != nil {
				out = append(out, fmt.Sprintf("%s: example %q: %v", path, line, err))
			}
		}
	}
	return out
}

// shellWords splits a command like a shell would, as far as examples need:
// quotes, and a redirection ending the command.
func shellWords(line string) []string {
	var words []string
	var cur strings.Builder
	in, quote := false, rune(0)
	flush := func() {
		if in {
			words = append(words, cur.String())
			cur.Reset()
			in = false
		}
	}
	for _, r := range line {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			quote, in = r, true
		case (r == '<' || r == '>') && !in:
			flush()
			return words
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
			in = true
		}
	}
	flush()
	return words
}
