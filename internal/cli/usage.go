package cli

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

// explain makes a command tree say what a person got wrong: argument errors
// name the missing or extra argument and print the command's usage, flag
// errors point to --help, and the list of a noun's verbs shows the arguments
// each verb takes (`list APP`), not only its name.
func explain(root *cobra.Command) {
	root.SetUsageFunc(usage)
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return fmt.Errorf("%w\nRun '%s --help' for its flags", err, c.CommandPath())
	})
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		if c.Args != nil {
			c.Args = explainArgs(c.Args)
		}
	}
	walk(root)
}

// cobraArgError matches the messages of cobra's own argument validators
// (ExactArgs, MinimumNArgs, MaximumNArgs, RangeArgs, NoArgs); messages of
// Armada's own validators already say what is wrong and are kept.
var cobraArgError = regexp.MustCompile(`^(accepts (\d+|at most \d+|between \d+ and \d+) arg\(s\), received \d+|requires at least \d+ arg\(s\), only received \d+|unknown command ".*" for ".*")$`)

func explainArgs(check cobra.PositionalArgs) cobra.PositionalArgs {
	return func(c *cobra.Command, args []string) error {
		err := check(c, args)
		if err == nil || !cobraArgError.MatchString(err.Error()) {
			return err
		}
		return argError(c, args)
	}
}

// argError says which arguments are missing, or how many there are too
// many, from the placeholders in the command's Use line. It never repeats an
// argument: a secret typed as one would end up in the error.
func argError(c *cobra.Command, args []string) error {
	words := argWords(c)
	var required []string
	variadic := false
	for _, w := range words {
		if strings.HasSuffix(w, "...") || strings.HasSuffix(w, "...]") {
			variadic = true
		}
		if !strings.HasPrefix(w, "[") {
			required = append(required, w)
		}
	}
	var msg string
	switch {
	case len(args) < len(required):
		msg = "missing " + strings.Join(required[len(args):], " ")
	case len(words) == 0:
		msg = fmt.Sprintf("%s takes no arguments, got %d", c.CommandPath(), len(args))
	case !variadic && len(args) > len(words):
		msg = fmt.Sprintf("too many arguments: expected %s, got %d", strings.Join(words, " "), len(args))
	default:
		msg = fmt.Sprintf("wrong number of arguments (%d)", len(args))
	}
	return errors.New(msg + "\nUsage: " + c.UseLine() + "\nRun '" + c.CommandPath() + " --help' for more")
}

// argWord is a placeholder in a Use line: APP, KEY=VALUE..., IP|none, or one
// in brackets when optional ([APP]).
var argWord = regexp.MustCompile(`^\[?[A-Z][A-Za-z0-9_=|.]*\]?$`)

// argWords returns the leading placeholders of the command's Use line, up to
// the first flag, group, or alternative.
func argWords(c *cobra.Command) []string {
	fields := strings.Fields(c.Use)
	var words []string
	for _, f := range fields[min(1, len(fields)):] {
		if !argWord.MatchString(f) {
			break
		}
		words = append(words, f)
	}
	return words
}

// verbLine is a verb with its arguments, as the list of a noun's verbs shows it.
func verbLine(c *cobra.Command) string {
	return strings.TrimSpace(c.Name() + " " + strings.Join(argWords(c), " "))
}

// usage is cobra's default usage with each verb listed with its arguments.
func usage(c *cobra.Command) error {
	w := c.OutOrStderr()
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	p("Usage:")
	if c.Runnable() && !c.HasAvailableSubCommands() {
		p("\n  %s", c.UseLine())
	}
	if c.HasAvailableSubCommands() {
		p("\n  %s [command]", c.CommandPath())
	}
	if len(c.Aliases) > 0 {
		p("\n\nAliases:\n  %s", c.NameAndAliases())
	}
	if c.HasExample() {
		p("\n\nExamples:\n%s", c.Example)
	}
	if c.HasAvailableSubCommands() && len(c.Groups()) > 0 {
		listGroups(w, c)
	} else if c.HasAvailableSubCommands() {
		p("\n\nAvailable Commands:")
		listVerbs(w, c)
	}
	if c.HasAvailableLocalFlags() {
		p("\n\nFlags:\n%s", strings.TrimRight(c.LocalFlags().FlagUsages(), " \n"))
	}
	if c.HasAvailableInheritedFlags() {
		p("\n\nGlobal Flags:\n%s", strings.TrimRight(c.InheritedFlags().FlagUsages(), " \n"))
	}
	if c.HasAvailableSubCommands() {
		p("\n\nUse \"%s [command] --help\" for more information about a command.", c.CommandPath())
	}
	p("\n")
	return nil
}

func listVerbs(w io.Writer, c *cobra.Command) {
	var subs []*cobra.Command
	width := 0
	for _, sub := range c.Commands() {
		if sub.IsAvailableCommand() || sub.Name() == "help" {
			subs = append(subs, sub)
			width = max(width, len(verbLine(sub)))
		}
	}
	for _, sub := range subs {
		_, _ = fmt.Fprintf(w, "\n  %-*s  %s", width, verbLine(sub), sub.Short)
	}
}

// listGroups lists the root's nouns under their groups (ADR 0052).
func listGroups(w io.Writer, c *cobra.Command) {
	width := 0
	for _, sub := range c.Commands() {
		width = max(width, len(sub.Name()))
	}
	for _, g := range c.Groups() {
		_, _ = fmt.Fprintf(w, "\n\n%s", g.Title)
		for _, sub := range c.Commands() {
			if sub.GroupID == g.ID && (sub.IsAvailableCommand() || sub.Name() == "help") {
				_, _ = fmt.Fprintf(w, "\n  %-*s  %s", width, sub.Name(), sub.Short)
			}
		}
	}
}
