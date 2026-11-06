// Package cli wires the armada command tree.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/version"
)

// globals holds persistent flags shared by subcommands.
type globals struct {
	configPath string
	// project is --project: the project whose apps a command names
	// (ADR 0026). Empty names apps of the default project and lists every
	// project.
	project string
}

// app returns the ID of app name in --project. name may already be an ID
// (web.staging) as long as --project does not name another project.
func (g *globals) app(name string) (string, error) {
	if g.project != "" && !spec.ValidProject(g.project) {
		return "", fmt.Errorf("invalid project %q", g.project)
	}
	if strings.Contains(name, ".") {
		p, _, ok := spec.SplitAppID(name)
		if !ok {
			return "", fmt.Errorf("invalid app %q: want NAME, or NAME.PROJECT for an app of another project", name)
		}
		if g.project != "" && g.project != p {
			return "", fmt.Errorf("%s belongs to project %s, not %s", name, p, g.project)
		}
		return name, nil
	}
	return spec.AppID(g.project, name), nil
}

// qualify replaces args[0], an app or job name, with its ID (see app).
func (g *globals) qualify(args []string) error {
	if len(args) == 0 {
		return nil
	}
	id, err := g.app(args[0])
	if err != nil {
		return err
	}
	args[0] = id
	return nil
}

// listed reports whether a listing shows the app with ID id: every app
// without --project, else only the project's.
func (g *globals) listed(id string) bool {
	if g.project == "" {
		return true
	}
	p, _, ok := spec.SplitAppID(id)
	return ok && p == g.project
}

// NewRootCommand builds the full command tree. Output goes to the writers
// configured on the returned command so tests can capture it.
func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   version.Name,
		Short: "Self-hosted container platform for a handful of machines",
		Long: version.Name + " turns a few machines into a container platform: apps, revisions,\n" +
			"rolling updates, domains, and automatic TLS.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.CompletionOptions.HiddenDefaultCmd = true

	g := &globals{}
	cmd.PersistentFlags().StringVar(&g.configPath, "config", clientconfig.DefaultPath(), "client config with admin credentials")
	cmd.PersistentFlags().StringVar(&g.project, "project", os.Getenv("ARMADA_PROJECT"),
		"project of the apps and jobs a command names (ADR 0026; or ARMADA_PROJECT); without it, names are in the default project and listings show every project")

	cmd.AddCommand(
		newVersionCommand(),
		newInitCommand(g),
		newServerCommand(g),
		newAgentCommand(),
		newDeployCommand(g),
		newStatusCommand(g),
		newScaleCommand(g),
		newTrafficCommand(g),
		newLogsCommand(g),
		newTopCommand(g),
		newEventsCommand(g),
		newAppCommand(g),
		newJobCommand(g),
		newVolumeCommand(g),
		newMetricsCommand(g),
		newExecCommand(g),
		newRollbackCommand(g),
		newRevisionsCommand(g),
		newClusterCommand(g),
		newDomainCommand(g),
		newSecretCommand(g),
		newProjectCommand(g),
		newAutomationCommand(g),
		newTokenCommand(g),
		newJoinCommand(),
		newNodeCommand(g),
		newDoctorCommand(),
		newBackupCommand(),
		newRestoreCommand(),
		newRuntimeCommand(),
		newRuntimeLogCommand(),
	)
	return cmd
}

// Execute runs the command tree with args and returns the process exit code.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return execute(ctx, args, nil, stdout, stderr)
}

// execute runs the command tree; a nil stdin means os.Stdin.
func execute(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cmd := NewRootCommand()
	cmd.SetArgs(args)
	if stdin != nil {
		cmd.SetIn(stdin)
	}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	if err := cmd.ExecuteContext(ctx); err != nil {
		var code exitCodeError
		if errors.As(err, &code) {
			return int(code)
		}
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}
