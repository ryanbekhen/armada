// Package cli wires the armada command tree: the client that talks to the
// control plane. Commands that run on a machine as root are in package daemon
// (the armadad binary).
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
		Short: "Manage apps on an Armada cluster",
		Long: version.Name + " manages apps on an Armada cluster: deploys, revisions, rolling\n" +
			"updates, domains, secrets, and jobs. It talks to the control plane with the\n" +
			"credentials in --config and needs no root. Machines run `armadad`.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.CompletionOptions.HiddenDefaultCmd = true

	g := &globals{}
	cmd.PersistentFlags().StringVar(&g.configPath, "config", clientconfig.DefaultPath(), "client config with admin credentials (default ~/.armada/config, else /etc/armada/admin.config)")
	cmd.PersistentFlags().StringVar(&g.project, "project", os.Getenv("ARMADA_PROJECT"),
		"project of the apps and jobs a command names (ADR 0026; or ARMADA_PROJECT); without it, names are in the default project and listings show every project")

	cmd.AddCommand(
		NewVersionCommand(),
		newServerCommand(g),
		newDeployCommand(g),
		newStatusCommand(g),
		newScaleCommand(g),
		newTrafficCommand(g),
		newLogsCommand(g),
		newTopCommand(g),
		newEventsCommand(g),
		newAppCommand(g),
		newAdminCommand(g),
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
		newNodeCommand(g),
	)
	return cmd
}

// Execute runs the command tree with args and returns the process exit code.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return Run(ctx, NewRootCommand(), args, nil, stdout, stderr)
}

// Run runs a command tree with args and returns the process exit code; a nil
// stdin means os.Stdin. armadad runs its own tree through it.
func Run(ctx context.Context, cmd *cobra.Command, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
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
