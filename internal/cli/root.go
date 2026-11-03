// Package cli wires the armada command tree.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/version"
)

// globals holds persistent flags shared by subcommands.
type globals struct {
	configPath string
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
		newJobCommand(g),
		newVolumeCommand(g),
		newMetricsCommand(g),
		newExecCommand(g),
		newRollbackCommand(g),
		newRevisionsCommand(g),
		newClusterCommand(g),
		newDomainCommand(g),
		newSecretCommand(g),
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
