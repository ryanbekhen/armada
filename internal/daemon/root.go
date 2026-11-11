// Package daemon wires the armadad command tree: the services that run on
// every machine (control plane, agent, embedded runtime) and the commands that
// set a machine up or inspect it as root. The armada client is package cli.
package daemon

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/cli"
	"github.com/ryanbekhen/armada/internal/clientconfig"
)

// Name is the daemon binary's name.
const Name = "armadad"

// globals holds persistent flags shared by subcommands.
type globals struct {
	// configPath is the client config init writes and doctor and admin
	// renew read.
	configPath string
}

// NewRootCommand builds the armadad command tree.
func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   Name,
		Short: "Run and set up an Armada machine",
		Long: Name + " runs on every machine of an Armada cluster: the control plane\n" +
			"(`armadad server`), the node agent (`armadad agent`), and the embedded\n" +
			"container runtime (`armadad runtime`), each under systemd. It also sets a\n" +
			"machine up (init, join) and inspects it (doctor). It runs as root.\n" +
			"Manage apps with `armada`.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.CompletionOptions.HiddenDefaultCmd = true

	g := &globals{}
	cmd.PersistentFlags().StringVar(&g.configPath, "config", clientconfig.DefaultPath(), "client config with user credentials")

	cmd.AddCommand(
		cli.NewVersionCommand(),
		newInitCommand(g),
		newServerCommand(),
		newAgentCommand(),
		newJoinCommand(),
		newDoctorCommand(g),
		newUserCommand(g),
		newBackupCommand(),
		newRestoreCommand(),
		newRuntimeCommand(),
		newRuntimeLogCommand(),
		newUpgradeCommand(),
	)
	return cmd
}

// Execute runs the command tree with args and returns the process exit code.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return cli.Run(ctx, NewRootCommand(), args, nil, stdout, stderr)
}
