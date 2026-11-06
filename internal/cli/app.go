package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

func newAppCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "app",
		Short: "Manage apps",
	}
	cmd.AddCommand(newAppRemoveCommand(g))
	return cmd
}

func newAppRemoveCommand(g *globals) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "remove APP --yes",
		Aliases: []string{"rm", "delete"},
		Short:   "Stop an app's replicas and remove it with its revisions and secrets",
		Long: "Stops serving the app, drains its replicas, and removes it with its revisions and\n" +
			"secrets. This cannot be undone. Its volumes and their data stay until\n" +
			"`armada volume rm`, and deploying the same name again finds them.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			if !yes {
				return fmt.Errorf("this removes app %s with its revisions and secrets; pass --yes to confirm", args[0])
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.RemoveApp(cmd.Context(), &armadav1.RemoveAppRequest{App: args[0]}); err != nil {
				return rpcErr(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Removing app %s: it is gone once its replicas have drained\n", args[0])
			return err
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm removing the app")
	return cmd
}
