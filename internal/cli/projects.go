package cli

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

func newProjectCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "project",
		Aliases: []string{"projects"},
		Short:   "Manage projects",
		Long: "Projects hold apps, jobs, secrets, domains, and volumes (ADR 0029). Names only\n" +
			"need to be unique within a project. Every cluster has the project default,\n" +
			"which holds everything deployed without --project.\n\n" +
			"Other commands name an app of a project with --project (or ARMADA_PROJECT),\n" +
			"or as NAME.PROJECT, which is also how status, events, and the internal host\n" +
			"name (NAME.PROJECT.internal) show it.",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "create NAME",
			Short: "Create a project",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				client, conn, err := dialAdmin(g)
				if err != nil {
					return err
				}
				defer conn.Close()
				if _, err := client.CreateProject(cmd.Context(), &armadav1.CreateProjectRequest{Name: args[0]}); err != nil {
					return rpcErr(err)
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Project %s created; deploy into it with `armada deploy -f FILE --project %s`.\n", args[0], args[0])
				return err
			},
		},
		&cobra.Command{
			Use:     "list",
			Aliases: []string{"ls"},
			Short:   "List projects",
			Args:    cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				client, conn, err := dialAdmin(g)
				if err != nil {
					return err
				}
				defer conn.Close()
				resp, err := client.ListProjects(cmd.Context(), &armadav1.ListProjectsRequest{})
				if err != nil {
					return rpcErr(err)
				}
				tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
				_, _ = fmt.Fprintln(tw, "PROJECT\tAPPS\tCREATED\tBY")
				now := time.Now()
				for _, p := range resp.Projects {
					_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", p.Name, p.Apps, ago(p.CreatedAt, now), dash(p.CreatedBy))
				}
				return tw.Flush()
			},
		},
		&cobra.Command{
			Use:     "remove NAME",
			Aliases: []string{"rm", "delete"},
			Short:   "Remove an empty project",
			Long: "Remove a project. It must be empty: remove its jobs, secrets, and volumes\n" +
				"first. The default project cannot be removed.",
			Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				client, conn, err := dialAdmin(g)
				if err != nil {
					return err
				}
				defer conn.Close()
				if _, err := client.DeleteProject(cmd.Context(), &armadav1.DeleteProjectRequest{Name: args[0]}); err != nil {
					return rpcErr(err)
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Project %s removed.\n", args[0])
				return err
			},
		},
	)
	return cmd
}
