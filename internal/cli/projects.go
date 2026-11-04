package cli

import (
	"errors"
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
			"name (NAME.PROJECT.internal) show it.\n\n" +
			"On a cluster with a cluster network, containers reach other apps only\n" +
			"through their internal names, resolve only their own project's names, and\n" +
			"the containers of every project but default are kept away from the nodes,\n" +
			"the private network, and the cloud's metadata service (network isolation;\n" +
			"for default, turn it on with `armada project set default --network-isolation`).",
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
				_, _ = fmt.Fprintln(tw, "PROJECT\tAPPS\tISOLATED\tCREATED\tBY")
				now := time.Now()
				for _, p := range resp.Projects {
					_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", p.Name, p.Apps, yesNo(p.NetworkIsolation), ago(p.CreatedAt, now), dash(p.CreatedBy))
				}
				return tw.Flush()
			},
		},
		newProjectSetCommand(g),
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

func newProjectSetCommand(g *globals) *cobra.Command {
	var isolation bool
	cmd := &cobra.Command{
		Use:   "set NAME --network-isolation[=false]",
		Short: "Change a project's settings",
		Long: "Change a project's settings (administrators only).\n\n" +
			"--network-isolation keeps the project's containers away from the nodes, the\n" +
			"control plane, the private network, and the cloud's metadata service: they\n" +
			"reach the internet, their node's DNS server, and internal and public\n" +
			"ingress (ADR 0029). Every project but default always has it; turn it on for\n" +
			"default once its apps no longer need the private network. It needs the\n" +
			"cluster network.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &armadav1.UpdateProjectRequest{Name: args[0]}
			if !cmd.Flags().Changed("network-isolation") {
				return errors.New("nothing to change: give --network-isolation or --network-isolation=false")
			}
			req.NetworkIsolation = &isolation
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			p, err := client.UpdateProject(cmd.Context(), req)
			if err != nil {
				return rpcErr(err)
			}
			state := "off"
			if p.NetworkIsolation {
				state = "on"
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Project %s: network isolation %s.\n", p.Name, state)
			return err
		},
	}
	cmd.Flags().BoolVar(&isolation, "network-isolation", false, "keep the project's containers away from the platform and the private network")
	return cmd
}
