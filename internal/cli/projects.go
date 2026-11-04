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
			"Every project has a kernel isolation level: replicas of sandbox projects run\n" +
			"in a userspace kernel, only on nodes that run the sandbox (the SANDBOX column\n" +
			"of `armada node list`); container runs them on the node's kernel. New projects\n" +
			"get sandbox, default has container; change it with `armada project set`.\n\n" +
			"On a cluster with a cluster network, containers reach other apps only\n" +
			"through their internal names, resolve only their own project's names, and\n" +
			"the containers of every project but default are kept away from the nodes,\n" +
			"the private network, and the cloud's metadata service (network isolation;\n" +
			"for default, turn it on with `armada project set default --network-isolation`).",
	}
	cmd.AddCommand(
		newProjectCreateCommand(g),
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
				_, _ = fmt.Fprintln(tw, "PROJECT\tAPPS\tISOLATION\tNETWORK\tCREATED\tBY")
				now := time.Now()
				for _, p := range resp.Projects {
					network := "open"
					if p.NetworkIsolation {
						network = "isolated"
					}
					_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n", p.Name, p.Apps, dash(p.Isolation), network, ago(p.CreatedAt, now), dash(p.CreatedBy))
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

func newProjectCreateCommand(g *globals) *cobra.Command {
	var isolation string
	cmd := &cobra.Command{
		Use:   "create NAME [--isolation sandbox|container]",
		Short: "Create a project",
		Long: "Create a project. Its replicas run in the sandbox (a userspace kernel) unless\n" +
			"an administrator gives --isolation container.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			p, err := client.CreateProject(cmd.Context(), &armadav1.CreateProjectRequest{Name: args[0], Isolation: isolation})
			if err != nil {
				return rpcErr(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Project %s created (isolation %s); deploy into it with `armada deploy -f FILE --project %s`.\n", p.Name, p.Isolation, p.Name)
			return err
		},
	}
	cmd.Flags().StringVar(&isolation, "isolation", "", "kernel isolation level: sandbox (default) or container")
	return cmd
}

func newProjectSetCommand(g *globals) *cobra.Command {
	var networkIsolation bool
	var isolation string
	cmd := &cobra.Command{
		Use:   "set NAME [--isolation sandbox|container] [--network-isolation[=false]]",
		Short: "Change a project's settings",
		Long: "Change a project's settings (administrators only).\n\n" +
			"--isolation sets the kernel isolation level of the project's replicas:\n" +
			"sandbox runs each in a userspace kernel, only on nodes that run the sandbox;\n" +
			"container runs them on the node's kernel. Revisions deployed afterwards use\n" +
			"the new level: deploy each app again (the same spec is enough) to move it.\n" +
			"Revisions with a weaker level can no longer be rolled back to.\n\n" +
			"--network-isolation keeps the project's containers away from the nodes, the\n" +
			"control plane, the private network, and the cloud's metadata service: they\n" +
			"reach the internet, their node's DNS server, and internal and public\n" +
			"ingress (ADR 0029). Every project but default always has it; turn it on for\n" +
			"default once its apps no longer need the private network. It needs the\n" +
			"cluster network.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &armadav1.UpdateProjectRequest{Name: args[0], Isolation: isolation}
			if cmd.Flags().Changed("network-isolation") {
				req.NetworkIsolation = &networkIsolation
			}
			if req.NetworkIsolation == nil && isolation == "" {
				return errors.New("nothing to change: give --isolation or --network-isolation")
			}
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
			msg := fmt.Sprintf("Project %s: isolation %s, network isolation %s.\n", p.Name, p.Isolation, state)
			if isolation != "" {
				msg += "Apps already deployed keep their level until they are deployed again.\n"
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), msg)
			return err
		},
	}
	cmd.Flags().StringVar(&isolation, "isolation", "", "kernel isolation level: sandbox or container")
	cmd.Flags().BoolVar(&networkIsolation, "network-isolation", false, "keep the project's containers away from the platform and the private network")
	return cmd
}
