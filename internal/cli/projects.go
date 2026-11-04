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
		newProjectShowCommand(g),
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
	var isolation, quota string
	cmd := &cobra.Command{
		Use:   "create NAME [--isolation sandbox|container] [--quota Q]",
		Short: "Create a project",
		Long: "Create a project. Its replicas run in the sandbox (a userspace kernel) unless\n" +
			"an administrator gives --isolation container. --quota bounds what it may\n" +
			"reserve (administrators only; see armada project set).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			req := &armadav1.CreateProjectRequest{Name: args[0], Isolation: isolation}
			if quota != "" {
				if req.Quota, err = parseQuotaFlag(quota); err != nil {
					return err
				}
			}
			p, err := client.CreateProject(cmd.Context(), req)
			if err != nil {
				return rpcErr(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Project %s created (isolation %s); deploy into it with `armada deploy -f FILE --project %s`.\n", p.Name, p.Isolation, p.Name)
			return err
		},
	}
	cmd.Flags().StringVar(&isolation, "isolation", "", "kernel isolation level: sandbox (default) or container")
	cmd.Flags().StringVar(&quota, "quota", "", quotaHelp)
	return cmd
}

func newProjectSetCommand(g *globals) *cobra.Command {
	var networkIsolation bool
	var isolation, quota string
	cmd := &cobra.Command{
		Use:   "set NAME [--isolation sandbox|container] [--quota Q] [--network-isolation[=false]]",
		Short: "Change a project's settings",
		Long: "Change a project's settings (administrators only).\n\n" +
			"--isolation sets the kernel isolation level of the project's replicas:\n" +
			"sandbox runs each in a userspace kernel, only on nodes that run the sandbox;\n" +
			"container runs them on the node's kernel. Revisions deployed afterwards use\n" +
			"the new level: deploy each app again (the same spec is enough) to move it.\n" +
			"Revisions with a weaker level can no longer be rolled back to.\n\n" +
			"--quota replaces what the project may reserve, for example\n" +
			"cpu=4,memory=8Gi,replicas=20,volumes=4,domains=2,secrets=50,jobs=2: CPU and\n" +
			"memory are the sum of its replicas' reservations (an autoscaled app counts\n" +
			"its scale.max, a job one attempt), jobs the attempts that run at once. Keys\n" +
			"left out are unlimited; none removes the quota. Lowering it below what the\n" +
			"project uses keeps what runs and refuses only what would grow past it.\n" +
			"egress=100M limits the bits per second each replica may send; like the\n" +
			"isolation level, revisions deployed afterwards use it.\n\n" +
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
			if quota != "" {
				var err error
				if req.Quota, err = parseQuotaFlag(quota); err != nil {
					return err
				}
			}
			if req.NetworkIsolation == nil && isolation == "" && req.Quota == nil {
				return errors.New("nothing to change: give --isolation, --quota, or --network-isolation")
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
			msg := fmt.Sprintf("Project %s: isolation %s, network isolation %s, quota %s.\n", p.Name, p.Isolation, state, quotaOf(p.Quota))
			if isolation != "" {
				msg += "Apps already deployed keep their level until they are deployed again.\n"
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), msg)
			return err
		},
	}
	cmd.Flags().StringVar(&isolation, "isolation", "", "kernel isolation level: sandbox or container")
	cmd.Flags().StringVar(&quota, "quota", "", quotaHelp)
	cmd.Flags().BoolVar(&networkIsolation, "network-isolation", false, "keep the project's containers away from the platform and the private network")
	return cmd
}

func newProjectShowCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "show NAME",
		Short: "Show a project's settings and what it uses",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.ListProjects(cmd.Context(), &armadav1.ListProjectsRequest{})
			if err != nil {
				return rpcErr(err)
			}
			for _, p := range resp.Projects {
				if p.Name != args[0] {
					continue
				}
				network := "open"
				if p.NetworkIsolation {
					network = "isolated"
				}
				tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
				_, _ = fmt.Fprintf(tw, "Project:\t%s\nApps:\t%d\nIsolation:\t%s\nNetwork:\t%s\nCreated:\t%s by %s\n",
					p.Name, p.Apps, dash(p.Isolation), network, ago(p.CreatedAt, time.Now()), dash(p.CreatedBy))
				_, _ = fmt.Fprintln(tw, "\nRESOURCE\tUSED\tQUOTA")
				used, quota := quotaOf(p.Used), quotaOf(p.Quota)
				for _, row := range quotaRows(used, quota) {
					_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", row[0], row[1], row[2])
				}
				return tw.Flush()
			}
			return fmt.Errorf("no project %s (see armada project list)", args[0])
		},
	}
}
