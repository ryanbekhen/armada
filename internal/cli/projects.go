package cli

import (
	"errors"
	"fmt"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/spec"
)

func newProjectCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "project",
		Aliases: []string{"projects"},
		Short:   "Manage projects",
		Long: "Projects hold apps, jobs, secrets, domains, and volumes (ADR 0026). Names only\n" +
			"need to be unique within a project. Every cluster has the project default,\n" +
			"which holds everything deployed without --project.\n\n" +
			"Commands work in the project `armada project use` saved, or the one --project\n" +
			"(or ARMADA_PROJECT) names, else default. An app of another project can also\n" +
			"be named NAME.PROJECT, which is how events and the internal host name\n" +
			"(NAME.PROJECT.internal) show it. Lists take -A for every project.\n\n" +
			"On a cluster with a cluster network, containers reach other apps only\n" +
			"through their internal names, resolve only their own project's names, and\n" +
			"the containers of every project but default are kept away from the nodes,\n" +
			"the private network, and the cloud's metadata service (network isolation;\n" +
			"for default, turn it on with `armada project set default --network-isolation`).",
	}
	cmd.AddCommand(
		newProjectCreateCommand(g),
		newProjectListCommand(g),
		newProjectSetCommand(g),
		newProjectShowCommand(g),
		newProjectUseCommand(g),
		&cobra.Command{
			Use:     "delete NAME",
			Aliases: []string{"rm"},
			Short:   "Delete an empty project",
			Long: "Delete a project. It must be empty: delete its apps, jobs, secrets, and\n" +
				"volumes first. The default project cannot be deleted.",
			Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				client, conn, err := dialAdmin(g)
				if err != nil {
					return err
				}
				defer conn.Close()
				if _, err := client.DeleteProject(cmd.Context(), &armadav1.DeleteProjectRequest{Name: args[0]}); err != nil {
					return RPCError(err)
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Deleted project %s.\n", args[0])
				return err
			},
		},
	)
	return cmd
}

func newProjectCreateCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "create NAME",
		Short: "Create a project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			p, err := client.CreateProject(cmd.Context(), &armadav1.CreateProjectRequest{Name: args[0]})
			if err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Created project %s.\n", p.Name)
			return err
		},
	}
}

func newProjectSetCommand(g *globals) *cobra.Command {
	var networkIsolation bool
	cmd := &cobra.Command{
		Use:   "set NAME --network-isolation[=false]",
		Short: "Change a project's settings",
		Long: "Change a project's settings (cluster-admin only).\n\n" +
			"--network-isolation keeps the project's containers away from the nodes, the\n" +
			"control plane, the private network, and the cloud's metadata service: they\n" +
			"reach the internet, their node's DNS server, and internal and public\n" +
			"ingress (ADR 0026). Every project but default always has it; turn it on for\n" +
			"default once its apps no longer need the private network. It needs the\n" +
			"cluster network.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &armadav1.UpdateProjectRequest{Name: args[0]}
			if cmd.Flags().Changed("network-isolation") {
				req.NetworkIsolation = &networkIsolation
			}
			if req.NetworkIsolation == nil {
				return errors.New("nothing to change: give --network-isolation")
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			p, err := client.UpdateProject(cmd.Context(), req)
			if err != nil {
				return RPCError(err)
			}
			state := "off"
			if p.NetworkIsolation {
				state = "on"
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Project %s: network isolation %s.\n", p.Name, state)
			return err
		},
	}
	cmd.Flags().BoolVar(&networkIsolation, "network-isolation", false, "keep the project's containers away from the platform and the private network")
	return cmd
}

func newProjectListCommand(g *globals) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List projects",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.check(); err != nil {
				return err
			}
			resp, err := listProjects(cmd, g)
			if err != nil {
				return err
			}
			if o.json() {
				return printJSON(cmd.OutOrStdout(), resp)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "PROJECT\tAPPS\tNETWORK\tCREATED\tBY")
			now := time.Now()
			for _, p := range resp.Projects {
				_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", p.Name, p.Apps, projectNetwork(p), ago(p.CreatedAt, now), dash(p.CreatedBy))
			}
			return tw.Flush()
		},
	}
	o = addOutput(cmd, false)
	return cmd
}

func listProjects(cmd *cobra.Command, g *globals) (*armadav1.ListProjectsResponse, error) {
	client, conn, err := dialAdmin(g)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	resp, err := client.ListProjects(cmd.Context(), &armadav1.ListProjectsRequest{})
	if err != nil {
		return nil, RPCError(err)
	}
	return resp, nil
}

func projectNetwork(p *armadav1.ProjectInfo) string {
	if p.NetworkIsolation {
		return "isolated"
	}
	return "open"
}

func newProjectUseCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "use NAME",
		Short: "Work in a project: commands without --project use it",
		Long: "Save NAME in the client config (--config) as the project commands work in when\n" +
			"neither --project nor ARMADA_PROJECT names one. `armada project use default`\n" +
			"goes back to the default project.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if !spec.ValidProject(name) {
				return fmt.Errorf("invalid project %q", name)
			}
			if name != spec.DefaultProject {
				resp, err := listProjects(cmd, g)
				if err != nil {
					return err
				}
				if !slices.ContainsFunc(resp.Projects, func(p *armadav1.ProjectInfo) bool { return p.Name == name }) {
					return fmt.Errorf("project %s not found", name)
				}
			}
			cc, err := clientconfig.Load(g.configPath)
			if err != nil {
				return err
			}
			cc.Project = name
			if name == spec.DefaultProject {
				cc.Project = ""
			}
			if err := cc.SaveFile(g.configPath); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Using project %s.\n", name)
			return err
		},
	}
}

func newProjectShowCommand(g *globals) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:   "show NAME",
		Short: "Show a project's settings",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.check(); err != nil {
				return err
			}
			resp, err := listProjects(cmd, g)
			if err != nil {
				return err
			}
			for _, p := range resp.Projects {
				if p.Name != args[0] {
					continue
				}
				if o.json() {
					return printJSON(cmd.OutOrStdout(), p)
				}
				tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
				_, _ = fmt.Fprintf(tw, "Project:\t%s\nApps:\t%d\nNetwork:\t%s\nCreated:\t%s by %s\n",
					p.Name, p.Apps, projectNetwork(p), ago(p.CreatedAt, time.Now()), dash(p.CreatedBy))
				return tw.Flush()
			}
			return fmt.Errorf("project %s not found", args[0])
		},
	}
	o = addOutput(cmd, false)
	return cmd
}
