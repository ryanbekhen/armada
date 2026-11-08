package cli

import (
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/clientconfig"
)

func newServerCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "server",
		Aliases: []string{"servers"},
		Short:   "List and remove control plane servers",
		Long: "List and remove control plane servers. Running a server and adding one\n" +
			"are done on the machine itself with `armadad server` and `armadad server join`.",
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newServerListCommand(g), newServerRemoveCommand(g))
	return cmd
}

func newServerListCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List control plane nodes and update the client config with them",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.ListServers(cmd.Context(), &armadav1.ListServersRequest{})
			if err != nil {
				return RPCError(err)
			}
			out := cmd.OutOrStdout()
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "NAME\tADDRESS\tROLE\tSTATUS\tVERSION")
			var addrs []string
			for _, s := range resp.Servers {
				role := "standby"
				if s.Leader {
					role = "leader"
				}
				st := "voting"
				switch {
				case !s.Member:
					st, role = "not a member", "-"
				case !s.Voting:
					st = "catching up"
				case !s.Reachable:
					st, role = "unreachable", "-"
				}
				// The leader first: a client tries the addresses in order.
				switch {
				case s.Member && s.Leader:
					addrs = append([]string{s.ApiAddr}, addrs...)
				case s.Member:
					addrs = append(addrs, s.ApiAddr)
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.Name, s.ApiAddr, role, st, orDash(s.Version))
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if msg := schemaNote(resp); msg != "" {
				_, _ = fmt.Fprintln(out, "\n"+msg)
			}
			return syncClientServers(cmd, g.configPath, addrs)
		},
	}
}

// syncClientServers records the control plane addresses in the client
// config, so the CLI keeps working when the server it knew goes away.
func syncClientServers(cmd *cobra.Command, path string, addrs []string) error {
	if len(addrs) == 0 {
		return nil
	}
	if _, err := clientconfig.CheckServers(addrs); err != nil {
		return err
	}
	cc, err := clientconfig.Load(path)
	if err != nil {
		return err
	}
	if slices.Equal(cc.Servers, addrs) {
		return nil
	}
	cc.Servers = addrs
	if err := cc.Save(path); err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.ErrOrStderr(), "Updated %s with %d control plane addresses.\n", path, len(addrs))
	return err
}

func newServerRemoveCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:     "remove NAME",
		Aliases: []string{"rm", "delete"},
		Short:   "Remove a control plane node",
		Long: "Remove a control plane node from the cluster. Stop `armadad server` on it first.\n" +
			"Its agent stays a node; remove that with `armada node remove`. The leader cannot\n" +
			"remove itself: stop it, and run this once another server leads.\n\n" +
			"A removed server still holds copies of the cluster CA key and master key: wipe\n" +
			"its data directory.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.RemoveServer(cmd.Context(), &armadav1.RemoveServerRequest{Name: args[0]}); err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Server %s removed. Wipe its data directory: it holds the cluster keys.\n", args[0])
			return err
		},
	}
}

// schemaNote explains a pending state migration (ADR 0012): it runs once
// every server's binary knows the new schema.
func schemaNote(resp *armadav1.ListServersResponse) string {
	newest := resp.GetStateSchema()
	var old []string
	for _, s := range resp.GetServers() {
		newest = max(newest, s.GetSchema())
	}
	for _, s := range resp.GetServers() {
		if s.GetSchema() < newest {
			old = append(old, s.GetName())
		}
	}
	if newest == resp.GetStateSchema() {
		return ""
	}
	return fmt.Sprintf("The state uses schema %d; upgraded servers know %d. The migration runs, and upgraded\n"+
		"servers can lead, once these servers are upgraded too: %s.", resp.GetStateSchema(), newest, strings.Join(old, ", "))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
