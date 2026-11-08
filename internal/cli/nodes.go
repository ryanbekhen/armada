package cli

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/spec"
)

// pollInterval is how often `node remove` checks for remaining replicas.
var pollInterval = 2 * time.Second

func newTokenCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "token", Aliases: []string{"tokens"}, Short: "Manage join tokens for new nodes and servers"}
	var (
		ttl       time.Duration
		forServer bool
		labels    []string
	)
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a single-use join token and print the join command",
		Long: "Create a single-use join token and print the command to run on the new node.\n\n" +
			"The token is a credential: anyone holding it before it expires can add a node.\n" +
			"Send it over a trusted channel. Only a hash is stored on the server.\n\n" +
			"With --server the token adds a control plane node, which receives the cluster\n" +
			"CA key and the secrets master key: it lasts at most an hour.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if forServer && !cmd.Flags().Changed("ttl") {
				ttl = 15 * time.Minute
			}
			req := &armadav1.CreateJoinTokenRequest{TtlSeconds: int64(ttl / time.Second), Server: forServer}
			for _, l := range labels {
				k, v, err := parseLabel(l)
				if err != nil {
					return err
				}
				if req.Labels == nil {
					req.Labels = map[string]string{}
				}
				req.Labels[k] = v
			}
			resp, err := client.CreateJoinToken(cmd.Context(), req)
			if err != nil {
				return RPCError(err)
			}
			kind, sub, unit, what := "Join", "join", "armada-agent", "node"
			if forServer {
				kind, sub, unit, what = "Server", "server join", "armada-server", "control plane node"
			}
			args := fmt.Sprintf("%s %s --ca-hash %s", sub, resp.JoinAddr, resp.CaHash)
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "%s token created; it works once and expires %s.\n\n", kind, resp.ExpiresAt.AsTime().Local().Format(time.RFC3339))
			_, _ = fmt.Fprintf(out, "Token (shown once): %s\n\n", resp.Token)
			_, _ = fmt.Fprintf(out, "On the new %s (same private network), this installs Armada, joins,\n", what)
			_, _ = fmt.Fprintf(out, "and starts it; paste the token when asked:\n\n")
			_, _ = fmt.Fprintf(out, "  %s\n\n", installCommand(resp.GetVersion(), args))
			if forServer {
				_, _ = fmt.Fprintf(out, "Copy /etc/armada/server.env from this server first, if it has one.\n")
			}
			_, _ = fmt.Fprintf(out, "Where Armada is already installed:\n\n")
			_, _ = fmt.Fprintf(out, "  sudo armadad %s\n", args)
			_, err = fmt.Fprintf(out, "  sudo systemctl enable --now %s\n", unit)
			return err
		},
	}
	create.Flags().DurationVar(&ttl, "ttl", time.Hour, "token lifetime (1m to 24h; server tokens: default 15m, at most 1h)")
	create.Flags().BoolVar(&forServer, "server", false, "create a token for a control plane node")
	create.Flags().StringArrayVar(&labels, "label", nil, "label KEY=VALUE for the node that joins with the token (repeatable)")
	cmd.AddCommand(create)
	return cmd
}

func newNodeCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "node", Aliases: []string{"nodes"}, Short: "List, label, cordon, and remove nodes"}
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List nodes",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.Status(cmd.Context(), &armadav1.StatusRequest{})
			if err != nil {
				return RPCError(err)
			}
			replicas := map[string]int{}
			for _, a := range resp.Apps {
				for _, r := range a.Replicas {
					replicas[r.NodeId]++
				}
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "NODE\tPRIVATE IP\tSTATE\tREPLICAS\tVERSION\tCERT EXPIRES\tLABELS")
			for _, n := range resp.Nodes {
				exp := "-"
				if n.CertExpiresAt != nil {
					exp = n.CertExpiresAt.AsTime().Local().Format(time.DateOnly)
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n", n.Id, n.PrivateIp, nodeState(n), replicas[n.Id], orDash(n.Version), exp, orDash(formatLabels(n.Labels)))
			}
			return tw.Flush()
		},
	}
	cordon := func(use, short string, on bool) *cobra.Command {
		return &cobra.Command{
			Use:   use + " NODE",
			Short: short,
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				client, conn, err := dialAdmin(g)
				if err != nil {
					return err
				}
				defer conn.Close()
				if _, err := client.CordonNode(cmd.Context(), &armadav1.CordonNodeRequest{Node: args[0], Cordoned: on}); err != nil {
					return RPCError(err)
				}
				msg := "Node %s is schedulable again.\n"
				if on {
					msg = "Node %s is cordoned; its replicas move to other nodes.\n"
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), msg, args[0])
				return err
			},
		}
	}
	var force bool
	var wait time.Duration
	remove := &cobra.Command{
		Use:     "remove NODE",
		Aliases: []string{"rm", "delete"},
		Short:   "Move a node's replicas away, then remove it and revoke its certificate",
		Long: "Cordon the node, wait until its replicas run elsewhere (drained like a rolling\n" +
			"update), then remove it from the cluster and revoke its certificate.\n\n" +
			"--force removes the node at once and deletes its replicas without draining;\n" +
			"use it only for a node that is gone for good. A node holding volumes is only\n" +
			"removed with --force; their records stay so a backup can be restored elsewhere.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			node := args[0]
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			ctx := cmd.Context()
			out := cmd.OutOrStdout()
			if !force {
				// Apps with volumes never move off their node (ADR 0023).
				vols, err := client.ListVolumes(ctx, &armadav1.ListVolumesRequest{})
				if err != nil {
					return RPCError(err)
				}
				var held []string
				for _, v := range vols.Volumes {
					if v.Node == node {
						held = append(held, v.App+"/"+v.Name)
					}
				}
				if len(held) > 0 {
					return fmt.Errorf("%s holds volumes %s, whose apps never move; back them up (armada volume backup) and restore them on another node (armada volume restore --node), or use --force", node, strings.Join(held, ", "))
				}
				if _, err := client.CordonNode(ctx, &armadav1.CordonNodeRequest{Node: node, Cordoned: true}); err != nil {
					return RPCError(err)
				}
				_, _ = fmt.Fprintf(out, "Cordoned %s; waiting for its replicas to move...\n", node)
				deadline := time.Now().Add(wait)
				for {
					resp, err := client.Status(ctx, &armadav1.StatusRequest{})
					if err != nil {
						return RPCError(err)
					}
					left := 0
					for _, a := range resp.Apps {
						for _, r := range a.Replicas {
							if r.NodeId == node {
								left++
							}
						}
					}
					if left == 0 {
						break
					}
					if time.Now().After(deadline) {
						return fmt.Errorf("%d replica(s) still on %s after %s; the node stays cordoned. Is there capacity elsewhere? Retry, or use --force", left, node, wait)
					}
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(pollInterval):
					}
				}
			}
			if _, err := client.RemoveNode(ctx, &armadav1.RemoveNodeRequest{Node: node, Force: force}); err != nil {
				return RPCError(err)
			}
			_, _ = fmt.Fprintf(out, "Removed node %s; its certificate is revoked.\n", node)
			_, err = fmt.Fprintf(out, "On that machine, stop armada-agent (or armada-server) and run `armadad runtime reset`;\n"+
				"its HAProxy keeps serving its last configuration until then.\n")
			return err
		},
	}
	remove.Flags().BoolVar(&force, "force", false, "remove now and delete its replicas without draining")
	remove.Flags().DurationVar(&wait, "wait", 10*time.Minute, "how long to wait for replicas to move")
	label := &cobra.Command{
		Use:   "label NODE KEY=VALUE... | KEY-...",
		Short: "Set or remove a node's labels",
		Long: "Set labels with KEY=VALUE and remove them with KEY-. Apps choose nodes by\n" +
			"label with placement.require (see the spec reference). Replicas whose node no\n" +
			"longer matches their app's placement move to other nodes, without dropping\n" +
			"below the serving count.\n\n" +
			"Keys are lowercase letters, digits, '.', '-', '_', and '/'; values the same\n" +
			"without '/'. Keys starting with \"armada.\" are set by Armada (armada.os,\n" +
			"armada.arch) and cannot be changed.",
		Example: "  armada node label raspi-1 region=sulawesi kind=raspi\n  armada node label raspi-1 kind-",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &armadav1.LabelNodeRequest{Node: args[0], Set: map[string]string{}}
			for _, a := range args[1:] {
				if k, ok := strings.CutSuffix(a, "-"); ok && !strings.Contains(a, "=") {
					req.Remove = append(req.Remove, k)
					continue
				}
				k, v, err := parseLabel(a)
				if err != nil {
					return err
				}
				req.Set[k] = v
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.LabelNode(cmd.Context(), req)
			if err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Labels of %s: %s\n", args[0], orDash(formatLabels(resp.Labels)))
			return err
		},
	}
	restrict := func(use, short string, on bool) *cobra.Command {
		return &cobra.Command{
			Use:   use + " NODE",
			Short: short,
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				client, conn, err := dialAdmin(g)
				if err != nil {
					return err
				}
				defer conn.Close()
				if _, err := client.RestrictNode(cmd.Context(), &armadav1.RestrictNodeRequest{Node: args[0], Restricted: on}); err != nil {
					return RPCError(err)
				}
				msg := "Node %s is open: any app may run there.\n"
				if on {
					msg = "Node %s is restricted: only apps whose placement.require names one of its labels run there;\n" +
						"other replicas move to other nodes.\n"
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), msg, args[0])
				return err
			},
		}
	}
	cmd.AddCommand(list, label,
		restrict("restrict", "Run only apps whose placement selects one of the node's labels", true),
		restrict("open", "Let any app run on a restricted node again", false),
		cordon("cordon", "Stop scheduling on a node and move its replicas away", true),
		cordon("uncordon", "Allow scheduling on a node again", false), remove)
	return cmd
}

func nodeState(n *armadav1.NodeStatus) string {
	s := n.State
	if n.Cordoned {
		s += ",cordoned"
	}
	if n.Restricted {
		s += ",restricted"
	}
	return s
}

// parseLabel splits KEY=VALUE and validates both parts.
func parseLabel(s string) (string, string, error) {
	k, v, ok := strings.Cut(s, "=")
	if !ok {
		return "", "", fmt.Errorf("label %q: want KEY=VALUE (or KEY- to remove)", s)
	}
	if err := spec.CheckAdminLabel(k, v); err != nil {
		return "", "", err
	}
	return k, v, nil
}

// formatLabels renders labels as "k=v,k2=v2", sorted by key.
func formatLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + labels[k]
	}
	return strings.Join(parts, ",")
}

// InstallURL is where the installer is published.
const InstallURL = "https://raw.githubusercontent.com/ryanbekhen/armada/main/install.sh"

// releaseTag matches the release tags install.sh accepts.
var releaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)

// installCommand is the one line that installs Armada on a new machine and
// runs `armadad ARGS` there, pinned to the server's release when it is one.
func installCommand(serverVersion, args string) string {
	env := ""
	if releaseTag.MatchString(serverVersion) {
		env = "ARMADA_VERSION=" + serverVersion + " "
	}
	return fmt.Sprintf("curl -fsSL %s | sudo %ssh -s - %s", InstallURL, env, args)
}
