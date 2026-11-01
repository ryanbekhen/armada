package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/agent"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/version"
)

// pollInterval is how often `node remove` checks for remaining replicas.
var pollInterval = 2 * time.Second

func newTokenCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Manage join tokens for new nodes and servers"}
	var (
		ttl       time.Duration
		forServer bool
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
			resp, err := client.CreateJoinToken(cmd.Context(), &armadav1.CreateJoinTokenRequest{TtlSeconds: int64(ttl / time.Second), Server: forServer})
			if err != nil {
				return rpcErr(err)
			}
			kind, join, what := "Join", "armada join", "node (same private network)"
			if forServer {
				kind, join, what = "Server", "armada server join", "control plane node (same private network)"
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "%s token created; it works once and expires %s.\n\n", kind, resp.ExpiresAt.AsTime().Local().Format(time.RFC3339))
			_, _ = fmt.Fprintf(out, "Token (shown once): %s\n\n", resp.Token)
			_, _ = fmt.Fprintf(out, "Run this as root on the new %s\n", what)
			_, _ = fmt.Fprintf(out, "and paste the token when asked:\n\n")
			_, err = fmt.Fprintf(out, "  %s %s --ca-hash %s\n", join, resp.JoinAddr, resp.CaHash)
			return err
		},
	}
	create.Flags().DurationVar(&ttl, "ttl", time.Hour, "token lifetime (1m to 24h; server tokens: default 15m, at most 1h)")
	create.Flags().BoolVar(&forServer, "server", false, "create a token for a control plane node")
	cmd.AddCommand(create)
	return cmd
}

func newJoinCommand() *cobra.Command {
	var (
		rtFlags                                         runtimeFlags
		tokenFile, caHash, privateIP, nodeName, dataDir string
	)
	cmd := &cobra.Command{
		Use:   "join ADDR --ca-hash sha256:HEX",
		Short: "Join this machine to a cluster as a node",
		Long: "Join this machine to a cluster as a node. Get ADDR, TOKEN, and the CA hash\n" +
			"from `armada token create`. The CA hash pins the cluster CA, so a machine in\n" +
			"the middle cannot pose as the server. Afterwards, run `armada agent`.\n\n" +
			"The token is read from --token-file, a hidden prompt, or stdin; never from\n" +
			"an argument, which would leak into shell history.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := args[0]
			if err := netutil.CheckPrivateListen(addr); err != nil {
				return fmt.Errorf("join address: %w", err)
			}
			raw, err := readSecretValue(cmd, tokenFile)
			if err != nil {
				return fmt.Errorf("read token: %w", err)
			}
			tok, err := pki.ParseJoinToken(strings.TrimSpace(string(raw)))
			if err != nil {
				return err
			}
			pin, err := pki.ParseCAHash(caHash)
			if err != nil {
				return err
			}
			ip, err := resolvePrivateIP(privateIP)
			if err != nil {
				return err
			}
			var ac agentConfig
			if err := rtFlags.apply(&ac, ip); err != nil {
				return err
			}
			if nodeName == "" {
				h, _ := os.Hostname()
				nodeName = sanitizeName(h, "")
				if nodeName == "" {
					return errors.New("cannot derive a node name from the hostname; pass --node-name")
				}
			}
			if _, err := pki.ParseIdentity(pki.Identity{Kind: pki.KindNode, Name: nodeName}.String()); err != nil {
				return err
			}
			if err := fsutil.MkdirPrivate(dataDir); err != nil {
				return fmt.Errorf("data dir: %w", err)
			}
			for _, f := range []string{fileNodeKey, fileAgent, fileCAKey} {
				if _, err := os.Stat(filepath.Join(dataDir, f)); err == nil {
					return fmt.Errorf("%s already belongs to a cluster (found %s)", dataDir, f)
				} else if !errors.Is(err, fs.ErrNotExist) {
					return err
				}
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			ca, err := pki.FetchPinnedCA(ctx, addr, pin)
			if err != nil {
				return err
			}
			conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(pki.JoinClientTLS(ca))))
			if err != nil {
				return err
			}
			defer conn.Close()
			keyPEM, csr, err := pki.NewNodeCSR(nodeName)
			if err != nil {
				return err
			}
			resp, err := armadav1.NewJoinServiceClient(conn).Join(ctx, &armadav1.JoinRequest{
				TokenId: tok.ID, TokenSecret: tok.Secret, NodeName: nodeName, PrivateIp: ip.String(), Csr: csr, Version: version.Get().Version,
			})
			if err != nil {
				return rpcErr(err)
			}
			// The server must hand back the CA we pinned and a certificate
			// for our key and name.
			if got, err := pki.ParseCertPEM(resp.CaCert); err != nil || pki.CAHash(got) != pki.CAHash(ca) {
				return errors.New("server returned a different CA than the pinned one")
			}
			servers, err := checkServers(resp.Servers)
			if err != nil {
				return err
			}
			// agent.json last: its presence marks a completed join.
			for _, f := range []struct {
				name string
				data []byte
			}{{fileCACert, resp.CaCert}, {fileNodeKey, keyPEM}, {fileNodeCert, resp.NodeCert}} {
				if err := fsutil.WriteFileAtomic(filepath.Join(dataDir, f.name), f.data, 0o600); err != nil {
					return err
				}
			}
			ac.NodeID = nodeName
			ac.PrivateIP = ip.String()
			ac.Servers = servers
			if err := saveAgentConfig(dataDir, ac); err != nil {
				return err
			}
			if _, err := agent.LoadCredentials(dataDir, nodeName); err != nil {
				for _, f := range []string{fileAgent, fileNodeCert, fileNodeKey, fileCACert} {
					_ = os.Remove(filepath.Join(dataDir, f))
				}
				return fmt.Errorf("server returned an unusable certificate: %w", err)
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Joined as node %s (%s); control plane %s.\n", nodeName, ip, strings.Join(servers, ", "))
			_, err = fmt.Fprint(out, nextStep("agent", dataDir))
			return err
		},
	}
	f := cmd.Flags()
	rtFlags.register(f)
	f.StringVar(&tokenFile, "token-file", "", "file holding the join token (default: prompt or stdin)")
	f.StringVar(&caHash, "ca-hash", "", "cluster CA hash, sha256:...")
	f.StringVar(&privateIP, "private-ip", "", "this node's private IP; auto-detected if empty")
	f.StringVar(&nodeName, "node-name", "", "node name (default: hostname)")
	f.StringVar(&dataDir, "data-dir", defaultDataDir, "directory for the node certificate")
	_ = cmd.MarkFlagRequired("ca-hash")
	return cmd
}

// checkServers validates control plane addresses received from a server.
func checkServers(addrs []string) ([]string, error) {
	if len(addrs) == 0 {
		return nil, errors.New("server returned no control plane address")
	}
	for _, a := range addrs {
		if err := netutil.CheckPrivateListen(a); err != nil {
			return nil, fmt.Errorf("server address: %w", err)
		}
	}
	return addrs, nil
}

func newNodeCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "node", Short: "List, cordon, and remove nodes"}
	list := &cobra.Command{
		Use:   "list",
		Short: "List nodes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.Status(cmd.Context(), &armadav1.StatusRequest{})
			if err != nil {
				return rpcErr(err)
			}
			replicas := map[string]int{}
			for _, a := range resp.Apps {
				for _, r := range a.Replicas {
					replicas[r.NodeId]++
				}
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "NODE\tPRIVATE IP\tSTATE\tREPLICAS\tCERT EXPIRES")
			for _, n := range resp.Nodes {
				exp := "-"
				if n.CertExpiresAt != nil {
					exp = n.CertExpiresAt.AsTime().Local().Format(time.DateOnly)
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", n.Id, n.PrivateIp, nodeState(n), replicas[n.Id], exp)
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
					return rpcErr(err)
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
		Use:   "remove NODE",
		Short: "Move a node's replicas away, then remove it and revoke its certificate",
		Long: "Cordon the node, wait until its replicas run elsewhere (drained like a rolling\n" +
			"update), then remove it from the cluster and revoke its certificate.\n\n" +
			"--force removes the node at once and deletes its replicas without draining;\n" +
			"use it only for a node that is gone for good.",
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
				if _, err := client.CordonNode(ctx, &armadav1.CordonNodeRequest{Node: node, Cordoned: true}); err != nil {
					return rpcErr(err)
				}
				_, _ = fmt.Fprintf(out, "Cordoned %s; waiting for its replicas to move...\n", node)
				deadline := time.Now().Add(wait)
				for {
					resp, err := client.Status(ctx, &armadav1.StatusRequest{})
					if err != nil {
						return rpcErr(err)
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
				return rpcErr(err)
			}
			_, _ = fmt.Fprintf(out, "Removed node %s; its certificate is revoked.\n", node)
			_, err = fmt.Fprintf(out, "On that machine, stop armada-agent (or armada-server) and run `armada runtime reset`;\n"+
				"its HAProxy keeps serving its last configuration until then.\n")
			return err
		},
	}
	remove.Flags().BoolVar(&force, "force", false, "remove now and delete its replicas without draining")
	remove.Flags().DurationVar(&wait, "wait", 10*time.Minute, "how long to wait for replicas to move")
	cmd.AddCommand(list, cordon("cordon", "Stop scheduling on a node and move its replicas away", true),
		cordon("uncordon", "Allow scheduling on a node again", false), remove)
	return cmd
}

func nodeState(n *armadav1.NodeStatus) string {
	if n.Cordoned {
		return n.State + ",cordoned"
	}
	return n.State
}
