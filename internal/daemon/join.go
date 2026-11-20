package daemon

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/agent"
	"github.com/ryanbekhen/armada/internal/cli"
	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/version"
)

func newJoinCommand() *cobra.Command {
	var (
		rtFlags                                         runtimeFlags
		tokenFile, caHash, privateIP, nodeName, dataDir string
		noPrivateIP                                     bool
		endpoint                                        string
	)
	cmd := &cobra.Command{
		Use:   "join ADDR --ca-hash sha256:HEX",
		Short: "Join this machine to a cluster as a node",
		Long: "Join this machine to a cluster as a node. Get ADDR, TOKEN, and the CA hash\n" +
			"from `armada node join-token`. The CA hash pins the cluster CA, so a machine in\n" +
			"the middle cannot pose as the server. Afterwards, run `armadad agent`.\n\n" +
			"The token is read from --token-file, a hidden prompt, or stdin; never from\n" +
			"an argument, which would leak into shell history.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := args[0]
			ip, mesh, err := prepareJoin(cmd.Flags(), addr, privateIP, endpoint, noPrivateIP)
			if err != nil {
				return err
			}
			raw, err := cli.ReadSecretValue(cmd, tokenFile)
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
			if err := mesh.loadKey(dataDir); err != nil {
				return err
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
				TokenId: tok.ID, TokenSecret: tok.Secret, NodeName: nodeName, PrivateIp: ipString(ip), Csr: csr, Version: version.Get().Version,
				NetworkKey: mesh.key, Endpoint: ipString(mesh.endpoint),
			})
			if err != nil {
				return cli.RPCError(err)
			}
			// The server must hand back the CA we pinned and a certificate
			// for our key and name.
			if got, err := pki.ParseCertPEM(resp.CaCert); err != nil || pki.CAHash(got) != pki.CAHash(ca) {
				return errors.New("server returned a different CA than the pinned one")
			}
			servers, err := clientconfig.CheckServers(resp.Servers)
			if err != nil {
				return err
			}
			if ip, err = mesh.address(ip, resp.NetworkMode, resp.MeshIp); err != nil {
				return err
			}
			note, err := rtFlags.useNodeSubnet(&ac, resp.NodeSubnet, resp.NetworkMode, ip)
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
			if mesh.on {
				// The servers are at mesh addresses, or in another site:
				// the tunnels come up with the cluster's peer list before
				// the agent starts (ADR 0049, ADR 0050).
				ac.Endpoint = mesh.endpoint.String()
				ac.ClusterCIDR, ac.MeshCIDR = resp.GetNetwork().GetClusterCidr(), resp.GetNetwork().GetMeshCidr()
				if err := upMesh(dataDir, &ac, resp.Network, slog.New(slog.DiscardHandler)); err != nil {
					return fmt.Errorf("%w; fix it and run `armada node delete %s` on the cluster before trying again", err, nodeName)
				}
			}
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
			if resp.NodeSubnet != "" {
				_, _ = fmt.Fprintf(out, "Container subnet: %s.\n", resp.NodeSubnet)
			}
			_, _ = fmt.Fprint(out, note)
			_, err = fmt.Fprint(out, nextStep("agent", dataDir))
			return err
		},
	}
	f := cmd.Flags()
	rtFlags.register(f)
	f.StringVar(&tokenFile, "token-file", "", "file holding the join token (default: prompt or stdin)")
	f.StringVar(&caHash, "ca-hash", "", "cluster CA hash, sha256:...")
	f.StringVar(&privateIP, "private-ip", "", "this node's private IP (default: the only private IPv4 address; a mesh cluster gives the node a mesh address instead)")
	f.BoolVar(&noPrivateIP, "no-private-ip", false, "joining from another site: send no private IP, and get a mesh address the other nodes reach over WireGuard (the default when the machine has no private IPv4 address)")
	f.StringVar(&endpoint, "endpoint", "", "joins over a public ADDR (mesh clusters, other sites): this machine's public IPv4 address, which other nodes send WireGuard packets to (default: the only public IPv4 address; behind one-to-one NAT, the mapped address)")
	f.StringVar(&nodeName, "node-name", "", "node name (default: hostname)")
	f.StringVar(&dataDir, "data-dir", defaultDataDir, "directory for the node certificate")
	_ = cmd.MarkFlagRequired("ca-hash")
	return cmd
}
