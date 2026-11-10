package daemon

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
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
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/version"
)

func newServerJoinCommand() *cobra.Command {
	var (
		rtFlags                                     runtimeFlags
		tokenFile, caHash, privateIP, name, dataDir string
		port, joinPort                              int
	)
	cmd := &cobra.Command{
		Use:   "join ADDR --ca-hash sha256:HEX",
		Short: "Add this machine to the cluster as a control plane node",
		Long: "Add this machine to the cluster as a control plane node. Get ADDR, the token,\n" +
			"and the CA hash from `armada token create --server`. The CA hash pins the\n" +
			"cluster CA, so a machine in the middle cannot pose as the server.\n\n" +
			"The new server receives the cluster CA key and the secrets master key, so the\n" +
			"token is as sensitive as they are. It is read from --token-file, a hidden\n" +
			"prompt, or stdin; never from an argument. Afterwards, run `armadad server`.\n\n" +
			"Run three control plane nodes to tolerate the loss of one; with two, losing\n" +
			"either stops the control plane.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := args[0]
			if err := netutil.CheckPrivateListen(addr); err != nil {
				return fmt.Errorf("join address: %w", err)
			}
			if port < 1 || port > 65534 {
				return fmt.Errorf("invalid --port %d", port)
			}
			if joinPort == 0 {
				joinPort = port + 1
			}
			if joinPort < 0 || joinPort > 65535 {
				return fmt.Errorf("invalid --join-port %d", joinPort)
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
			ip, err := resolvePrivateIP(privateIP)
			if err != nil {
				return err
			}
			var ac agentConfig
			if err := rtFlags.apply(&ac, ip); err != nil {
				return err
			}
			if name == "" {
				h, _ := os.Hostname()
				name = sanitizeName(h, "")
				if name == "" {
					return errors.New("cannot derive a name from the hostname; pass --name")
				}
			}
			for _, id := range []pki.Identity{{Kind: pki.KindServer, Name: name}, {Kind: pki.KindNode, Name: name}} {
				if _, err := pki.ParseIdentity(id.String()); err != nil {
					return err
				}
			}
			if err := fsutil.MkdirPrivate(dataDir); err != nil {
				return fmt.Errorf("data dir: %w", err)
			}
			for _, f := range []string{fileCAKey, fileNodeKey, fileAgent, fileMasterKey, dirEtcd} {
				if _, err := os.Stat(filepath.Join(dataDir, f)); err == nil {
					return fmt.Errorf("%s already belongs to a cluster (found %s)", dataDir, f)
				} else if !errors.Is(err, fs.ErrNotExist) {
					return err
				}
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), time.Minute)
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
			nodeKey, csr, err := pki.NewNodeCSR(name)
			if err != nil {
				return err
			}
			_, peerPort := etcdPorts(dataDir)
			resp, err := armadav1.NewJoinServiceClient(conn).JoinServer(ctx, &armadav1.JoinServerRequest{
				TokenId: tok.ID, TokenSecret: tok.Secret, Name: name, PrivateIp: ip.String(), NodeCsr: csr,
				Version: version.Get().Version, ApiPort: int32(port), JoinPort: int32(joinPort), EtcdPeerPort: int32(peerPort), //nolint:gosec // ports validated above
			})
			if err != nil {
				return cli.RPCError(err)
			}
			if err := checkJoinedServer(resp, ca, name); err != nil {
				return fmt.Errorf("%w; run `armada server remove %s` on the cluster before trying again", err, name)
			}
			servers, err := clientconfig.CheckServers(resp.Servers)
			if err != nil {
				return err
			}
			note, err := rtFlags.useNodeSubnet(&ac, resp.NodeSubnet, resp.NetworkMode, ip)
			if err != nil {
				return fmt.Errorf("%w; run `armada server remove %s` on the cluster before trying again", err, name)
			}

			// agent.json last: its presence marks a completed join.
			files := []struct {
				name string
				data []byte
			}{
				{fileCACert, resp.CaCert}, {fileCAKey, resp.CaKey},
				{fileServerCert, resp.ServerCert}, {fileServerKey, resp.ServerKey},
				{fileNodeKey, nodeKey}, {fileNodeCert, resp.NodeCert},
			}
			for _, f := range files {
				if err := fsutil.WriteFileAtomic(filepath.Join(dataDir, f.name), f.data, 0o600); err != nil {
					return err
				}
			}
			if err := secrets.WriteKeyFile(filepath.Join(dataDir, fileMasterKey), secrets.NewValue(resp.MasterKey)); err != nil {
				return fmt.Errorf("master key: %w", err)
			}
			if err := fsutil.MkdirPrivate(filepath.Join(dataDir, dirEtcd)); err != nil {
				return err
			}
			if err := fsutil.WriteFileAtomic(filepath.Join(dataDir, fileEtcdInitial), []byte(resp.InitialCluster+"\n"), 0o600); err != nil {
				return err
			}
			ac.NodeID = name
			ac.PrivateIP = ip.String()
			ac.Servers = servers
			if err := saveAgentConfig(dataDir, ac); err != nil {
				return err
			}
			if _, err := agent.LoadCredentials(dataDir, name); err != nil {
				return fmt.Errorf("server returned an unusable node certificate: %w", err)
			}

			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Joined as control plane node %s (%s).\n", name, ip)
			if resp.NodeSubnet != "" {
				_, _ = fmt.Fprintf(out, "Container subnet: %s.\n", resp.NodeSubnet)
			}
			_, _ = fmt.Fprint(out, note)
			_, _ = fmt.Fprint(out, nextStep("server", dataDir))
			if len(servers) == 2 {
				_, _ = fmt.Fprintln(out, "With two control plane nodes, losing either one stops the control plane; add a third.")
			}
			return nil
		},
	}
	f := cmd.Flags()
	rtFlags.register(f)
	f.StringVar(&tokenFile, "token-file", "", "file holding the server token (default: prompt or stdin)")
	f.StringVar(&caHash, "ca-hash", "", "cluster CA hash, sha256:...")
	f.StringVar(&privateIP, "private-ip", "", "this machine's private IP; auto-detected if empty")
	f.StringVar(&name, "name", "", "server and node name (default: hostname)")
	f.StringVar(&dataDir, "data-dir", defaultDataDir, "directory for cluster state and keys")
	f.IntVar(&port, "port", defaultPort, "control plane port on the private IP")
	f.IntVar(&joinPort, "join-port", 0, "join listener port on the private IP (default: --port + 1)")
	_ = cmd.MarkFlagRequired("ca-hash")
	return cmd
}

// checkJoinedServer verifies what a server returned to a joining control
// plane node: the pinned CA with its key, and certificates for our name.
func checkJoinedServer(resp *armadav1.JoinServerResponse, pinned *x509.Certificate, name string) error {
	got, err := pki.ParseCertPEM(resp.CaCert)
	if err != nil || pki.CAHash(got) != pki.CAHash(pinned) {
		return errors.New("server returned a different CA than the pinned one")
	}
	if _, err := pki.LoadCA(resp.CaCert, resp.CaKey); err != nil {
		return fmt.Errorf("server returned an unusable CA key: %w", err)
	}
	if _, err := pki.ServerTLS(resp.CaCert, resp.ServerCert, resp.ServerKey); err != nil {
		return fmt.Errorf("server returned an unusable server certificate: %w", err)
	}
	id, err := serverIdentity(resp.ServerCert)
	if err != nil || id.Name != name {
		return errors.New("server returned a certificate for another server")
	}
	roots := x509.NewCertPool()
	roots.AddCert(pinned)
	leaf, _ := pki.ParseCertPEM(resp.ServerCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("server certificate is not signed by the cluster CA: %w", err)
	}
	if resp.InitialCluster == "" {
		return errors.New("server returned no etcd cluster")
	}
	return nil
}
