package daemon

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
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
		userName                                    string
		port, joinPort                              int
	)
	cmd := &cobra.Command{
		Use:   "join ADDR --ca-hash sha256:HEX",
		Short: "Add this machine to the cluster as a control plane node",
		Long: "Add this machine to the cluster as a control plane node. Get ADDR, the token,\n" +
			"and the CA hash from `armada server join-token`. The CA hash pins the\n" +
			"cluster CA, so a machine in the middle cannot pose as the server.\n\n" +
			"The new server receives the cluster CA key and the secrets master key, so the\n" +
			"token is as sensitive as they are. It is read from --token-file, a hidden\n" +
			"prompt, or stdin; never from an argument. Afterwards, run `armadad server`.\n\n" +
			"Like `armadad init`, it writes " + clientconfig.SystemPath + " for the machine's\n" +
			"cluster-admins (group " + clientconfig.Group + ") and ~/.armada/config of the person running it\n" +
			"through sudo, both with a certificate for --user-name signed by the cluster CA.\n" +
			"The certificate has the rights the cluster gives that user; a name the cluster\n" +
			"has no record of is a cluster-admin, as the first user is. Existing files stay.\n\n" +
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
				return fmt.Errorf("%w; run `armada server delete %s` on the cluster before trying again", err, name)
			}
			servers, err := clientconfig.CheckServers(resp.Servers)
			if err != nil {
				return err
			}
			note, err := rtFlags.useNodeSubnet(&ac, resp.NodeSubnet, resp.NetworkMode, ip)
			if err != nil {
				return fmt.Errorf("%w; run `armada server delete %s` on the cluster before trying again", err, name)
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
			// Like init: the machine's cluster-admins, and the person who
			// ran this through sudo, can use armada here at once. The cluster
			// already exists, so a failure only warns.
			configs, err := joinedClientConfigs(resp, servers, userName)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: client config: %v\n", err)
			}

			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Joined as control plane node %s (%s).\n", name, ip)
			for _, c := range configs {
				_, _ = fmt.Fprintf(out, "Client config: %s\n", c)
			}
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
	f.StringVar(&privateIP, "private-ip", "", "this machine's private IP (default: the only private IPv4 address)")
	f.StringVar(&name, "name", "", "server and node name (default: hostname)")
	f.StringVar(&dataDir, "data-dir", defaultDataDir, "directory for cluster state and keys")
	f.IntVar(&port, "port", defaultPort, "control plane port on the private IP")
	f.IntVar(&joinPort, "join-port", 0, "join listener port on the private IP (default: --port + 1)")
	f.StringVar(&userName, "user-name", "", "user named in the client configs written here (default: the user running it)")
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

// joinedClientConfigs writes the machine's shared admin config and, run
// through sudo, the person's own, each kept when it exists. The
// certificate names userName, else the sudo user, else the current user,
// and is signed with the CA the cluster handed over.
func joinedClientConfigs(resp *armadav1.JoinServerResponse, servers []string, userName string) ([]string, error) {
	if os.Geteuid() != 0 {
		return nil, nil
	}
	person := sudoUser()
	if userName == "" {
		userName = "admin"
		if person != nil {
			userName = sanitizeName(person.Username, "admin")
		} else if u, err := user.Current(); err == nil {
			userName = sanitizeName(u.Username, "admin")
		}
	}
	if _, err := pki.ParseIdentity(pki.Identity{Kind: pki.KindUser, Name: userName}.String()); err != nil {
		return nil, err
	}
	ca, err := pki.LoadCA(resp.CaCert, resp.CaKey)
	if err != nil {
		return nil, err
	}
	cert, key, err := ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindUser, Name: userName}, Client: true})
	if err != nil {
		return nil, err
	}
	cc := &clientconfig.Config{Servers: servers, CA: string(resp.CaCert), Cert: string(cert), Key: string(key)}
	var written []string
	if _, err := os.Stat(clientconfig.SystemPath); errors.Is(err, fs.ErrNotExist) {
		if _, err := cc.SaveShared(clientconfig.SystemPath); err != nil {
			return written, err
		}
		written = append(written, clientconfig.SystemPath+" ("+userName+")")
	}
	if person != nil {
		switch own, err := cc.SaveOwn(person); {
		case err == nil:
			written = append(written, own+" ("+userName+")")
		case errors.Is(err, fs.ErrExist):
		default:
			return written, fmt.Errorf("%s's ~/.armada/config: %w", person.Username, err)
		}
	}
	return written, nil
}
