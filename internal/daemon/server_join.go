package daemon

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
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
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/version"
)

func newServerJoinCommand() *cobra.Command {
	var (
		rtFlags                                     runtimeFlags
		tokenFile, caHash, privateIP, name, dataDir string
		userName, endpoint                          string
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
			"cluster-admins (group " + clientconfig.Group + "), with a certificate for --user-name signed by\n" +
			"the cluster CA that the server renews, and adds the person running it through\n" +
			"sudo to the group.\n" +
			"The certificate has the rights the cluster gives that user; a name the cluster\n" +
			"has no record of is recorded as a cluster-admin, as the first user is (a leader\n" +
			"too old to record it gets no config written). An existing file stays.\n\n" +
			"Run three control plane nodes to tolerate the loss of one; with two, losing\n" +
			"either stops the control plane.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := args[0]
			ip, mesh, err := prepareJoin(cmd.Flags(), addr, privateIP, endpoint, false)
			if err != nil {
				return err
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
			if err := mesh.loadKey(dataDir); err != nil {
				return err
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
			// The user of the client configs written below: the leader
			// records it before this machine signs its certificate.
			clientUser, err := joinUserName(userName)
			if err != nil {
				return err
			}
			_, peerPort := etcdPorts(dataDir)
			resp, err := armadav1.NewJoinServiceClient(conn).JoinServer(ctx, &armadav1.JoinServerRequest{
				TokenId: tok.ID, TokenSecret: tok.Secret, Name: name, PrivateIp: ipString(ip), NodeCsr: csr,
				NetworkKey: mesh.key, Endpoint: ipString(mesh.endpoint),
				Version: version.Get().Version, ApiPort: int32(port), JoinPort: int32(joinPort), EtcdPeerPort: int32(peerPort), //nolint:gosec // ports validated above
				UserName: clientUser,
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
			if ip, err = mesh.address(ip, resp.NetworkMode, resp.MeshIp); err != nil {
				return fmt.Errorf("%w; run `armada server delete %s` on the cluster before trying again", err, name)
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
			if mesh.on {
				// etcd and the API listen on the mesh address: the tunnel
				// comes up with the cluster's peer list now, and again from
				// it when `armadad server` starts.
				ac.Endpoint = mesh.endpoint.String()
				ac.ClusterCIDR, ac.MeshCIDR = resp.GetNetwork().GetClusterCidr(), resp.GetNetwork().GetMeshCidr()
				if err := upMesh(dataDir, &ac, resp.Network, slog.New(slog.DiscardHandler)); err != nil {
					return fmt.Errorf("%w; fix it and run `armada server delete %s` on the cluster before trying again", err, name)
				}
			}
			if err := saveAgentConfig(dataDir, ac); err != nil {
				return err
			}
			if _, err := agent.LoadCredentials(dataDir, name); err != nil {
				return fmt.Errorf("server returned an unusable node certificate: %w", err)
			}
			// Like init: the machine's cluster-admins, and the person who
			// ran this through sudo, can use armada here at once. The cluster
			// already exists, so a failure only warns.
			configs, err := joinedClientConfigs(resp, servers, clientUser)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: client config: %v\n", err)
			}
			groupNote := ""
			if person := sudoUser(); person != nil && clientUser != "" {
				switch joined, err := joinAdminGroup(ctx, person); {
				case err != nil:
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: add %s to the %s group yourself (sudo usermod -aG %s %s): %v\n", person.Username, clientconfig.Group, clientconfig.Group, person.Username, err)
				case joined:
					groupNote = adminGroupNote(person.Username)
				}
			}

			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Joined as control plane node %s (%s).\n", name, ip)
			for _, c := range configs {
				_, _ = fmt.Fprintf(out, "Client config: %s\n", c)
			}
			if groupNote != "" {
				_, _ = fmt.Fprintf(out, "%s.\n", groupNote)
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
	f.StringVar(&privateIP, "private-ip", "", "this machine's private IP (default: the only private IPv4 address; not in a mesh cluster)")
	f.StringVar(&endpoint, "endpoint", "", "mesh clusters (a public ADDR): this machine's public IPv4 address, which other nodes send WireGuard packets to (default: the only public IPv4 address; behind one-to-one NAT, the mapped address)")
	f.StringVar(&name, "name", "", "server and node name (default: hostname)")
	f.StringVar(&dataDir, "data-dir", defaultDataDir, "directory for cluster state and keys")
	f.IntVar(&port, "port", defaultPort, "control plane port on the private IP")
	f.IntVar(&joinPort, "join-port", 0, "join listener port on the private IP (default: --port + 1)")
	f.StringVar(&userName, "user-name", "", "user named in the client config written here (default: the user running it)")
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

// joinUserName returns the user of the client configs a joining server
// writes: userName, else the sudo user, else the current user; "" when not
// run as root (no configs are written).
func joinUserName(userName string) (string, error) {
	if os.Geteuid() != 0 {
		return "", nil
	}
	if userName == "" {
		userName = "admin"
		if person := sudoUser(); person != nil {
			userName = sanitizeName(person.Username, "admin")
		} else if u, err := user.Current(); err == nil {
			userName = sanitizeName(u.Username, "admin")
		}
	}
	if _, err := pki.ParseIdentity(pki.Identity{Kind: pki.KindUser, Name: userName}.String()); err != nil {
		return "", err
	}
	return userName, nil
}

// joinedClientConfigs writes the machine's shared admin config, kept when
// it exists; the person who ran the join reads it through the group
// (joinAdminGroup). The
// certificate names userName (joinUserName) and is signed with the CA the
// cluster handed over, only once the leader recorded the name: the cluster
// refuses certificates of names it has no record of.
func joinedClientConfigs(resp *armadav1.JoinServerResponse, servers []string, userName string) ([]string, error) {
	if userName == "" {
		return nil, nil
	}
	if !resp.GetUserRecorded() {
		return nil, fmt.Errorf("the leader did not record user %s (it may run an older Armada), so no client config was written; "+
			"once every server is upgraded, create the user with `armada rbac user create %s --role cluster-admin -o FILE`", userName, userName)
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
	return written, nil
}
