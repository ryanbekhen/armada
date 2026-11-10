package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/netutil"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/store"
)

var nonLabel = regexp.MustCompile(`[^a-z0-9-]+`)

// sanitizeName turns a hostname or user name into an identity-safe label.
func sanitizeName(s, fallback string) string {
	s = strings.ToLower(strings.SplitN(s, ".", 2)[0])
	s = strings.Trim(nonLabel.ReplaceAllString(s, "-"), "-")
	if len(s) > 63 {
		s = strings.TrimRight(s[:63], "-")
	}
	if s == "" {
		return fallback
	}
	return s
}

func newInitCommand(g *globals) *cobra.Command {
	var (
		rtFlags   runtimeFlags
		dataDir   string
		privateIP string
		nodeName  string
		adminName string
		port      int
		cidr      string
		mode      string
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new cluster on this machine",
		Long: "init creates the cluster CA, server and node certificates, the state database,\n" +
			"and an admin client config. Run it once on the first machine, then start `armadad server`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ip, err := resolvePrivateIP(privateIP)
			if err != nil {
				return err
			}
			var ac agentConfig
			if err := rtFlags.apply(&ac, ip); err != nil {
				return err
			}
			if rtFlags.flags.Changed("container-subnet") {
				return errors.New("--container-subnet does not apply to init: every node gets a subnet of --cluster-cidr")
			}
			network, err := clusterNetwork(cidr, mode, ip)
			if err != nil {
				return err
			}
			if port < 1 || port > 65535 {
				return fmt.Errorf("invalid --port %d", port)
			}
			if nodeName == "" {
				h, _ := os.Hostname()
				nodeName = sanitizeName(h, "node-1")
			}
			if adminName == "" {
				adminName = "admin"
				if u, err := user.Current(); err == nil {
					adminName = sanitizeName(u.Username, "admin")
				}
			}
			for _, id := range []pki.Identity{{Kind: pki.KindNode, Name: nodeName}, {Kind: pki.KindAdmin, Name: adminName}} {
				if _, err := pki.ParseIdentity(id.String()); err != nil {
					return err
				}
			}
			listen := net.JoinHostPort(ip.String(), strconv.Itoa(port))

			if err := fsutil.MkdirPrivate(dataDir); err != nil {
				return fmt.Errorf("data dir: %w", err)
			}
			for _, f := range []string{fileCAKey, dirEtcd, fileMasterKey} {
				if _, err := os.Stat(filepath.Join(dataDir, f)); err == nil {
					return fmt.Errorf("%s is already initialized (found %s)", dataDir, f)
				} else if !errors.Is(err, fs.ErrNotExist) {
					return err
				}
			}
			// The admin config goes where every administrator of this
			// machine finds it, unless the operator names another file.
			if !cmd.Flag("config").Changed && os.Getenv(clientconfig.EnvPath) == "" {
				g.configPath = clientconfig.SystemPath
			}
			if _, err := os.Stat(g.configPath); err == nil {
				return fmt.Errorf("client config %s already exists; move it away or pass --config", g.configPath)
			}

			ca, err := pki.NewCA(nodeName)
			if err != nil {
				return err
			}
			caKey, err := ca.KeyPEM()
			if err != nil {
				return err
			}
			srvCert, srvKey, err := ca.Issue(pki.IssueRequest{
				Identity: pki.Identity{Kind: pki.KindServer, Name: nodeName},
				DNSNames: []string{pki.ServerName},
				IPs:      []net.IP{ip.AsSlice()},
				Server:   true,
			})
			if err != nil {
				return err
			}
			nodeKey, csr, err := pki.NewNodeCSR(nodeName)
			if err != nil {
				return err
			}
			nodeCert, err := ca.SignNodeCSR(csr, nodeName, pki.NodeValidity)
			if err != nil {
				return err
			}
			adminCert, adminKey, err := ca.Issue(pki.IssueRequest{Identity: pki.Identity{Kind: pki.KindAdmin, Name: adminName}, Client: true})
			if err != nil {
				return err
			}

			files := map[string][]byte{
				fileCACert: ca.CertPEM, fileCAKey: caKey,
				fileServerCert: srvCert, fileServerKey: srvKey,
				fileNodeCert: nodeCert.PEM, fileNodeKey: nodeKey,
			}
			for name, data := range files {
				if err := fsutil.WriteFileAtomic(filepath.Join(dataDir, name), data, 0o600); err != nil {
					return err
				}
			}

			if err := secrets.GenerateKeyFile(filepath.Join(dataDir, fileMasterKey)); err != nil {
				return fmt.Errorf("master key: %w", err)
			}

			ctx := cmd.Context()
			st, member, err := openState(ctx, dataDir, slog.New(slog.DiscardHandler))
			if err != nil {
				return err
			}
			defer func() { _ = member.Close() }()
			if err := st.UpsertServer(ctx, store.Server{Name: nodeName, PrivateIP: ip.String(), APIAddr: listen, MemberID: member.ID()}); err != nil {
				return err
			}
			if err := st.SetMeta(ctx, metaCluster, pki.Fingerprint(ca.Cert)); err != nil {
				return err
			}
			keys, err := secrets.LoadKeyFile(filepath.Join(dataDir, fileMasterKey))
			if err != nil {
				return err
			}
			if err := st.SetMeta(ctx, metaMasterKey, keys.ID()); err != nil {
				return err
			}
			if err := st.InitNetwork(ctx, network); err != nil {
				return err
			}
			if err := st.UpsertNode(ctx, store.Node{ID: nodeName, PrivateIP: ip.String()}); err != nil {
				return err
			}
			node, err := st.GetNode(ctx, nodeName)
			if err != nil {
				return err
			}
			if _, err := rtFlags.useNodeSubnet(&ac, node.Subnet, network.Mode, ip); err != nil {
				return err
			}
			ac.NodeID = nodeName
			ac.PrivateIP = ip.String()
			ac.Servers = []string{listen}
			if err := saveAgentConfig(dataDir, ac); err != nil {
				return err
			}
			// The first administrator is on record (ADR 0028), with every
			// certificate of its name accepted.
			if err := st.KnowAdmin(ctx, adminName); err != nil {
				return err
			}
			if err := st.RecordNodeCert(ctx, nodeName, store.NodeCert{Serial: nodeCert.Serial, NotAfter: nodeCert.NotAfter}, ""); err != nil {
				return err
			}

			cc := &clientconfig.Config{Servers: []string{listen}, CA: string(ca.CertPEM), Cert: string(adminCert), Key: string(adminKey)}
			shared := false
			if g.configPath == clientconfig.SystemPath {
				if shared, err = cc.SaveShared(g.configPath); err != nil {
					return err
				}
			} else if err := cc.Save(g.configPath); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Cluster initialized.\n\n")
			_, _ = fmt.Fprintf(out, "  node:        %s (%s)\n", nodeName, ip)
			_, _ = fmt.Fprintf(out, "  api:         %s (private, mTLS)\n", listen)
			_, _ = fmt.Fprintf(out, "  network:     %s, cluster CIDR %s (this node %s)\n", network.Mode, network.ClusterCIDR, node.Subnet)
			_, _ = fmt.Fprintf(out, "  data dir:    %s\n", dataDir)
			_, _ = fmt.Fprintf(out, "  admin:       %s, credentials in %s\n", adminName, g.configPath)
			_, _ = fmt.Fprintf(out, "  CA SHA-256:  %s\n\n", pki.Fingerprint(ca.Cert))
			_, _ = fmt.Fprint(out, nextStep("server", dataDir))
			_, _ = fmt.Fprintf(out, "Then add nodes with `armada token create`, and control plane nodes with\n")
			_, _ = fmt.Fprintf(out, "`armada token create --server` (three servers tolerate the loss of one).\n")
			switch {
			case shared:
				_, _ = fmt.Fprintf(out, "The armada client needs no root: members of the %s group read %s.\n", clientconfig.Group, g.configPath)
				_, _ = fmt.Fprintf(out, "Add an administrator with `sudo usermod -aG %s NAME` (they log in again);\n", clientconfig.Group)
				_, _ = fmt.Fprintf(out, "membership is full control of the cluster. For another machine or person,\n")
				_, _ = fmt.Fprintf(out, "`armada admin add NAME -o FILE` makes a config of their own.\n")
			case g.configPath == clientconfig.SystemPath:
				_, _ = fmt.Fprintf(out, "No %s group here, so %s is root's only: create the group\n", clientconfig.Group, g.configPath)
				_, _ = fmt.Fprintf(out, "(groupadd --system %s), then chgrp %s and chmod 0640 it to share it.\n", clientconfig.Group, clientconfig.Group)
			default:
				_, _ = fmt.Fprintf(out, "The armada client needs no root: copy %s to ~/.armada/config\n", g.configPath)
				_, _ = fmt.Fprintf(out, "(mode 0600) of your own user; for other people, `armada admin add NAME -o FILE`.\n")
			}
			_, _ = fmt.Fprintf(out, "Keep %s private: it contains the cluster CA key and the master key\n", dataDir)
			_, _ = fmt.Fprintln(out, "that encrypts secrets. Back it up with `armadad backup`, or secrets are lost.")
			return nil
		},
	}
	f := cmd.Flags()
	rtFlags.register(f)
	f.StringVar(&dataDir, "data-dir", defaultDataDir, "directory for cluster state and keys")
	f.StringVar(&privateIP, "private-ip", "", "this node's private IP; auto-detected if empty")
	f.StringVar(&nodeName, "node-name", "", "node name (default: hostname)")
	f.StringVar(&adminName, "admin-name", "", "admin identity name (default: current user)")
	f.IntVar(&port, "port", defaultPort, "control plane port on the private IP")
	f.StringVar(&cidr, "cluster-cidr", defaultClusterCIDR, "private IPv4 range for containers; each node gets a /24 of it (set once, /12 to /20)")
	f.StringVar(&mode, "network", store.NetworkPlain, "how traffic between nodes' containers travels: plain (VXLAN, not encrypted) or wireguard (encrypted); set once")
	return cmd
}

// defaultClusterCIDR stays clear of the bridge subnet of clusters created
// before the cluster network (ADR 0025).
const defaultClusterCIDR = "10.120.0.0/16"

// clusterNetwork validates --cluster-cidr and --network for a cluster whose
// first node has privateIP.
func clusterNetwork(cidr, mode string, privateIP netip.Addr) (store.Network, error) {
	if mode != store.NetworkPlain && mode != store.NetworkWireGuard {
		return store.Network{}, fmt.Errorf("invalid --network %q: plain or wireguard", mode)
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return store.Network{}, fmt.Errorf("invalid --cluster-cidr: %w", err)
	}
	if err := store.CheckClusterCIDR(p); err != nil {
		return store.Network{}, fmt.Errorf("invalid --cluster-cidr: %w", err)
	}
	if p.Contains(privateIP) {
		return store.Network{}, fmt.Errorf("--cluster-cidr %s contains the private IP %s; pick a range the network does not use", p, privateIP)
	}
	return store.Network{Mode: mode, ClusterCIDR: p}, nil
}

func resolvePrivateIP(flag string) (netip.Addr, error) {
	if flag == "" {
		return netutil.DetectPrivateIP()
	}
	return netutil.CheckPrivateIP(flag)
}
