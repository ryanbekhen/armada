package daemon

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/store"
)

// recordUser records a user name the cluster has no record of with
// cluster-admin (store.KnowUser) in the state of the server in dataDir,
// before the CA signs a certificate for it outside the API: the cluster
// refuses a later certificate of a name with no record. Tests replace it.
var recordUser = func(ctx context.Context, dataDir, name string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	c, release, err := stateClient(ctx, dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = release() }()
	st, err := store.NewEtcd(ctx, c, etcdPrefix)
	if err != nil {
		return err
	}
	return st.KnowUser(ctx, name)
}

func newUserCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "user", Short: "Recover a user's credentials on a server"}
	cmd.AddCommand(newUserRenewCommand(g))
	return cmd
}

func newUserRenewCommand(g *globals) *cobra.Command {
	dataDir := defaultDataDir
	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew a user certificate with the cluster CA on this server",
		Long: "Get a new one-year certificate for a new key, under the same name, signed\n" +
			"by the cluster CA in the data directory, and rewrite the client config\n" +
			"(--config, default ~/.armada/config, else /etc/armada/admin.config; another\n" +
			"user's config stays theirs, a shared one stays shared).\n" +
			"For a certificate that has already expired; while it is valid,\n" +
			"`armada user renew` does the same through the control plane.\n" +
			"The user keeps the roles on record; a name the cluster has no record of\n" +
			"is recorded first, with cluster-admin (the cluster refuses certificates\n" +
			"of names it has no record of). It needs the cluster state: run it on a\n" +
			"server whose control plane is running or can start.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cc, err := clientconfig.Load(g.configPath)
			if err != nil {
				return err
			}
			cert, err := pki.ParseCertPEM([]byte(cc.Cert))
			if err != nil {
				return fmt.Errorf("%s: %w", g.configPath, err)
			}
			id, err := pki.IdentityFromCert(cert)
			if err == nil {
				id, _ = id.Principal()
			}
			if err != nil || id.Kind != pki.KindUser {
				return fmt.Errorf("%s does not hold a user certificate", g.configPath)
			}
			keyPEM, csr, err := pki.NewCSR(id)
			if err != nil {
				return err
			}
			pem, err := readPrivate(dataDir, fileCACert, fileCAKey)
			if err != nil {
				return err
			}
			ca, err := pki.LoadCA(pem[0], pem[1])
			if err != nil {
				return err
			}
			if err := recordUser(cmd.Context(), dataDir, id.Name); err != nil {
				return fmt.Errorf("record %s in the cluster state: %w", id, err)
			}
			c, err := ca.SignUserCSR(csr, id.Name)
			if err != nil {
				return err
			}
			// The config may be another user's copy: keep it theirs.
			owner, err := os.Stat(g.configPath)
			if err != nil {
				return err
			}
			cc.Cert, cc.Key, cc.CA = string(c.PEM), string(keyPEM), string(ca.CertPEM)
			if err := cc.SaveFile(g.configPath); err != nil {
				return err
			}
			if st, ok := owner.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
				if err := os.Chown(g.configPath, int(st.Uid), int(st.Gid)); err != nil {
					return fmt.Errorf("give %s back to its owner: %w", g.configPath, err)
				}
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Renewed %s (valid until %s).\n", id, c.NotAfter.Format(time.DateOnly))
			return err
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", dataDir, "server data directory holding the cluster CA")
	return cmd
}
