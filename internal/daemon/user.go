package daemon

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/pki"
)

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
			"`armada rbac user renew` does the same through the control plane.\n" +
			"The user keeps the roles on record (cluster-admin for one the cluster\n" +
			"has no record of).",
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
