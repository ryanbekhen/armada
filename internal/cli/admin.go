package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/pki"
)

func newAdminCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "admin", Short: "Manage your administrator credentials"}
	cmd.AddCommand(newAdminRenewCommand(g))
	return cmd
}

func newAdminRenewCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew the administrator certificate in your client config",
		Long: "Get a new one-year certificate for a new key, under the same name, and\n" +
			"rewrite the client config (--config, default ~/.armada/config). Run it\n" +
			"before the current certificate expires: an expired one cannot renew.\n" +
			"`armadad doctor` warns 30 days ahead. The old certificate stays valid\n" +
			"until it expires. For a certificate that has already expired, run\n" +
			"`armadad admin renew` as root on a server.",
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
			if err != nil || id.Kind != pki.KindAdmin {
				return fmt.Errorf("%s does not hold an administrator certificate", g.configPath)
			}
			keyPEM, csr, err := pki.NewCSR(id)
			if err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.RenewAdminCertificate(cmd.Context(), &armadav1.RenewAdminCertificateRequest{Csr: csr})
			if err != nil {
				return RPCError(err)
			}
			certPEM, caPEM, expires := resp.GetCert(), resp.GetCaCert(), resp.GetExpiresAt().AsTime()
			cc.Cert, cc.Key, cc.CA = string(certPEM), string(keyPEM), string(caPEM)
			if err := cc.SaveFile(g.configPath); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Renewed %s (valid until %s).\n", id, expires.Format(time.DateOnly))
			return err
		},
	}
	return cmd
}
