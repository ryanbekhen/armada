package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/pki"
)

func newAdminCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "admin", Short: "Manage administrators and your own credentials"}
	cmd.AddCommand(newAdminCreateCommand(g), newAdminListCommand(g), newAdminRenewCommand(g), newAdminDeleteCommand(g))
	return cmd
}

func newAdminCreateCommand(g *globals) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "create NAME -o FILE",
		Short: "Give a person an administrator certificate of their own",
		Long: "Create a client config for a new administrator, with a certificate under\n" +
			"their own name (one year), so the audit log names them and their access\n" +
			"can be removed alone. Give them FILE (it holds their private key); they\n" +
			"keep it as ~/.armada/config, mode 0600. Certificates the name was given\n" +
			"before stop working. An administrator has full control of the cluster.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if out == "" {
				return errors.New("give the file to write with -o")
			}
			// Never overwrite another key.
			if _, err := os.Lstat(out); err == nil {
				return fmt.Errorf("%s already exists; choose another file", out)
			} else if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			cc, err := clientconfig.Load(g.configPath)
			if err != nil {
				return err
			}
			if !pki.ValidName(name) {
				return fmt.Errorf("invalid name %q: letters, digits, '.', '_', '-', at most 63", name)
			}
			keyPEM, csr, err := pki.NewCSR(pki.Identity{Kind: pki.KindAdmin, Name: name})
			if err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.AddAdmin(cmd.Context(), &armadav1.AddAdminRequest{Name: name, Csr: csr})
			if err != nil {
				return RPCError(err)
			}
			person := &clientconfig.Config{Servers: cc.Servers, CA: string(resp.GetCaCert()), Cert: string(resp.GetCert()), Key: string(keyPEM)}
			if err := person.SaveFile(out); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s for admin:%s (valid until %s): full control of the cluster, hand it over privately.\n",
				out, name, resp.GetExpiresAt().AsTime().Format(time.DateOnly))
			return err
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "client config file to create")
	return cmd
}

func newAdminListCommand(g *globals) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the administrators on record",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.check(); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.ListAdmins(cmd.Context(), &armadav1.ListAdminsRequest{})
			if err != nil {
				return RPCError(err)
			}
			if o.json() {
				return printJSON(cmd.OutOrStdout(), resp)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "NAME\tSTATUS\tADDED\tBY")
			for _, a := range resp.GetAdmins() {
				st, added, by := "active", "-", a.GetAddedBy()
				if a.GetRemoved() {
					st = "removed"
				}
				if a.GetName() == resp.GetYou() {
					st += " (you)"
				}
				if a.GetAddedAt() != nil {
					added = a.GetAddedAt().AsTime().Local().Format(time.DateOnly)
				}
				if by == "" {
					by = "-"
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.GetName(), st, added, by)
			}
			return tw.Flush()
		},
	}
	o = addOutput(cmd, false)
	return cmd
}

func newAdminDeleteCommand(g *globals) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "delete NAME --yes",
		Aliases: []string{"rm"},
		Short:   "Revoke every certificate of an administrator",
		Long: "Revoke every certificate of an administrator, at once and on every\n" +
			"server. `armada admin create NAME` gives the name a new one later. You\n" +
			"cannot delete yourself.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				return fmt.Errorf("this revokes every certificate of %s; pass --yes to confirm", args[0])
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.RemoveAdmin(cmd.Context(), &armadav1.RemoveAdminRequest{Name: args[0]}); err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Deleted administrator %s: their certificates are refused.\n", args[0])
			return err
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm deleting the administrator")
	return cmd
}

func newAdminRenewCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew the administrator certificate in your client config",
		Long: "Get a new one-year certificate for a new key, under the same name, and\n" +
			"rewrite the client config (--config, default ~/.armada/config, else\n" +
			"/etc/armada/admin.config, which needs sudo). Run it\n" +
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
