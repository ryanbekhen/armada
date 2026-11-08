package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/fsutil"
	"github.com/ryanbekhen/armada/internal/pki"
)

func newMetricsCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Credentials for the Prometheus metrics endpoint",
		Long: "The leader serves Prometheus metrics on `armadad server --metrics-listen IP:PORT`,\n" +
			"over TLS, only to metrics (or admin) client certificates.",
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newMetricsCredentialsCommand(g))
	return cmd
}

func newMetricsCredentialsCommand(g *globals) *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "credentials NAME",
		Short: "Create a client certificate that may only scrape metrics",
		Long: "Create a key and a client certificate (metrics:NAME) that may only scrape the\n" +
			"metrics endpoint, and write ca.pem, cert.pem, and key.pem to a new directory.\n" +
			"The key is generated here and never sent to the server. The certificate lasts\n" +
			"a year and cannot be revoked short of replacing the cluster CA: keep the key\n" +
			"with the scraper only.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if _, err := pki.ParseIdentity(pki.KindMetrics + ":" + name); err != nil {
				return errors.New("invalid name: use letters, digits, '.', '_', and '-' (at most 63)")
			}
			if dir == "" {
				dir = "armada-metrics-" + name
			}
			// A new directory: never overwrite another key.
			if err := os.Mkdir(dir, 0o700); err != nil {
				if errors.Is(err, fs.ErrExist) {
					return fmt.Errorf("%s already exists; choose another --output", dir)
				}
				return err
			}
			keyPEM, csr, err := pki.NewCSR(pki.Identity{Kind: pki.KindMetrics, Name: name})
			if err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				_ = os.Remove(dir)
				return err
			}
			defer conn.Close()
			resp, err := client.IssueMetricsCertificate(cmd.Context(), &armadav1.IssueMetricsCertificateRequest{Name: name, Csr: csr})
			if err != nil {
				_ = os.Remove(dir)
				return RPCError(err)
			}
			for _, f := range []struct {
				name string
				data []byte
			}{{"ca.pem", resp.GetCaCert()}, {"cert.pem", resp.GetCert()}, {"key.pem", keyPEM}} {
				if err := fsutil.WriteFileAtomic(filepath.Join(dir, f.name), f.data, 0o600); err != nil {
					return err
				}
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s/{ca,cert,key}.pem for metrics:%s (valid until %s).\n"+
				"Scrape https://<server private IP>:<port>/metrics with them and server name %q.\n",
				dir, name, resp.GetExpiresAt().AsTime().Format(time.DateOnly), pki.ServerName)
			return err
		},
	}
	cmd.Flags().StringVarP(&dir, "output", "o", "", "directory to create for the files (default: armada-metrics-NAME)")
	return cmd
}
