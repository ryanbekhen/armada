package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/pki"
)

func newAutomationCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "automation",
		Short: "Manage automation identities",
		Long: "Automation identities (ADR 0026) are for tools that manage projects on an\n" +
			"operator's behalf, such as a CI system or a self-service portal. Such a tool\n" +
			"manages the apps, jobs, secrets, domains, and volumes of the projects in its\n" +
			"scope, and nothing else: no nodes, tokens, servers, backups, the network, or\n" +
			"the default project. Only administrators change a scope.",
	}
	cmd.AddCommand(newAutomationSetCommand(g), newAutomationListCommand(g), newAutomationCredentialsCommand(g),
		newAutomationRenewCommand(g), newAutomationRemoveCommand(g))
	return cmd
}

func newAutomationSetCommand(g *globals) *cobra.Command {
	var projects, labels []string
	var create bool
	var quota string
	cmd := &cobra.Command{
		Use:   "set NAME [--project P]... [--create-projects] [--label KEY=VALUE]... [--quota Q]",
		Short: "Create an automation identity or replace its scope",
		Long: "Create an automation identity or replace its scope. --project names a project\n" +
			"it manages (repeat it); --create-projects lets it create projects, which it\n" +
			"then manages, and remove the ones it manages; --label KEY=VALUE allows its\n" +
			"apps to require that node label (repeat it); --quota is the quota of every\n" +
			"project it creates (cpu=4,memory=8Gi,replicas=20,volumes=4,domains=2,\n" +
			"secrets=50,jobs=2; without it they have none). Its certificates stay valid.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &armadav1.SetAutomationRequest{Name: args[0], Projects: projects, CreateProjects: create}
			if quota != "" {
				q, err := parseQuotaFlag(quota)
				if err != nil {
					return err
				}
				req.Quota = q
			}
			allowed := map[string][]string{}
			var keys []string
			for _, l := range labels {
				k, v, ok := strings.Cut(l, "=")
				if !ok || k == "" || v == "" {
					return fmt.Errorf("--label %q: want KEY=VALUE", l)
				}
				if _, seen := allowed[k]; !seen {
					keys = append(keys, k)
				}
				allowed[k] = append(allowed[k], v)
			}
			for _, k := range keys {
				req.Labels = append(req.Labels, &armadav1.LabelAllowance{Key: k, Values: allowed[k]})
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			a, err := client.SetAutomation(cmd.Context(), req)
			if err != nil {
				return rpcErr(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Automation %s manages %s; give a tool its credentials with `armada automation credentials %s`.\n",
				a.Name, scopeText(a), a.Name)
			return err
		},
	}
	cmd.Flags().StringArrayVar(&projects, "project", nil, "a project it manages (repeat for more)")
	cmd.Flags().BoolVar(&create, "create-projects", false, "it may create projects, and remove the ones it manages")
	cmd.Flags().StringArrayVar(&labels, "label", nil, "a node label KEY=VALUE its apps may require (repeat for more)")
	cmd.Flags().StringVar(&quota, "quota", "", "the "+quotaHelp+" of each project it creates")
	return cmd
}

func scopeText(a *armadav1.AutomationInfo) string {
	s := "no projects"
	if len(a.Projects) > 0 {
		s = "projects " + strings.Join(a.Projects, ", ")
	}
	if a.CreateProjects {
		s += " and the projects it creates"
	}
	return s
}

func newAutomationListCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List automation identities",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.ListAutomations(cmd.Context(), &armadav1.ListAutomationsRequest{})
			if err != nil {
				return rpcErr(err)
			}
			if len(resp.Automations) == 0 {
				_, err := fmt.Fprintln(cmd.OutOrStdout(), "No automation identities.")
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "NAME\tPROJECTS\tCREATE\tLABELS\tQUOTA\tCERTIFICATES\tEXPIRES")
			for _, a := range resp.Automations {
				var ls []string
				for _, l := range a.Labels {
					for _, v := range l.Values {
						ls = append(ls, l.Key+"="+v)
					}
				}
				exp := "-"
				if a.CertExpiresAt != nil {
					exp = a.CertExpiresAt.AsTime().Format(time.DateOnly)
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%t\t%s\t%s\t%d\t%s\n", a.Name, dash(strings.Join(a.Projects, ",")), a.CreateProjects,
					dash(strings.Join(ls, ",")), quotaOf(a.Quota), a.Certificates, exp)
			}
			return tw.Flush()
		},
	}
}

func newAutomationCredentialsCommand(g *globals) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "credentials NAME -o FILE",
		Short: "Write a client config for a tool",
		Long: "Create a key and a certificate for automation:NAME and write a client config\n" +
			"(the control plane addresses, the CA, the certificate, and the key) to a new\n" +
			"file with mode 0600. The key is generated here and never sent to the server.\n" +
			"The tool uses it like an admin config (`armada --config FILE` or the API with\n" +
			"its PEM fields). The certificate lasts 90 days: renew it with\n" +
			"`armada automation renew --config FILE`, and cut the tool off at once with\n" +
			"`armada automation remove NAME`.",
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
			keyPEM, csr, err := pki.NewCSR(pki.Identity{Kind: pki.KindAutomation, Name: name})
			if err != nil {
				return errors.New("invalid name: use lowercase letters, digits, and single hyphens")
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.IssueAutomationCertificate(cmd.Context(), &armadav1.IssueAutomationCertificateRequest{Name: name, Csr: csr})
			if err != nil {
				return rpcErr(err)
			}
			tool := &clientconfig.Config{Servers: cc.Servers, CA: string(resp.GetCaCert()), Cert: string(resp.GetCert()), Key: string(keyPEM)}
			if err := tool.SaveFile(out); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s for automation:%s (valid until %s). Keep it with the tool only.\n",
				out, name, resp.GetExpiresAt().AsTime().Format(time.DateOnly))
			return err
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "client config file to create")
	return cmd
}

func newAutomationRenewCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "renew --config FILE",
		Short: "Renew the certificate of an automation client config",
		Long: "Run by the tool with its own client config (--config or ARMADA_CONFIG): get a\n" +
			"new 90-day certificate for a new key and rewrite the file. Every other\n" +
			"certificate of the identity is revoked; the one in the file is replaced.",
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
			if err != nil || id.Kind != pki.KindAutomation {
				return fmt.Errorf("%s does not hold an automation certificate", g.configPath)
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
			resp, err := client.RenewAutomationCertificate(cmd.Context(), &armadav1.RenewAutomationCertificateRequest{Csr: csr})
			if err != nil {
				return rpcErr(err)
			}
			cc.Cert, cc.Key, cc.CA = string(resp.GetCert()), string(keyPEM), string(resp.GetCaCert())
			if err := cc.SaveFile(g.configPath); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Renewed %s (valid until %s).\n", id, resp.GetExpiresAt().AsTime().Format(time.DateOnly))
			return err
		},
	}
}

func newAutomationRemoveCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:     "remove NAME",
		Aliases: []string{"rm", "delete"},
		Short:   "Remove an automation identity and revoke its certificates",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.DeleteAutomation(cmd.Context(), &armadav1.DeleteAutomationRequest{Name: args[0]}); err != nil {
				return rpcErr(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Automation %s removed; its certificates no longer work.\n", args[0])
			return err
		},
	}
}
