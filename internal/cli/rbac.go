package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/pki"
)

// Access control (ADR 0033): users (people) and services (tools) hold
// roles in the cluster or in one space.

const (
	kindUser    = "user"
	kindService = "service"
)

func newPrincipalCommand(g *globals, kind string) *cobra.Command {
	cmd := &cobra.Command{Use: kind, Aliases: []string{kind + "s"}, Short: "People, each with a certificate of their own",
		Long: "Users are people. Each has a certificate of their own and holds roles:\n" +
			"viewer, deployer, or admin in a space (viewer also over the whole cluster),\n" +
			"space-creator, or cluster-admin. Only cluster-admin manages access;\n" +
			"`armada role list` shows the roles and who holds them."}
	if kind == kindService {
		cmd.Short = "Programs such as a CI system, each with a certificate of their own"
		cmd.Long = "Services are programs such as a CI system. Each has certificates of its own\n" +
			"and holds roles like a user; `armada role list` shows the roles and who\n" +
			"holds them."
	}
	cmd.AddCommand(newPrincipalCreateCommand(g, kind), newPrincipalListCommand(g, kind), newPrincipalShowCommand(g, kind),
		newPrincipalCredentialsCommand(g, kind), newRenewOwnCommand(g, kind), newPrincipalUpdateCommand(g, kind),
		newPrincipalDeleteCommand(g, kind))
	return cmd
}

// roleFlags are --role with the explicit --space it is given in.
type roleFlags struct{ role string }

func (r *roleFlags) register(cmd *cobra.Command, usage string) {
	cmd.Flags().StringVar(&r.role, "role", "", usage)
}

// assignment returns the role and its space: --space only when given on
// the command line, never the saved or environment space, so a role
// over the cluster is not given in a space by accident.
func (r *roleFlags) assignment(cmd *cobra.Command, g *globals) *armadav1.RoleAssignment {
	a := &armadav1.RoleAssignment{Role: r.role}
	if f := cmd.Flag("space"); f != nil && f.Changed {
		a.Space = g.space
	}
	return a
}

// labelFlags is --allow-label KEY=VALUE, repeated.
type labelFlags struct{ values []string }

func (l *labelFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&l.values, "allow-label", nil, "a node label KEY=VALUE its apps' placement may require (repeat for more)")
}

func (l *labelFlags) allowances() ([]*armadav1.LabelAllowance, error) {
	allowed := map[string][]string{}
	var keys []string
	for _, s := range l.values {
		k, v, ok := strings.Cut(s, "=")
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("--allow-label %q: want KEY=VALUE", s)
		}
		if _, seen := allowed[k]; !seen {
			keys = append(keys, k)
		}
		allowed[k] = append(allowed[k], v)
	}
	out := make([]*armadav1.LabelAllowance, 0, len(keys))
	for _, k := range keys {
		out = append(out, &armadav1.LabelAllowance{Key: k, Values: allowed[k]})
	}
	return out, nil
}

// newFile refuses to overwrite a file: it may hold another key.
func newFile(path string) error {
	if path == "" {
		return errors.New("give the file to write with -o")
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s already exists; choose another file", path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// writeCredentials writes a client config for key and the issued
// certificate, with the servers of the caller's own config. With ssh, the
// config reaches the servers through that SSH host, so it names the
// servers' own addresses, as the cluster lists them, not the caller's
// (which may be a tunnel on the caller's machine).
func writeCredentials(cmd *cobra.Command, g *globals, client armadav1.AdminServiceClient, out, who, ssh string, keyPEM []byte, resp *armadav1.IssueMetricsCertificateResponse) error {
	cc, err := clientconfig.Load(g.configPath)
	if err != nil {
		return err
	}
	servers := cc.Servers
	if ssh != "" {
		list, err := client.ListServers(cmd.Context(), &armadav1.ListServersRequest{})
		if err != nil {
			return RPCError(err)
		}
		if servers = serverAddrs(list); len(servers) == 0 {
			return errors.New("the cluster lists no server addresses")
		}
	}
	c := &clientconfig.Config{Servers: servers, SSH: ssh, CA: string(resp.GetCaCert()), Cert: string(resp.GetCert()), Key: string(keyPEM)}
	if err := c.SaveFile(out); err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s for %s (valid until %s); it holds a private key, hand it over privately.\n",
		out, who, resp.GetExpiresAt().AsTime().Format(time.DateOnly))
	return err
}

func newPrincipalCreateCommand(g *globals, kind string) *cobra.Command {
	var out, ssh string
	var role roleFlags
	var labels labelFlags
	cmd := &cobra.Command{
		Use:   "create NAME -o FILE [--role ROLE [--space P]] [--allow-label KEY=VALUE]...",
		Short: "Create a user with a certificate of their own",
		Long: "Create a user and write their client config to FILE: a certificate under\n" +
			"their own name (one year) for a key made here. Give them FILE privately; they\n" +
			"keep it as ~/.armada/config, mode 0600. --role gives a first role (in\n" +
			"--space for viewer, deployer, and admin); give more with\n" +
			"`armada role grant`. A user with no role can only renew.",
		Example: "  armada user create ana -o ana.config --role deployer --space shop\n" +
			"  armada user create ops -o ops.config --role cluster-admin\n" +
			"  armada user create ops -o ops.config --role cluster-admin --ssh ops@bastion.example.com",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if ssh != "" {
				if err := clientconfig.CheckSSH(ssh); err != nil {
					return err
				}
			}
			allow, err := labels.allowances()
			if err != nil {
				return err
			}
			var roles []*armadav1.RoleAssignment
			if role.role != "" {
				roles = append(roles, role.assignment(cmd, g))
			}
			if kind == kindUser {
				if err := newFile(out); err != nil {
					return err
				}
				if !pki.ValidName(name) {
					return fmt.Errorf("invalid name %q: letters, digits, '.', '_', '-', at most 63", name)
				}
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if kind == kindService {
				p, err := client.CreateService(cmd.Context(), &armadav1.CreateServiceRequest{Name: name, Roles: roles, Labels: allow})
				if err != nil {
					return RPCError(err)
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Created service %s (%s). Give it a client config with `armada service credentials %s -o FILE`.\n",
					name, rolesText(p.GetRoles()), name)
				return err
			}
			keyPEM, csr, err := pki.NewCSR(pki.Identity{Kind: pki.KindUser, Name: name})
			if err != nil {
				return err
			}
			resp, err := client.CreateUser(cmd.Context(), &armadav1.CreateUserRequest{Name: name, Csr: csr, Roles: roles, Labels: allow})
			if err != nil {
				return RPCError(err)
			}
			return writeCredentials(cmd, g, client, out, "user:"+name, ssh, keyPEM, resp)
		},
	}
	if kind == kindService {
		cmd.Use = "create NAME [--role ROLE [--space P]] [--allow-label KEY=VALUE]..."
		cmd.Short = "Create a service"
		cmd.Long = "Create a service, a tool that uses the API, with a first role (in --space\n" +
			"for viewer, deployer, and admin). Give it a client config with\n" +
			"`armada service credentials`, and more roles with\n" +
			"`armada role grant`."
		cmd.Example = "  armada service create ci --role deployer --space shop\n" +
			"  armada service create portal --role space-creator"
	} else {
		cmd.Flags().StringVarP(&out, "output", "o", "", "client config file to create")
		cmd.Flags().StringVar(&ssh, "ssh", "", "reach the servers through this SSH host ([user@]host or a ~/.ssh/config alias): `ssh -W` to their private addresses, mTLS inside")
	}
	role.register(cmd, "a first role: viewer, deployer, admin (with --space), space-creator, or cluster-admin")
	labels.register(cmd)
	return cmd
}

func rolesText(roles []*armadav1.RoleAssignment) string {
	if len(roles) == 0 {
		return "no role"
	}
	parts := make([]string, len(roles))
	for i, r := range roles {
		parts[i] = r.GetRole()
		if r.GetSpace() != "" {
			parts[i] += " in " + r.GetSpace()
		}
	}
	return strings.Join(parts, ", ")
}

func labelsText(ls []*armadav1.LabelAllowance) string {
	var out []string
	for _, l := range ls {
		for _, v := range l.GetValues() {
			out = append(out, l.GetKey()+"="+v)
		}
	}
	return dash(strings.Join(out, ","))
}

func listPrincipals(cmd *cobra.Command, g *globals, kind string) (*armadav1.ListPrincipalsResponse, error) {
	client, conn, err := dialAdmin(g)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	resp, err := client.ListPrincipals(cmd.Context(), &armadav1.ListPrincipalsRequest{Kind: kind})
	if err != nil {
		return nil, RPCError(err)
	}
	return resp, nil
}

func newPrincipalListCommand(g *globals, kind string) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List " + kind + "s and their roles",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.check(); err != nil {
				return err
			}
			resp, err := listPrincipals(cmd, g, kind)
			if err != nil {
				return err
			}
			if o.json() {
				return printJSON(cmd.OutOrStdout(), resp)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			if kind == kindService {
				_, _ = fmt.Fprintln(tw, "NAME\tROLES\tCERTIFICATES\tEXPIRES")
			} else {
				_, _ = fmt.Fprintln(tw, "NAME\tROLES\tSTATUS\tCREATED BY")
			}
			for _, p := range resp.GetPrincipals() {
				if kind == kindService {
					exp := "-"
					if p.GetCertExpiresAt() != nil {
						exp = p.GetCertExpiresAt().AsTime().Format(time.DateOnly)
					}
					_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", p.GetName(), rolesText(p.GetRoles()), p.GetCertificates(), exp)
					continue
				}
				st := "active"
				if p.GetRemoved() {
					st = "deleted"
				}
				if resp.GetYouKind() == kind && p.GetName() == resp.GetYou() {
					st += " (you)"
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.GetName(), rolesText(p.GetRoles()), st, dash(p.GetCreatedBy()))
			}
			return tw.Flush()
		},
	}
	o = addOutput(cmd, false)
	return cmd
}

func newPrincipalShowCommand(g *globals, kind string) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:   "show NAME",
		Short: "Show a " + kind + "'s roles and allowed node labels",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.check(); err != nil {
				return err
			}
			resp, err := listPrincipals(cmd, g, kind)
			if err != nil {
				return err
			}
			i := slices.IndexFunc(resp.GetPrincipals(), func(p *armadav1.Principal) bool { return p.GetName() == args[0] })
			if i < 0 {
				return fmt.Errorf("%s %s not found", kind, args[0])
			}
			p := resp.GetPrincipals()[i]
			if o.json() {
				return printJSON(cmd.OutOrStdout(), p)
			}
			w := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(w, "%s:%s\n", kind, p.GetName())
			if p.GetRemoved() {
				_, _ = fmt.Fprintln(w, "  status:       deleted")
			}
			_, _ = fmt.Fprintf(w, "  roles:        %s\n", rolesText(p.GetRoles()))
			_, _ = fmt.Fprintf(w, "  node labels:  %s\n", labelsText(p.GetLabels()))
			if p.GetCreatedAt() != nil {
				_, _ = fmt.Fprintf(w, "  created:      %s by %s\n", p.GetCreatedAt().AsTime().Local().Format(time.DateOnly), dash(p.GetCreatedBy()))
			}
			if kind == kindService {
				exp := "-"
				if p.GetCertExpiresAt() != nil {
					exp = p.GetCertExpiresAt().AsTime().Format(time.DateOnly)
				}
				_, _ = fmt.Fprintf(w, "  certificates: %d, newest until %s\n", p.GetCertificates(), exp)
			}
			return nil
		},
	}
	o = addOutput(cmd, false)
	return cmd
}

func newPrincipalCredentialsCommand(g *globals, kind string) *cobra.Command {
	var out, ssh string
	cmd := &cobra.Command{
		Use:   "credentials NAME -o FILE",
		Short: "Write a new client config for a user, revoking their older certificates",
		Long: "Make a key here and a new certificate for user NAME (one year), and write\n" +
			"their client config to FILE. Certificates the user was given before stop\n" +
			"working: use it when a key is lost or leaked.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := newFile(out); err != nil {
				return err
			}
			if ssh != "" {
				if err := clientconfig.CheckSSH(ssh); err != nil {
					return err
				}
			}
			pk := pki.KindUser
			if kind == kindService {
				pk = pki.KindService
			}
			keyPEM, csr, err := pki.NewCSR(pki.Identity{Kind: pk, Name: name})
			if err != nil {
				return fmt.Errorf("invalid name %q", name)
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			req := &armadav1.IssuePrincipalCertificateRequest{Name: name, Csr: csr}
			var resp *armadav1.IssueMetricsCertificateResponse
			if kind == kindService {
				resp, err = client.IssueServiceCertificate(cmd.Context(), req)
			} else {
				resp, err = client.IssueUserCertificate(cmd.Context(), req)
			}
			if err != nil {
				return RPCError(err)
			}
			return writeCredentials(cmd, g, client, out, kind+":"+name, ssh, keyPEM, resp)
		},
	}
	if kind == kindService {
		cmd.Short = "Write a client config for a service"
		cmd.Long = "Make a key here and a certificate for service NAME (90 days), and write a\n" +
			"client config to FILE (mode 0600). The tool uses it with `armada --config\n" +
			"FILE`, or the API with its PEM fields, and renews it with\n" +
			"`armada service renew --config FILE`. Its other certificates stay valid\n" +
			"until it renews or is deleted."
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "client config file to create")
	cmd.Flags().StringVar(&ssh, "ssh", "", "reach the servers through this SSH host ([user@]host or a ~/.ssh/config alias): `ssh -W` to their private addresses, mTLS inside")
	return cmd
}

// newRenewOwnCommand renews the certificate in the caller's own config.
func newRenewOwnCommand(g *globals, kind string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew the user certificate in your client config",
		Long: "Get a new one-year certificate for a new key, under the same name, and\n" +
			"rewrite the client config (--config, default ~/.armada/config, else\n" +
			"/etc/armada/admin.config, which needs sudo). Run it before the current\n" +
			"certificate expires: an expired one cannot renew. `armadad doctor` warns 30\n" +
			"days ahead. The old certificate stays valid until it expires. For one that\n" +
			"has expired, run `armadad user renew` as root on a server.",
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
			if err != nil || id.Kind != kind {
				return fmt.Errorf("%s does not hold a %s certificate", g.configPath, kind)
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
			resp, err := client.RenewOwnCertificate(cmd.Context(), &armadav1.RenewOwnCertificateRequest{Csr: csr})
			if err != nil {
				return RPCError(err)
			}
			cc.Cert, cc.Key, cc.CA = string(resp.GetCert()), string(keyPEM), string(resp.GetCaCert())
			if err := cc.SaveFile(g.configPath); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Renewed %s (valid until %s).\n", id, resp.GetExpiresAt().AsTime().Format(time.DateOnly))
			return err
		},
	}
	if kind == kindService {
		cmd.Use = "renew --config FILE"
		cmd.Short = "Renew the certificate of a service's client config"
		cmd.Long = "Run by the tool with its own client config (--config or ARMADA_CONFIG): get\n" +
			"a new 90-day certificate for a new key and rewrite the file. Every other\n" +
			"certificate of the service is revoked; the one in the file is replaced."
	}
	return cmd
}

func newPrincipalUpdateCommand(g *globals, kind string) *cobra.Command {
	var labels labelFlags
	var clear bool
	cmd := &cobra.Command{
		Use:   "update NAME (--allow-label KEY=VALUE... | --clear-labels)",
		Short: "Replace the node labels a " + kind + "'s apps may require",
		Long: "Replace the node label values the apps a " + kind + " deploys may name in\n" +
			"placement.require (armada.* labels are always allowed): restricted nodes\n" +
			"can be kept for some spaces. Roles change with `armada role grant` and `armada role revoke`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if clear == (len(labels.values) > 0) {
				return errors.New("give --allow-label KEY=VALUE (repeat it) or --clear-labels")
			}
			allow, err := labels.allowances()
			if err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			p, err := client.UpdatePrincipal(cmd.Context(), &armadav1.UpdatePrincipalRequest{Kind: kind, Name: args[0], Labels: allow})
			if err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Updated %s %s: node labels %s.\n", kind, args[0], labelsText(p.GetLabels()))
			return err
		},
	}
	labels.register(cmd)
	cmd.Flags().BoolVar(&clear, "clear-labels", false, "allow no node labels")
	return cmd
}

func newPrincipalDeleteCommand(g *globals, kind string) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "delete NAME --yes",
		Aliases: []string{"rm"},
		Short:   "Delete a " + kind + " and revoke every certificate of it",
		Long: "Revoke every certificate of the " + kind + ", at once and on every server, and\n" +
			"take its roles back. You cannot delete yourself.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				return fmt.Errorf("this revokes every certificate of %s %s; pass --yes to confirm", kind, args[0])
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.DeletePrincipal(cmd.Context(), &armadav1.DeletePrincipalRequest{Kind: kind, Name: args[0]}); err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Deleted %s %s; its certificates are refused.\n", kind, args[0])
			return err
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm deleting")
	return cmd
}

func newRoleCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "role",
		Aliases: []string{"roles"},
		Short:   "List the roles and who holds them; grant and revoke them",
		Long: "Roles are built in: viewer, deployer, or admin in a space (viewer also over\n" +
			"the whole cluster), space-creator, and cluster-admin. Users and services\n" +
			"hold them; only cluster-admin grants and revokes them.",
	}
	var lo, so *outputFlag
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the roles, where each may be given, and who holds it",
		Long: "List the roles, where each may be given, and who holds it: a user or\n" +
			"service, with the space in parentheses for a role given in one.\n" +
			"`armada role show ROLE` says what a role allows.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := lo.check(); err != nil {
				return err
			}
			resp, err := listRoles(cmd, g)
			if err != nil {
				return err
			}
			if lo.json() {
				return printJSON(cmd.OutOrStdout(), resp)
			}
			// Only cluster-admin lists who holds what; others see the roles.
			holders, err := roleHolders(cmd, g)
			if err != nil && status.Code(err) != codes.PermissionDenied {
				return RPCError(err)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			if holders == nil {
				_, _ = fmt.Fprintln(tw, "ROLE\tGIVEN IN")
			} else {
				_, _ = fmt.Fprintln(tw, "ROLE\tGIVEN IN\tHELD BY")
			}
			for _, r := range resp.GetRoles() {
				if holders == nil {
					_, _ = fmt.Fprintf(tw, "%s\t%s\n", r.GetName(), roleScope(r))
					continue
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", r.GetName(), roleScope(r), dash(strings.Join(holders[r.GetName()], ", ")))
			}
			return tw.Flush()
		},
	}
	show := &cobra.Command{
		Use:   "show ROLE",
		Short: "Show what a role allows and the API methods it reaches",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := so.check(); err != nil {
				return err
			}
			resp, err := listRoles(cmd, g)
			if err != nil {
				return err
			}
			i := slices.IndexFunc(resp.GetRoles(), func(r *armadav1.RoleInfo) bool { return r.GetName() == args[0] })
			if i < 0 {
				names := make([]string, 0, len(resp.GetRoles()))
				for _, r := range resp.GetRoles() {
					names = append(names, r.GetName())
				}
				return fmt.Errorf("unknown role %q; the roles: %s", args[0], strings.Join(names, ", "))
			}
			r := resp.GetRoles()[i]
			if so.json() {
				return printJSON(cmd.OutOrStdout(), r)
			}
			w := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(w, "%s\n  given in:  %s\n  allows:    %s\n  methods:   %s\n", r.GetName(), roleScope(r), r.GetDescription(),
				strings.Join(r.GetMethods(), ", "))
			return nil
		},
	}
	lo, so = addOutput(list, false), addOutput(show, false)
	cmd.AddCommand(list, show, newRoleChangeCommand(g, true), newRoleChangeCommand(g, false))
	return cmd
}

// roleHolders lists who holds each role: "user ana (shop)", "service ci".
func roleHolders(cmd *cobra.Command, g *globals) (map[string][]string, error) {
	client, conn, err := dialAdmin(g)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	resp, err := client.ListPrincipals(cmd.Context(), &armadav1.ListPrincipalsRequest{})
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, p := range resp.GetPrincipals() {
		for _, r := range p.GetRoles() {
			h := p.GetKind() + " " + p.GetName()
			if r.GetSpace() != "" {
				h += " (" + r.GetSpace() + ")"
			}
			out[r.GetRole()] = append(out[r.GetRole()], h)
		}
	}
	return out, nil
}

func roleScope(r *armadav1.RoleInfo) string {
	switch {
	case r.GetCluster() && r.GetSpace():
		return "the cluster, or a space"
	case r.GetCluster():
		return "the cluster"
	}
	return "a space"
}

func listRoles(cmd *cobra.Command, g *globals) (*armadav1.ListRolesResponse, error) {
	client, conn, err := dialAdmin(g)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	resp, err := client.ListRoles(cmd.Context(), &armadav1.ListRolesRequest{})
	if err != nil {
		return nil, RPCError(err)
	}
	return resp, nil
}

// principalFlags is --user NAME or --service NAME.
type principalFlags struct{ user, service string }

func (p *principalFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&p.user, "user", "", "the user")
	cmd.Flags().StringVar(&p.service, "service", "", "the service")
}

func (p *principalFlags) get(required bool) (kind, name string, err error) {
	switch {
	case p.user != "" && p.service != "":
		return "", "", errors.New("give --user or --service, not both")
	case p.user != "":
		return kindUser, p.user, nil
	case p.service != "":
		return kindService, p.service, nil
	case required:
		return "", "", errors.New("give --user NAME or --service NAME")
	}
	return "", "", nil
}

func newRoleChangeCommand(g *globals, grant bool) *cobra.Command {
	var who principalFlags
	cmd := &cobra.Command{
		Use:   "grant ROLE (--user NAME | --service NAME) [--space SPACE]",
		Short: "Give a user or service a role",
		Long: "Give a role: viewer (in --space, or without it over the whole cluster),\n" +
			"deployer or admin (in --space; not in default), space-creator, or\n" +
			"cluster-admin. It applies to the next call the user or service makes.",
		Example: "  armada role grant deployer --user ana --space shop\n" +
			"  armada role grant viewer --service ci",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, name, err := who.get(true)
			if err != nil {
				return err
			}
			role := roleFlags{role: args[0]}
			req := &armadav1.AssignmentRequest{Kind: kind, Name: name, Role: role.assignment(cmd, g)}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			call, verb := client.CreateAssignment, "Gave"
			if !grant {
				call, verb = client.DeleteAssignment, "Took back"
			}
			p, err := call(cmd.Context(), req)
			if err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s %s; %s %s now holds %s.\n", verb, rolesText([]*armadav1.RoleAssignment{req.GetRole()}),
				kind, name, rolesText(p.GetRoles()))
			return err
		},
	}
	if !grant {
		cmd.Use = "revoke ROLE (--user NAME | --service NAME) [--space SPACE]"
		cmd.Short = "Take a role back from a user or service"
		cmd.Long = "Take a role back. You cannot take cluster-admin from yourself."
		cmd.Example = "  armada role revoke deployer --user ana --space shop"
	}
	who.register(cmd)
	return cmd
}
