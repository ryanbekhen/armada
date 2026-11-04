package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
)

// readTerminalSecret reads a value from the terminal without echo; tests
// replace it.
var readTerminalSecret = func(cmd *cobra.Command) ([]byte, error) {
	f, ok := cmd.InOrStdin().(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return nil, errNotTerminal
	}
	_, _ = fmt.Fprint(cmd.ErrOrStderr(), "Value (input hidden): ")
	b, err := term.ReadPassword(int(f.Fd()))
	_, _ = fmt.Fprintln(cmd.ErrOrStderr())
	return b, err
}

var errNotTerminal = errors.New("not a terminal")

func newSecretCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "secret",
		Aliases: []string{"secrets"},
		Short:   "Manage app secrets (values are write-only)",
		Long: "Secrets are encrypted at rest and only decrypted for the nodes that run the app.\n" +
			"Values are never shown again after they are set and are never accepted as\n" +
			"command-line arguments, which would leak into shell history.",
	}
	cmd.AddCommand(newSecretSetCommand(g), newSecretListCommand(g), newSecretRemoveCommand(g))
	return cmd
}

func newSecretSetCommand(g *globals) *cobra.Command {
	var (
		fromFile   string
		noRollout  bool
		allowEmpty bool
		w          waitFlags
	)
	cmd := &cobra.Command{
		Use:   "set APP NAME",
		Short: "Set a secret from stdin, a hidden prompt, or --from-file",
		Long: "Set a secret from stdin, a hidden prompt, or --from-file.\n\n" +
			"From stdin, one trailing newline is removed (as added by echo); --from-file\n" +
			"stores the file's bytes exactly. If the app's current revision uses the\n" +
			"secret, a new revision with the new value is rolled out (see --no-rollout).",
		Example: "  armada secret set web db-password < password.txt\n" +
			"  printf %s \"$TOKEN\" | armada secret set web api-token\n" +
			"  armada secret set web tls-key --from-file key.pem",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			app, name := args[0], args[1]
			if err := spec.ValidateName(app); err != nil {
				return fmt.Errorf("app: %w", err)
			}
			if err := spec.ValidateSecretName(name); err != nil {
				return err
			}
			value, err := readSecretValue(cmd, fromFile)
			if err != nil {
				return err
			}
			if len(value) == 0 && !allowEmpty {
				return errors.New("the secret value is empty (pass --allow-empty if that is intended)")
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.SetSecret(cmd.Context(), &armadav1.SetSecretRequest{App: app, Name: name, Value: value, Rollout: !noRollout})
			clear(value)
			if err != nil {
				return rpcErr(err)
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Secret %s of app %s set (version %d).\n", name, app, resp.Version)
			if resp.Revision == "" {
				if noRollout {
					_, _ = fmt.Fprintf(out, "Running replicas keep the previous value until the app's next rollout (e.g. `armada deploy`).\n")
				}
				return nil
			}
			_, _ = fmt.Fprintf(out, "Rolling out %s with the new value.\n", resp.Revision)
			if !w.wait {
				return nil
			}
			return waitRollout(cmd.Context(), client, app, resp.Revision, w.timeout, out)
		},
	}
	f := cmd.Flags()
	f.StringVar(&fromFile, "from-file", "", "read the value from this file instead of stdin")
	f.BoolVar(&noRollout, "no-rollout", false, "store the value without rolling out the app")
	f.BoolVar(&allowEmpty, "allow-empty", false, "allow an empty value")
	w.register(cmd)
	return cmd
}

// readSecretValue reads at most secrets.MaxSize bytes from a file, a hidden
// terminal prompt, or piped stdin.
func readSecretValue(cmd *cobra.Command, fromFile string) ([]byte, error) {
	if fromFile != "" {
		f, err := os.Open(fromFile) //nolint:gosec // the operator chooses the file
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return readLimited(f)
	}
	b, err := readTerminalSecret(cmd)
	if err == nil {
		return b, nil
	}
	if !errors.Is(err, errNotTerminal) {
		return nil, err
	}
	b, err = readLimited(cmd.InOrStdin())
	if err != nil {
		return nil, err
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r")), nil
}

func readLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, secrets.MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > secrets.MaxSize {
		return nil, fmt.Errorf("the secret is larger than %d bytes", secrets.MaxSize)
	}
	return b, nil
}

func newSecretListCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:     "list APP",
		Aliases: []string{"ls"},
		Short:   "List an app's secrets (names and versions only)",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.ListSecrets(cmd.Context(), &armadav1.ListSecretsRequest{App: args[0]})
			if err != nil {
				return rpcErr(err)
			}
			if len(resp.Secrets) == 0 {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "App %s has no secrets.\n", args[0])
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "NAME\tVERSION\tUPDATED\tBY\tUSED BY")
			for _, s := range resp.Secrets {
				used := "-"
				if len(s.UsedBy) > 0 {
					used = strings.Join(s.UsedBy, ",")
				}
				_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", s.Name, s.Version,
					s.UpdatedAt.AsTime().Local().Format(time.DateTime), s.UpdatedBy, used)
			}
			return tw.Flush()
		},
	}
}

func newSecretRemoveCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:     "rm APP NAME",
		Aliases: []string{"remove", "delete"},
		Short:   "Delete every version of a secret the app no longer uses",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.DeleteSecret(cmd.Context(), &armadav1.DeleteSecretRequest{App: args[0], Name: args[1]}); err != nil {
				return rpcErr(err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Secret %s of app %s deleted.\n", args[1], args[0])
			return nil
		},
	}
}
