package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
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

// Limits on a file for armada secret import.
const (
	maxEnvKey     = 256
	maxSecretFile = 16 << 20
)

func newSecretCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "secret",
		Aliases: []string{"secrets"},
		Short:   "Manage app secrets (values are write-only)",
		Long: "Secrets are encrypted at rest and only decrypted for the nodes that run the app.\n" +
			"Values are never shown again after they are set and are never accepted as\n" +
			"command-line arguments, which would leak into shell history.",
	}
	cmd.AddCommand(newSecretSetCommand(g), newSecretImportCommand(g), newSecretListCommand(g), newSecretDeleteCommand(g))
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
			if err := spec.ValidateSecretName(name); err != nil {
				return err
			}
			value, err := ReadSecretValue(cmd, fromFile)
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
				return RPCError(err)
			}
			out := cmd.OutOrStdout()
			if resp.Revision == "" {
				_, err := fmt.Fprintf(out, "Set secret %s of %s (version %d).\n", name, app, resp.Version)
				return err
			}
			_, _ = fmt.Fprintf(out, "Set secret %s of %s (version %d); rolling out %s.\n", name, app, resp.Version, resp.Revision)
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

func newSecretImportCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "import APP FILE",
		Short: "Set many secrets from a file of KEY=VALUE lines",
		Long: "Set many secrets from a file of KEY=VALUE lines (- reads stdin).\n\n" +
			"DATABASE_URL becomes the secret database-url. Blank lines and lines starting\n" +
			"with # are skipped. A value is everything after the first =, kept exactly,\n" +
			"quotes included. Nothing rolls out: running replicas keep the previous values\n" +
			"until the app's next update. Run it for each app that needs the values.",
		Example: "  armada secret import api .env\n" +
			"  # then in the spec:\n" +
			"  #   env:\n" +
			"  #     - name: DATABASE_URL\n" +
			"  #       secretRef: database-url",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args[:1]); err != nil {
				return err
			}
			in := cmd.InOrStdin()
			if args[1] != "-" {
				f, err := os.Open(args[1])
				if err != nil {
					return err
				}
				defer f.Close()
				in = f
			}
			entries, err := parseSecretFile(in)
			if err != nil {
				return fmt.Errorf("%s: %w", args[1], err)
			}
			defer func() {
				for _, e := range entries {
					clear(e.value)
				}
			}()
			if len(entries) == 0 {
				return fmt.Errorf("%s has no KEY=VALUE lines", args[1])
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			return importSecrets(cmd.Context(), client, args[0], entries, cmd.OutOrStdout())
		},
	}
}

// secretEntry is one line of a file for armada secret import.
type secretEntry struct {
	key   string
	name  string
	value []byte
}

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// parseSecretFile reads KEY=VALUE lines. Errors name a line by its number and
// never quote it, since a malformed line may well be a secret.
func parseSecretFile(r io.Reader) ([]secretEntry, error) {
	sc := bufio.NewScanner(io.LimitReader(r, maxSecretFile+1))
	sc.Buffer(make([]byte, 0, 64<<10), secrets.MaxSize+maxEnvKey+2)
	var (
		out    []secretEntry
		byName = map[string]int{}
		total  int
	)
	for n := 1; sc.Scan(); n++ {
		total += len(sc.Bytes()) + 1
		line := bytes.TrimSuffix(sc.Bytes(), []byte("\r"))
		if t := bytes.TrimSpace(line); len(t) == 0 || t[0] == '#' {
			continue
		}
		key, value, ok := bytes.Cut(line, []byte("="))
		if !ok || !envKeyRe.Match(key) {
			return nil, fmt.Errorf("line %d: want KEY=VALUE", n)
		}
		name := strings.ReplaceAll(strings.ToLower(string(key)), "_", "-")
		if err := spec.ValidateSecretName(name); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		if first, dup := byName[name]; dup {
			return nil, fmt.Errorf("line %d: secret %s was already set on line %d", n, name, first)
		}
		byName[name] = n
		out = append(out, secretEntry{key: string(key), name: name, value: bytes.Clone(value)})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("a line is larger than %d bytes", secrets.MaxSize)
	}
	if total > maxSecretFile {
		return nil, fmt.Errorf("the file is larger than %d bytes", maxSecretFile)
	}
	return out, nil
}

// importSecrets sets each secret without a rollout. It stops at the first
// failure and says how far it got; running it again is harmless.
func importSecrets(ctx context.Context, client armadav1.AdminServiceClient, app string, entries []secretEntry, out io.Writer) error {
	for i, e := range entries {
		resp, err := client.SetSecret(ctx, &armadav1.SetSecretRequest{App: app, Name: e.name, Value: e.value})
		if err != nil {
			return fmt.Errorf("secret %s (%d of %d set before it): %w", e.name, i, len(entries), RPCError(err))
		}
		_, _ = fmt.Fprintf(out, "%s -> %s (version %d)\n", e.key, e.name, resp.GetVersion())
	}
	_, _ = fmt.Fprintf(out, "Set %d secrets of %s; running replicas get them with the app's next update.\n", len(entries), app)
	return nil
}

// ReadSecretValue reads at most secrets.MaxSize bytes from a file, a hidden
// terminal prompt, or piped stdin.
func ReadSecretValue(cmd *cobra.Command, fromFile string) ([]byte, error) {
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
	var o *outputFlag
	cmd := &cobra.Command{
		Use:     "list APP",
		Aliases: []string{"ls"},
		Short:   "List an app's secrets (names and versions only)",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			if err := o.check(); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.ListSecrets(cmd.Context(), &armadav1.ListSecretsRequest{App: args[0]})
			if err != nil {
				return RPCError(err)
			}
			if o.json() {
				return printJSON(cmd.OutOrStdout(), resp)
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
	o = addOutput(cmd, false)
	return cmd
}

func newSecretDeleteCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:     "delete APP NAME",
		Aliases: []string{"rm"},
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
				return RPCError(err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted secret %s of %s.\n", args[1], args[0])
			return nil
		},
	}
}
