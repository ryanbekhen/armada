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
	"slices"
	"strconv"
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
		Short:   "Keys and values the apps of a space share (values are write-only)",
		Long: "A secret is a named set of keys in a space; every app and job of the space\n" +
			"can use its keys (SECRET/KEY in a spec, or envFrom). The secret named after\n" +
			"an app is that app's own: a spec's secretRef with no secret names its keys.\n\n" +
			"Values are encrypted at rest, only decrypted for the nodes that run a replica\n" +
			"that uses them, never shown again, and never accepted as command-line\n" +
			"arguments, which would leak into shell history.",
		Example: "  armada secret create db --from-env-file db.env\n" +
			"  armada secret set db PASSWORD < password.txt\n" +
			"  armada secret list\n" +
			"  armada secret show db",
	}
	cmd.AddCommand(newSecretListCommand(g), newSecretShowCommand(g), newSecretCreateCommand(g), newSecretSetCommand(g),
		newSecretUnsetCommand(g), newSecretDeleteCommand(g), newSecretImportCommand(g))
	return cmd
}

// secretID returns the ID of the secret named name in the space (see
// globals.app), after checking the name.
func (g *globals) secretID(name string) (string, error) {
	id, err := g.app(name)
	if err != nil {
		return "", err
	}
	_, short, _ := spec.SplitAppID(id)
	if err := spec.ValidateSecretName(short); err != nil {
		return "", err
	}
	return id, nil
}

func newSecretSetCommand(g *globals) *cobra.Command {
	var (
		fromFile    string
		fromEnvFile string
		noRollout   bool
		allowEmpty  bool
		w           waitFlags
	)
	cmd := &cobra.Command{
		Use:   "set SECRET KEY | SECRET --from-env-file FILE",
		Short: "Set a key from stdin, a hidden prompt, or --from-file; or many from --from-env-file",
		Long: "Set a key of a secret from stdin, a hidden prompt, or --from-file, creating\n" +
			"the secret if it does not exist.\n\n" +
			"From stdin, one trailing newline is removed (as added by echo); --from-file\n" +
			"stores the file's bytes exactly. Every app whose current revision uses the\n" +
			"key rolls out with the new value (see --no-rollout).\n\n" +
			"--from-env-file sets a key for each KEY=VALUE line, keeping the keys as\n" +
			"written; nothing rolls out, so apps get the values with their next deploy.",
		Example: "  armada secret set db PASSWORD < password.txt\n" +
			"  printf %s \"$TOKEN\" | armada secret set api API_TOKEN\n" +
			"  armada secret set tls key --from-file key.pem\n" +
			"  armada secret set db --from-env-file db.env",
		Args: func(cmd *cobra.Command, args []string) error {
			if fromEnvFile != "" {
				if len(args) != 1 {
					return errors.New("--from-env-file takes the secret only: armada secret set SECRET --from-env-file FILE")
				}
				return nil
			}
			return cobra.ExactArgs(2)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			secret, err := g.secretID(args[0])
			if err != nil {
				return err
			}
			if fromEnvFile != "" {
				if fromFile != "" {
					return errors.New("--from-file and --from-env-file: use one")
				}
				return setFromEnvFile(cmd, g, secret, fromEnvFile, false)
			}
			key := args[1]
			if err := spec.ValidateSecretKey(key); err != nil {
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
			resp, err := client.SetSecret(cmd.Context(), &armadav1.SetSecretRequest{App: secret, Name: key, Value: value, Rollout: !noRollout})
			clear(value)
			if err != nil {
				return RPCError(err)
			}
			out := cmd.OutOrStdout()
			revs := resp.GetRevisions()
			if len(revs) == 0 && resp.GetRevision() != "" {
				revs = []string{resp.GetRevision()} // an older server
			}
			if len(revs) == 0 {
				_, err := fmt.Fprintf(out, "Set secret %s of %s (version %d).\n", key, secret, resp.Version)
				return err
			}
			_, _ = fmt.Fprintf(out, "Set secret %s of %s (version %d); rolling out %s.\n", key, secret, resp.Version, strings.Join(revs, ", "))
			if !w.wait {
				return nil
			}
			for _, rev := range revs {
				if err := waitRollout(cmd.Context(), client, rev[:strings.LastIndex(rev, "--r")], rev, w.timeout, out); err != nil {
					return err
				}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&fromFile, "from-file", "", "read the value from this file instead of stdin")
	f.StringVar(&fromEnvFile, "from-env-file", "", "set a key for each KEY=VALUE line of this file (- reads stdin)")
	f.BoolVar(&noRollout, "no-rollout", false, "store the value without rolling out the apps that use it")
	f.BoolVar(&allowEmpty, "allow-empty", false, "allow an empty value")
	w.register(cmd)
	return cmd
}

func newSecretCreateCommand(g *globals) *cobra.Command {
	var fromEnvFile string
	cmd := &cobra.Command{
		Use:   "create SECRET --from-env-file FILE",
		Short: "Create a secret with a key for each KEY=VALUE line of a file",
		Long: "Create a secret with a key for each KEY=VALUE line of a file (- reads stdin),\n" +
			"keeping the keys as written. Blank lines and lines starting with # are\n" +
			"skipped; a value is everything after the first =, kept exactly, quotes\n" +
			"included. It refuses a secret that exists: change one with armada secret set.",
		Example: "  armada secret create db --from-env-file db.env\n" +
			"  # then in a spec:\n" +
			"  #   envFrom:\n" +
			"  #     - secret: db\n" +
			"  #   env:\n" +
			"  #     - name: DATABASE_URL\n" +
			"  #       secretRef: db/DATABASE_URL",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			secret, err := g.secretID(args[0])
			if err != nil {
				return err
			}
			return setFromEnvFile(cmd, g, secret, fromEnvFile, true)
		},
	}
	cmd.Flags().StringVar(&fromEnvFile, "from-env-file", "", "KEY=VALUE lines, one key each (- reads stdin)")
	_ = cmd.MarkFlagRequired("from-env-file")
	return cmd
}

// setFromEnvFile sets a key of secret for each line of file, keys as
// written; with create, only when the secret has no keys yet.
func setFromEnvFile(cmd *cobra.Command, g *globals, secret, file string, create bool) error {
	entries, err := readSecretFile(cmd, file, false)
	if err != nil {
		return err
	}
	defer clearEntries(entries)
	client, conn, err := dialAdmin(g)
	if err != nil {
		return err
	}
	defer conn.Close()
	if create {
		resp, err := client.ListSecrets(cmd.Context(), &armadav1.ListSecretsRequest{App: secret})
		if err != nil {
			return RPCError(err)
		}
		if len(resp.GetSecrets()) > 0 {
			return fmt.Errorf("secret %s exists; change its keys with armada secret set %s KEY, or --from-env-file", secret, secret)
		}
	}
	return importSecrets(cmd.Context(), client, secret, entries, cmd.OutOrStdout())
}

// newSecretImportCommand is the command before ADR 0052, kept working:
// it turns DATABASE_URL into the key database-url.
func newSecretImportCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:    "import APP FILE",
		Short:  "Set many keys of an app's secret from a file of KEY=VALUE lines",
		Hidden: true,
		Long: "Set many keys of an app's secret from a file of KEY=VALUE lines (- reads\n" +
			"stdin). DATABASE_URL becomes the key database-url. Nothing rolls out.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			moved(cmd, "armada secret import APP FILE", "armada secret set APP --from-env-file FILE (which keeps the keys as written)")
			if err := g.qualify(args[:1]); err != nil {
				return err
			}
			entries, err := readSecretFile(cmd, args[1], true)
			if err != nil {
				return err
			}
			defer clearEntries(entries)
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			return importSecrets(cmd.Context(), client, args[0], entries, cmd.OutOrStdout())
		},
	}
}

// readSecretFile reads KEY=VALUE lines from file (- is stdin); with
// convert, DATABASE_URL becomes the key database-url, as before ADR 0052.
func readSecretFile(cmd *cobra.Command, file string, convert bool) ([]secretEntry, error) {
	in := cmd.InOrStdin()
	if file != "-" {
		f, err := os.Open(file) //nolint:gosec // the operator chooses the file
		if err != nil {
			return nil, err
		}
		defer f.Close()
		in = f
	}
	entries, err := parseSecretFile(in, convert)
	if err != nil {
		clearEntries(entries)
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s has no KEY=VALUE lines", file)
	}
	return entries, nil
}

func clearEntries(entries []secretEntry) {
	for _, e := range entries {
		clear(e.value)
	}
}

// secretEntry is one line of a file for armada secret import.
type secretEntry struct {
	key   string
	name  string
	value []byte
}

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// parseSecretFile reads KEY=VALUE lines; with convert, DATABASE_URL becomes
// the key database-url. Errors name a line by its number and never quote it,
// since a malformed line may well be a secret.
func parseSecretFile(r io.Reader, convert bool) ([]secretEntry, error) {
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
		if !ok || (convert && !envKeyRe.Match(key)) || (!convert && spec.ValidateSecretKey(string(key)) != nil) {
			return nil, fmt.Errorf("line %d: want KEY=VALUE, KEY a variable name or lowercase letters, digits, and hyphens", n)
		}
		name := string(key)
		if convert {
			name = strings.ReplaceAll(strings.ToLower(name), "_", "-")
		}
		if err := spec.ValidateSecretKey(name); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		if first, dup := byName[name]; dup {
			return nil, fmt.Errorf("line %d: key %s was already set on line %d", n, name, first)
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

// importSecrets sets each key without a rollout. It stops at the first
// failure and says how far it got; running it again is harmless.
func importSecrets(ctx context.Context, client armadav1.AdminServiceClient, secret string, entries []secretEntry, out io.Writer) error {
	for i, e := range entries {
		resp, err := client.SetSecret(ctx, &armadav1.SetSecretRequest{App: secret, Name: e.name, Value: e.value})
		if err != nil {
			return fmt.Errorf("secret %s (%d of %d set before it): %w", e.name, i, len(entries), RPCError(err))
		}
		if e.name == e.key {
			_, _ = fmt.Fprintf(out, "%s (version %d)\n", e.key, resp.GetVersion())
		} else {
			_, _ = fmt.Fprintf(out, "%s -> %s (version %d)\n", e.key, e.name, resp.GetVersion())
		}
	}
	_, _ = fmt.Fprintf(out, "Set %d secrets of %s; running replicas get them with the app's next update.\n", len(entries), secret)
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
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the secrets of the space (names and key counts only)",
		Example: "  armada secret list\n" +
			"  armada secret list -A",
		// One argument is the command before ADR 0052: an app's keys.
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.check(); err != nil {
				return err
			}
			if len(args) == 1 {
				moved(cmd, "armada secret list APP", "armada secret show APP")
				secret, err := g.secretID(args[0])
				if err != nil {
					return err
				}
				return showSecret(cmd, g, o, secret, "NAME")
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			spaces := []string{g.scope()}
			if g.allSpaces {
				resp, err := client.ListSpaces(cmd.Context(), &armadav1.ListSpacesRequest{})
				if err != nil {
					return RPCError(err)
				}
				spaces = nil
				for _, p := range resp.GetSpaces() {
					spaces = append(spaces, p.GetName())
				}
			}
			all := &armadav1.ListSpaceSecretsResponse{}
			var inSpace []string
			for _, p := range spaces {
				resp, err := client.ListSpaceSecrets(cmd.Context(), &armadav1.ListSpaceSecretsRequest{Space: p})
				if err != nil {
					return RPCError(err)
				}
				for _, sec := range resp.GetSecrets() {
					all.Secrets = append(all.Secrets, sec)
					inSpace = append(inSpace, p)
				}
			}
			if o.json() {
				return printJSON(cmd.OutOrStdout(), all)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			head := "NAME\tKEYS\tUPDATED\tBY\tUSED BY"
			if g.allSpaces {
				head = "SPACE\t" + head
			}
			_, _ = fmt.Fprintln(tw, head)
			for i, sec := range all.GetSecrets() {
				if g.allSpaces {
					_, _ = fmt.Fprintf(tw, "%s\t", inSpace[i])
				}
				used := "-"
				if len(sec.GetUsedBy()) > 0 {
					used = strings.Join(sec.GetUsedBy(), ",")
				}
				_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", sec.GetName(), sec.GetKeys(),
					sec.GetUpdatedAt().AsTime().Local().Format(time.DateTime), sec.GetUpdatedBy(), used)
			}
			return tw.Flush()
		},
	}
	o = addOutput(cmd, false)
	return cmd
}

func newSecretShowCommand(g *globals) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:     "show SECRET",
		Short:   "List a secret's keys, their versions, and the revisions that use them",
		Example: "  armada secret show db",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.check(); err != nil {
				return err
			}
			secret, err := g.secretID(args[0])
			if err != nil {
				return err
			}
			return showSecret(cmd, g, o, secret, "KEY")
		},
	}
	o = addOutput(cmd, false)
	return cmd
}

// showSecret prints a secret's keys; head names the first column (NAME
// for the command before ADR 0052, whose output stays the same).
func showSecret(cmd *cobra.Command, g *globals, o *outputFlag, secret, head string) error {
	client, conn, err := dialAdmin(g)
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := client.ListSecrets(cmd.Context(), &armadav1.ListSecretsRequest{App: secret})
	if err != nil {
		return RPCError(err)
	}
	if o.json() {
		return printJSON(cmd.OutOrStdout(), resp)
	}
	if len(resp.GetSecrets()) == 0 && head == "KEY" {
		return fmt.Errorf("secret %s has no keys; armada secret list shows the space's secrets", secret)
	}
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, head+"\tVERSION\tUPDATED\tBY\tUSED BY")
	for _, s := range resp.Secrets {
		used := usedBy(secret, s.UsedBy)
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", s.Name, s.Version,
			s.UpdatedAt.AsTime().Local().Format(time.DateTime), s.UpdatedBy, used)
	}
	return tw.Flush()
}

func newSecretUnsetCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:     "unset SECRET KEY",
		Short:   "Delete every version of a key no app uses",
		Example: "  armada secret unset db OLD_PASSWORD",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return unsetKey(cmd, g, args[0], args[1])
		},
	}
}

func unsetKey(cmd *cobra.Command, g *globals, name, key string) error {
	secret, err := g.secretID(name)
	if err != nil {
		return err
	}
	if err := spec.ValidateSecretKey(key); err != nil {
		return err
	}
	client, conn, err := dialAdmin(g)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := client.DeleteSecret(cmd.Context(), &armadav1.DeleteSecretRequest{App: secret, Name: key}); err != nil {
		return RPCError(err)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted secret %s of %s.\n", key, secret)
	return nil
}

func newSecretDeleteCommand(g *globals) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "delete SECRET --yes",
		Aliases: []string{"rm"},
		Short:   "Delete a secret with every key, once no app uses it",
		Example: "  armada secret delete old-db --yes",
		// Two arguments are the command before ADR 0052: one key.
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 2 {
				moved(cmd, "armada secret delete APP NAME", "armada secret unset APP NAME")
				return unsetKey(cmd, g, args[0], args[1])
			}
			secret, err := g.secretID(args[0])
			if err != nil {
				return err
			}
			if !yes {
				return fmt.Errorf("this deletes every key of secret %s; pass --yes to confirm", secret)
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.DeleteSecret(cmd.Context(), &armadav1.DeleteSecretRequest{App: secret, Whole: true}); err != nil {
				return RPCError(err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted secret %s.\n", secret)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm deleting every key")
	return cmd
}

// usedBy lists the revisions that use a key, app by app: the revisions of
// the secret's own app as revisionRuns does (r1,r2), others with their app's
// name (worker:r3-r5).
func usedBy(secret string, revisions []string) string {
	if len(revisions) == 0 {
		return "-"
	}
	var apps []string
	byApp := map[string][]string{}
	for _, r := range revisions {
		app := r
		if i := strings.LastIndex(r, "--r"); i > 0 {
			app = r[:i]
		}
		if _, ok := byApp[app]; !ok {
			apps = append(apps, app)
		}
		byApp[app] = append(byApp[app], r)
	}
	var parts []string
	for _, app := range apps {
		runs := revisionRuns(app, byApp[app])
		if app != secret {
			runs = app + ":" + runs
		}
		parts = append(parts, runs)
	}
	return strings.Join(parts, ",")
}

// revisionRuns lists an app's revisions short, runs of consecutive ones as
// one range: api--r20,api--r19,...,api--r11 is r11-r20. A name of another
// form is listed as it is.
func revisionRuns(app string, revisions []string) string {
	if len(revisions) == 0 {
		return "-"
	}
	var nums []int
	for _, r := range revisions {
		n, err := strconv.Atoi(strings.TrimPrefix(r, app+"--r"))
		if err != nil || n < 1 || !strings.HasPrefix(r, app+"--r") {
			return strings.Join(revisions, ",")
		}
		nums = append(nums, n)
	}
	slices.Sort(nums)
	nums = slices.Compact(nums)
	var parts []string
	for i := 0; i < len(nums); {
		j := i
		for j+1 < len(nums) && nums[j+1] == nums[j]+1 {
			j++
		}
		switch j {
		case i:
			parts = append(parts, fmt.Sprintf("r%d", nums[i]))
		case i + 1:
			parts = append(parts, fmt.Sprintf("r%d", nums[i]), fmt.Sprintf("r%d", nums[j]))
		default:
			parts = append(parts, fmt.Sprintf("r%d-r%d", nums[i], nums[j]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}
