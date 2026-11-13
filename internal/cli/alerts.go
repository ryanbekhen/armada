package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/fsutil"
)

const alertLong = "Alerts tell people about events that need them (ADR 0045): a node lost, a\n" +
	"replica out of memory or crashing, a failed rollout, job, certificate, or\n" +
	"backup, and the like. The leader sends a notice to every channel that wants\n" +
	"the event, and a second one when a lasting condition, such as a lost node,\n" +
	"is resolved. Repeats within 10 minutes are not sent again, and a channel gets\n" +
	"at most 20 notices a minute; the rest are summed up in one.\n\n" +
	"A channel is a JSON webhook, Slack, Discord, Telegram, or email (SMTP). Its\n" +
	"URL, bot token, or password is read from a file or stdin (-), stored\n" +
	"encrypted, and never shown. Only cluster admins manage channels."

func newAlertCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "alert",
		Aliases: []string{"alerts"},
		Short:   "Send notices about events to Slack, Discord, Telegram, email, or a webhook",
		Long:    alertLong,
	}
	channel := &cobra.Command{
		Use:     "channel",
		Aliases: []string{"channels"},
		Short:   "Manage where notices go",
		Long:    alertLong,
	}
	channel.AddCommand(newAlertChannelCommand(g, true), newAlertChannelCommand(g, false), newAlertListCommand(g),
		&cobra.Command{
			Use:     "delete NAME",
			Aliases: []string{"rm"},
			Short:   "Delete an alert channel",
			Args:    cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				client, conn, err := dialAdmin(g)
				if err != nil {
					return err
				}
				defer conn.Close()
				if _, err := client.DeleteAlertChannel(cmd.Context(), &armadav1.DeleteAlertChannelRequest{Name: args[0]}); err != nil {
					return RPCError(err)
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Deleted alert channel %s.\n", args[0])
				return err
			},
		})
	test := &cobra.Command{
		Use:   "test NAME",
		Short: "Send a test notice to a channel now",
		Long:  "Send a test notice to a channel and wait for it, so a wrong URL, token,\nchat, or mail server shows at once.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := client.TestAlertChannel(cmd.Context(), &armadav1.TestAlertChannelRequest{Name: args[0]}); err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Sent a test notice to %s.\n", args[0])
			return err
		},
	}
	cmd.AddCommand(channel, test)
	return cmd
}

// alertSecretFlags read a channel's secret; each type uses one.
var alertSecretFlags = []string{"url", "token", "password"}

func newAlertChannelCommand(g *globals, create bool) *cobra.Command {
	var (
		typ, chatID, smtpHost, smtpUser, from string
		to, spaces, reasons                   []string
		secrets                               = map[string]*string{}
	)
	cmd := &cobra.Command{
		Use:   "create NAME --type TYPE",
		Short: "Add an alert channel",
		Long: "Add an alert channel. Without --reason it gets the events that need a person;\n" +
			"--reason names others (--reason all for every event). --space keeps only\n" +
			"events of those spaces' apps (events of nodes and certificates have no\n" +
			"space and are left out then).\n\n" +
			"  webhook   --url -      POST of a JSON object per notice\n" +
			"  slack     --url -      an incoming webhook URL\n" +
			"  discord   --url -      a channel webhook URL\n" +
			"  telegram  --token - --chat-id ID   a bot token from @BotFather and the chat\n" +
			"  email     --smtp-host H:P --from A --to A,B [--smtp-user U --password -]\n\n" +
			"URLs must be https://, or http:// to a private IP address. Email uses TLS on\n" +
			"port 465 and STARTTLS on other ports (plain SMTP only to a private IP).",
		Example: "  armada alert channel create ops --type slack --url - < slack-webhook-url\n" +
			"  armada alert channel create oncall --type telegram --chat-id -1001234567890 --token - < bot-token\n" +
			"  armada alert channel create mail --type email --smtp-host smtp.example.com:587 \\\n" +
			"    --smtp-user alerts@example.com --password - --from alerts@example.com --to ops@example.com < smtp-password\n" +
			"  armada alert test ops",
		Args: cobra.ExactArgs(1),
	}
	if !create {
		cmd.Use, cmd.Short = "update NAME", "Change an alert channel"
		cmd.Long = "Change only the fields given; the type stays. An empty --space or --reason\n" +
			"removes that filter, and --url, --token, or --password replaces the secret."
		cmd.Example = "  armada alert channel update ops --space shop,billing --reason Crashed,OutOfMemory\n" +
			"  armada alert channel update ops --reason ''        # back to the default: warnings\n" +
			"  armada alert channel update ops --url - < new-webhook-url"
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		ch := cmd.Flags().Changed
		req := &armadav1.AlertChannelRequest{
			Channel: &armadav1.AlertChannel{Name: args[0], Type: typ, ChatId: chatID, SmtpHost: smtpHost, SmtpUser: smtpUser,
				From: from, To: to, Spaces: spaces, Reasons: reasons},
			SetChatId: ch("chat-id"), SetSmtp: ch("smtp-host") || ch("smtp-user"), SetFrom: ch("from"), SetTo: ch("to"),
			SetSpaces: ch("space"), SetReasons: ch("reason"),
		}
		for _, f := range alertSecretFlags {
			if !ch(f) {
				continue
			}
			if req.SetSecret {
				return errors.New("give only one of --url, --token, and --password")
			}
			// Never from an argument: shell history keeps those.
			v, err := readSecretArg(cmd, f, *secrets[f])
			if err != nil {
				return err
			}
			req.SetSecret, req.Secret = true, v
		}
		client, conn, err := dialAdmin(g)
		if err != nil {
			return err
		}
		defer conn.Close()
		if create {
			if typ == "" {
				return errors.New("--type is required: webhook, slack, discord, telegram, or email")
			}
			if _, err := client.CreateAlertChannel(cmd.Context(), req); err != nil {
				return RPCError(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Created alert channel %s; send a test notice with: armada alert test %s\n", args[0], args[0])
			return err
		}
		if !req.SetSecret && !req.SetChatId && !req.SetSmtp && !req.SetFrom && !req.SetTo && !req.SetSpaces && !req.SetReasons {
			return errors.New("nothing to change; see armada alert channel update --help")
		}
		if _, err := client.UpdateAlertChannel(cmd.Context(), req); err != nil {
			return RPCError(err)
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Updated alert channel %s.\n", args[0])
		return err
	}
	f := cmd.Flags()
	if create {
		f.StringVar(&typ, "type", "", "webhook, slack, discord, telegram, or email")
	}
	for _, name := range alertSecretFlags {
		var v string
		secrets[name] = &v
	}
	f.StringVar(secrets["url"], "url", "", "file holding the webhook URL (webhook, slack, discord), or - for stdin")
	f.StringVar(secrets["token"], "token", "", "file holding the Telegram bot token, or - for stdin")
	f.StringVar(secrets["password"], "password", "", "file holding the SMTP password, or - for stdin")
	f.StringVar(&chatID, "chat-id", "", "Telegram chat: an ID such as -1001234567890, or @channelname")
	f.StringVar(&smtpHost, "smtp-host", "", "mail server as host:port, e.g. smtp.example.com:587")
	f.StringVar(&smtpUser, "smtp-user", "", "user name at the mail server (with --password)")
	f.StringVar(&from, "from", "", "sender address of the emails")
	f.StringSliceVar(&to, "to", nil, "recipients, comma separated (at most 10)")
	f.StringSliceVar(&spaces, "space", nil, "only events of these spaces' apps, comma separated")
	f.StringSliceVar(&reasons, "reason", nil, "only these event reasons, comma separated, or all (default: the ones that need a person)")
	return cmd
}

// readSecretArg reads a secret flag: a file (mode 0600) or "-" for stdin.
func readSecretArg(cmd *cobra.Command, flag, arg string) ([]byte, error) {
	var b []byte
	var err error
	if arg == "-" {
		b, err = io.ReadAll(io.LimitReader(cmd.InOrStdin(), 64<<10))
	} else {
		b, err = fsutil.ReadPrivateFile(arg)
	}
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", flag, err)
	}
	return bytes.TrimSpace(b), nil
}

func newAlertListCommand(g *globals) *cobra.Command {
	var o *outputFlag
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List alert channels and how sending went",
		Long: "List alert channels. SENT and FAILED count notices since the current leader\n" +
			"started; LAST ERROR says why the last notice that failed did.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.check(); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.ListAlertChannels(cmd.Context(), &armadav1.ListAlertChannelsRequest{})
			if err != nil {
				return RPCError(err)
			}
			if o.json() {
				return printJSON(cmd.OutOrStdout(), resp)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "CHANNEL\tTYPE\tTO\tSPACES\tREASONS\tSENT\tFAILED\tLAST SENT\tLAST ERROR")
			now := time.Now()
			for _, c := range resp.Channels {
				reasons := strings.Join(c.Reasons, ",")
				if reasons == "" {
					reasons = "warnings"
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n", c.Name, c.Type, dash(alertTarget(c)),
					dash(strings.Join(c.Spaces, ",")), reasons, c.Sent, c.Failed, ago(c.LastSent, now), dash(c.LastError))
			}
			return tw.Flush()
		},
	}
	o = addOutput(cmd, false)
	return cmd
}

// alertTarget says where a channel's notices go, without its secret.
func alertTarget(c *armadav1.AlertChannel) string {
	switch c.Type {
	case "telegram":
		return c.ChatId
	case "email":
		return strings.Join(c.To, ",")
	}
	return ""
}
