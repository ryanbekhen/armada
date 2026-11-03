package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

// maxEventsSince matches how long the control plane keeps events.
const maxEventsSince = 24 * time.Hour

func newEventsCommand(g *globals) *cobra.Command {
	var (
		output string
		node   string
		since  time.Duration
		follow bool
	)
	cmd := &cobra.Command{
		Use:   "events [APP]",
		Short: "Show what the cluster did: crashes, rollouts, lost nodes",
		Long: "Show events from the last hour (or --since, at most 24h), oldest first: replicas scheduled,\n" +
			"started, crashed, moved, or removed; rollouts started, completed, failed, or rolled back; nodes\n" +
			"connected, lost, cordoned, or removed; apps that cannot be placed; domains and certificates.\n\n" +
			"With APP, only that app and its replicas; with --node, only that node and its replicas.\n" +
			"An event that repeats within 10 minutes is counted rather than shown again.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if output != outputText && output != outputJSON {
				return fmt.Errorf("unsupported output format %q (want %q or %q)", output, outputText, outputJSON)
			}
			if since < time.Second || since > maxEventsSince {
				return fmt.Errorf("--since must be between 1s and %s", maxEventsSince)
			}
			req := &armadav1.EventsRequest{Node: node, SinceSeconds: int64(since / time.Second), Follow: follow}
			if len(args) == 1 {
				req.App = args[0]
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			stream, err := client.Events(cmd.Context(), req)
			if err != nil {
				return rpcErr(err)
			}
			out := cmd.OutOrStdout()
			header := output == outputText
			for {
				e, err := stream.Recv()
				if errors.Is(err, io.EOF) {
					if header {
						_, _ = fmt.Fprintln(out, "No events.")
					}
					return nil
				}
				if err != nil {
					if cmd.Context().Err() != nil {
						return nil
					}
					return rpcErr(err)
				}
				if output == outputJSON {
					b, err := protojson.Marshal(e)
					if err != nil {
						return err
					}
					_, _ = fmt.Fprintln(out, string(b))
					continue
				}
				if header {
					_, _ = fmt.Fprintf(out, eventFormat, "TIME", "KIND", "OBJECT", "REASON", "COUNT", "MESSAGE")
					header = false
				}
				_, _ = fmt.Fprintf(out, eventFormat, eventTime(e.GetLast().AsTime(), time.Now()), e.GetKind(),
					printable(e.GetObject()), printable(e.GetReason()), fmt.Sprint(e.GetCount()), printable(e.GetMessage()))
			}
		},
	}
	f := cmd.Flags()
	f.StringVarP(&output, "output", "o", outputText, "output format: text or json (one event per line)")
	f.StringVar(&node, "node", "", "only events about this node and its replicas")
	f.DurationVar(&since, "since", time.Hour, "how far back to start (at most 24h)")
	f.BoolVarP(&follow, "follow", "f", false, "keep printing new events")
	return cmd
}

// Fixed widths, so followed events line up without buffering.
const eventFormat = "%-14s  %-11s  %-28s  %-15s  %5s  %s\n"

// eventTime shows the time of day for today's events and the date too for
// older ones.
func eventTime(t, now time.Time) string {
	t = t.Local()
	if y, m, d := t.Date(); y == now.Year() && m == now.Month() && d == now.Day() {
		return t.Format("15:04:05")
	}
	return t.Format("Jan 02 15:04:05")
}

// printable replaces control characters, so a message cannot move the
// cursor or forge lines in the terminal.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}
