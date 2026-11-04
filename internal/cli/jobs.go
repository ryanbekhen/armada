package cli

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

func newJobCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "job",
		Aliases: []string{"jobs"},
		Short:   "Run and inspect jobs (kind: job)",
		Long: "Jobs run a container to completion, on demand or on a schedule. Deploy one with\n" +
			"`armada deploy -f job.yaml` (kind: job), then start runs with `armada job run` or\n" +
			"let its schedule start them. `armada logs JOB` shows the newest run's output.",
	}
	cmd.AddCommand(newJobRunCommand(g), newJobListCommand(g), newJobRunsCommand(g), newJobCancelCommand(g), newJobRemoveCommand(g))
	return cmd
}

func newJobRunCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "run JOB",
		Short: "Start a run of a job now",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.RunJob(cmd.Context(), &armadav1.RunJobRequest{Job: args[0]})
			if err != nil {
				return rpcErr(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Started run %d of %s; follow it with `armada logs %s -f`\n", resp.Run, args[0], args[0])
			return err
		},
	}
}

func newJobListCommand(g *globals) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List jobs with their schedule and latest run",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkOutput(output); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.ListJobs(cmd.Context(), &armadav1.ListJobsRequest{})
			if err != nil {
				return rpcErr(err)
			}
			resp.Jobs = slices.DeleteFunc(resp.Jobs, func(j *armadav1.JobInfo) bool { return !g.listed(j.Name) })
			out := cmd.OutOrStdout()
			if output == outputJSON {
				return printJSON(out, resp)
			}
			if len(resp.Jobs) == 0 {
				_, err := fmt.Fprintln(out, "No jobs.")
				return err
			}
			now := time.Now()
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "JOB\tSCHEDULE\tLAST RUN\tSTATE\tFINISHED\tNEXT RUN")
			for _, j := range resp.Jobs {
				sched := "-"
				if j.Schedule != "" {
					sched = j.Schedule
					if j.TimeZone != "" {
						sched += " (" + j.TimeZone + ")"
					}
				}
				last, state, finished := "-", "-", "-"
				if r := j.LastRun; r != nil {
					last, state, finished = strconv.FormatInt(r.Run, 10), r.State, ago(r.FinishedAt, now)
				}
				next := "-"
				if j.NextRun != nil {
					next = "in " + humanDuration(j.NextRun.AsTime().Sub(now))
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", j.Name, sched, last, state, finished, next)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", outputText, "output format: text or json")
	return cmd
}

func newJobRunsCommand(g *globals) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "runs JOB",
		Short: "List a job's runs, newest first",
		Long: "List a job's runs, newest first. Finished runs beyond the job's history (5 by default)\n" +
			"are removed; their logs are kept for 24 hours.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			if err := checkOutput(output); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.ListJobRuns(cmd.Context(), &armadav1.ListJobRunsRequest{Job: args[0]})
			if err != nil {
				return rpcErr(err)
			}
			out := cmd.OutOrStdout()
			if output == outputJSON {
				return printJSON(out, resp)
			}
			if len(resp.Runs) == 0 {
				_, err := fmt.Fprintf(out, "No runs yet; start one with `armada job run %s`.\n", args[0])
				return err
			}
			return printRuns(out, resp.Runs, time.Now())
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", outputText, "output format: text or json")
	return cmd
}

func printRuns(out io.Writer, runs []*armadav1.JobRunInfo, now time.Time) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "RUN\tSTATE\tTRIGGER\tATTEMPTS\tNODE\tSTARTED\tDURATION\tEXIT\tMESSAGE")
	for _, r := range runs {
		dur, exit := "-", "-"
		if r.StartedAt != nil {
			end := now
			if r.FinishedAt != nil {
				end = r.FinishedAt.AsTime()
			}
			dur = humanDuration(end.Sub(r.StartedAt.AsTime()))
		}
		// Only an exited container has an exit code; a timeout or a lost
		// node does not.
		if r.State == "succeeded" || r.ExitCode != 0 {
			exit = strconv.Itoa(int(r.ExitCode))
		}
		node := r.Node
		if node == "" {
			node = "-"
		}
		msg := printable(r.Message)
		if msg == "" {
			msg = "-"
		}
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n", r.Run, r.State, r.Trigger, r.Attempts, node, ago(r.StartedAt, now), dur, exit, msg)
	}
	return tw.Flush()
}

func newJobCancelCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "cancel JOB",
		Short: "Stop a job's pending and running runs",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			resp, err := client.CancelJob(cmd.Context(), &armadav1.CancelJobRequest{Job: args[0]})
			if err != nil {
				return rpcErr(err)
			}
			out := cmd.OutOrStdout()
			if len(resp.Runs) == 0 {
				_, err := fmt.Fprintf(out, "%s has no active runs.\n", args[0])
				return err
			}
			for _, r := range resp.Runs {
				if _, err := fmt.Fprintf(out, "Cancelled run %d of %s\n", r, args[0]); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func newJobRemoveCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:     "remove JOB",
		Aliases: []string{"rm", "delete"},
		Short:   "Delete a job, stopping its runs and removing their records and logs",
		Long:    "Delete a job, stopping its runs and removing their records and logs. Its secrets are kept;\nremove them with `armada secret rm`.",
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
			if _, err := client.DeleteJob(cmd.Context(), &armadav1.DeleteJobRequest{Job: args[0]}); err != nil {
				return rpcErr(err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Deleted job %s\n", args[0])
			return err
		},
	}
}

func checkOutput(output string) error {
	if output != outputText && output != outputJSON {
		return fmt.Errorf("unsupported output format %q (want %q or %q)", output, outputText, outputJSON)
	}
	return nil
}

func printJSON(out io.Writer, m proto.Message) error {
	b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(m)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(b))
	return err
}

// ago shows how long ago t was, or "-" if unset.
func ago(t *timestamppb.Timestamp, now time.Time) string {
	if t == nil {
		return "-"
	}
	return humanDuration(now.Sub(t.AsTime())) + " ago"
}

// humanDuration rounds d for display: 42s, 5m, 3h, 2d.
func humanDuration(d time.Duration) string {
	switch {
	case d < 0:
		d = 0
		fallthrough
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
