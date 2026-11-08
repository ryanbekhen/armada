package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	var (
		wait    bool
		timeout time.Duration
	)
	cmd := &cobra.Command{
		Use:   "run JOB",
		Short: "Start a run of a job now",
		Long: "Start a run of a job now.\n\n" +
			"With --wait the command ends when the run does and fails unless the run\n" +
			"succeeded, so a script can stop on a failed step such as a migration. A\n" +
			"run still going after --timeout keeps going; cancel it with `armada job cancel`.",
		Example: "  armada job run migrate --wait --timeout 5m",
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
			resp, err := client.RunJob(cmd.Context(), &armadav1.RunJobRequest{Job: args[0]})
			if err != nil {
				return RPCError(err)
			}
			out := cmd.OutOrStdout()
			if !wait {
				_, err = fmt.Fprintf(out, "Started run %d of %s; follow it with `armada logs %s -f`\n", resp.Run, args[0], args[0])
				return err
			}
			_, _ = fmt.Fprintf(out, "Started run %d of %s; waiting for it to end\n", resp.Run, args[0])
			return waitJobRun(cmd.Context(), client, args[0], resp.Run, timeout, out)
		},
	}
	cmd.Flags().BoolVar(&wait, "wait", false, "wait until the run ends; fail unless it succeeded")
	cmd.Flags().DurationVar(&timeout, "timeout", 15*time.Minute, "how long --wait waits")
	return cmd
}

// waitJobRun polls until a run has ended and fails unless it succeeded.
func waitJobRun(ctx context.Context, client armadav1.AdminServiceClient, job string, run int64, timeout time.Duration, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tick := time.NewTicker(waitPoll)
	defer tick.Stop()
	for {
		resp, err := client.ListJobRuns(ctx, &armadav1.ListJobRunsRequest{Job: job})
		switch {
		case err == nil:
			i := slices.IndexFunc(resp.GetRuns(), func(r *armadav1.JobRunInfo) bool { return r.GetRun() == run })
			if i < 0 {
				return fmt.Errorf("run %d of %s is gone; it left the job's history before it could be read", run, job)
			}
			if done, err := jobRunResult(resp.GetRuns()[i]); done {
				if err == nil {
					_, _ = fmt.Fprintf(out, "Run %d of %s succeeded\n", run, job)
				}
				return err
			}
		case ctx.Err() == nil && status.Code(err) != codes.Unavailable:
			// Unavailable passes: the control plane changes leader and the
			// run goes on.
			return RPCError(err)
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("run %d of %s did not end within %s; it keeps going (`armada job cancel %s` stops it)", run, job, timeout, job)
			}
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// jobRunResult reports whether a run has ended, and why when it did not succeed.
func jobRunResult(r *armadav1.JobRunInfo) (bool, error) {
	switch r.GetState() {
	case "pending", "running":
		return false, nil
	case "succeeded":
		return true, nil
	}
	why := r.GetState()
	if c := r.GetExitCode(); c != 0 {
		why += fmt.Sprintf(" with exit code %d", c)
	}
	if m := printable(r.GetMessage()); m != "" {
		why += ": " + m
	}
	return true, fmt.Errorf("run %d of %s %s; see `armada logs %s --run %d`", r.GetRun(), r.GetJob(), why, r.GetJob(), r.GetRun())
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
				return RPCError(err)
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
				return RPCError(err)
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
				return RPCError(err)
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
				return RPCError(err)
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
